import json
import subprocess
import sys
import textwrap

import pytest
from src.steps.common import StepsCommon
from src.libs.common import to_base64
from src.env_vars import NODE_1
from src.node.waku_node import WakuNode
from src.node.wrappers_manager import WrapperManager
from src.node.wrapper_helpers import (
    EventCollector,
    assert_event_invariants,
    create_message_bindings,
    get_node_multiaddr,
    wait_for_connected,
    wait_for_propagated,
    wait_for_sent,
    wait_for_error,
)
from src.test_data import DEFAULT_CLUSTER_ID
from tests.wrappers_tests.conftest import build_node_config

PROPAGATED_TIMEOUT_S = 30.0
SENT_AFTER_STORE_TIMEOUT_S = 60.0

# Default-cluster shard-0 pubsub topic; used to subscribe the S11 docker store
# peer so it joins the same relay mesh as the wrapper nodes (wrapper config
# uses numShardsInNetwork=1 => shard 0).
STORE_PEER_PUBSUB_TOPIC = f"/waku/2/rs/{DEFAULT_CLUSTER_ID}/0"

S01_EXPECTED_ERROR_FRAGMENT = "not initialized"
S01_SUBPROCESS_TIMEOUT_S = 30
S01_RESULT_MARKER = "__S01_RESULT__"
SEND_AFTER_DESTROY_RESULT_MARKER = "__SEND_AFTER_DESTROY_RESULT__"
SEND_AFTER_DESTROY_SUBPROCESS_TIMEOUT_S = 60

# S05: malformed content topics break shard resolution inside
# SubscriptionManager.subscribe(), forcing the auto-subscribe step to fail.
# Each case targets a distinct validator branch.
# Fragment match: the bindings return Err("Failed to auto-subscribe before
# sending: ..."). We match on the capitalized verb phrase "Failed to
# auto-subscribe" because the bare word "auto-subscribe" also appears in
# success-path log strings (e.g. "Auto-subscribing to topic on send") and
# would produce false positives if we matched on that.
S05_EXPECTED_ERROR_FRAGMENT = "Failed to auto-subscribe"
S05_MALFORMED_CONTENT_TOPICS = [
    # No leading slash — parser rejects with "must start with slash".
    ("s05-invalid-no-leading-slash", "no-leading-slash"),
    # Empty string — parser rejects empty content topic.
    ("", "empty"),
    # Only 3 segments — content topics need /app/version/name/encoding.
    ("/app/1/name", "missing-encoding-segment"),
    # Empty middle segment between slashes.
    ("/app//name/proto", "empty-middle-segment"),
]


# Run send() in a subprocess so a missing C-ABI guard (which can SIGSEGV)
# fails the test cleanly instead of taking the runner down.
_S01_SUBPROCESS_SCRIPT = textwrap.dedent(
    f"""
    import json
    import sys
    from pathlib import Path

    _project_root = Path({repr(__file__)}).resolve().parents[2]
    _bindings_path = _project_root / "vendor" / "logos-delivery-python-bindings" / "waku"
    if str(_bindings_path) not in sys.path:
        sys.path.insert(0, str(_bindings_path))
    if str(_project_root) not in sys.path:
        sys.path.insert(0, str(_project_root))

    from wrapper import NodeWrapper, ffi
    from src.node.wrappers_manager import WrapperManager
    from src.node.wrapper_helpers import create_message_bindings

    sender = WrapperManager(NodeWrapper(ctx=ffi.NULL, config_buffer=None, event_cb_handler=None))
    send_result = sender.send_message(message=create_message_bindings())

    print({repr(S01_RESULT_MARKER)} + json.dumps({{
        "is_ok": send_result.is_ok(),
        "ok": send_result.ok_value if send_result.is_ok() else None,
        "err": send_result.err() if send_result.is_err() else None,
    }}))
    sys.exit(0)
    """
).strip()


# Uses destroy_keep_ctx() so self.ctx stays non-nil after destroy — forces
# the send call to reach the C side with the original (now-stale) pointer.
_SEND_AFTER_DESTROY_SUBPROCESS_SCRIPT = textwrap.dedent(
    f"""
    import json
    import sys
    from pathlib import Path

    _project_root = Path({repr(__file__)}).resolve().parents[2]
    _bindings_path = _project_root / "vendor" / "logos-delivery-python-bindings" / "waku"
    if str(_bindings_path) not in sys.path:
        sys.path.insert(0, str(_bindings_path))
    if str(_project_root) not in sys.path:
        sys.path.insert(0, str(_project_root))

    from src.node.wrappers_manager import WrapperManager
    from src.node.wrapper_helpers import EventCollector, create_message_bindings
    from tests.wrappers_tests.conftest import build_node_config

    collector = EventCollector()

    create_result = WrapperManager.create_and_start(
        config=build_node_config(),
        event_cb=collector.event_callback,
    )
    if create_result.is_err():
        print({repr(SEND_AFTER_DESTROY_RESULT_MARKER)} + json.dumps({{
            "stage": "create_and_start",
            "is_ok": False,
            "ok": None,
            "err": create_result.err(),
            "events_after_send": [],
        }}))
        sys.exit(0)

    sender = create_result.ok_value

    stop_result = sender.stop_node()
    if stop_result.is_err():
        print({repr(SEND_AFTER_DESTROY_RESULT_MARKER)} + json.dumps({{
            "stage": "stop_node",
            "is_ok": False,
            "ok": None,
            "err": stop_result.err(),
            "events_after_send": [],
        }}))
        sys.exit(0)

    destroy_result = sender.destroy_keep_ctx()
    if destroy_result.is_err():
        print({repr(SEND_AFTER_DESTROY_RESULT_MARKER)} + json.dumps({{
            "stage": "destroy_keep_ctx",
            "is_ok": False,
            "ok": None,
            "err": destroy_result.err(),
            "events_after_send": [],
        }}))
        sys.exit(0)

    events_before_send = len(collector.events)

    envelope = create_message_bindings()
    send_result = sender.send_message(message=envelope)

    new_events = collector.events[events_before_send:]

    payload = {{
        "stage": "send_message",
        "is_ok": send_result.is_ok(),
        "ok": send_result.ok_value if send_result.is_ok() else None,
        "err": send_result.err() if send_result.is_err() else None,
        "events_after_send": [str(e) for e in new_events],
    }}
    print({repr(SEND_AFTER_DESTROY_RESULT_MARKER)} + json.dumps(payload))
    sys.exit(0)
    """
).strip()


class TestS01NilOrUninitializedHandle(StepsCommon):
    """S01 — send() on a nil/destroyed handle must Err, no events, no crash."""

    def test_s01_send_on_uninitialized_handle(self):
        completed = subprocess.run(
            [sys.executable, "-c", _S01_SUBPROCESS_SCRIPT],
            capture_output=True,
            text=True,
            timeout=S01_SUBPROCESS_TIMEOUT_S,
        )

        assert completed.returncode == 0, (
            f"send() crashed on a nil handle (returncode={completed.returncode}). " f"stdout={completed.stdout!r} stderr={completed.stderr!r}"
        )

        result_line = next(
            (l for l in completed.stdout.splitlines() if l.startswith(S01_RESULT_MARKER)),
            None,
        )
        assert result_line, f"missing result marker. stdout={completed.stdout!r} stderr={completed.stderr!r}"

        result = json.loads(result_line[len(S01_RESULT_MARKER) :])

        assert result["is_ok"] is False, f"expected Err, got Ok({result['ok']!r})"
        assert S01_EXPECTED_ERROR_FRAGMENT in (
            result["err"] or ""
        ), f"expected error to mention {S01_EXPECTED_ERROR_FRAGMENT!r}, got: {result['err']!r}"

    def test_s01_send_on_destroyed_handle(self):
        completed = subprocess.run(
            [sys.executable, "-c", _SEND_AFTER_DESTROY_SUBPROCESS_SCRIPT],
            capture_output=True,
            text=True,
            timeout=SEND_AFTER_DESTROY_SUBPROCESS_TIMEOUT_S,
        )

        assert completed.returncode == 0, (
            f"send() crashed on a destroyed handle (returncode={completed.returncode}). " f"stdout={completed.stdout!r} stderr={completed.stderr!r}"
        )

        result_line = next(
            (l for l in completed.stdout.splitlines() if l.startswith(SEND_AFTER_DESTROY_RESULT_MARKER)),
            None,
        )
        assert result_line, f"missing result marker. stdout={completed.stdout!r} stderr={completed.stderr!r}"

        result = json.loads(result_line[len(SEND_AFTER_DESTROY_RESULT_MARKER) :])

        assert result["stage"] == "send_message", f"setup failed at stage {result['stage']!r}: {result['err']!r}"
        assert result["is_ok"] is False, f"expected Err, got Ok({result['ok']!r})"
        assert S01_EXPECTED_ERROR_FRAGMENT in (
            result["err"] or ""
        ), f"expected error to mention {S01_EXPECTED_ERROR_FRAGMENT!r}, got: {result['err']!r}"
        assert result["events_after_send"] == [], f"expected no events after send(), got: {result['events_after_send']}"


class TestS03SendOnAlreadySubscribedTopic(StepsCommon):
    """
    S03 — Send on already-subscribed content topic.
    Sender explicitly calls subscribe_content_topic() before send().
    The send path must behave identically to the auto-subscribe case:
    Propagated arrives, no Sent (store disabled), no Error.
    Topology mirrors S06 (relay-only sender + relay peer, no store).
    Purpose: proves the send path is identical when auto-subscription is skipped.
    """

    def test_s03_send_on_already_subscribed_content_topic(self, node_config):
        sender_collector = EventCollector()
        content_topic = "/test/1/s03-already-subscribed/proto"

        node_config.update(
            {
                "relay": True,
                "store": False,
                "lightpush": False,
                "filter": False,
                "discv5Discovery": False,
                "numShardsInNetwork": 1,
                "reliabilityEnabled": True,
            }
        )

        sender_result = WrapperManager.create_and_start(
            config=node_config,
            event_cb=sender_collector.event_callback,
        )
        assert sender_result.is_ok(), f"Failed to start sender: {sender_result.err()}"

        with sender_result.ok_value as sender:
            peer_config = {
                **node_config,
                "staticnodes": [get_node_multiaddr(sender)],
                "portsShift": 1,
            }

            peer_result = WrapperManager.create_and_start(config=peer_config)
            assert peer_result.is_ok(), f"Failed to start relay peer: {peer_result.err()}"

            with peer_result.ok_value:
                assert wait_for_connected(sender_collector) is not None, "Sender did not reach Connected/PartiallyConnected state"

                # Explicit subscribe before send — this is what S03 is about.
                # The send path must still return Ok(RequestId) and emit the
                # same events as the auto-subscribe topology in S06.
                subscribe_result = sender.subscribe_content_topic(content_topic)
                assert subscribe_result.is_ok(), f"subscribe_content_topic failed: {subscribe_result.err()}"

                message = create_message_bindings(
                    payload=to_base64("S03 already-subscribed test payload"),
                    contentTopic=content_topic,
                )

                send_result = sender.send_message(message=message)
                assert send_result.is_ok(), f"send() failed: {send_result.err()}"

                request_id = send_result.ok_value
                assert request_id, "send() returned an empty RequestId"

                propagated = wait_for_propagated(
                    collector=sender_collector,
                    request_id=request_id,
                    timeout_s=PROPAGATED_TIMEOUT_S,
                )
                assert propagated is not None, (
                    f"No message_propagated event within {PROPAGATED_TIMEOUT_S}s. " f"Collected events: {sender_collector.events}"
                )
                assert propagated["requestId"] == request_id

                error = wait_for_error(sender_collector, request_id, timeout_s=0)
                assert error is None, f"Unexpected message_error event: {error}"

                sent = wait_for_sent(sender_collector, request_id, timeout_s=0)
                assert sent is None, f"Unexpected message_sent event (store is disabled): {sent}"

                assert_event_invariants(sender_collector, request_id)


class TestS04UnsubscribeThenSendSameTopic(StepsCommon):
    """
    S04 — Unsubscribe, then send the same content topic again.
    Sender subscribes to topic A, unsubscribes from A, then sends on A.
    The send path must re-establish topic interest and deliver normally.
    Topology mirrors S06 (relay-only sender + relay peer, no store).
    Expected: send() returns Ok(RequestId), Propagated arrives,
    no Sent (store disabled), no Error.
    Purpose: verifies send() re-establishes topic interest after local unsubscribe.
    """

    def test_s04_unsubscribe_then_send_same_content_topic(self, node_config):
        sender_collector = EventCollector()
        content_topic = "/test/1/s04-unsubscribe-resend/proto"

        node_config.update(
            {
                "relay": True,
                "store": False,
                "lightpush": False,
                "filter": False,
                "discv5Discovery": False,
                "numShardsInNetwork": 1,
                "reliabilityEnabled": True,
            }
        )

        sender_result = WrapperManager.create_and_start(
            config=node_config,
            event_cb=sender_collector.event_callback,
        )
        assert sender_result.is_ok(), f"Failed to start sender: {sender_result.err()}"

        with sender_result.ok_value as sender:
            peer_config = {
                **node_config,
                "staticnodes": [get_node_multiaddr(sender)],
                "portsShift": 1,
            }

            peer_result = WrapperManager.create_and_start(config=peer_config)
            assert peer_result.is_ok(), f"Failed to start relay peer: {peer_result.err()}"

            with peer_result.ok_value:
                assert wait_for_connected(sender_collector) is not None, "Sender did not reach Connected/PartiallyConnected state"

                # subscribe -> unsubscribe -> send: send() must re-establish
                # topic interest internally.
                subscribe_result = sender.subscribe_content_topic(content_topic)
                assert subscribe_result.is_ok(), f"subscribe_content_topic failed: {subscribe_result.err()}"

                unsubscribe_result = sender.unsubscribe_content_topic(content_topic)
                assert unsubscribe_result.is_ok(), f"unsubscribe_content_topic failed: {unsubscribe_result.err()}"

                message = create_message_bindings(
                    payload=to_base64("S04 unsubscribe-then-send test payload"),
                    contentTopic=content_topic,
                )

                send_result = sender.send_message(message=message)
                assert send_result.is_ok(), f"send() failed after unsubscribe: {send_result.err()}"

                request_id = send_result.ok_value
                assert request_id, "send() returned an empty RequestId"

                propagated = wait_for_propagated(
                    collector=sender_collector,
                    request_id=request_id,
                    timeout_s=PROPAGATED_TIMEOUT_S,
                )
                assert propagated is not None, (
                    f"No message_propagated event within {PROPAGATED_TIMEOUT_S}s "
                    f"after unsubscribe + send. Collected events: {sender_collector.events}"
                )
                assert propagated["requestId"] == request_id

                error = wait_for_error(sender_collector, request_id, timeout_s=0)
                assert error is None, f"Unexpected message_error event: {error}"

                sent = wait_for_sent(sender_collector, request_id, timeout_s=0)
                assert sent is None, f"Unexpected message_sent event (store is disabled): {sent}"

                assert_event_invariants(sender_collector, request_id)


class TestS05AutoSubscribeFailureBeforeTaskCreation(StepsCommon):
    """
    S05 — Auto-subscribe failure before task creation.
    Sender is initialized but auto-subscription is forced to fail by using a
    malformed content topic that breaks shard resolution inside
    SubscriptionManager.subscribe().
    Expected: send() returns Err with an "auto-subscribe" message, no events.
    Purpose: covers the last synchronous error path before request ID creation,
    across several distinct validator branches.
    """

    @pytest.mark.parametrize(
        "content_topic",
        [topic for topic, _ in S05_MALFORMED_CONTENT_TOPICS],
        ids=[case_id for _, case_id in S05_MALFORMED_CONTENT_TOPICS],
    )
    def test_s05_send_fails_when_auto_subscribe_fails(self, node_config, content_topic):
        sender_collector = EventCollector()

        node_config.update(
            {
                "relay": True,
                "numShardsInNetwork": 1,
            }
        )

        sender_result = WrapperManager.create_and_start(
            config=node_config,
            event_cb=sender_collector.event_callback,
        )
        assert sender_result.is_ok(), f"Failed to start sender: {sender_result.err()}"

        with sender_result.ok_value as sender:
            # Malformed content topic — SubscriptionManager.subscribe() cannot
            # resolve it to a shard, so auto-subscribe inside send() fails.
            message = create_message_bindings(
                payload=to_base64("S05 auto-subscribe failure payload"),
                contentTopic=content_topic,
            )

            send_result = sender.send_message(message=message)

            assert send_result.is_err(), (
                f"send() must return Err when auto-subscribe fails for " f"content_topic={content_topic!r}, got Ok({send_result.ok_value!r})"
            )

            error_message = send_result.err() or ""
            assert S05_EXPECTED_ERROR_FRAGMENT in error_message, (
                f"expected error to mention {S05_EXPECTED_ERROR_FRAGMENT!r} " f"for content_topic={content_topic!r}, got: {error_message!r}"
            )

            # No request id was created, so no events should be emitted.
            assert sender_collector.events == [] or all(
                event.get("eventType") == "connection_status_change" for event in sender_collector.events
            ), f"Unexpected events after a pre-task-creation failure: {sender_collector.events}"


class TestS11EdgeSenderLightpushAndStore(StepsCommon):
    """
    S11 — Edge sender with lightpush path and store validation.
    Edge sender has no local relay; it publishes via a wrapper lightpush peer
    and validates delivery via a docker store peer. Reliability enabled.
    Topology:
        [LightpushPeer] wrapper, relay=True, lightpush=True, store=False
        [StorePeer]     docker WakuNode, relay=true, store=true,
                        dials the lightpush peer via add_peers and subscribes
                        to the same shard-0 pubsub topic so it joins the
                        relay mesh and archives propagated messages.
        [Edge]          wrapper, mode="Edge",
                        staticnodes=[lightpush_peer],
                        storenode=store_peer,
                        reliabilityEnabled=True
    Expected: send() returns Ok(RequestId), Propagated arrives, then Sent
    (store validation succeeds), no Error.
    Purpose: edge-mode fully validated success path against a real docker
    store node (cross-implementation check).
    """

    def test_s11_edge_lightpush_with_store_validation(self, node_config):
        sender_collector = EventCollector()

        common = {
            "filter": False,
            "discv5Discovery": True,
            "numShardsInNetwork": 1,
        }

        lightpush_config = build_node_config(
            relay=True,
            lightpush=True,
            store=False,
            **common,
        )

        lightpush_result = WrapperManager.create_and_start(config=lightpush_config)
        assert lightpush_result.is_ok(), f"Failed to start lightpush peer: {lightpush_result.err()}"

        with lightpush_result.ok_value as lightpush_peer:
            lightpush_multiaddr = get_node_multiaddr(lightpush_peer)

            # Docker store peer — real nwaku node running as the store backend.
            # Dial the lightpush peer via add_peers and subscribe to the same
            # shard-0 pubsub topic so it joins the relay mesh and archives
            # messages propagated by the lightpush peer.
            store_peer = WakuNode(NODE_1, f"s11_store_{self.test_id}")
            store_peer.start(relay="true", store="true")
            self.add_node_peer(store_peer, [lightpush_multiaddr])
            store_peer.set_relay_subscriptions([STORE_PEER_PUBSUB_TOPIC])
            store_multiaddr = store_peer.get_multiaddr_with_id()

            edge_config = build_node_config(
                mode="Edge",
                # assuming disc5v already happened
                staticnodes=[lightpush_multiaddr, store_multiaddr],
                reliabilityEnabled=True,
                **common,
            )

            edge_result = WrapperManager.create_and_start(
                config=edge_config,
                event_cb=sender_collector.event_callback,
            )
            assert edge_result.is_ok(), f"Failed to start edge sender: {edge_result.err()}"

            with edge_result.ok_value as edge_sender:
                message = create_message_bindings(
                    payload=to_base64("S11 edge lightpush + store test payload"),
                    contentTopic="/test/1/s11-edge-lightpush-store/proto",
                )

                send_result = edge_sender.send_message(message=message)
                assert send_result.is_ok(), f"send() failed: {send_result.err()}"

                request_id = send_result.ok_value
                assert request_id, "send() returned an empty RequestId"

                propagated = wait_for_propagated(
                    collector=sender_collector,
                    request_id=request_id,
                    timeout_s=PROPAGATED_TIMEOUT_S,
                )
                assert propagated is not None, (
                    f"No message_propagated event within {PROPAGATED_TIMEOUT_S}s. " f"Collected events: {sender_collector.events}"
                )
                assert propagated["requestId"] == request_id

                sent = wait_for_sent(
                    collector=sender_collector,
                    request_id=request_id,
                    timeout_s=SENT_AFTER_STORE_TIMEOUT_S,
                )
                assert sent is not None, (
                    f"No message_sent event within {SENT_AFTER_STORE_TIMEOUT_S}s " f"after propagation. Collected events: {sender_collector.events}"
                )
                assert sent["requestId"] == request_id

                error = wait_for_error(sender_collector, request_id, timeout_s=0)
                assert error is None, f"Unexpected message_error event: {error}"

                assert_event_invariants(sender_collector, request_id)
