import base64
from concurrent.futures import ThreadPoolExecutor

import pytest
from src.env_vars import NODE_2
from src.steps.common import StepsCommon
from src.steps.store import StepsStore
from src.libs.common import delay, to_base64
from src.libs.custom_logger import get_custom_logger
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

logger = get_custom_logger(__name__)

PROPAGATED_TIMEOUT_S = 30.0
RECOVERY_TIMEOUT_S = 45.0

# MaxTimeInCache from send_service.nim.
MAX_TIME_IN_CACHE_S = 60.0
# Extra slack to cover the background retry loop tick after the window expires.
CACHE_EXPIRY_SLACK_S = 10.0
ERROR_AFTER_CACHE_EXPIRY_TIMEOUT_S = MAX_TIME_IN_CACHE_S + CACHE_EXPIRY_SLACK_S
RETRY_WINDOW_EXPIRED_MSG = "Unable to send within retry time window"

# Payload above DefaultMaxWakuMessageSize (150KiB), so the relay publish
# rejects it instead of failing with NO_PEERS_TO_RELAY.
OVERSIZED_PAYLOAD_BYTES = 200 * 1024
ERROR_TIMEOUT_S = 30.0
MESSAGE_SIZE_EXCEEDED_MSG = "Message size exceeded"

# S30: concurrent sends on the same content topic during initial auto-subscribe.
S30_CONCURRENT_SENDS = 5
S30_CONTENT_TOPIC = "/test/1/s30-concurrent/proto"

# S31: concurrent sends across mixed topics during peer churn.
S31_BURST_SIZE = 8
S31_CONTENT_TOPICS = [
    "/test/1/s31-topic-a/proto",
    "/test/1/s31-topic-b/proto",
    "/test/1/s31-topic-c/proto",
    "/test/1/s31-topic-d/proto",
    "/test/1/s31-topic-e/proto",
    "/test/1/s31-topic-f/proto",
    "/test/1/s31-topic-g/proto",
    "/test/1/s31-topic-h/proto",
]


class TestS12IsolatedSenderNoPeers(StepsCommon):
    """
    S12 — Isolated sender, no peers.
    Sender has relay enabled but zero relay peers and zero lightpush peers.
    Expected: send() returns Ok(RequestId), but eventually a message_error
    event arrives (no route to propagate).
    """

    def test_s12_send_with_no_peers_produces_error(self, node_config):
        sender_collector = EventCollector()

        node_config.update(
            {
                "relay": True,
                "store": False,
                "lightpush": False,
                "filter": False,
                "discv5Discovery": False,
                "numShardsInNetwork": 1,
            }
        )

        sender_result = WrapperManager.create_and_start(
            config=node_config,
            event_cb=sender_collector.event_callback,
        )
        assert sender_result.is_ok(), f"Failed to start sender: {sender_result.err()}"

        with sender_result.ok_value as sender:
            message = create_message_bindings(
                payload=to_base64("S12 isolated sender payload"),
                contentTopic="/test/1/s12-isolated/proto",
            )

            send_result = sender.send_message(message=message)
            assert send_result.is_ok(), f"send() must return Ok(RequestId) even with no peers, got: {send_result.err()}"

            request_id = send_result.ok_value
            assert request_id, "send() returned an empty RequestId"

            error = wait_for_error(
                collector=sender_collector,
                request_id=request_id,
                timeout_s=ERROR_AFTER_CACHE_EXPIRY_TIMEOUT_S,
            )
            assert error is not None, (
                f"No message_error event within {ERROR_AFTER_CACHE_EXPIRY_TIMEOUT_S}s "
                f"(MaxTimeInCache={MAX_TIME_IN_CACHE_S}s + slack) for isolated sender. "
                f"Collected events: {sender_collector.events}"
            )
            assert error["requestId"] == request_id

            propagated = wait_for_propagated(sender_collector, request_id, timeout_s=0)
            assert propagated is None, f"Unexpected message_propagated event for isolated sender: {propagated}"


class TestS21ErrorWhenRetryWindowExpires(StepsCommon):
    """
    S21: delivery retry window expires before any valid path recovers.
    """

    def test_s21_error_when_retry_window_expires(self, node_config):
        sender_collector = EventCollector()

        node_config.update(
            {
                "relay": True,
                "store": False,
                "lightpush": False,
                "filter": False,
                "discv5Discovery": False,
                "numShardsInNetwork": 1,
            }
        )

        sender_result = WrapperManager.create_and_start(
            config=node_config,
            event_cb=sender_collector.event_callback,
        )
        assert sender_result.is_ok(), f"Failed to start sender: {sender_result.err()}"

        with sender_result.ok_value as sender_node:
            message = create_message_bindings()
            send_result = sender_node.send_message(message=message)
            assert send_result.is_ok(), f"send() must return Ok(RequestId) even with no peers, got: {send_result.err()}"

            request_id = send_result.ok_value
            assert request_id, "send() returned an empty RequestId"

            # No peer
            error_event = wait_for_error(
                collector=sender_collector,
                request_id=request_id,
                timeout_s=ERROR_AFTER_CACHE_EXPIRY_TIMEOUT_S,
            )
            assert error_event is not None, (
                f"No MessageErrorEvent received within {ERROR_AFTER_CACHE_EXPIRY_TIMEOUT_S}s "
                f"(MaxTimeInCache={MAX_TIME_IN_CACHE_S}s + slack). "
                f"Collected events: {sender_collector.events}"
            )
            logger.info(f"S21 received error event: {error_event}")

            assert error_event.get("error") == RETRY_WINDOW_EXPIRED_MSG, (
                f"Unexpected error message in message_error event.\n"
                f"Expected: {RETRY_WINDOW_EXPIRED_MSG!r}\n"
                f"Got:      {error_event.get('error')!r}\n"
                f"Full event: {error_event}"
            )

            assert_event_invariants(sender_collector, request_id)


class TestS13RelayHardFailureWithoutFallback(StepsCommon):
    """
    S13: relay path is reachable (a relay peer is connected, so the publish
    gets past NO_PEERS_TO_RELAY), but the relay publish fails for another
    reason. An oversized payload is used so the relay processor rejects the
    message immediately. No lightpush fallback is configured.
      - Expected: Ok(RequestId), then a message_error event.
    """

    def test_s13_relay_hard_failure_without_fallback(self, node_config):
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

        with sender_result.ok_value as sender_node:
            relay_config = {
                **node_config,
                "staticnodes": [get_node_multiaddr(sender_node)],
                "portsShift": 1,
            }

            relay_result = WrapperManager.create_and_start(config=relay_config)
            assert relay_result.is_ok(), f"Failed to start relay peer: {relay_result.err()}"

            with relay_result.ok_value:
                # A connected relay peer means the publish gets past
                # NO_PEERS_TO_RELAY and actually reaches the relay processor.
                assert wait_for_connected(sender_collector) is not None, (
                    f"Sender did not reach Connected/PartiallyConnected. " f"Collected events: {sender_collector.events}"
                )

                oversized_payload = base64.b64encode(b"x" * OVERSIZED_PAYLOAD_BYTES).decode()
                message = create_message_bindings(
                    payload=oversized_payload,
                    contentTopic="/test/1/s13-relay-hard-failure/proto",
                )

                send_result = sender_node.send_message(message=message)
                assert send_result.is_ok(), f"send() must return Ok(RequestId), got: {send_result.err()}"

                request_id = send_result.ok_value
                assert request_id, "send() returned an empty RequestId"

                error_event = wait_for_error(
                    collector=sender_collector,
                    request_id=request_id,
                    timeout_s=ERROR_TIMEOUT_S,
                )
                assert error_event is not None, (
                    f"No message_error event within {ERROR_TIMEOUT_S}s from the " f"relay processor. Collected events: {sender_collector.events}"
                )
                assert error_event["requestId"] == request_id
                assert MESSAGE_SIZE_EXCEEDED_MSG in (error_event.get("error") or ""), (
                    f"Expected error to contain {MESSAGE_SIZE_EXCEEDED_MSG!r}.\n" f"Got: {error_event.get('error')!r}\n" f"Full event: {error_event}"
                )

                propagated = wait_for_propagated(sender_collector, request_id, timeout_s=0)
                assert propagated is None, f"Unexpected message_propagated event for a failed relay publish: {propagated}"

                assert_event_invariants(sender_collector, request_id)


class TestS30ConcurrentSendsDuringAutoSubscribe(StepsCommon):
    """
    S30: concurrent sends on the same content topic during initial auto-subscribe.
      - Sender starts unsubscribed to the target topic.
      - Several send() calls are issued at nearly the same time.
      - Each call must return Ok(RequestId) with a unique id.
      - Each request id must get its own propagated event,
        with no dropped or cross-associated events.
    """

    def test_s30_concurrent_sends_during_auto_subscribe(self, node_config):
        sender_collector = EventCollector()

        node_config.update(
            {
                "relay": True,
                "store": False,
                "discv5Discovery": False,
                "numShardsInNetwork": 1,
            }
        )

        sender_result = WrapperManager.create_and_start(
            config=node_config,
            event_cb=sender_collector.event_callback,
        )
        assert sender_result.is_ok(), f"Failed to start sender: {sender_result.err()}"

        with sender_result.ok_value as sender_node:
            # Relay peer so the sender has a propagation path.
            relay_config = {
                **node_config,
                "staticnodes": [get_node_multiaddr(sender_node)],
                "portsShift": 1,
            }

            relay_result = WrapperManager.create_and_start(config=relay_config)
            assert relay_result.is_ok(), f"Failed to start relay peer: {relay_result.err()}"

            with relay_result.ok_value:
                # Build one message per send, with distinct payloads so we can
                # detect any cross-association between request ids and events.
                messages = [
                    create_message_bindings(
                        contentTopic=S30_CONTENT_TOPIC,
                        payload=to_base64(f"s30-concurrent-{i}"),
                    )
                    for i in range(S30_CONCURRENT_SENDS)
                ]

                # Fire all sends concurrently. The sender is not yet subscribed
                # to S30_CONTENT_TOPIC, so this exercises the auto-subscribe path
                # under contention.
                with ThreadPoolExecutor(max_workers=S30_CONCURRENT_SENDS) as pool:
                    send_results = list(pool.map(sender_node.send_message, messages))

                # Every send must return Ok(RequestId).
                request_ids = []
                for i, send_result in enumerate(send_results):
                    assert send_result.is_ok(), f"Concurrent send #{i} failed: {send_result.err()}"
                    request_id = send_result.ok_value
                    assert request_id, f"Concurrent send #{i} returned an empty RequestId"
                    request_ids.append(request_id)

                # Request ids must be unique across concurrent sends.
                assert len(set(request_ids)) == len(request_ids), f"Duplicate RequestIds returned by concurrent sends: {request_ids}"

                # Each request id must get its own propagated event and no error.
                for request_id in request_ids:
                    propagated_event = wait_for_propagated(
                        collector=sender_collector,
                        request_id=request_id,
                        timeout_s=PROPAGATED_TIMEOUT_S,
                    )
                    assert propagated_event is not None, (
                        f"No MessagePropagatedEvent for request_id={request_id} "
                        f"within {PROPAGATED_TIMEOUT_S}s. "
                        f"Collected events: {sender_collector.events}"
                    )

                    error_event = wait_for_error(
                        collector=sender_collector,
                        request_id=request_id,
                        timeout_s=0,
                    )
                    assert error_event is None, f"Unexpected message_error for request_id={request_id}: {error_event}"

                # Cross-association guard: every event with a requestId must
                # belong to exactly one of the request ids we issued.
                issued = set(request_ids)
                for event in sender_collector.snapshot():
                    event_request_id = event.get("requestId")
                    if event_request_id is None:
                        continue
                    assert event_request_id in issued, (
                        f"Event carries an unknown requestId={event_request_id!r}, " f"not in issued set {issued}. Event: {event}"
                    )

                # Per-request invariants apply to every concurrent send
                # (correct requestId, no duplicate terminal events,
                # Sent never before Propagated).
                for request_id in request_ids:
                    assert_event_invariants(sender_collector, request_id)


class TestS31ConcurrentSendsMixedTopicsDuringChurn(StepsStore):
    """
    S31: concurrent sends across mixed content topics during peer churn.
    """

    @pytest.mark.docker_required
    def test_s31_concurrent_sends_mixed_topics_during_churn(self, node_config):
        sender_collector = EventCollector()

        relay_peer = WakuNode(NODE_2, f"s31_relay_peer_{self.test_id}")
        relay_peer.start(relay="true", discv5_discovery="false")
        relay_peer.set_relay_subscriptions([self.test_pubsub_topic])

        lightpush_peer = WakuNode(NODE_2, f"s31_lightpush_peer_{self.test_id}")
        lightpush_peer.start(relay="true", lightpush="true", discv5_discovery="false")
        lightpush_peer.set_relay_subscriptions([self.test_pubsub_topic])

        store_peer = WakuNode(NODE_2, f"s31_store_peer_{self.test_id}")
        store_peer.start(relay="true", store="true", discv5_discovery="false")
        store_peer.set_relay_subscriptions([self.test_pubsub_topic])

        churn_peers = [relay_peer, lightpush_peer, store_peer]

        # Mesh docker peers so a lightpushed message can fan out to the store peer.
        peer_multiaddrs = [p.get_multiaddr_with_id() for p in churn_peers]
        for peer in churn_peers:
            others = [a for a in peer_multiaddrs if a != peer.get_multiaddr_with_id()]
            peer.add_peers(others)

        node_config.update(
            {
                "mode": "Edge",
                "relay": True,
                "lightpush": True,
                "store": False,
                "discv5Discovery": False,
                "numShardsInNetwork": 1,
                "lightpushnode": lightpush_peer.get_multiaddr_with_id(),
            }
        )

        sender_result = WrapperManager.create_and_start(
            config=node_config,
            event_cb=sender_collector.event_callback,
        )
        assert sender_result.is_ok(), f"Failed to start sender: {sender_result.err()}"

        with sender_result.ok_value as sender_node:
            sender_multiaddr = get_node_multiaddr(sender_node)
            for peer in churn_peers:
                peer.add_peers([sender_multiaddr])
            delay(3)  # let docker peers connect to the sender

            all_request_ids: list[str] = []
            phase1_ids = self._s31_fire_burst(sender_node, phase_label="phase1")
            all_request_ids.extend(phase1_ids)

            for peer in churn_peers:
                peer.restart()
            delay(1)  # small window so the restart is actually in-flight
            phase2_ids = self._s31_fire_burst(sender_node, phase_label="phase2")
            all_request_ids.extend(phase2_ids)

            # Wait for all peers to be ready again and re-attach the sender.
            for peer in churn_peers:
                peer.ensure_ready(timeout_duration=20)
                peer.add_peers([sender_multiaddr])

            peer_multiaddrs = [p.get_multiaddr_with_id() for p in churn_peers]
            for peer in churn_peers:
                others = [a for a in peer_multiaddrs if a != peer.get_multiaddr_with_id()]
                peer.add_peers(others)
            delay(3)

            phase3_ids = self._s31_fire_burst(sender_node, phase_label="phase3")
            all_request_ids.extend(phase3_ids)

            assert len(set(all_request_ids)) == len(all_request_ids), f"Duplicate RequestIds across bursts: {all_request_ids}"

            # Phase 1 ran before any churn, so the mesh was stable — standard timeout.
            # Phase 3 ran right after restart + re-attach, so the mesh needed to
            # re-stabilize — use the recovery timeout to avoid CI flakiness.
            phase_timeouts = [
                (phase1_ids, PROPAGATED_TIMEOUT_S),
                (phase3_ids, RECOVERY_TIMEOUT_S),
            ]
            for request_ids, timeout_s in phase_timeouts:
                for request_id in request_ids:
                    propagated_event = wait_for_propagated(
                        collector=sender_collector,
                        request_id=request_id,
                        timeout_s=timeout_s,
                    )
                    assert propagated_event is not None, (
                        f"No MessagePropagatedEvent for stable-phase "
                        f"request_id={request_id} within {timeout_s}s. "
                        f"Collected events: {sender_collector.events}"
                    )

                    error_event = wait_for_error(
                        collector=sender_collector,
                        request_id=request_id,
                        timeout_s=0,
                    )
                    assert error_event is None, f"Unexpected message_error event for stable-phase " f"request_id={request_id}: {error_event}"

            for request_id in phase2_ids:
                error_event = wait_for_error(
                    collector=sender_collector,
                    request_id=request_id,
                    timeout_s=0,
                )
                assert error_event is None, f"Unexpected terminal message_error for phase-2 " f"request_id={request_id} after recovery: {error_event}"

            issued = set(all_request_ids)
            for event in sender_collector.snapshot():
                event_request_id = event.get("requestId")
                if event_request_id is None:
                    continue
                assert event_request_id in issued, (
                    f"Event carries an unknown requestId={event_request_id!r}, " f"not in issued set {issued}. Event: {event}"
                )

            # Use the hash the wrapper emitted on message_sent so the store
            # lookup matches the exact bytes that were actually published.
            phase3_hashes = []
            for request_id in phase3_ids:
                sent_event = wait_for_sent(
                    collector=sender_collector,
                    request_id=request_id,
                    timeout_s=RECOVERY_TIMEOUT_S,
                )
                assert sent_event is not None, (
                    f"No message_sent event for phase-3 request_id={request_id} "
                    f"within {RECOVERY_TIMEOUT_S}s. Collected events: {sender_collector.events}"
                )
                msg_hash = sent_event.get("messageHash")
                assert msg_hash, f"message_sent event missing messageHash: {sent_event}"
                phase3_hashes.append(msg_hash)

            # 3 phases × S31_BURST_SIZE messages, so the page must fit them all,
            # otherwise phase-3 hashes (which sort last in ascending order) get cut off.
            self.check_sent_message_is_stored(
                expected_hashes=phase3_hashes,
                store_node=store_peer,
                pubsub_topic=self.test_pubsub_topic,
                page_size=S31_BURST_SIZE * 3,
                ascending="true",
            )

            # Per-request invariants apply across all phases, including the
            # retry-path bursts (phase 2). If retries ever emit duplicate
            # Propagated events or reorder Sent before Propagated, this catches it.
            for request_id in all_request_ids:
                assert_event_invariants(sender_collector, request_id)

    def _s31_fire_burst(self, sender_node, *, phase_label: str) -> list[str]:
        """Fire S31_BURST_SIZE concurrent sends, one per topic in S31_CONTENT_TOPICS.
        Returns the list of RequestIds. Asserts every send returned Ok."""
        messages = [
            self.create_message(
                contentTopic=S31_CONTENT_TOPICS[i],
                payload=to_base64(f"s31-{phase_label}-{i}"),
            )
            for i in range(S31_BURST_SIZE)
        ]

        with ThreadPoolExecutor(max_workers=S31_BURST_SIZE) as pool:
            send_results = list(pool.map(sender_node.send_message, messages))

        request_ids = []
        for i, send_result in enumerate(send_results):
            assert send_result.is_ok(), f"{phase_label}: concurrent send #{i} failed: {send_result.err()}"
            request_id = send_result.ok_value
            assert request_id, f"{phase_label}: concurrent send #{i} returned an empty RequestId"
            request_ids.append(request_id)

        return request_ids
