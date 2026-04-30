from concurrent.futures import ThreadPoolExecutor
from time import time_ns

import pytest
from src.env_vars import NODE_2
from src.steps.common import StepsCommon
from src.libs.common import delay, to_base64
from src.libs.custom_logger import get_custom_logger
from src.node.waku_node import WakuNode
from src.node.wrappers_manager import WrapperManager
from src.node.wrapper_helpers import (
    EventCollector,
    create_message_bindings,
    get_node_multiaddr,
    wait_for_propagated,
    wait_for_sent,
    wait_for_error,
)
from src.steps.store import StepsStore

logger = get_custom_logger(__name__)


PROPAGATED_TIMEOUT_S = 30.0
SENT_TIMEOUT_S = 10.0
NO_SENT_OBSERVATION_S = 5.0
SENT_AFTER_STORE_TIMEOUT_S = 60.0
NO_STORE_OBSERVATION_S = 60.0

# MaxTimeInCache from send_service.nim.
MAX_TIME_IN_CACHE_S = 60.0
# Extra slack to cover the background retry loop tick after the window expires.
CACHE_EXPIRY_SLACK_S = 10.0
ERROR_AFTER_CACHE_EXPIRY_TIMEOUT_S = MAX_TIME_IN_CACHE_S + CACHE_EXPIRY_SLACK_S
RETRY_WINDOW_EXPIRED_MSG = "Unable to send within retry time window"

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


class TestSendBeforeRelay(StepsStore):
    def test_s17_send_before_relay_peers_joins(self, node_config):
        """
        S17: sender starts isolated, calls send()
          - send() returns Ok(RequestId) immediately
          - Propagated event eventually arrives
        """
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
            message = create_message_bindings()
            send_result = sender_node.send_message(message=message)
            assert send_result.is_ok(), f"send() must return Ok(RequestId) even with no peers, got: {send_result.err()}"

            request_id = send_result.ok_value
            assert request_id, "send() returned an empty RequestId"

            # Step 2: start a relay peer with store enabled.
            relay_config = {
                **node_config,
                "staticnodes": [get_node_multiaddr(sender_node)],
                "portsshift": 1,
                "store": True,
            }

            relay_result = WrapperManager.create_and_start(config=relay_config)
            assert relay_result.is_ok(), f"Failed to start relay peer: {relay_result.err()}"

            with relay_result.ok_value:
                propagated_event = wait_for_propagated(
                    collector=sender_collector,
                    request_id=request_id,
                    timeout_s=PROPAGATED_TIMEOUT_S,
                )
                assert propagated_event is not None, (
                    f"No MessagePropagatedEvent received within {PROPAGATED_TIMEOUT_S}s "
                    f"after relay peer joined. Collected events: {sender_collector.events}"
                )
                sent_event = wait_for_sent(
                    collector=sender_collector,
                    request_id=request_id,
                    timeout_s=SENT_TIMEOUT_S,
                )
                assert sent_event is not None, (
                    f"No MessageSentEvent received within {SENT_TIMEOUT_S}s "
                    f"from a store-enabled relay peer. Collected events: {sender_collector.events}"
                )

    def test_s23_no_sent_event_when_relay_has_no_store(self, node_config):
        """
        S23: non-ephemeral message, reliability enabled, no store peer ever reachable.
          - Expected: Ok(RequestId), Propagated event only, no Sent and no terminal error.
        """
        sender_collector = EventCollector()

        node_config.update(
            {
                "relay": True,
                "store": False,
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

        with sender_result.ok_value as sender_node:
            message = create_message_bindings(ephemeral=False)
            send_result = sender_node.send_message(message=message)
            assert send_result.is_ok(), f"send() must return Ok(RequestId) even with no peers, got: {send_result.err()}"

            request_id = send_result.ok_value
            assert request_id, "send() returned an empty RequestId"

            relay_config = {
                **node_config,
                "staticnodes": [get_node_multiaddr(sender_node)],
                "portsshift": 1,
                "store": False,
            }

            relay_result = WrapperManager.create_and_start(config=relay_config)
            assert relay_result.is_ok(), f"Failed to start relay peer: {relay_result.err()}"

            with relay_result.ok_value:
                propagated_event = wait_for_propagated(
                    collector=sender_collector,
                    request_id=request_id,
                    timeout_s=PROPAGATED_TIMEOUT_S,
                )
                assert propagated_event is not None, (
                    f"No MessagePropagatedEvent received within {PROPAGATED_TIMEOUT_S}s "
                    f"after relay peer joined. Collected events: {sender_collector.events}"
                )

                sent_event = wait_for_sent(
                    collector=sender_collector,
                    request_id=request_id,
                    timeout_s=NO_STORE_OBSERVATION_S,
                )
                assert sent_event is None, (
                    f"Unexpected MessageSentEvent within {NO_STORE_OBSERVATION_S}s "
                    f"when relay peer has store=false.\n"
                    f"Sent event: {sent_event}\n"
                    f"Collected events: {sender_collector.events}"
                )

                # Regression guard: current behavior must NOT convert "no store
                # reachable" into an immediate terminal error. If a future change
                # starts emitting one, this assertion will catch it.
                error_event = wait_for_error(
                    collector=sender_collector,
                    request_id=request_id,
                    timeout_s=0,
                )
                assert error_event is None, (
                    f"Unexpected terminal error event when no store peer is reachable. "
                    f"S23 expects silent behavior (Propagated only).\n"
                    f"Error event: {error_event}\n"
                    f"Collected events: {sender_collector.events}"
                )

    @pytest.mark.ignore("scenario might be not possible to simulate")
    def test_s19_store_peer_appears_after_propagation(self, node_config):
        """
        S19: a store peer comes online later.
          - send() returns Ok(RequestId) immediately
          - Propagated --- relay peer
          - Sent when store peer is reachable
        """
        sender_collector = EventCollector()

        node_config.update({"relay": True, "store": False, "discv5Discovery": False, "numShardsInNetwork": 1, "reliabilityEnabled": True})

        sender_result = WrapperManager.create_and_start(
            config=node_config,
            event_cb=sender_collector.event_callback,
        )
        assert sender_result.is_ok(), f"Failed to start sender: {sender_result.err()}"

        with sender_result.ok_value as sender_node:
            # relay peer
            relay_config = {
                **node_config,
                "staticnodes": [get_node_multiaddr(sender_node)],
                "portsshift": 1,
                "store": False,
                "reliabilityEnabled": True,
            }

            relay_result = WrapperManager.create_and_start(config=relay_config)
            assert relay_result.is_ok(), f"Failed to start relay peer: {relay_result.err()}"

            with relay_result.ok_value as relay_peer:
                # send(). Must return Ok(RequestId) immediately.
                message = create_message_bindings()
                send_result = sender_node.send_message(message=message)
                assert send_result.is_ok(), f"send() must return Ok(RequestId), got: {send_result.err()}"

                request_id = send_result.ok_value
                assert request_id, "send() returned an empty RequestId"

                # Propagated should arrive via the relay peer.
                propagated_event = wait_for_propagated(
                    collector=sender_collector,
                    request_id=request_id,
                    timeout_s=PROPAGATED_TIMEOUT_S,
                )
                assert propagated_event is not None, (
                    f"No MessagePropagatedEvent received within {PROPAGATED_TIMEOUT_S}s. " f"Collected events: {sender_collector.events}"
                )

                early_sent_event = wait_for_sent(
                    collector=sender_collector,
                    request_id=request_id,
                    timeout_s=NO_SENT_OBSERVATION_S,
                )
                assert early_sent_event is None, f"MessageSentEvent arrived before any store peer was reachable. " f"Event: {early_sent_event}"

                # Store peer
                store_node = WakuNode(NODE_2, f"store_node")
                store_node.start(relay="true", store="true", discv5_discovery="false", cluster_id=node_config["clusterId"], shard=0)
                store_node.set_relay_subscriptions([self.test_pubsub_topic])
                relay_multiaddr = get_node_multiaddr(relay_peer)
                sender_multiaddr = get_node_multiaddr(sender_node)
                store_node.add_peers([relay_multiaddr, sender_multiaddr])
                self.wait_for_autoconnection([store_node], hard_wait=10)
                delay(3)

                sent_event = wait_for_sent(
                    collector=sender_collector,
                    request_id=request_id,
                    timeout_s=SENT_AFTER_STORE_TIMEOUT_S,
                )

                assert sent_event is not None, (
                    f"No MessageSentEvent received within {SENT_AFTER_STORE_TIMEOUT_S}s "
                    f"after store peer joined. Collected events: {sender_collector.events}"
                )

                self.check_published_message_is_stored(
                    store_node=store_node,
                    pubsub_topic=self.test_pubsub_topic,
                    messages_to_check=[message],
                    page_size=5,
                    ascending="true",
                )

    def test_s20_store_misses_initially_then_retry_succeeds(self, node_config):
        """
        S20: relay propagation succeeds, initial store query misses,
        a retry republishes, and a store peer eventually archives the message.

        Covers state flow:
            SuccessfullyPropagated -> NextRoundRetry
              -> SuccessfullyPropagated -> SuccessfullyValidated
        """
        sender_collector = EventCollector()

        node_config.update(
            {
                "relay": True,
                "store": False,
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

        with sender_result.ok_value as sender_node:
            # Relay-only peer: gives the sender a propagation path but no store.
            relay_config = {
                **node_config,
                "staticnodes": [get_node_multiaddr(sender_node)],
                "portsshift": 1,
                "store": False,
            }

            relay_result = WrapperManager.create_and_start(config=relay_config)
            assert relay_result.is_ok(), f"Failed to start relay peer: {relay_result.err()}"

            with relay_result.ok_value as relay_peer:
                message = create_message_bindings(ephemeral=False)
                send_result = sender_node.send_message(message=message)
                assert send_result.is_ok(), f"send() must return Ok(RequestId), got: {send_result.err()}"

                request_id = send_result.ok_value
                assert request_id, "send() returned an empty RequestId"

                # First round: propagation succeeds via the relay peer.
                propagated_event = wait_for_propagated(
                    collector=sender_collector,
                    request_id=request_id,
                    timeout_s=PROPAGATED_TIMEOUT_S,
                )
                assert propagated_event is not None, (
                    f"No MessagePropagatedEvent received within {PROPAGATED_TIMEOUT_S}s. " f"Collected events: {sender_collector.events}"
                )

                early_sent_event = wait_for_sent(
                    collector=sender_collector,
                    request_id=request_id,
                    timeout_s=NO_SENT_OBSERVATION_S,
                )
                assert early_sent_event is None, (
                    f"MessageSentEvent arrived before any store peer was reachable. "
                    f"Initial store validation should have missed and triggered a retry. "
                    f"Event: {early_sent_event}"
                )

                store_node = WakuNode(NODE_2, f"s20_store_node_{self.test_id}")
                store_node.start(relay="true", store="true", discv5_discovery="false")
                store_node.set_relay_subscriptions([self.test_pubsub_topic])

                relay_multiaddr = get_node_multiaddr(relay_peer)
                sender_multiaddr = get_node_multiaddr(sender_node)
                store_node.add_peers([relay_multiaddr, sender_multiaddr])
                delay(3)

                # Retry round: republish reaches the store peer, validation passes.
                sent_event = wait_for_sent(
                    collector=sender_collector,
                    request_id=request_id,
                    timeout_s=SENT_AFTER_STORE_TIMEOUT_S,
                )
                assert sent_event is not None, (
                    f"No MessageSentEvent received within {SENT_AFTER_STORE_TIMEOUT_S}s "
                    f"after the store peer joined. The retry round should have "
                    f"republished the message and the store peer should have archived it. "
                    f"Collected events: {sender_collector.events}"
                )

                self.check_published_message_is_stored(
                    store_node=store_node,
                    pubsub_topic=self.test_pubsub_topic,
                    messages_to_check=[message],
                    page_size=5,
                    ascending="true",
                )

    def test_s21_error_when_retry_window_expires(self, node_config):
        """
        S21: delivery retry window expires before any valid path recovers.
        """
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

    def test_s22_non_ephemeral_message_with_reliability_disabled(self, node_config):
        """
        S22: non-ephemeral message with reliabilityEnabled disabled.
          - propagation path exists ,reliabilityEnabled = false.
          - Expected: Ok(RequestId), Propagated event only, no Sent event.
          Note: S17 already covers the positive path of this test with reliabilityEnabled=True.
        """
        sender_collector = EventCollector()

        node_config.update(
            {
                "relay": True,
                "store": False,
                "discv5Discovery": False,
                "numShardsInNetwork": 1,
                "reliabilityEnabled": False,
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
                "portsshift": 1,
                "store": True,
            }

            relay_result = WrapperManager.create_and_start(config=relay_config)
            assert relay_result.is_ok(), f"Failed to start relay peer: {relay_result.err()}"

            with relay_result.ok_value:
                message = create_message_bindings(ephemeral=False)
                send_result = sender_node.send_message(message=message)
                assert send_result.is_ok(), f"send() must return Ok(RequestId), got: {send_result.err()}"

                request_id = send_result.ok_value
                assert request_id, "send() returned an empty RequestId"

                propagated_event = wait_for_propagated(
                    collector=sender_collector,
                    request_id=request_id,
                    timeout_s=PROPAGATED_TIMEOUT_S,
                )
                assert propagated_event is not None, (
                    f"No MessagePropagatedEvent received within {PROPAGATED_TIMEOUT_S}s. " f"Collected events: {sender_collector.events}"
                )

                sent_event = wait_for_sent(
                    collector=sender_collector,
                    request_id=request_id,
                    timeout_s=SENT_TIMEOUT_S,
                )
                assert sent_event is None, (
                    f"Unexpected MessageSentEvent received when reliabilityEnabled is disabled.\n"
                    f"Sent event: {sent_event}\n"
                    f"Collected events: {sender_collector.events}"
                )

    def test_s24_ephemeral_message_with_reachable_store(self, node_config):
        """
        S24: ephemeral message, reliability enabled, reachable store peer.
          - Setup: propagation path exists, relay peer has store=True (reachable),
          - Expected: Ok(RequestId), Propagated event only, no Sent event.
        """

        sender_collector = EventCollector()

        node_config.update(
            {
                "relay": True,
                "store": False,
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

        with sender_result.ok_value as sender_node:
            relay_config = {
                **node_config,
                "staticnodes": [get_node_multiaddr(sender_node)],
                "portsshift": 1,
                "store": True,
            }

            relay_result = WrapperManager.create_and_start(config=relay_config)
            assert relay_result.is_ok(), f"Failed to start relay peer: {relay_result.err()}"

            with relay_result.ok_value:
                message = create_message_bindings(ephemeral=True)
                send_result = sender_node.send_message(message=message)
                assert send_result.is_ok(), f"send() must return Ok(RequestId), got: {send_result.err()}"

                request_id = send_result.ok_value
                assert request_id, "send() returned an empty RequestId"

                propagated_event = wait_for_propagated(
                    collector=sender_collector,
                    request_id=request_id,
                    timeout_s=PROPAGATED_TIMEOUT_S,
                )
                assert propagated_event is not None, (
                    f"No MessagePropagatedEvent received within {PROPAGATED_TIMEOUT_S}s. " f"Collected events: {sender_collector.events}"
                )

                sent_event = wait_for_sent(
                    collector=sender_collector,
                    request_id=request_id,
                    timeout_s=NO_STORE_OBSERVATION_S,
                )
                assert sent_event is None, (
                    f"Unexpected MessageSentEvent for an ephemeral message. "
                    f"Ephemeral messages must never be store-validated.\n"
                    f"Sent event: {sent_event}\n"
                    f"Collected events: {sender_collector.events}"
                )

    def test_s26_lightpush_peer_churn_alternate_remains(self, node_config):
        """
        S26: multiple lightpush peers, the selected one disappears,
             an alternate remains.
          - send() returns Ok(RequestId) during peer churn.
          - Propagated event eventually arrives (via the surviving peer, peer2).
          - No message_error event.
        """
        sender_collector = EventCollector()

        # Two lightpush server peers: relay+lightpush, connected to each other.
        peer1_config = {
            **node_config,
            "relay": True,
            "lightpush": True,
            "store": False,
            "filter": False,
            "discv5Discovery": True,
            "numShardsInNetwork": 1,
            "portsshift": 1,
        }
        peer1_result = WrapperManager.create_and_start(config=peer1_config)
        assert peer1_result.is_ok(), f"Failed to start lightpush peer1: {peer1_result.err()}"
        peer1 = peer1_result.ok_value

        peer2_config = {
            **peer1_config,
            "staticnodes": [get_node_multiaddr(peer1)],
            "portsshift": 2,
        }
        peer2_result = WrapperManager.create_and_start(config=peer2_config)
        assert peer2_result.is_ok(), f"Failed to start lightpush peer2: {peer2_result.err()}"

        with peer2_result.ok_value as peer2:
            sender_config = {
                **node_config,
                "mode": "Edge",
                "relay": True,
                "lightpush": True,
                "store": False,
                "filter": False,
                "discv5Discovery": False,
                "numShardsInNetwork": 1,
                "portsshift": 3,
                "lightpushnode": get_node_multiaddr(peer1),
                "staticnodes": [
                    get_node_multiaddr(peer1),
                    get_node_multiaddr(peer2),
                ],
            }

            sender_result = WrapperManager.create_and_start(
                config=sender_config,
                event_cb=sender_collector.event_callback,
            )
            assert sender_result.is_ok(), f"Failed to start sender: {sender_result.err()}"

            with sender_result.ok_value as sender_node:
                delay(2)
                stop_result = peer1.stop_and_destroy()
                assert stop_result.is_ok(), f"Failed to stop peer1: {stop_result.err()}"

                message = create_message_bindings()
                send_result = sender_node.send_message(message=message)
                assert send_result.is_ok(), f"send() must return Ok(RequestId) during peer churn, got: {send_result.err()}"

                request_id = send_result.ok_value
                assert request_id, "send() returned an empty RequestId"

                # Expect Propagated via the surviving lightpush peer (peer2).
                propagated_event = wait_for_propagated(
                    collector=sender_collector,
                    request_id=request_id,
                    timeout_s=PROPAGATED_TIMEOUT_S,
                )
                assert propagated_event is not None, (
                    f"No MessagePropagatedEvent within {PROPAGATED_TIMEOUT_S}s "
                    f"after the selected lightpush peer disappeared. "
                    f"Collected events: {sender_collector.events}"
                )

                error_event = wait_for_error(
                    collector=sender_collector,
                    request_id=request_id,
                    timeout_s=0,
                )
                assert error_event is None, f"Unexpected message_error event during peer churn: {error_event}"

    def test_s30_concurrent_sends_during_auto_subscribe(self, node_config):
        """
        S30: concurrent sends on the same content topic during initial auto-subscribe.
          - Sender starts unsubscribed to the target topic.
          - Several send() calls are issued at nearly the same time.
          - Each call must return Ok(RequestId) with a unique id.
          - Each request id must get its own propagated event,
            with no dropped or cross-associated events.
        """
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
                "portsshift": 1,
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
                for event in sender_collector.events:
                    event_request_id = event.get("requestId")
                    if event_request_id is None:
                        continue
                    assert event_request_id in issued, (
                        f"Event carries an unknown requestId={event_request_id!r}, " f"not in issued set {issued}. Event: {event}"
                    )

    @pytest.mark.note("S31 exposes nwaku crash in json_serialization writer")
    def test_s31_concurrent_sends_mixed_topics_during_churn(self, node_config):
        """
        S31: concurrent sends across mixed content topics during peer churn.
        """
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

            for request_id in phase1_ids + phase3_ids:
                propagated_event = wait_for_propagated(
                    collector=sender_collector,
                    request_id=request_id,
                    timeout_s=PROPAGATED_TIMEOUT_S,
                )
                assert propagated_event is not None, (
                    f"No MessagePropagatedEvent for stable-phase "
                    f"request_id={request_id} within {PROPAGATED_TIMEOUT_S}s. "
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
            for event in sender_collector.events:
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
                    timeout_s=PROPAGATED_TIMEOUT_S,
                )
                assert sent_event is not None, (
                    f"No message_sent event for phase-3 request_id={request_id} "
                    f"within {PROPAGATED_TIMEOUT_S}s. Collected events: {sender_collector.events}"
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


class TestS06CoreSenderRelayOnly(StepsCommon):
    """
    S06 — Core sender with relay peers only, no store.
    Sender has local relay enabled and is connected to one relay peer.
    Expected: send() returns Ok(RequestId), message_propagated event arrives,
    no message_sent (store disabled), no message_error.
    """

    def test_s06_relay_propagation_without_store(self, node_config):
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
            peer_config = {
                **node_config,
                "staticnodes": [get_node_multiaddr(sender)],
                "portsshift": 1,
            }

            peer_result = WrapperManager.create_and_start(config=peer_config)
            assert peer_result.is_ok(), f"Failed to start relay peer: {peer_result.err()}"

            with peer_result.ok_value:
                message = self.create_message(
                    payload=to_base64("S06 relay-only test payload"),
                    contentTopic="/test/1/s06-relay-only/proto",
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
