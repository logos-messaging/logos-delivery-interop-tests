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
    assert_event_invariants,
    create_message_bindings,
    get_node_multiaddr,
    wait_for_propagated,
    wait_for_sent,
    wait_for_error,
)
from src.steps.store import StepsStore
from tests.wrappers_tests.conftest import build_node_config

logger = get_custom_logger(__name__)


PROPAGATED_TIMEOUT_S = 30.0
SENT_TIMEOUT_S = 10.0
NO_SENT_OBSERVATION_S = 5.0
SENT_AFTER_STORE_TIMEOUT_S = 60.0

# MaxTimeInCache from send_service.nim.
MAX_TIME_IN_CACHE_S = 60.0
# Extra slack to cover the background retry loop tick after the window expires.
CACHE_EXPIRY_SLACK_S = 10.0
ERROR_AFTER_CACHE_EXPIRY_TIMEOUT_S = MAX_TIME_IN_CACHE_S + CACHE_EXPIRY_SLACK_S
RETRY_WINDOW_EXPIRED_MSG = "Unable to send within retry time window"


@pytest.mark.smoke
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

                assert_event_invariants(sender_collector, request_id)

    def test_s17_no_sent_event_when_relay_has_no_store(self, node_config):
        """
        S17 negative: relay peerstore=false, there shouldn't be a Sent event,.
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
                    timeout_s=SENT_TIMEOUT_S,
                )
                assert sent_event is None, (
                    f"Unexpected MessageSentEvent received when relay peer has store=false.\n"
                    f"Sent event: {sent_event}\n"
                    f"Collected events: {sender_collector.events}"
                )

                assert_event_invariants(sender_collector, request_id)

    def test_s19_store_peer_appears_after_propagation(self, node_config):
        """
        S19: a store peer comes online later.
           question for Zoltan , is reliability = true mandatory for the store peer ?
           what is the effect of the reliability here ?
          - send() returns Ok(RequestId) immediately
          - Propagated --- relay peer
          - Sent when store peer is reachable
        """
        sender_collector = EventCollector()

        node_config.update(
            {
                "relay": True,
                "store": False,
                "discv5Discovery": False,
                "numShardsInNetwork": 1,
                # "p2preliability": True,
            }
        )

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
                # "p2preliability": False, # commented as the option not supported
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
                store_node.start(relay="true", store="true", discv5_discovery="false")
                store_node.set_relay_subscriptions([self.test_pubsub_topic])
                relay_multiaddr = get_node_multiaddr(relay_peer)
                sender_multiaddr = get_node_multiaddr(sender_node)
                store_node.add_peers([relay_multiaddr, sender_multiaddr])
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

                assert_event_invariants(sender_collector, request_id)

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

            assert_event_invariants(sender_collector, request_id)


class TestS07CoreSenderRelayAndStore(StepsCommon):
    """
    S07 — Core sender with relay peers and store peer, reliability enabled.
    Sender relays message to a store-capable peer; delivery service validates
    the message reached the store via p2p reliability check.
    Expected: Propagated, then Sent.
    """

    def test_s07_relay_propagation_with_store_validation(self, node_config):
        sender_collector = EventCollector()

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
                "portsshift": 1,
                "store": True,
            }

            peer_result = WrapperManager.create_and_start(config=peer_config)
            assert peer_result.is_ok(), f"Failed to start store peer: {peer_result.err()}"

            with peer_result.ok_value:
                message = create_message_bindings(
                    payload=to_base64("S07 relay+store test payload"),
                    contentTopic="/test/1/s07-relay-store/proto",
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

                sent = wait_for_sent(
                    collector=sender_collector,
                    request_id=request_id,
                    timeout_s=SENT_TIMEOUT_S,
                )
                assert sent is not None, (
                    f"No message_sent event within {SENT_TIMEOUT_S}s after propagation. " f"Collected events: {sender_collector.events}"
                )
                assert sent["requestId"] == request_id

                error = wait_for_error(sender_collector, request_id, timeout_s=0)
                assert error is None, f"Unexpected message_error event: {error}"

                assert_event_invariants(sender_collector, request_id)


class TestS10EdgeSenderLightpushOnly(StepsCommon):
    """
    S10 — Edge sender with lightpush path only, no store peer.
    Edge sender has no local relay; it publishes via a lightpush service node.
    Expected: Propagated only (no Sent, no Error).
    """

    def test_s10_edge_lightpush_propagation(self, node_config):
        sender_collector = EventCollector()

        common = {
            "store": False,
            "filter": False,
            "discv5Discovery": False,
            "numShardsInNetwork": 1,
        }

        # 1. Service node: relay + lightpush server (gateway for the edge sender).
        service_config = build_node_config(relay=True, lightpush=True, **common)

        service_result = WrapperManager.create_and_start(config=service_config)
        assert service_result.is_ok(), f"Failed to start service node: {service_result.err()}"

        with service_result.ok_value as service_node:
            service_multiaddr = get_node_multiaddr(service_node)

            # 2. Relay peer: forms gossipsub mesh with the service node so it
            #    has someone to relay-publish to after receiving lightpush.
            relay_config = build_node_config(
                relay=True,
                staticnodes=[service_multiaddr],
                **common,
            )

            relay_result = WrapperManager.create_and_start(config=relay_config)
            assert relay_result.is_ok(), f"Failed to start relay peer: {relay_result.err()}"

            with relay_result.ok_value:
                # 3. Edge sender: lightpush client only, no relay.
                edge_config = build_node_config(
                    mode="Edge",
                    relay=False,
                    lightpushnode=service_multiaddr,
                    staticnodes=[service_multiaddr],
                    **common,
                )

                edge_result = WrapperManager.create_and_start(
                    config=edge_config,
                    event_cb=sender_collector.event_callback,
                )
                assert edge_result.is_ok(), f"Failed to start edge sender: {edge_result.err()}"

                with edge_result.ok_value as edge_sender:
                    message = create_message_bindings(
                        payload=to_base64("S10 edge lightpush test payload"),
                        contentTopic="/test/1/s10-edge-lightpush/proto",
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

                    sent = wait_for_sent(sender_collector, request_id, timeout_s=NO_SENT_OBSERVATION_S)
                    assert sent is None, f"Unexpected message_sent event (no store peer): {sent}"

                    error = wait_for_error(sender_collector, request_id, timeout_s=0)
                    assert error is None, f"Unexpected message_error event: {error}"

                    assert_event_invariants(sender_collector, request_id)


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

                assert_event_invariants(sender_collector, request_id)
