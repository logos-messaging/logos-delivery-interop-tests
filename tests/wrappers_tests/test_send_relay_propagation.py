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
from tests.wrappers_tests.conftest import free_port

logger = get_custom_logger(__name__)

PROPAGATED_TIMEOUT_S = 30.0
SENT_TIMEOUT_S = 10.0
NO_SENT_OBSERVATION_S = 5.0
SENT_AFTER_STORE_TIMEOUT_S = 60.0
NO_STORE_OBSERVATION_S = 60.0

# S20 stabilization delays for gossipsub mesh formation.
MESH_STABILIZATION_S = 10
STORE_JOIN_STABILIZATION_S = 10


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

                message = create_message_bindings(
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
                "portsShift": 1,
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


class TestS17SendBeforeRelayPeersJoin(StepsCommon):
    """
    S17: sender starts isolated, calls send()
      - send() returns Ok(RequestId) immediately
      - Propagated event eventually arrives after a relay peer joins
    """

    def test_s17_send_before_relay_peers_joins(self, node_config):
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
                "portsShift": 1,
                "store": True,
            }

            relay_result = WrapperManager.create_and_start(config=relay_config)
            assert relay_result.is_ok(), f"Failed to start relay peer: {relay_result.err()}"

            with relay_result.ok_value:
                # Match the gating part2's tests use: wait until the sender
                # actually reports Connected/PartiallyConnected before asserting
                # on propagation. Without this, the wait_for_propagated poll can
                # miss the event because the sender's mesh hasn't formed yet.
                assert wait_for_connected(sender_collector) is not None, (
                    f"Sender did not reach Connected/PartiallyConnected after " f"relay peer joined. Collected events: {sender_collector.events}"
                )

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


class TestS19StorePeerAppearsAfterPropagation(StepsStore):
    """
    S19: a store peer comes online later.
      - send() returns Ok(RequestId) immediately
      - Propagated --- relay peer
      - Sent when store peer is reachable
    """

    @pytest.mark.docker_required
    @pytest.mark.xfail(reason="fails to republish after store peer joins mesh see https://github.com/logos-messaging/logos-delivery/issues/3848")
    def test_s19_store_peer_appears_after_propagation(self, node_config):
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
                "tcpPort": free_port(),
                "discv5UdpPort": free_port(),
                "restPort": free_port(),
                "staticnodes": [get_node_multiaddr(sender_node)],
                "store": False,
                "reliabilityEnabled": True,
            }

            relay_result = WrapperManager.create_and_start(config=relay_config)
            assert relay_result.is_ok(), f"Failed to start relay peer: {relay_result.err()}"

            with relay_result.ok_value as relay_peer:
                # Wait until the sender actually reports a connection before
                # sending. Without this, send() can race the static-peer
                # dial on slower runners (same gate S17 uses).
                assert wait_for_connected(sender_collector) is not None, (
                    f"Sender did not reach Connected/PartiallyConnected after " f"relay peer joined. Collected events: {sender_collector.events}"
                )
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
                self.wait_for_autoconnection([store_node], hard_wait=40)
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


class TestS20StoreMissesInitiallyThenRetrySucceeds(StepsStore):
    """
    S20: relay propagation succeeds, the first store query misses
    (the store peer is reachable but does not yet have the message),
    a later retry republishes through the relay mesh, and the store
    peer then archives it.

    Covers state flow:
        SuccessfullyPropagated -> NextRoundRetry
          -> SuccessfullyPropagated -> SuccessfullyValidated
    """

    @pytest.mark.docker_required
    @pytest.mark.skip(reason="Forcing the miss store round not possible")
    def test_s20_store_misses_initially_then_retry_succeeds(self, node_config):
        sender_collector = EventCollector()
        store_node = WakuNode(NODE_2, f"s20_store_node_{self.test_id}")
        store_node.start(
            relay="true",
            store="true",
            discv5_discovery="false",
            cluster_id=node_config["clusterId"],
            shard=0,
        )
        store_multiaddr = store_node.get_multiaddr_with_id()

        node_config.update(
            {
                "relay": True,
                "store": False,
                "discv5Discovery": False,
                "numShardsInNetwork": 1,
                "reliabilityEnabled": True,
                "storenode": store_multiaddr,
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
                "store": False,
            }
            relay_result = WrapperManager.create_and_start(config=relay_config)
            assert relay_result.is_ok(), f"Failed to start relay peer: {relay_result.err()}"

            with relay_result.ok_value as relay_peer:
                # Wait for the sender to see the relay peer before publishing.
                assert wait_for_connected(sender_collector) is not None, (
                    f"Sender did not reach Connected/PartiallyConnected. " f"Collected events: {sender_collector.events}"
                )

                # Let the gossipsub mesh form between sender and relay peer.
                delay(MESH_STABILIZATION_S)

                message = create_message_bindings(ephemeral=False)
                send_result = sender_node.send_message(message=message)
                assert send_result.is_ok(), f"send() must return Ok(RequestId), got: {send_result.err()}"

                request_id = send_result.ok_value
                assert request_id, "send() returned an empty RequestId"

                # Round 1: propagation succeeds via the relay peer.
                propagated_event = wait_for_propagated(
                    collector=sender_collector,
                    request_id=request_id,
                    timeout_s=PROPAGATED_TIMEOUT_S,
                )
                assert propagated_event is not None, (
                    f"No MessagePropagatedEvent within {PROPAGATED_TIMEOUT_S}s. " f"Collected events: {sender_collector.events}"
                )

                # The store peer is reachable for queries but never received
                # the message via gossipsub, so the first store query must
                # miss and Sent must NOT arrive yet.
                early_sent_event = wait_for_sent(
                    collector=sender_collector,
                    request_id=request_id,
                    timeout_s=NO_SENT_OBSERVATION_S,
                )
                assert early_sent_event is None, (
                    f"MessageSentEvent arrived before the store could have the message. "
                    f"Initial store query should have missed. Event: {early_sent_event}"
                )

                # Now subscribe the store to the test topic and wire it into
                # the relay mesh so the next retry round's republish reaches
                # the store via gossipsub.
                store_node.set_relay_subscriptions([self.test_pubsub_topic])
                store_node.add_peers([get_node_multiaddr(sender_node), get_node_multiaddr(relay_peer)])
                self.wait_for_autoconnection([store_node], hard_wait=10)
                delay(STORE_JOIN_STABILIZATION_S)

                # Round 2: retry republishes, store archives, next query hits.
                sent_event = wait_for_sent(
                    collector=sender_collector,
                    request_id=request_id,
                    timeout_s=SENT_AFTER_STORE_TIMEOUT_S,
                )
                assert sent_event is not None, (
                    f"No MessageSentEvent within {SENT_AFTER_STORE_TIMEOUT_S}s "
                    f"after the store joined the relay mesh. The retry round "
                    f"should have republished and the store should have archived. "
                    f"Collected events: {sender_collector.events}"
                )

                self.check_published_message_is_stored(
                    store_node=store_node,
                    pubsub_topic=self.test_pubsub_topic,
                    messages_to_check=[message],
                    page_size=5,
                    ascending="true",
                )

                assert_event_invariants(sender_collector, request_id)


class TestS22NonEphemeralWithReliabilityDisabled(StepsCommon):
    """
    S22: non-ephemeral message with reliabilityEnabled disabled.
      - propagation path exists ,reliabilityEnabled = false.
      - Expected: Ok(RequestId), Propagated event only, no Sent event.
      Note: S17 already covers the positive path of this test with reliabilityEnabled=True.
    """

    def test_s22_non_ephemeral_message_with_reliability_disabled(self, node_config):
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
                "portsShift": 1,
                "store": True,
            }

            relay_result = WrapperManager.create_and_start(config=relay_config)
            assert relay_result.is_ok(), f"Failed to start relay peer: {relay_result.err()}"

            with relay_result.ok_value:
                # Wait for the sender to actually establish the mesh before
                # publishing, matching part2's pattern. Otherwise the publish
                # races with mesh formation and message_propagated may not fire.
                assert wait_for_connected(sender_collector) is not None, (
                    f"Sender did not reach Connected/PartiallyConnected. " f"Collected events: {sender_collector.events}"
                )

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
                    timeout_s=NO_SENT_OBSERVATION_S,
                )
                assert sent_event is None, (
                    f"Unexpected MessageSentEvent received when reliabilityEnabled is disabled.\n"
                    f"Sent event: {sent_event}\n"
                    f"Collected events: {sender_collector.events}"
                )

                assert_event_invariants(sender_collector, request_id)


class TestS23NoSentEventWhenRelayHasNoStore(StepsCommon):
    """
    S23: non-ephemeral message, reliability enabled, no store peer ever reachable.
      - Expected: Ok(RequestId), Propagated event only, no Sent and no terminal error.
    """

    def test_s23_no_sent_event_when_relay_has_no_store(self, node_config):
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
                "portsShift": 1,
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

                assert_event_invariants(sender_collector, request_id)


class TestS24EphemeralMessageWithReachableStore(StepsCommon):
    """
    S24: ephemeral message, reliability enabled, reachable store peer.
      - Setup: propagation path exists, relay peer has store=True (reachable),
      - Expected: Ok(RequestId), Propagated event only, no Sent event.
    """

    def test_s24_ephemeral_message_with_reachable_store(self, node_config):
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
                "portsShift": 1,
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

                assert_event_invariants(sender_collector, request_id)
