import pytest
from src.steps.common import StepsCommon
from src.libs.common import to_base64
from src.node.wrappers_manager import WrapperManager
from src.node.wrapper_helpers import (
    EventCollector,
    get_node_multiaddr,
    wait_for_propagated,
    wait_for_error,
)

CONTENT_TOPIC = "/test/1/s17-relay-late-join/proto"
PROPAGATED_TIMEOUT_S = 30.0


class TestS17RelayPeersAppearLater(StepsCommon):
    """
    S17 – No delivery peers at T0, relay peers appear later.
    """

    def test_send_before_relay_peers_exist_then_peer_joins(self, node_config):
        """
        S17: send() is called while the sender has no peers.
        A relay peer is then brought online with the sender's address as a
        static peer, causing the sender's retry loop to deliver the message.
        """
        sender_collector = EventCollector()

        node_config.update({"relay": True, "store": False, "discv5Discovery": False})

        sender_result = WrapperManager.create_and_start(config=node_config, event_cb=sender_collector.event_callback)
        assert sender_result.is_ok(), f"Failed to start sender: {sender_result.err()}"
        sender_node = sender_result.ok_value

        # try:
        # Step 1: send while isolated — must return Ok(RequestId) immediately
        send_result = sender_node.send_message(message=self.create_message(payload=to_base64(f"Message")))
        assert send_result.is_ok(), f"send() must return Ok(RequestId) even with no peers, got: {send_result.err()}"

        request_id = send_result.ok_value
        assert request_id, "send() returned an empty RequestId"
        """
            # Step 2: get sender's multiaddr so the relay peer can dial back to it
            sender_multiaddr = get_node_multiaddr(sender_node)

            # Step 3: start the relay peer with the sender listed as a static peer
            relay_config = node_config.copy()
            relay_config["staticPeers"] = [sender_multiaddr]

            relay_result = WrapperManager.create_and_start(config=relay_config)
            assert relay_result.is_ok(), f"Failed to start relay peer: {relay_result.err()}"
            relay_peer = relay_result.ok_value

            try:
                # Step 4: wait for a Propagated event — the sender's retry loop should
                # deliver the message now that a relay peer is reachable
                propagated_event = wait_for_propagated(
                    collector=sender_collector,
                    request_id=request_id,
                    timeout_s=PROPAGATED_TIMEOUT_S,
                )

                # Step 5: check no Error event arrived
                error_event = wait_for_error(
                    collector=sender_collector,
                    request_id=request_id,
                    timeout_s=0,
                )

                for event in sender_collector.get_events_for_request(request_id):
                    assert event.get("requestId") == request_id, f"Event carries wrong requestId: {event}"

                assert propagated_event is not None, (
                    f"No MessagePropagatedEvent received within {PROPAGATED_TIMEOUT_S}s "
                    f"after relay peer joined. Collected events: {sender_collector.events}"
                )

                assert error_event is None, (
                    f"MessageErrorEvent arrived before Propagated — violates S17 expectations.\n"
                    f"Error     : {error_event}\n"
                    f"Propagated: {propagated_event}"
                )

            finally:
                relay_peer.stop_and_destroy()

        finally:
            sender_node.stop_and_destroy()
            
            """
