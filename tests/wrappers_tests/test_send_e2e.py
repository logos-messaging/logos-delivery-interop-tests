"""
S17 – No delivery peers at T0, relay peers appear later.

Setup:   Sender starts isolated (no peers).
Action:  send() is called immediately.
Then:    A relay peer is started with the sender's multiaddr as a static peer,
         causing both nodes to connect and the sender's retry loop to deliver.
Expected:
  - send() returns Ok(RequestId) synchronously even with no peers.
  - A MessagePropagatedEvent with the same RequestId arrives once the
    relay peer joins.
  - No MessageErrorEvent arrives before the Propagated event.

Reference: issue #163, scenario S17.
"""

import pytest

from src.node.wrappers_manager import WrapperManager
from src.node.wrappers_helpers import (
    EventCollector,
    get_node_multiaddr,
    wait_for_propagated,
    wait_for_error,
)

CONTENT_TOPIC = "/test/1/s17-relay-late-join/proto"
PROPAGATED_TIMEOUT_S = 30.0


class TestS17RelayPeersAppearLater:
    @pytest.fixture
    def sender_collector(self):
        return EventCollector()

    @pytest.fixture
    def sender_node(self, node_config, sender_collector):
        # node_config is provided by the conftest.py fixture;
        # override only what differs from the default for an isolated sender.
        node_config.update({"relay": True, "store": False, "discv5Discovery": False})

        result = WrapperManager.create_and_start(config=node_config, event_cb=sender_collector.event_callback)
        assert result.is_ok(), f"Failed to start sender: {result.err()}"

        node = result.ok_value
        yield node
        node.stop_and_destroy()

    def test_send_before_relay_peers_exist_then_peer_joins(self, sender_node, sender_collector, node_config):
        """
        S17: send() is called while the sender has no peers.
        A relay peer is then brought online with the sender's address as a
        static peer, causing the sender's retry loop to deliver the message.
        """

        # Step 1: send while isolated — must return Ok(RequestId) immediately
        message = {
            "contentTopic": CONTENT_TOPIC,
            "payload": "UzE3IHJlbGF5IGxhdGUgam9pbg==",  # base64("S17 relay late join")
        }

        send_result = sender_node.send_message(message)

        assert send_result.is_ok(), f"send() must return Ok(RequestId) even with no peers, got: {send_result.err()}"

        request_id = send_result.ok_value
        assert request_id, "send() returned an empty RequestId"

        # Step 2: get sender's multiaddr so the relay peer can dial back to it
        sender_multiaddr = get_node_multiaddr(sender_node)

        # Step 3: start the relay peer with the sender listed as a static peer.
        # node_config produces a fresh config with its own free ports each call.
        node_config.update({"relay": True, "store": False, "discv5Discovery": False})
        node_config["staticPeers"] = [sender_multiaddr]

        relay_peer_result = WrapperManager.create_and_start(config=node_config)
        assert relay_peer_result.is_ok(), f"Failed to start relay peer: {relay_peer_result.err()}"
        relay_peer = relay_peer_result.ok_value

        try:
            # Step 4: wait for a Propagated event — the sender's retry loop should
            # deliver the message now that a relay peer is reachable
            propagated_event = wait_for_propagated(
                collector=sender_collector,
                request_id=request_id,
                timeout_s=PROPAGATED_TIMEOUT_S,
            )

            # Step 5: check no Error arrived before Propagated
            error_event = wait_for_error(
                collector=sender_collector,
                request_id=request_id,
                timeout_s=0,
            )

            # All events for this request must carry the same requestId
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
