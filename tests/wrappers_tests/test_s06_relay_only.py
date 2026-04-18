import time
from time import time_ns

import pytest
from src.libs.common import to_base64
from src.node.wrappers_manager import WrapperManager
from src.node.wrapper_helpers import (
    EventCollector,
    get_node_multiaddr,
    wait_for_propagated,
    wait_for_sent,
    wait_for_error,
)
from tests.wrappers_tests.conftest import build_node_config

CONTENT_TOPIC = "/test/1/s06-relay-only/proto"
PROPAGATED_TIMEOUT_S = 30.0


class TestS06CoreSenderRelayOnly:
    """
    S06 — Core sender with relay peers only, no store.
    Sender has local relay enabled and is connected to one relay peer.
    Expected: send() returns Ok(RequestId), message_propagated event arrives,
    no message_sent (store disabled), no message_error.
    """

    def test_relay_propagation_without_store(self, node_config):
        sender_collector = EventCollector()

        sender_config = build_node_config(relay=True, store=False, lightpush=False, filter=False, discv5Discovery=False)
        sender_result = WrapperManager.create_and_start(config=sender_config, event_cb=sender_collector.event_callback)
        assert sender_result.is_ok(), f"Failed to start sender: {sender_result.err()}"
        sender = sender_result.ok_value

        try:
            sender_multiaddr = get_node_multiaddr(sender)

            peer_config = build_node_config(
                relay=True, store=False, lightpush=False, filter=False, discv5Discovery=False, staticnodes=[sender_multiaddr]
            )
            peer_result = WrapperManager.create_and_start(config=peer_config)
            assert peer_result.is_ok(), f"Failed to start relay peer: {peer_result.err()}"
            peer = peer_result.ok_value

            try:
                time.sleep(2)

                message = {
                    "payload": to_base64("S06 relay-only test payload"),
                    "contentTopic": CONTENT_TOPIC,
                    "timestamp": int(f"{time_ns():019d}"),
                }

                send_result = sender.send_message(message=message)
                assert send_result.is_ok(), f"send() failed: {send_result.err()}"

                request_id = send_result.ok_value
                assert request_id, "send() returned an empty RequestId"

                propagated = wait_for_propagated(sender_collector, request_id, timeout_s=PROPAGATED_TIMEOUT_S)
                assert propagated is not None, (
                    f"No message_propagated event within {PROPAGATED_TIMEOUT_S}s. " f"Collected events: {sender_collector.events}"
                )
                assert propagated["requestId"] == request_id

                error = wait_for_error(sender_collector, request_id, timeout_s=0)
                assert error is None, f"Unexpected message_error event: {error}"

                sent = wait_for_sent(sender_collector, request_id, timeout_s=0)
                assert sent is None, f"Unexpected message_sent event (store is disabled): {sent}"

            finally:
                peer.stop_and_destroy()

        finally:
            sender.stop_and_destroy()
