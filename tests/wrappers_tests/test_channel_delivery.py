import base64
import time

from src.libs.common import delay, to_base64
from src.node.wrappers_manager import WrapperManager
from src.node.wrapper_helpers import (
    EventCollector,
    create_message_bindings,
    get_node_multiaddr,
    wait_for_connected,
)

CHANNEL_ID = "rc05-channel"
CONTENT_TOPIC = "/test/1/rc05-channel/proto"
SENDER_A = "rc05-sender-a"
SENDER_B = "rc05-sender-b"

CHANNEL_RECEIVED_EVENT = "channel_message_received"

MESH_SETTLE_S = 10
DELIVERY_TIMEOUT_S = 50.0


def wait_for_channel_received(collector, channel_id, timeout_s, poll_interval_s=0.5):
    deadline = time.monotonic() + timeout_s
    while True:
        for event in collector.snapshot():
            if event.get("eventType") == CHANNEL_RECEIVED_EVENT and event.get("channelId") == channel_id:
                return event
        if time.monotonic() >= deadline:
            return None
        time.sleep(poll_interval_s)


class TestChannelDelivery:
    def test_rc05_basic_a_to_b_delivery(self, node_config):
        """RC05: A's channel send is delivered to B on the matching channel + topic.

        Relay-only (store + reliability off); only B subscribes. B must fire a
        channel_message_received event carrying the payload intact and tagged with A's senderId.
        """
        payload_b64 = to_base64("rc05 hello from A")

        node_config.update(
            {
                "relay": True,
                "store": False,
                "reliabilityEnabled": False,
                "numShardsInNetwork": 1,
            }
        )

        receiver_collector = EventCollector()
        receiver_result = WrapperManager.create_and_start(config=node_config, event_cb=receiver_collector.event_callback)
        assert receiver_result.is_ok(), f"Failed to start receiver: {receiver_result.err()}"

        with receiver_result.ok_value as receiver:
            sender_config = {
                **node_config,
                "staticnodes": [get_node_multiaddr(receiver)],
                "portsShift": 1,
            }
            sender_collector = EventCollector()
            sender_result = WrapperManager.create_and_start(config=sender_config, event_cb=sender_collector.event_callback)
            assert sender_result.is_ok(), f"Failed to start sender: {sender_result.err()}"

            with sender_result.ok_value as sender:
                assert wait_for_connected(sender_collector) is not None, "Sender did not reach Connected/PartiallyConnected state"

                subscribe_result = receiver.subscribe_content_topic(CONTENT_TOPIC)
                assert subscribe_result.is_ok(), f"receiver subscribe_content_topic failed: {subscribe_result.err()}"
                subscribe_result = sender.subscribe_content_topic(CONTENT_TOPIC)
                assert subscribe_result.is_ok(), f"sender subscribe_content_topic failed: {subscribe_result.err()}"

                receiver_create = receiver.channel_create(CHANNEL_ID, CONTENT_TOPIC, SENDER_B)
                assert receiver_create.is_ok(), f"receiver channel_create failed: {receiver_create.err()}"

                sender_create = sender.channel_create(CHANNEL_ID, CONTENT_TOPIC, SENDER_A)
                assert sender_create.is_ok(), f"sender channel_create failed: {sender_create.err()}"

                delay(MESH_SETTLE_S)

                send_result = sender.channel_send(CHANNEL_ID, create_message_bindings(payload=payload_b64))
                assert send_result.is_ok(), f"channel_send failed: {send_result.err()}"
                assert send_result.ok_value, f"channel_send returned an empty handle: {send_result.ok_value!r}"

                received = wait_for_channel_received(receiver_collector, CHANNEL_ID, DELIVERY_TIMEOUT_S)
                assert received is not None, (
                    f"No {CHANNEL_RECEIVED_EVENT} on B for {CHANNEL_ID} within {DELIVERY_TIMEOUT_S}s. "
                    f"Collected events: {receiver_collector.snapshot()}"
                )
                assert base64.b64decode(received["payload"]) == base64.b64decode(
                    payload_b64
                ), f"delivered payload mismatch: got {received['payload']!r}, sent {payload_b64!r}"
                assert (
                    received["senderId"] == SENDER_A
                ), f"received event must carry the originator's senderId {SENDER_A!r}, got {received.get('senderId')!r}"
