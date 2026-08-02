import base64
import time

from src.libs.common import delay, to_base64
from src.node.subprocess_node import ChannelSenderProcess
from src.node.wrappers_manager import WrapperManager
from src.node.wrapper_helpers import (
    EventCollector,
    create_message_bindings,
    get_node_multiaddr,
    unique_channel_id,
    wait_for_connected,
)

RC05_CHANNEL_PREFIX = "rc05-channel"
CONTENT_TOPIC = "/test/1/rc05-channel/proto"
SENDER_A = "rc05-sender-a"
SENDER_B = "rc05-sender-b"

CHANNEL_RECEIVED_EVENT = "channel_message_received"
MESSAGE_RECEIVED_EVENT = "message_received"

RC06_CHANNEL_PREFIX = "rc06-channel"
RC06_CONTENT_TOPIC = "/test/1/rc06-channel/proto"

RC07_CHANNEL_PREFIX = "rc07-channel"
RC07_CONTENT_TOPIC = "/test/1/rc07-channel/proto"
RC07_OTHER_CONTENT_TOPIC = "/test/1/rc07-other/proto"

RC08_CHANNEL_PREFIX = "rc08-channel"
RC08_CONTENT_TOPIC = "/test/1/rc08-channel/proto"
# A reply references what it answers only once that landed in the sender's SDS
# history; replying immediately races that write and asserts nothing.
RC08_CAUSAL_SETTLE_S = 5

RC09_CHANNEL_PREFIX = "rc09-channel"
RC09_CONTENT_TOPIC = "/test/1/rc09-channel/proto"

CLOSED_CHANNEL_PREFIX = "rc-closed-channel"
CLOSED_CONTENT_TOPIC = "/test/1/rc-closed-channel/proto"

MESH_SETTLE_S = 10
DELIVERY_TIMEOUT_S = 50.0
# Once the unmarked message has provably reached B's messaging layer, the
# channel ingress decision has already been made on that same event, so this is
# just a short grace window to catch any late channel_message_received.
NO_CHANNEL_DELIVERY_WINDOW_S = 10.0

# A has no peer to dial before it sends, so no mesh to settle.
RC09_SENDER_SETTLE_S = 2
# nim-sds DefaultRepairTMin: a repair request rides on an outgoing message only
# after T_min has passed.
RC09_REPAIR_REQUEST_DELAY_S = 35
RC09_RECOVERY_TIMEOUT_S = 90.0


def wait_for_channel_received(collector, channel_id, timeout_s, poll_interval_s=0.5):
    deadline = time.monotonic() + timeout_s
    while True:
        for event in collector.snapshot():
            if event.get("eventType") == CHANNEL_RECEIVED_EVENT and event.get("channelId") == channel_id:
                return event
        if time.monotonic() >= deadline:
            return None
        time.sleep(poll_interval_s)


def wait_for_channel_received_count(collector, channel_id, count, timeout_s, poll_interval_s=0.5):
    """Channel events for `channel_id`, oldest first; waits for `count` of them.

    Returns whatever has arrived when the timeout expires, so a caller can
    assert on both the order and the shortfall.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        received = [e for e in collector.snapshot() if e.get("eventType") == CHANNEL_RECEIVED_EVENT and e.get("channelId") == channel_id]
        if len(received) >= count or time.monotonic() >= deadline:
            return received
        time.sleep(poll_interval_s)


def channel_payloads(events):
    """Decoded payloads of channel events, oldest first."""
    return [base64.b64decode(event["payload"]) for event in events]


def wait_for_message_received(collector, content_topic, timeout_s, poll_interval_s=0.5):
    """Wait for a messaging-layer message_received event on `content_topic`.

    Used to prove a raw relay message actually reached the receiver, independent
    of the channel layer (the content topic lives under the nested `message`).
    """
    deadline = time.monotonic() + timeout_s
    while True:
        for event in collector.snapshot():
            if event.get("eventType") == MESSAGE_RECEIVED_EVENT and (event.get("message") or {}).get("contentTopic") == content_topic:
                return event
        if time.monotonic() >= deadline:
            return None
        time.sleep(poll_interval_s)


class TestChannelDelivery:
    def test_rc05_basic_a_to_b_delivery(self, node_config):
        """RC05: A's channel send is delivered to B on the matching channel + topic.

        Relay-only (store + reliability off). B must fire a channel_message_received
        event carrying the payload intact and tagged with A's senderId.

        A runs in a separate, storage-isolated process: co-located nodes share the
        library's SDS Persistency singleton and B drops A's own message as a
        duplicate. See src/node/subprocess_node.py.
        """
        channel_id = unique_channel_id(RC05_CHANNEL_PREFIX)
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

            subscribe_result = receiver.subscribe_content_topic(CONTENT_TOPIC)
            assert subscribe_result.is_ok(), f"receiver subscribe_content_topic failed: {subscribe_result.err()}"

            receiver_create = receiver.channel_create(channel_id, CONTENT_TOPIC, SENDER_B)
            assert receiver_create.is_ok(), f"receiver channel_create failed: {receiver_create.err()}"

            with ChannelSenderProcess(
                sender_config,
                content_topic=CONTENT_TOPIC,
                channel_id=channel_id,
                sender_id=SENDER_A,
                payload_b64=payload_b64,
                settle_s=MESH_SETTLE_S,
            ):
                received = wait_for_channel_received(receiver_collector, channel_id, DELIVERY_TIMEOUT_S)
                assert received is not None, (
                    f"No {CHANNEL_RECEIVED_EVENT} on B for {channel_id} within {DELIVERY_TIMEOUT_S}s. "
                    f"Collected events: {receiver_collector.snapshot()}"
                )
                assert base64.b64decode(received["payload"]) == base64.b64decode(
                    payload_b64
                ), f"delivered payload mismatch: got {received['payload']!r}, sent {payload_b64!r}"
                assert (
                    received["senderId"] == SENDER_A
                ), f"received event must carry the originator's senderId {SENDER_A!r}, got {received.get('senderId')!r}"

    def test_rc06_missing_marker_dropped(self, node_config):
        """RC06: a plain message on the channel's content topic but without the
        Reliable-Channel spec marker is dropped at channel ingress.

        A publishes a raw relay message (no RELIABLE-CHANNEL-API/1 meta) on B's
        content topic. B's messaging layer still surfaces it (message_received),
        proving the message arrived, but the channel ingress filter drops it: no
        channel_message_received fires for the channel.
        """
        channel_id = unique_channel_id(RC06_CHANNEL_PREFIX)
        payload_b64 = to_base64("rc06 unmarked message")

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

                subscribe_result = receiver.subscribe_content_topic(RC06_CONTENT_TOPIC)
                assert subscribe_result.is_ok(), f"receiver subscribe_content_topic failed: {subscribe_result.err()}"
                subscribe_result = sender.subscribe_content_topic(RC06_CONTENT_TOPIC)
                assert subscribe_result.is_ok(), f"sender subscribe_content_topic failed: {subscribe_result.err()}"

                # Only B runs a channel; A never marks its traffic.
                receiver_create = receiver.channel_create(channel_id, RC06_CONTENT_TOPIC, SENDER_B)
                assert receiver_create.is_ok(), f"receiver channel_create failed: {receiver_create.err()}"

                delay(MESH_SETTLE_S)

                # Plain relay publish: right content topic, but no Reliable-Channel
                # marker, so B's channel ingress filter must drop it.
                send_result = sender.send_message(create_message_bindings(contentTopic=RC06_CONTENT_TOPIC, payload=payload_b64))
                assert send_result.is_ok(), f"send_message failed: {send_result.err()}"

                # It reaches B's messaging layer, so the drop below is the marker
                # filter at work, not a message that simply never arrived.
                arrived = wait_for_message_received(receiver_collector, RC06_CONTENT_TOPIC, DELIVERY_TIMEOUT_S)
                assert arrived is not None, (
                    f"receiver never saw a {MESSAGE_RECEIVED_EVENT} for {RC06_CONTENT_TOPIC} within {DELIVERY_TIMEOUT_S}s; "
                    f"cannot conclude the channel dropped it. Collected events: {receiver_collector.snapshot()}"
                )

                # The channel ingress filter drops the unmarked message: no channel event.
                leaked = wait_for_channel_received(receiver_collector, channel_id, NO_CHANNEL_DELIVERY_WINDOW_S)
                assert leaked is None, f"an unmarked message must not surface as a {CHANNEL_RECEIVED_EVENT}; got: {leaked!r}"

    def test_rc07_wrong_content_topic_dropped(self, node_config):
        """RC07: a correctly-marked channel message published on a different
        content topic is dropped at channel ingress.

        A runs the same channelId as B but on RC07_OTHER_CONTENT_TOPIC. B is
        subscribed to that topic too, so B's messaging layer still surfaces the
        message (message_received), proving it arrived, but B's channel is bound
        to RC07_CONTENT_TOPIC and must not fire channel_message_received.
        """
        channel_id = unique_channel_id(RC07_CHANNEL_PREFIX)
        payload_b64 = to_base64("rc07 message on the wrong content topic")

        node_config.update(
            {
                "relay": True,
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

            for content_topic in (RC07_CONTENT_TOPIC, RC07_OTHER_CONTENT_TOPIC):
                subscribe_result = receiver.subscribe_content_topic(content_topic)
                assert subscribe_result.is_ok(), f"receiver subscribe_content_topic {content_topic} failed: {subscribe_result.err()}"

            receiver_create = receiver.channel_create(channel_id, RC07_CONTENT_TOPIC, SENDER_B)
            assert receiver_create.is_ok(), f"receiver channel_create failed: {receiver_create.err()}"

            with ChannelSenderProcess(
                sender_config,
                content_topic=RC07_OTHER_CONTENT_TOPIC,
                channel_id=channel_id,
                sender_id=SENDER_A,
                payload_b64=payload_b64,
                settle_s=MESH_SETTLE_S,
            ):
                arrived = wait_for_message_received(receiver_collector, RC07_OTHER_CONTENT_TOPIC, DELIVERY_TIMEOUT_S)
                assert arrived is not None, (
                    f"receiver never saw a {MESSAGE_RECEIVED_EVENT} for {RC07_OTHER_CONTENT_TOPIC} within {DELIVERY_TIMEOUT_S}s; "
                    f"cannot conclude the channel dropped it. Collected events: {receiver_collector.snapshot()}"
                )

                leaked = wait_for_channel_received(receiver_collector, channel_id, NO_CHANNEL_DELIVERY_WINDOW_S)
                assert leaked is None, f"a message on a foreign content topic must not surface as a {CHANNEL_RECEIVED_EVENT}; got: {leaked!r}"

    def test_rc08_bidirectional_exchange_preserves_causal_order(self, node_config):
        """RC08: A and B exchange interleaved messages on one channel, and each
        side delivers the other's in causal order.

        Each reply is sent only after the message it answers has landed, so m2
        references m1 and m3 references m2. B must deliver m1 then m3, A must
        deliver m2.
        """
        channel_id = unique_channel_id(RC08_CHANNEL_PREFIX)
        m1, m2, m3 = "rc08 from A", "rc08 reply from B", "rc08 follow-up from A"

        node_config.update(
            {
                "relay": True,
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

            subscribe_result = receiver.subscribe_content_topic(RC08_CONTENT_TOPIC)
            assert subscribe_result.is_ok(), f"receiver subscribe_content_topic failed: {subscribe_result.err()}"

            receiver_create = receiver.channel_create(channel_id, RC08_CONTENT_TOPIC, SENDER_B)
            assert receiver_create.is_ok(), f"receiver channel_create failed: {receiver_create.err()}"

            with ChannelSenderProcess(
                sender_config,
                content_topic=RC08_CONTENT_TOPIC,
                channel_id=channel_id,
                sender_id=SENDER_A,
                payload_b64=to_base64(m1),
                settle_s=MESH_SETTLE_S,
            ) as sender:
                first = wait_for_channel_received(receiver_collector, channel_id, DELIVERY_TIMEOUT_S)
                assert first is not None, (
                    f"B never saw A's first message within {DELIVERY_TIMEOUT_S}s; "
                    f"nothing to reply to. Collected events: {receiver_collector.snapshot()}"
                )

                # B replies only now, so m2 carries m1 in its causal history.
                delay(RC08_CAUSAL_SETTLE_S)
                reply_result = receiver.channel_send(channel_id, create_message_bindings(payload=to_base64(m2)))
                assert reply_result.is_ok(), f"receiver channel_send failed: {reply_result.err()}"

                delivered_to_a = sender.wait_for_received(1, DELIVERY_TIMEOUT_S)
                assert channel_payloads(delivered_to_a) == [m2.encode()], f"A must deliver B's reply; got {channel_payloads(delivered_to_a)!r}"

                # Same race on A's side.
                delay(RC08_CAUSAL_SETTLE_S)
                sender.send(to_base64(m3))

                delivered_to_b = wait_for_channel_received_count(receiver_collector, channel_id, 2, DELIVERY_TIMEOUT_S)
                assert channel_payloads(delivered_to_b) == [m1.encode(), m3.encode()], (
                    f"B must deliver A's messages in causal order; got {channel_payloads(delivered_to_b)!r}. "
                    f"Collected events: {receiver_collector.snapshot()}"
                )

    def test_rc09_offline_receiver_recovers_via_sds_repair(self, node_config):
        """RC09: A sends while B is not up yet; B joins and still delivers the
        missed message, via SDS-R repair.

        Nothing re-publishes on its own (the unacked sweep only counts attempts,
        the periodic-sync callback is unwired), so recovery goes: B learns m1
        exists from m2's causal history and parks m2, rides a repair request on
        its own next send, A rebroadcasts m1, the parked m2 is released. B must
        end up with m1 then m2.
        """
        channel_id = unique_channel_id(RC09_CHANNEL_PREFIX)
        m1, m2, m3 = "rc09 sent while B is away", "rc09 sent after B joins", "rc09 from B"

        node_config.update(
            {
                "relay": True,
                "store": False,
                "reliabilityEnabled": False,
                "numShardsInNetwork": 1,
            }
        )
        # A comes up first with nobody to dial; B joins later and dials A.
        sender_config = {**node_config, "portsShift": 1}

        with ChannelSenderProcess(
            sender_config,
            content_topic=RC09_CONTENT_TOPIC,
            channel_id=channel_id,
            sender_id=SENDER_A,
            payload_b64=to_base64(m1),
            settle_s=RC09_SENDER_SETTLE_S,
        ) as sender:
            receiver_collector = EventCollector()
            receiver_config = {**node_config, "staticnodes": [sender.multiaddr]}
            receiver_result = WrapperManager.create_and_start(config=receiver_config, event_cb=receiver_collector.event_callback)
            assert receiver_result.is_ok(), f"Failed to start receiver: {receiver_result.err()}"

            with receiver_result.ok_value as receiver:
                assert wait_for_connected(receiver_collector) is not None, "Receiver did not reach Connected/PartiallyConnected state"

                subscribe_result = receiver.subscribe_content_topic(RC09_CONTENT_TOPIC)
                assert subscribe_result.is_ok(), f"receiver subscribe_content_topic failed: {subscribe_result.err()}"

                receiver_create = receiver.channel_create(channel_id, RC09_CONTENT_TOPIC, SENDER_B)
                assert receiver_create.is_ok(), f"receiver channel_create failed: {receiver_create.err()}"

                delay(MESH_SETTLE_S)

                # m2 is B's only clue it missed m1: SDS parks it and books a repair request.
                sender.send(to_base64(m2))

                delay(RC09_REPAIR_REQUEST_DELAY_S)

                # The request only travels on B's own outgoing traffic.
                repair_carrier = receiver.channel_send(channel_id, create_message_bindings(payload=to_base64(m3)))
                assert repair_carrier.is_ok(), f"receiver channel_send failed: {repair_carrier.err()}"

                recovered = wait_for_channel_received_count(receiver_collector, channel_id, 2, RC09_RECOVERY_TIMEOUT_S)
                assert channel_payloads(recovered) == [m1.encode(), m2.encode()], (
                    f"B must recover the message it missed and release the parked one, in causal order; "
                    f"got {channel_payloads(recovered)!r}. Collected events: {receiver_collector.snapshot()}"
                )

    def test_receive_after_close_emits_no_channel_event(self, node_config):
        """A closed channel must not deliver: B closes its channel, then A sends a
        valid channel message on the same channel + content topic.

        B stays subscribed to the content topic, so B's messaging layer still
        surfaces the message (message_received), proving it arrived, but the
        closed channel must not fire channel_message_received.
        """
        channel_id = unique_channel_id(CLOSED_CHANNEL_PREFIX)
        payload_b64 = to_base64("message for a closed channel")

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

            subscribe_result = receiver.subscribe_content_topic(CLOSED_CONTENT_TOPIC)
            assert subscribe_result.is_ok(), f"receiver subscribe_content_topic failed: {subscribe_result.err()}"

            receiver_create = receiver.channel_create(channel_id, CLOSED_CONTENT_TOPIC, SENDER_B)
            assert receiver_create.is_ok(), f"receiver channel_create failed: {receiver_create.err()}"

            receiver_close = receiver.channel_close(channel_id)
            assert receiver_close.is_ok(), f"receiver channel_close failed: {receiver_close.err()}"

            with ChannelSenderProcess(
                sender_config,
                content_topic=CLOSED_CONTENT_TOPIC,
                channel_id=channel_id,
                sender_id=SENDER_A,
                payload_b64=payload_b64,
                settle_s=MESH_SETTLE_S,
            ):
                arrived = wait_for_message_received(receiver_collector, CLOSED_CONTENT_TOPIC, DELIVERY_TIMEOUT_S)
                assert arrived is not None, (
                    f"receiver never saw a {MESSAGE_RECEIVED_EVENT} for {CLOSED_CONTENT_TOPIC} within {DELIVERY_TIMEOUT_S}s; "
                    f"cannot conclude the closed channel stayed silent. Collected events: {receiver_collector.snapshot()}"
                )

                leaked = wait_for_channel_received(receiver_collector, channel_id, NO_CHANNEL_DELIVERY_WINDOW_S)
                assert leaked is None, f"a closed channel must not emit {CHANNEL_RECEIVED_EVENT}; got: {leaked!r}"
