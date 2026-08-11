"""Repro harness for the SDS persistence crash. Skipped — out of scope.

Issue #191 lists "SDS state survives node restart" as Nim-side, not E2E. Kept
only to reproduce the teardown segfault: drop the skip marker, then drive it
with log/sds_crash_report/sds_wal_repro.sh (seed files are there too).

The FIXED channelId is deliberate — it accumulates persisted state instead of
avoiding it like unique_channel_id(). Enough state segfaults the node on stop
in Persistency.reset, killing the pytest process, so never run it unattended.
"""

import pytest

from src.libs.common import delay, to_base64
from src.node.subprocess_node import ChannelSenderProcess
from src.node.wrappers_manager import WrapperManager
from src.node.wrapper_helpers import EventCollector, create_message_bindings, get_node_multiaddr
from tests.wrappers_tests.test_channel_delivery import channel_payloads, wait_for_channel_received, wait_for_channel_received_count

REPRO_CHANNEL_ID = "repro-fixed-channel"
REPRO_CONTENT_TOPIC = "/test/1/repro-fixed-channel/proto"
SENDER_A = "repro-sender-a"
SENDER_B = "repro-sender-b"

MESH_SETTLE_S = 10
CAUSAL_SETTLE_S = 5
DELIVERY_TIMEOUT_S = 50.0


@pytest.mark.skip(
    reason="out of scope for the channel-layer E2E round (issue #191: SDS state across restarts is Nim-side); crashes the runner on purpose"
)
class TestChannelPersistenceRepro:
    def test_fixed_channel_id_exchange(self, node_config):
        """The RC08 exchange on a fixed channelId.

        Exit code is the driver's signal: 0 delivered, 1 stale causal history,
        139 crash in the library.
        """
        m1, m2, m3 = "repro from A", "repro reply from B", "repro follow-up from A"

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

            subscribe_result = receiver.subscribe_content_topic(REPRO_CONTENT_TOPIC)
            assert subscribe_result.is_ok(), f"receiver subscribe_content_topic failed: {subscribe_result.err()}"

            receiver_create = receiver.channel_create(REPRO_CHANNEL_ID, REPRO_CONTENT_TOPIC, SENDER_B)
            assert receiver_create.is_ok(), f"receiver channel_create failed: {receiver_create.err()}"

            with ChannelSenderProcess(
                sender_config,
                content_topic=REPRO_CONTENT_TOPIC,
                channel_id=REPRO_CHANNEL_ID,
                sender_id=SENDER_A,
                payload_b64=to_base64(m1),
                settle_s=MESH_SETTLE_S,
            ) as sender:
                first = wait_for_channel_received(receiver_collector, REPRO_CHANNEL_ID, DELIVERY_TIMEOUT_S)
                assert first is not None, f"B never saw A's first message. Collected events: {receiver_collector.snapshot()}"

                delay(CAUSAL_SETTLE_S)
                reply_result = receiver.channel_send(REPRO_CHANNEL_ID, create_message_bindings(payload=to_base64(m2)))
                assert reply_result.is_ok(), f"receiver channel_send failed: {reply_result.err()}"

                delivered_to_a = sender.wait_for_received(1, DELIVERY_TIMEOUT_S)
                assert channel_payloads(delivered_to_a) == [m2.encode()], f"A must deliver B's reply; got {channel_payloads(delivered_to_a)!r}"

                delay(CAUSAL_SETTLE_S)
                sender.send(to_base64(m3))

                delivered_to_b = wait_for_channel_received_count(receiver_collector, REPRO_CHANNEL_ID, 2, DELIVERY_TIMEOUT_S)
                assert channel_payloads(delivered_to_b) == [
                    m1.encode(),
                    m3.encode(),
                ], f"B must deliver A's messages in causal order; got {channel_payloads(delivered_to_b)!r}"
