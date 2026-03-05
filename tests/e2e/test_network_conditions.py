import pytest
import logging
from time import time, sleep
from src.libs.custom_logger import get_custom_logger
from src.env_vars import NODE_1, NODE_2
from src.node.waku_node import WakuNode
from src.steps.relay import StepsRelay
from src.libs.common import delay
from src.steps.common import StepsCommon
from src.steps.network_conditions import TrafficController
from src.libs.common import to_base64

logger = get_custom_logger(__name__)


class TestNetworkConditions(StepsRelay):
    @pytest.fixture(scope="function", autouse=True)
    def setup_nodes(self, request):
        self.node1 = WakuNode(NODE_1, f"node1_{request.cls.test_id}")
        self.node2 = WakuNode(NODE_2, f"node2_{request.cls.test_id}")
        self.tc = TrafficController()

    def test_relay_with_latency_between_two_nodes(self):
        logger.info("Starting node1 and node2 with relay enabled")
        self.node1.start(relay="true")
        self.node2.start(relay="true", discv5_bootstrap_node=self.node1.get_enr_uri())

        logger.info("Subscribing both nodes to relay topic")
        self.node1.set_relay_subscriptions([self.test_pubsub_topic])
        self.node2.set_relay_subscriptions([self.test_pubsub_topic])

        logger.info("Waiting for autoconnection")
        self.wait_for_autoconnection([self.node1, self.node2], hard_wait=10)

        logger.debug("Applying 5000ms latency to node2")
        self.tc.add_latency(self.node2, ms=5000)
        message = self.create_message()

        logger.debug("Publishing message from node1")

        self.node1.send_relay_message(message, self.test_pubsub_topic)
        logger.debug("Fetching relay messages on node2")
        t0 = time()
        messages = self.node2.get_relay_messages(self.test_pubsub_topic)
        dt = time() - t0
        assert messages, "Messages aren't arrive"
        assert dt >= 4.5, f"Expected slow GET due to latency, got {dt}"
        assert dt <= 10.5, "msg took too long"
        self.tc.clear(self.node2)

    @pytest.mark.timeout(60 * 8)
    def test_relay_7_nodes_3sec_latency(self):
        self.node1 = WakuNode(NODE_1, f"node1_{self.test_id}")
        self.node2 = WakuNode(NODE_2, f"node2_{self.test_id}")
        self.node3 = WakuNode(NODE_2, f"node3_{self.test_id}")
        self.node4 = WakuNode(NODE_2, f"node4_{self.test_id}")
        self.node5 = WakuNode(NODE_2, f"node5_{self.test_id}")
        self.node6 = WakuNode(NODE_2, f"node6_{self.test_id}")
        self.node7 = WakuNode(NODE_2, f"node7_{self.test_id}")

        nodes = [self.node1, self.node2, self.node3, self.node4, self.node5, self.node6, self.node7]

        logger.info("Starting nodes with chain bootstrap")
        self.node1.start(relay="true")
        self.node2.start(relay="true", discv5_bootstrap_node=self.node1.get_enr_uri())
        self.node3.start(relay="true", discv5_bootstrap_node=self.node2.get_enr_uri())
        self.node4.start(relay="true", discv5_bootstrap_node=self.node3.get_enr_uri())
        self.node5.start(relay="true", discv5_bootstrap_node=self.node4.get_enr_uri())
        self.node6.start(relay="true", discv5_bootstrap_node=self.node5.get_enr_uri())
        self.node7.start(relay="true", discv5_bootstrap_node=self.node6.get_enr_uri())

        logger.info("Subscribing all nodes to relay topic")
        for node in nodes:
            node.set_relay_subscriptions([self.test_pubsub_topic])

        logger.info("Waiting for autoconnection")
        self.wait_for_autoconnection(nodes, hard_wait=60)

        logger.info("Applying 3s latency to node3")
        self.tc.add_latency(self.node3, ms=3000)

        t_start = time()
        _ = self.node3.get_relay_messages(self.test_pubsub_topic)
        elapsed = time() - t_start

        logger.info(f"Observed GET latency on node3: {elapsed:.2f}s")
        assert elapsed >= 2.8, f"Expected ~3s latency on node3 GET, got {elapsed:.2f}s"

    @pytest.mark.timeout(60 * 6)
    def test_relay_4_nodes_sender_latency(self):
        self.node3 = WakuNode(NODE_2, f"node3_{self.test_id}")
        self.node4 = WakuNode(NODE_2, f"node4_{self.test_id}")

        logger.info("Starting 4 nodes with relay enabled (bootstrap chain)")
        self.node1.start(relay="true")
        self.node2.start(relay="true", discv5_bootstrap_node=self.node1.get_enr_uri())
        self.node3.start(relay="true", discv5_bootstrap_node=self.node2.get_enr_uri())
        self.node4.start(relay="true", discv5_bootstrap_node=self.node3.get_enr_uri())

        nodes = [self.node1, self.node2, self.node3, self.node4]

        for n in nodes:
            n.set_relay_subscriptions([self.test_pubsub_topic])

        self.wait_for_autoconnection(nodes, hard_wait=40)

        latency_ms = 3000
        logger.info(f"Applying {latency_ms}ms latency on sender node1")
        self.tc.add_latency(self.node1, ms=latency_ms)

        t_pub0 = time()
        self.node1.send_relay_message(self.create_message(), self.test_pubsub_topic)
        publish_dt = time() - t_pub0

        assert publish_dt > ((latency_ms * 2) / 1000.0) - 0.4, f"Expected publish call to be slowed by sender latency. "
        assert publish_dt <= ((latency_ms * 2) / 1000.0) + 0.4, f"Publish call took too long"
        # latency is doubled as request + response both will have latency

        deadline = t_pub0 + 10.0
        received = False

        while time() < deadline:
            msgs = self.node4.get_relay_messages(self.test_pubsub_topic) or []
            if msgs:
                received = True
                break
            delay(0.2)

        assert received, f"node4 did not receive any relay message within {deadline}"

        self.tc.clear(self.node1)

    @pytest.mark.timeout(60 * 8)
    def test_relay_4_nodes_two_publishers_compare_latency(self):
        self.node3 = WakuNode(NODE_2, f"node3_{self.test_id}")
        self.node4 = WakuNode(NODE_2, f"node4_{self.test_id}")

        logger.info("Starting 4 nodes ")
        self.node1.start(relay="true")
        self.node2.start(relay="true", discv5_bootstrap_node=self.node1.get_enr_uri())
        self.node3.start(relay="true", discv5_bootstrap_node=self.node2.get_enr_uri())
        self.node4.start(relay="true", discv5_bootstrap_node=self.node3.get_enr_uri())

        nodes = [self.node1, self.node2, self.node3, self.node4]

        for n in nodes:
            n.set_relay_subscriptions([self.test_pubsub_topic])

        self.wait_for_autoconnection(nodes, hard_wait=60)

        latency_ms = 3000
        logger.debug(f"Applying {latency_ms}ms latency on node1 only")
        self.tc.add_latency(self.node1, ms=latency_ms)

        node1_dts = []
        node2_dts = []
        _ = self.node4.get_relay_messages(self.test_pubsub_topic)

        for i in range(5):
            t0 = time()
            self.node1.send_relay_message(self.create_message(), self.test_pubsub_topic)
            node1_dts.append(time() - t0)

            t0 = time()
            self.node2.send_relay_message(
                self.create_message(),
                self.test_pubsub_topic,
            )
            node2_dts.append(time() - t0)

            delay(0.2)

        for dt in node1_dts:
            assert dt <= ((latency_ms * 2) / 1000.0) + 0.4, "node1 publish took too long"

        for dt in node2_dts:
            assert dt < 1.0, f"Expected node2 publish to be fast"

        deadline = time() + 10.0
        received = False
        while time() < deadline:
            msgs = self.node4.get_relay_messages(self.test_pubsub_topic) or []
            if msgs:
                received = True
                break
            delay(0.2)

        assert received, f"node4 did not receive any relay message within time"

        self.tc.clear(self.node1)

    @pytest.mark.timeout(60 * 6)
    @pytest.mark.parametrize(
        "latency_ms",
        [
            200,
            500,
            1000,
            5000,
            7000,
        ],
    )
    def test_relay_different_latency_between_two_nodes(self, latency_ms):
        logger.info("Starting node1 and node2 with relay enabled")
        self.node1.start(relay="true")
        self.node2.start(relay="true", discv5_bootstrap_node=self.node1.get_enr_uri())

        logger.info("Subscribing both nodes to relay topic")
        self.node1.set_relay_subscriptions([self.test_pubsub_topic])
        self.node2.set_relay_subscriptions([self.test_pubsub_topic])

        logger.info("Waiting for autoconnection")
        self.wait_for_autoconnection([self.node1, self.node2], hard_wait=10)

        logger.info(f"Applying {latency_ms}ms latency to node2")
        self.tc.clear(self.node2)
        if latency_ms > 0:
            self.tc.add_latency(self.node2, ms=latency_ms)

        message = self.create_message()
        self.node1.send_relay_message(message, self.test_pubsub_topic)
        t0 = time()
        messages = self.node2.get_relay_messages(self.test_pubsub_topic)
        dt = time() - t0

        assert messages, "No relay messages returned (publish/relay may have failed)"
        expected_s = (latency_ms / 1000.0) * 2
        tolerance_s = 0.5
        assert dt >= expected_s - tolerance_s, f"Expected >= {expected_s - tolerance_s}s, got {dt}s"
        assert dt <= expected_s + tolerance_s, f"Expected <= {expected_s + tolerance_s}s, got {dt}s"
        self.tc.clear(self.node2)

    @pytest.mark.timeout(60 * 10)
    def test_latency_with_load_sender_side(self):
        latency_ms = 3000
        total_messages = 50
        wait_time = 40.0
        acceptable_msgs = total_messages / 2
        self.node3 = WakuNode(NODE_2, f"node3_{self.test_id}")
        self.node4 = WakuNode(NODE_2, f"node4_{self.test_id}")
        logger.info("Starting 4 nodes with relay enabled")
        self.node1.start(relay="true")
        self.node2.start(relay="true", discv5_bootstrap_node=self.node1.get_enr_uri())
        self.node3.start(relay="true", discv5_bootstrap_node=self.node1.get_enr_uri())
        self.node4.start(relay="true", discv5_bootstrap_node=self.node1.get_enr_uri())

        logger.info("Subscribing all nodes to relay topic")
        for n in [self.node1, self.node2, self.node3, self.node4]:
            n.set_relay_subscriptions([self.test_pubsub_topic])

        self.wait_for_autoconnection([self.node1, self.node2, self.node3, self.node4], hard_wait=30)

        _ = self.node4.get_relay_messages(self.test_pubsub_topic)

        logger.info(f"Applying {latency_ms}ms latency on sender node1")
        self.tc.clear(self.node1)
        self.tc.add_latency(self.node1, ms=latency_ms)

        logger.info(f"Sending {total_messages} messages from node1")
        for i in range(total_messages):
            self.node1.send_relay_message(self.create_message(), self.test_pubsub_topic)

        received_count = 0
        last_count = 0
        ticks = 0

        deadline = time() + wait_time
        while time() < deadline:
            msgs = self.node4.get_relay_messages(self.test_pubsub_topic) or []
            if len(msgs) > last_count:
                ticks += 1
                last_count = len(msgs)
            received_count = max(received_count, len(msgs))
            if received_count >= acceptable_msgs:
                break
            delay(1)

        logger.info(f"Node4 received {received_count} messages " f"(min_expected={acceptable_msgs}, total_sent={total_messages})")

        assert received_count >= acceptable_msgs, "relay stalled or dropped all traffic; "
        self.tc.clear(self.node1)

    def test_relay_4_nodes_sender_packet_loss(self):
        self.node3 = WakuNode(NODE_2, f"node3_{self.test_id}")
        self.node4 = WakuNode(NODE_2, f"node4_{self.test_id}")

        logger.info("Starting 4 nodes with relay enabled (bootstrap chain)")
        self.node1.start(relay="true")
        self.node2.start(relay="true", discv5_bootstrap_node=self.node1.get_enr_uri())
        self.node3.start(relay="true", discv5_bootstrap_node=self.node2.get_enr_uri())
        self.node4.start(relay="true", discv5_bootstrap_node=self.node3.get_enr_uri())

        nodes = [self.node1, self.node2, self.node3, self.node4]
        for n in nodes:
            n.set_relay_subscriptions([self.test_pubsub_topic])

        self.wait_for_autoconnection(nodes, hard_wait=20)

        loss_percent = 30.0
        logger.info(f"Applying {loss_percent}% packet loss on sender node1")
        self.tc.add_packet_loss(self.node1, percent=loss_percent)

        _ = self.node4.get_relay_messages(self.test_pubsub_topic)

        self.node1.send_relay_message(self.create_message(), self.test_pubsub_topic)

        self.tc.log_tc_stats(self.node1)
        deadline = time() + 10.0
        received = False
        cnt = 0

        while time() < deadline:
            msgs = self.node4.get_relay_messages(self.test_pubsub_topic) or []
            if msgs:
                received = True
                break
            delay(0.2)
            cnt = cnt + 1

        assert received, f"Node4 did not receive any relay message"
        logger.info(f"Node4 received messages from node1 after " f"{cnt} trails")

        self.tc.clear(self.node1)

    @pytest.mark.xfail(reason="Fails under high packet loss percentage 50")
    def test_relay_4_nodes_sender_packet_loss_50_15sec_timeout(self):
        self.node3 = WakuNode(NODE_2, f"node3_{self.test_id}")
        self.node4 = WakuNode(NODE_2, f"node4_{self.test_id}")

        self.node1.start(relay="true")
        self.node2.start(relay="true", discv5_bootstrap_node=self.node1.get_enr_uri())
        self.node3.start(relay="true", discv5_bootstrap_node=self.node2.get_enr_uri())
        self.node4.start(relay="true", discv5_bootstrap_node=self.node3.get_enr_uri())

        nodes = [self.node1, self.node2, self.node3, self.node4]
        for n in nodes:
            n.set_relay_subscriptions([self.test_pubsub_topic])

        self.wait_for_autoconnection(nodes, hard_wait=20)

        loss = 50.0
        total_msgs = 30
        window_s = 15.0

        self.tc.clear(self.node1)
        self.tc.add_packet_loss(self.node1, percent=loss)

        _ = self.node4.get_relay_messages(self.test_pubsub_topic)

        batch_tag = f"loss={loss}-{self.test_id}"
        batch_tag_b64 = to_base64(batch_tag)

        for _ in range(total_msgs):
            self.node1.send_relay_message(self.create_message(), self.test_pubsub_topic)

        self.tc.log_tc_stats(self.node1)
        delay(window_s)

        msgs = self.node4.get_relay_messages(self.test_pubsub_topic) or []
        received = len(msgs)

        logger.info(f"[LOSS={loss}%] sent={total_msgs} received={received} window={window_s}s")

        self.tc.clear(self.node1)

        assert received > int(total_msgs * 0.8), "No messages received under 50% packet loss"

    @pytest.mark.timeout(60 * 10)
    @pytest.mark.xfail(reason="Fails under high packet loss percentage")
    @pytest.mark.parametrize("loss", [40.0, 60.0], ids=["loss40", "loss60"])
    def test_relay_4_nodes_sender_packet_loss_delivery_ratio_simple(self, loss):
        self.node3 = WakuNode(NODE_2, f"node3_{self.test_id}")
        self.node4 = WakuNode(NODE_2, f"node4_{self.test_id}")

        self.node1.start(relay="true")
        self.node2.start(relay="true", discv5_bootstrap_node=self.node1.get_enr_uri())
        self.node3.start(relay="true", discv5_bootstrap_node=self.node2.get_enr_uri())
        self.node4.start(relay="true", discv5_bootstrap_node=self.node3.get_enr_uri())

        nodes = [self.node1, self.node2, self.node3, self.node4]
        for n in nodes:
            n.set_relay_subscriptions([self.test_pubsub_topic])

        self.wait_for_autoconnection(nodes, hard_wait=20)

        total_msgs = 30
        window_s = 40.0

        self.tc.clear(self.node1)
        self.tc.add_packet_loss(self.node1, percent=loss)

        _ = self.node4.get_relay_messages(self.test_pubsub_topic)

        for _ in range(total_msgs):
            self.node1.send_relay_message(self.create_message(), self.test_pubsub_topic)

        self.tc.log_tc_stats(self.node1)
        delay(window_s)

        msgs = self.node4.get_relay_messages(self.test_pubsub_topic) or []
        received = len(msgs)

        logger.info(f"[LOSS={loss}%] sent={total_msgs} received={received} window={window_s}s")

        self.tc.clear(self.node1)

        assert received > int(total_msgs * 0.8), f"No messages received at {loss}% packet loss"

    @pytest.mark.timeout(60 * 10)
    def test_relay_packet_loss_correlated_vs_uncorrelated(self):
        self.node3 = WakuNode(NODE_2, f"node3_{self.test_id}")
        self.node4 = WakuNode(NODE_2, f"node4_{self.test_id}")

        self.node1.start(relay="true")
        self.node2.start(relay="true", discv5_bootstrap_node=self.node1.get_enr_uri())
        self.node3.start(relay="true", discv5_bootstrap_node=self.node2.get_enr_uri())
        self.node4.start(relay="true", discv5_bootstrap_node=self.node3.get_enr_uri())

        nodes = [self.node1, self.node2, self.node3, self.node4]
        for n in nodes:
            n.set_relay_subscriptions([self.test_pubsub_topic])

        self.wait_for_autoconnection(nodes, hard_wait=20)

        total_msgs = 5
        window_s = 30.0
        loss = 50.0

        self.tc.add_packet_loss(self.node1, percent=loss)
        _ = self.node4.get_relay_messages(self.test_pubsub_topic)

        for _ in range(total_msgs):
            self.node1.send_relay_message(self.create_message(), self.test_pubsub_topic)

        delay(window_s)
        uncorrelated = len(self.node4.get_relay_messages(self.test_pubsub_topic) or [])
        self.tc.clear(self.node1)

        self.tc.add_packet_loss_correlated(self.node1, percent=loss, correlation=75.0)
        _ = self.node4.get_relay_messages(self.test_pubsub_topic)

        for _ in range(total_msgs):
            self.node1.send_relay_message(self.create_message(), self.test_pubsub_topic)

        delay(window_s)
        correlated = len(self.node4.get_relay_messages(self.test_pubsub_topic) or [])
        self.tc.clear(self.node1)

        logger.debug(f"uncorrelated={uncorrelated} correlated={correlated}")
        assert uncorrelated >= correlated
        assert correlated > 0

    @pytest.mark.timeout(60 * 10)
    def test_relay_packet_loss_sender_vs_receiver(self):
        self.node3 = WakuNode(NODE_2, f"node3_{self.test_id}")
        self.node4 = WakuNode(NODE_2, f"node4_{self.test_id}")

        self.node1.start(relay="true")
        self.node2.start(relay="true", discv5_bootstrap_node=self.node1.get_enr_uri())
        self.node3.start(relay="true", discv5_bootstrap_node=self.node2.get_enr_uri())
        self.node4.start(relay="true", discv5_bootstrap_node=self.node3.get_enr_uri())

        nodes = [self.node1, self.node2, self.node3, self.node4]
        for n in nodes:
            n.set_relay_subscriptions([self.test_pubsub_topic])

        self.wait_for_autoconnection(nodes, hard_wait=20)

        total_msgs = 30
        window_s = 30.0
        loss = 50.0

        self.tc.add_packet_loss(self.node1, percent=loss)
        _ = self.node4.get_relay_messages(self.test_pubsub_topic)

        for _ in range(total_msgs):
            self.node1.send_relay_message(self.create_message(), self.test_pubsub_topic)

        delay(window_s)
        sender_loss = len(self.node4.get_relay_messages(self.test_pubsub_topic) or [])
        self.tc.clear(self.node1)

        self.tc.add_packet_loss(self.node4, percent=loss)
        _ = self.node4.get_relay_messages(self.test_pubsub_topic)

        for _ in range(total_msgs):
            self.node1.send_relay_message(self.create_message(), self.test_pubsub_topic)

        delay(window_s)
        receiver_loss = len(self.node4.get_relay_messages(self.test_pubsub_topic) or [])
        logger.debug(f"sender_loss={sender_loss} receiver_loss={receiver_loss}")
        self.tc.clear(self.node4)

        assert sender_loss > 0
        assert receiver_loss > 0

    @pytest.mark.timeout(60 * 10)
    def test_relay_packet_loss_applied_mid_way(self):
        self.node3 = WakuNode(NODE_2, f"node3_{self.test_id}")
        self.node4 = WakuNode(NODE_2, f"node4_{self.test_id}")

        self.node1.start(relay="true")
        self.node2.start(relay="true", discv5_bootstrap_node=self.node1.get_enr_uri())
        self.node3.start(relay="true", discv5_bootstrap_node=self.node2.get_enr_uri())
        self.node4.start(relay="true", discv5_bootstrap_node=self.node3.get_enr_uri())

        nodes = [self.node1, self.node2, self.node3, self.node4]
        for n in nodes:
            n.set_relay_subscriptions([self.test_pubsub_topic])

        self.wait_for_autoconnection(nodes, hard_wait=20)

        window_s = 30.0
        _ = self.node4.get_relay_messages(self.test_pubsub_topic)

        for _ in range(10):
            self.node1.send_relay_message(self.create_message(), self.test_pubsub_topic)

        self.tc.add_packet_loss(self.node1, percent=50.0)

        for _ in range(20):
            self.node1.send_relay_message(self.create_message(), self.test_pubsub_topic)

        delay(window_s)
        received = len(self.node4.get_relay_messages(self.test_pubsub_topic) or [])
        self.tc.clear(self.node1)

        assert received > 0

    @pytest.mark.timeout(60 * 2)
    def test_relay_2_nodes_low_bandwidth_reliability(self):
        msg_count = 200
        max_wait = 50
        poll_sleep = 0.5

        self.node1 = WakuNode(NODE_1, f"node1_{self.test_id}")
        self.node2 = WakuNode(NODE_2, f"node2_{self.test_id}")

        self.node1.start(relay="true")
        self.node2.start(
            relay="true",
            discv5_bootstrap_node=self.node1.get_enr_uri(),
            rest_relay_cache_capacity="250",
        )

        self.node1.set_relay_subscriptions([self.test_pubsub_topic])
        self.node2.set_relay_subscriptions([self.test_pubsub_topic])

        self.wait_for_autoconnection([self.node1, self.node2], hard_wait=10)

        self.tc.add_bandwidth(self.node1, rate="256kbit")

        for _ in range(msg_count):
            self.node1.send_relay_message(self.create_message(), self.test_pubsub_topic)

        t0 = time()
        received = 0
        while time() - t0 < max_wait:
            msgs = self.node2.get_relay_messages(self.test_pubsub_topic) or []
            received = len(msgs)
            if received >= msg_count:
                break
            sleep(poll_sleep)

        elapsed = time() - t0
        logger.info(f"low_bw_elapsed={elapsed:.2f}s received={received} msg_count={msg_count}")

        assert received >= msg_count

    @pytest.mark.timeout(60 * 8)
    def test_relay_2_nodes_low_bandwidth_sending_over_time(self):
        msg_count = 200
        cache_capacity = "250"

        send_interval_s = 0.05
        poll_interval_s = 0.5
        max_wait_s = 240
        min_received = 150

        self.node1 = WakuNode(NODE_1, f"node1_{self.test_id}")
        self.node2 = WakuNode(NODE_2, f"node2_{self.test_id}")

        self.node1.start(relay="true")
        self.node2.start(
            relay="true",
            discv5_bootstrap_node=self.node1.get_enr_uri(),
            rest_relay_cache_capacity=cache_capacity,
        )

        self.node1.set_relay_subscriptions([self.test_pubsub_topic])
        self.node2.set_relay_subscriptions([self.test_pubsub_topic])

        self.wait_for_autoconnection([self.node1, self.node2], hard_wait=10)

        # mirror your suite's "low bandwidth" shaping values (rate + burst/limit handled by the tc wrapper defaults)
        self.tc.add_bandwidth(self.node1, rate="256kbit")

        received = 0
        for _ in range(msg_count):
            self.node1.send_relay_message(self.create_message(), self.test_pubsub_topic)
            sleep(send_interval_s)

        t0 = time()
        while time() - t0 < max_wait_s and received < msg_count:
            msgs = self.node2.get_relay_messages(self.test_pubsub_topic) or []
            if msgs:
                received += len(msgs)
            if received >= msg_count:
                break
            sleep(poll_interval_s)

        total_time = time() - t0

        logger.info(
            "low_bw_reliability "
            f"rate=256kbit msg_count={msg_count} cache_capacity={cache_capacity} "
            f"send_interval_s={send_interval_s} poll_interval_s={poll_interval_s} "
            f"recv_duration={total_time:.2f}s"
        )

        assert received >= min_received, f"received {received}/{msg_count} under low bandwidth"

    @pytest.mark.timeout(60 * 8)
    def test_relay_2_nodes_bandwidth_low_vs_high_drain_time(self):
        msg_count = 200
        cache = "250"
        poll_sleep = 0.5
        max_wait = 200

        self.node1 = WakuNode(NODE_1, f"node1_{self.test_id}")
        self.node2 = WakuNode(NODE_2, f"node2_{self.test_id}")

        self.node1.start(relay="true", rest_relay_cache_capacity=cache)
        self.node2.start(
            relay="true",
            discv5_bootstrap_node=self.node1.get_enr_uri(),
            rest_relay_cache_capacity=cache,
        )

        self.node1.set_relay_subscriptions([self.test_pubsub_topic])
        self.node2.set_relay_subscriptions([self.test_pubsub_topic])

        self.wait_for_autoconnection([self.node1, self.node2], hard_wait=10)

        self.tc.add_bandwidth(self.node1, rate="256kbit")

        _ = self.node2.get_relay_messages(self.test_pubsub_topic)

        for _ in range(msg_count):
            self.node1.send_relay_message(self.create_message(), self.test_pubsub_topic)

        total_low_msgs = 0
        t0 = time()
        while total_low_msgs < msg_count and (time() - t0) < max_wait:
            msgs = self.node2.get_relay_messages(self.test_pubsub_topic) or []
            total_low_msgs += len(msgs)
            sleep(poll_sleep)
        low_rate_t = time() - t0

        self.tc.add_bandwidth(self.node1, rate="10mbit")

        _ = self.node2.get_relay_messages(self.test_pubsub_topic)

        for _ in range(msg_count):
            self.node1.send_relay_message(self.create_message(), self.test_pubsub_topic)

        total_high_msgs = 0
        t1 = time()
        while total_high_msgs < msg_count and (time() - t1) < max_wait:
            msgs = self.node2.get_relay_messages(self.test_pubsub_topic) or []
            total_high_msgs += len(msgs)
            sleep(poll_sleep)
        high_rate_t = time() - t1

        logger.info(
            f"low_rate_t={low_rate_t:.2f}s high_rate_t={high_rate_t:.2f}s "
            f"total_low_msgs={total_low_msgs} total_high_msgs={total_high_msgs} "
            f"msg_count={msg_count} cache={cache}"
        )

        assert total_low_msgs >= msg_count
        assert total_high_msgs >= msg_count
        assert high_rate_t < low_rate_t

    @pytest.mark.timeout(60 * 6)
    def test_relay_2_nodes_packet_reordering(self):
        msg_count = 200
        cache_capacity = "200"
        poll_sleep = 0.5
        max_wait = 120

        self.node1 = WakuNode(NODE_1, f"node1_{self.test_id}")
        self.node2 = WakuNode(NODE_2, f"node2_{self.test_id}")

        self.node1.start(relay="true")
        self.node2.start(
            relay="true",
            discv5_bootstrap_node=self.node1.get_enr_uri(),
            rest_relay_cache_capacity=cache_capacity,
        )

        self.node1.set_relay_subscriptions([self.test_pubsub_topic])
        self.node2.set_relay_subscriptions([self.test_pubsub_topic])

        self.wait_for_autoconnection([self.node1, self.node2], hard_wait=10)

        self.tc.add_packet_reordering(self.node2, percent=25, correlation=50)

        for _ in range(msg_count):
            self.node1.send_relay_message(self.create_message(), self.test_pubsub_topic)

        received = 0
        t0 = time()
        while received < msg_count and time() - t0 < max_wait:
            msgs = self.node2.get_relay_messages(self.test_pubsub_topic) or []
            received += len(msgs)
            sleep(poll_sleep)

        elapsed = time() - t0

        logger.info(f"packet_reordering " f"reorder=25% corr=50% " f"msg_count={msg_count} received={received} " f"elapsed={elapsed:.2f}s")

        assert received >= msg_count

    @pytest.mark.timeout(60 * 6)
    def test_relay_2_nodes_temporary_blackout_recovers_no_helpers(self):
        msgs_count = 100
        self.node1 = WakuNode(NODE_1, f"node1_{self.test_id}")
        self.node2 = WakuNode(NODE_2, f"node2_{self.test_id}")
        self.tc = TrafficController()

        logger.info("Starting node1 and node2 with relay enabled")
        self.node1.start(relay="true")
        self.node2.start(relay="true", discv5_bootstrap_node=self.node1.get_enr_uri())

        logger.info("Subscribing both nodes to relay topic")
        self.node1.set_relay_subscriptions([self.test_pubsub_topic])
        self.node2.set_relay_subscriptions([self.test_pubsub_topic])

        logger.info("Waiting for autoconnection")
        self.wait_for_autoconnection([self.node1, self.node2], hard_wait=15)
        logger.info(f"Applying 100%% packet loss on both nodes ")
        self.tc.clear(self.node1)
        self.tc.clear(self.node2)
        self.tc.add_packet_loss(self.node1, percent=100.0)
        self.tc.add_packet_loss(self.node2, percent=100.0)

        delay(5)
        logger.info("Clearing tc rules (restore connectivity)")
        self.tc.clear(self.node1)
        self.tc.clear(self.node2)

        logger.info("Waiting for peer list recovery on both nodes")
        peers1 = 0
        while time() < time() + 30.0:
            peers1 = self.node1.get_peers() or []
            peers2 = self.node2.get_peers() or []
            if len(peers1) > 0 and len(peers2) > 0:
                break
            delay(0.5)

        assert len(peers1) > 0, "Peers did not recover after blackout (would require restart)"

        logger.info("Publishing after recovery")
        for _ in range(msgs_count):
            self.node1.send_relay_message(self.create_message(), self.test_pubsub_topic)
        delay(5)
        msgs = self.node2.get_relay_messages(self.test_pubsub_topic) or []
        assert len(msgs) >= msgs_count - 10, "Post-recovery message was not delivered"
        logger.info(f"{len(msgs)} messages were delivered")
        self.tc.clear(self.node1)
        self.tc.clear(self.node2)

    @pytest.mark.timeout(60)
    def test_relay_with_latency_except_rest(self):
        logger.info("Starting node1 and node2 with relay enabled")
        self.node1.start(relay="true")
        self.node2.start(relay="true", discv5_bootstrap_node=self.node1.get_enr_uri())

        logger.info("Subscribing both nodes to relay topic")
        self.node1.set_relay_subscriptions([self.test_pubsub_topic])
        self.node2.set_relay_subscriptions([self.test_pubsub_topic])

        logger.info("Waiting for autoconnection")
        self.wait_for_autoconnection([self.node1, self.node2], hard_wait=10)

        latency_ms = 9000

        logger.info(f"Applying latency to node1 except REST")
        self.tc.add_latency_except_rest(
            self.node1,
            ms=latency_ms,
            rest_port=self.node1.start_args["rest-port"],
            metrics_port=self.node1.start_args.get("metrics-server-port"),
        )

        _ = self.node2.get_relay_messages(self.test_pubsub_topic)

        logger.info("Publishing message from node1")
        t0 = time()
        self.node1.send_relay_message(self.create_message(), self.test_pubsub_topic)
        self.tc.log_tc_stats(self.node1)
        deadline = t0 + 4.0
        msg_received = False
        arrival_time = 0
        while time() < deadline:
            msgs = self.node2.get_relay_messages(self.test_pubsub_topic) or []
            if msgs:
                arrival_time = time() - t0
                msg_received = True
                break
            delay(0.2)

        assert msg_received, "node2 did not receive message under latency"

        expected_s = latency_ms / 1000.0
        assert arrival_time >= expected_s - 0.5, f"Expected >= {expected_s - 0.5}s, got {arrival_time}s"
        logger.info(f" arrival delay: {arrival_time:.2f}s")

        self.tc.clear(self.node2)
