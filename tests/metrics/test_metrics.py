import pytest
from src.env_vars import DEFAULT_NWAKU
from src.libs.common import delay
from src.node.waku_node import WakuNode
from src.steps.filter import StepsFilter
from src.steps.light_push import StepsLightPush
from src.steps.metrics import StepsMetrics
from src.steps.relay import StepsRelay
from src.steps.store import StepsStore


class TestMetrics(StepsRelay, StepsMetrics, StepsFilter, StepsLightPush, StepsStore):
    @pytest.mark.xfail(reason="these metrics are new from libp2p and has no values yet")
    def test_metrics_initial_value(self):
        node = WakuNode(DEFAULT_NWAKU, f"node1_{self.test_id}")
        node.start(relay="true", filter="true", store="true", lightpush="true")
        delay(5)
        self.validate_initial_metrics(node)

    @pytest.mark.usefixtures("setup_main_relay_nodes", "subscribe_main_relay_nodes", "relay_warm_up")
    def test_metrics_after_relay_publish(self):
        self.node1.send_relay_message(self.create_message(), self.test_pubsub_topic)
        delay(0.5)
        self.node2.get_relay_messages(self.test_pubsub_topic)
        delay(5)
        for node in self.main_nodes:
            if node.is_nwaku():
                self.check_metric(node, "libp2p_peers", 1)
                self.check_metric(node, "libp2p_pubsub_peers", 1)
                self.check_metric(node, "libp2p_pubsub_topics", 1)
                self.check_metric(node, "libp2p_pubsub_subscriptions_total", 1)
                self.check_metric(node, 'libp2p_gossipsub_peers_per_topic_mesh{topic="other"}', 1)
                self.check_metric(node, "logos_delivery_peer_store_size", 1)
                self.check_metric(node, "logos_delivery_histogram_message_size_count", 1)
                self.check_metric(node, 'logos_delivery_node_messages_total{type="relay"}', 1)

    @pytest.mark.usefixtures("setup_main_relay_node", "setup_main_filter_node", "subscribe_main_nodes")
    def test_metrics_after_filter_get(self):
        message = self.create_message()
        self.node1.send_relay_message(message, self.test_pubsub_topic)
        delay(0.5)
        self.get_filter_messages(message["contentTopic"], pubsub_topic=self.test_pubsub_topic, node=self.node2)
        delay(5)
        self.check_metric(self.node1, "libp2p_peers", 1)
        self.check_metric(self.node1, "libp2p_pubsub_peers", 1)
        self.check_metric(self.node1, "libp2p_pubsub_topics", 1)
        self.check_metric(self.node1, "libp2p_pubsub_subscriptions_total", 1)
        self.check_metric(self.node1, "logos_delivery_peer_store_size", 1)
        self.check_metric(self.node1, "logos_delivery_histogram_message_size_count", 1)
        self.check_metric(self.node1, 'logos_delivery_node_messages_total{type="relay"}', 1)
        if self.node2.is_nwaku():
            self.check_metric(
                self.node2,
                f'logos_delivery_service_peers{{protocol="/vac/waku/filter-subscribe/2.0.0-beta1",peerId="{self.node1.get_tcp_address()}"}}',
                1,
            )
            self.check_metric(self.node2, "libp2p_peers", 1)
            self.check_metric(self.node2, "libp2p_total_dial_attempts_total", 1)
            self.check_metric(self.node2, "logos_delivery_peer_store_size", 1)

    def test_metrics_after_light_push(self):
        self.setup_first_receiving_node()
        self.setup_second_receiving_node(lightpush="false", relay="true")
        self.setup_first_lightpush_node()
        self.subscribe_to_pubsub_topics_via_relay()
        payload = self.create_payload(self.test_pubsub_topic)
        self.light_push_node1.send_light_push_message(payload)
        delay(0.5)
        self.receiving_node1.get_relay_messages(self.test_pubsub_topic)
        delay(5)
        if self.light_push_node1.is_nwaku():
            self.check_metric(
                self.light_push_node1,
                f'logos_delivery_service_peers{{protocol="/vac/waku/lightpush/2.0.0-beta1",peerId="{self.receiving_node1.get_tcp_address()}"}}',
                1,
            )
            self.check_metric(self.light_push_node1, "libp2p_peers", 1)
            self.check_metric(self.light_push_node1, "logos_delivery_peer_store_size", 1)
        if self.receiving_node1.is_nwaku():
            self.check_metric(self.receiving_node1, "libp2p_peers", 1)
            self.check_metric(self.receiving_node1, "libp2p_pubsub_peers", 1)
            self.check_metric(self.receiving_node1, "libp2p_pubsub_topics", 1)
            self.check_metric(self.receiving_node1, "libp2p_pubsub_subscriptions_total", 1)
            self.check_metric(self.receiving_node1, "logos_delivery_peer_store_size", 1)
            self.check_metric(self.receiving_node1, "logos_delivery_histogram_message_size_count", 1)
            self.check_metric(self.receiving_node1, 'logos_delivery_node_messages_total{type="relay"}', 1)

    def test_metrics_after_store_get(self, node_setup):
        self.publish_message(message=self.create_message())
        self.check_published_message_is_stored(page_size=50, ascending="true")
        delay(5)
        self.check_metric(self.publishing_node1, "libp2p_peers", 1)
        self.check_metric(self.publishing_node1, "libp2p_pubsub_peers", 1)
        self.check_metric(self.publishing_node1, "libp2p_pubsub_topics", 1)
        self.check_metric(self.publishing_node1, "libp2p_pubsub_subscriptions_total", 1)
        self.check_metric(self.publishing_node1, "logos_delivery_peer_store_size", 1)
        self.check_metric(self.publishing_node1, "logos_delivery_histogram_message_size_count", 1)
        self.check_metric(self.publishing_node1, 'logos_delivery_node_messages_total{type="relay"}', 1)
        if self.store_node1.is_nwaku():
            self.check_metric(
                self.store_node1,
                f'logos_delivery_service_peers{{protocol="/vac/waku/store-query/3.0.0",peerId="{self.publishing_node1.get_tcp_address()}"}}',
                1,
            )
            self.check_metric(self.store_node1, "libp2p_peers", 1)
            self.check_metric(self.store_node1, "libp2p_pubsub_peers", 1)
            self.check_metric(self.store_node1, "libp2p_pubsub_topics", 1)
            self.check_metric(self.store_node1, "libp2p_pubsub_subscriptions_total", 1)
            self.check_metric(self.store_node1, "logos_delivery_peer_store_size", 1)
            self.check_metric(self.store_node1, "logos_delivery_histogram_message_size_count", 1)
            self.check_metric(self.store_node1, 'logos_delivery_node_messages_total{type="relay"}', 1)
