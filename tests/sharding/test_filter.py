import pytest
from src.env_vars import NODE_1, NODE_2
from src.libs.common import delay
from src.libs.custom_logger import get_custom_logger
from src.steps.relay import StepsRelay
from src.steps.sharding import StepsSharding
from src.test_data import CONTENT_TOPICS_DIFFERENT_SHARDS, PUBSUB_TOPICS_SAME_CLUSTER

logger = get_custom_logger(__name__)


class TestFilterStaticSharding(StepsSharding):
    def test_filter_works_with_static_sharding(self):
        self.setup_first_relay_node_with_filter(pubsub_topic=self.test_pubsub_topic)
        self.setup_second_node_as_filter(pubsub_topic=self.test_pubsub_topic)
        self.subscribe_first_relay_node(pubsub_topics=[self.test_pubsub_topic])
        self.subscribe_filter_node(self.node2, content_topics=[self.test_content_topic], pubsub_topic=self.test_pubsub_topic)
        self.check_published_message_reaches_filter_peer(pubsub_topic=self.test_pubsub_topic)

    def test_filter_static_sharding_multiple_shards(self):
        self.setup_first_relay_node_with_filter(pubsub_topic=PUBSUB_TOPICS_SAME_CLUSTER)
        self.setup_second_node_as_filter(pubsub_topic=PUBSUB_TOPICS_SAME_CLUSTER)
        self.subscribe_first_relay_node(pubsub_topics=PUBSUB_TOPICS_SAME_CLUSTER)
        for content_topic, pubsub_topic in zip(CONTENT_TOPICS_DIFFERENT_SHARDS, PUBSUB_TOPICS_SAME_CLUSTER):
            self.subscribe_filter_node(self.node2, content_topics=[content_topic], pubsub_topic=pubsub_topic)
        for content_topic, pubsub_topic in zip(CONTENT_TOPICS_DIFFERENT_SHARDS, PUBSUB_TOPICS_SAME_CLUSTER):
            self.check_published_message_reaches_filter_peer(content_topic=content_topic, pubsub_topic=pubsub_topic)


class TestFilterAutoSharding(StepsSharding):
    def test_filter_works_with_auto_sharding(self):
        self.setup_first_relay_node_with_filter(
            cluster_id=self.auto_cluster, content_topic=self.test_content_topic, pubsub_topic=self.test_pubsub_topic, num_shards_in_network=1
        )
        self.setup_third_relay_node(cluster_id=self.auto_cluster, content_topic=self.test_content_topic, num_shards_in_network=1)
        self.setup_second_node_as_filter(cluster_id=self.auto_cluster, content_topic=self.test_content_topic, pubsub_topic=self.test_pubsub_topic)
        self.subscribe_first_relay_node(content_topics=[self.test_content_topic])
        self.subscribe_optional_relay_nodes(content_topics=[self.test_content_topic])
        self.subscribe_filter_node(self.node2, content_topics=[self.test_content_topic], pubsub_topic=self.test_pubsub_topic)
        self.check_published_message_reaches_filter_peer(content_topic=self.test_content_topic)

    def test_filter_auto_sharding_multiple_content_topics(self):
        self.setup_first_relay_node_with_filter(
            cluster_id=self.auto_cluster,
            content_topic=CONTENT_TOPICS_DIFFERENT_SHARDS,
            pubsub_topic=PUBSUB_TOPICS_SAME_CLUSTER,
            num_shards_in_network=8,
        )
        self.setup_third_relay_node(
            cluster_id=self.auto_cluster,
            content_topic=CONTENT_TOPICS_DIFFERENT_SHARDS,
            num_shards_in_network=8,
        )
        self.setup_second_node_as_filter(
            cluster_id=self.auto_cluster, content_topic=CONTENT_TOPICS_DIFFERENT_SHARDS, pubsub_topic=self.test_pubsub_topic
        )
        self.subscribe_first_relay_node(content_topics=CONTENT_TOPICS_DIFFERENT_SHARDS)
        self.subscribe_optional_relay_nodes(content_topics=CONTENT_TOPICS_DIFFERENT_SHARDS)
        for content_topic, pubsub_topic in zip(CONTENT_TOPICS_DIFFERENT_SHARDS, PUBSUB_TOPICS_SAME_CLUSTER):
            self.subscribe_filter_node(self.node2, content_topics=[content_topic], pubsub_topic=pubsub_topic)
        for content_topic in CONTENT_TOPICS_DIFFERENT_SHARDS:
            self.check_published_message_reaches_filter_peer(content_topic=content_topic)
