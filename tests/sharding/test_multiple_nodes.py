import pytest
from src.env_vars import ADDITIONAL_NODES, NODE_2
from src.libs.custom_logger import get_custom_logger
from src.steps.relay import StepsRelay
from src.steps.sharding import StepsSharding

logger = get_custom_logger(__name__)


class TestMultipleNodes(StepsSharding):
    def test_static_shard_relay(self):
        self.setup_main_relay_nodes(pubsub_topic=self.test_pubsub_topic)
        self.setup_optional_relay_nodes(pubsub_topic=self.test_pubsub_topic)
        self.subscribe_main_relay_nodes(pubsub_topics=[self.test_pubsub_topic])
        self.subscribe_optional_relay_nodes(pubsub_topics=[self.test_pubsub_topic])
        self.check_published_message_reaches_relay_peer(pubsub_topic=self.test_pubsub_topic)

    def test_static_shard_relay_10_nwaku_nodes(self):
        self.setup_first_relay_node_with_filter(pubsub_topic=self.test_pubsub_topic)
        self.setup_nwaku_relay_nodes(num_nodes=9, pubsub_topic=self.test_pubsub_topic)
        self.subscribe_main_relay_nodes(pubsub_topics=[self.test_pubsub_topic])
        self.subscribe_optional_relay_nodes(pubsub_topics=[self.test_pubsub_topic])
        self.check_published_message_reaches_relay_peer(pubsub_topic=self.test_pubsub_topic)

    def test_auto_shard_relay(self):
        self.setup_main_relay_nodes(
            cluster_id=self.auto_cluster, content_topic=self.test_content_topic, num_shards_in_network=self.num_shards_in_network
        )
        self.setup_optional_relay_nodes(
            cluster_id=self.auto_cluster, content_topic=self.test_content_topic, num_shards_in_network=self.num_shards_in_network
        )
        self.subscribe_main_relay_nodes(content_topics=[self.test_content_topic])
        self.subscribe_optional_relay_nodes(content_topics=[self.test_content_topic])
        self.check_published_message_reaches_relay_peer(content_topic=self.test_content_topic)

    def test_auto_shard_relay_10_nwaku_nodes(self):
        self.setup_first_relay_node_with_filter(
            cluster_id=self.auto_cluster, content_topic=self.test_content_topic, num_shards_in_network=self.num_shards_in_network
        )
        self.setup_nwaku_relay_nodes(
            num_nodes=8, cluster_id=self.auto_cluster, content_topic=self.test_content_topic, num_shards_in_network=self.num_shards_in_network
        )
        self.subscribe_main_relay_nodes(content_topics=[self.test_content_topic])
        self.subscribe_optional_relay_nodes(content_topics=[self.test_content_topic])
        self.check_published_message_reaches_relay_peer(content_topic=self.test_content_topic)
