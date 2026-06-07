import pytest
from src.env_vars import NODE_1, NODE_2
from src.libs.common import delay
from src.libs.custom_logger import get_custom_logger
from src.steps.sharding import StepsSharding
from src.test_data import CONTENT_TOPICS_DIFFERENT_SHARDS, CONTENT_TOPICS_SHARD_0, CONTENT_TOPICS_SHARD_7, PUBSUB_TOPICS_SAME_CLUSTER


logger = get_custom_logger(__name__)


class TestRunningNodesAutosharding(StepsSharding):
    @pytest.mark.parametrize("content_topic", CONTENT_TOPICS_DIFFERENT_SHARDS)
    def test_single_content_topic(self, content_topic):
        self.setup_main_relay_nodes(cluster_id=self.auto_cluster, num_shards_in_network=self.num_shards_in_network, content_topic=content_topic)
        self.subscribe_first_relay_node(content_topics=[content_topic])
        self.subscribe_second_relay_node(content_topics=[content_topic])
        self.check_published_message_reaches_relay_peer(content_topic=content_topic)

    @pytest.mark.parametrize("content_topic_list", [CONTENT_TOPICS_SHARD_0, CONTENT_TOPICS_SHARD_7])
    def test_multiple_content_topics_same_shard(self, content_topic_list):
        self.setup_main_relay_nodes(
            cluster_id=self.auto_cluster,
            num_shards_in_network=self.num_shards_in_network,
            content_topic=content_topic_list,
        )
        self.subscribe_first_relay_node(content_topics=content_topic_list)
        self.subscribe_second_relay_node(content_topics=content_topic_list)
        for content_topic in content_topic_list:
            self.check_published_message_reaches_relay_peer(content_topic=content_topic)

    def test_multiple_content_topics_different_shard(self):
        self.setup_main_relay_nodes(
            cluster_id=self.auto_cluster, num_shards_in_network=self.num_shards_in_network, content_topic=CONTENT_TOPICS_DIFFERENT_SHARDS
        )
        self.subscribe_first_relay_node(content_topics=CONTENT_TOPICS_DIFFERENT_SHARDS)
        self.subscribe_second_relay_node(content_topics=CONTENT_TOPICS_DIFFERENT_SHARDS)
        for content_topic in CONTENT_TOPICS_DIFFERENT_SHARDS:
            self.check_published_message_reaches_relay_peer(content_topic=content_topic)

    def test_2_nodes_different_content_topic_same_shard(self):
        self.setup_first_relay_node_with_filter(
            cluster_id=self.auto_cluster, content_topic="/newsService/1.0/weekly/protobuf", num_shards_in_network=self.num_shards_in_network
        )
        self.setup_second_relay_node(
            cluster_id=self.auto_cluster, content_topic="/newsService/1.0/alerts/xml", num_shards_in_network=self.num_shards_in_network
        )
        self.subscribe_first_relay_node(content_topics=["/newsService/1.0/weekly/protobuf"])
        self.subscribe_second_relay_node(content_topics=["/newsService/1.0/alerts/xml"])
        # relay; node2's REST cache only serves its own subscribed content topic (404 for node1's),
        # so the arrival is asserted via the node log instead
        self.check_published_message_reaches_relay_peer(content_topic="/newsService/1.0/weekly/protobuf", peer_list=[self.node1])
        assert self.node2.search_waku_log_for_string(
            r"received relay message.*contentTopic.*/newsService/1.0/weekly/protobuf", use_regex=True
        ), "Message on the shared shard did not reach node2's relay"

    @pytest.mark.skip(
        reason="Pending confirmation from nwaku devs on expected cross-shard behavior: should node2 receive messages published by node1 when nodes are on different shards?"
    )
    def test_2_nodes_different_content_topic_different_shard(self):
        self.setup_first_relay_node_with_filter(
            cluster_id=self.auto_cluster, content_topic="/myapp/1/latest/proto", num_shards_in_network=self.num_shards_in_network
        )
        # shard=1 overrides the default --shard=0 so node2 only relays its own content topic's shard
        self.setup_second_relay_node(
            cluster_id=self.auto_cluster,
            content_topic="/waku/2/content/test.js",
            shard="1",
            num_shards_in_network=self.num_shards_in_network,
        )
        self.subscribe_first_relay_node(content_topics=["/myapp/1/latest/proto"])
        self.subscribe_second_relay_node(content_topics=["/waku/2/content/test.js"])
        try:
            self.check_published_message_reaches_relay_peer(content_topic="/myapp/1/latest/proto")
            raise AssertionError("Message on shard 0 unexpectedly reached node2 on shard 1")
        except Exception as ex:
            assert "404 Client Error" in str(ex), f"Expected node2 to not have the message, got: {ex}"

    def test_content_topic_not_in_docker_flags(self):
        self.setup_main_relay_nodes(cluster_id=2, pubsub_topic=self.test_pubsub_topic)
        self.subscribe_main_relay_nodes(content_topics=[self.test_content_topic])
        self.check_published_message_reaches_relay_peer(content_topic=self.test_content_topic)

    def test_content_topic_and_pubsub_topic_not_in_docker_flags(self):
        self.setup_main_relay_nodes(cluster_id=2)
        self.subscribe_main_relay_nodes(content_topics=[self.test_content_topic])
        try:
            self.check_published_message_reaches_relay_peer(content_topic=self.test_content_topic)
        except Exception as ex:
            assert f"Peer NODE_2:{NODE_2} couldn't find any messages" in str(ex)

    def test_multiple_content_topics_and_multiple_pubsub_topics(self):
        # nwaku drops the pubsub-topic CLI arg, so the pubsub topics are subscribed via REST instead
        self.setup_main_relay_nodes(
            cluster_id=self.auto_cluster,
            content_topic=CONTENT_TOPICS_DIFFERENT_SHARDS,
            num_shards_in_network=self.num_shards_in_network,
        )
        self.subscribe_main_relay_nodes(content_topics=CONTENT_TOPICS_DIFFERENT_SHARDS)
        self.subscribe_main_relay_nodes(pubsub_topics=PUBSUB_TOPICS_SAME_CLUSTER)
        for content_topic in CONTENT_TOPICS_DIFFERENT_SHARDS:
            self.check_published_message_reaches_relay_peer(content_topic=content_topic)
        for pubsub_topic in PUBSUB_TOPICS_SAME_CLUSTER:
            self.check_published_message_reaches_relay_peer(pubsub_topic=pubsub_topic)

    def test_node_uses_both_auto_and_regular_apis(self):
        self.setup_main_relay_nodes(cluster_id=self.auto_cluster, pubsub_topic=self.test_pubsub_topic)
        self.subscribe_main_relay_nodes(content_topics=["/toychat/2/huilong/proto"])
        self.check_published_message_reaches_relay_peer(content_topic="/toychat/2/huilong/proto")
        self.subscribe_main_relay_nodes(pubsub_topics=[self.test_pubsub_topic])
        self.check_published_message_reaches_relay_peer(pubsub_topic=self.test_pubsub_topic)

    def test_sender_uses_auto_api_receiver_uses_regular_api(self):
        self.setup_main_relay_nodes(cluster_id=self.auto_cluster, pubsub_topic=self.test_pubsub_topic, num_shards_in_network=1)
        self.subscribe_first_relay_node(content_topics=[self.test_content_topic])
        self.subscribe_second_relay_node(pubsub_topics=[self.test_pubsub_topic])
        self.relay_message(self.node1, self.create_message(contentTopic=self.test_content_topic))
        delay(0.1)
        get_messages_response = self.retrieve_relay_message(self.node2, pubsub_topic=self.test_pubsub_topic)
        assert get_messages_response, f"Peer NODE_2 couldn't find any messages"
        assert len(get_messages_response) == 1, f"Expected 1 message but got {len(get_messages_response)}"

    def test_sender_uses_regular_api_receiver_uses_auto_api(self):
        self.setup_main_relay_nodes(
            cluster_id=self.auto_cluster, pubsub_topic=self.test_pubsub_topic, num_shards_in_network=self.num_shards_in_network
        )
        self.subscribe_first_relay_node(pubsub_topics=[self.test_pubsub_topic])
        self.subscribe_second_relay_node(content_topics=[self.test_content_topic])
        self.relay_message(self.node1, self.create_message(contentTopic=self.test_content_topic), pubsub_topic=self.test_pubsub_topic)
        delay(0.1)
        get_messages_response = self.retrieve_relay_message(self.node2, content_topic=self.test_content_topic)
        assert get_messages_response, f"Peer NODE_2 couldn't find any messages"
        assert len(get_messages_response) == 1, f"Expected 1 message but got {len(get_messages_response)}"
