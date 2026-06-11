import pytest
from src.env_vars import NODE_1, NODE_2
from src.libs.common import delay, to_base64
from src.libs.custom_logger import get_custom_logger
from src.steps.relay import StepsRelay
from src.steps.sharding import StepsSharding
from src.test_data import CONTENT_TOPICS_DIFFERENT_SHARDS, CONTENT_TOPICS_SHARD_0


logger = get_custom_logger(__name__)


class TestRelayAutosharding(StepsSharding):
    def test_publish_without_subscribing_via_api_works(self):
        self.setup_main_relay_nodes(
            cluster_id=self.auto_cluster, content_topic=self.test_content_topic, num_shards_in_network=self.num_shards_in_network
        )
        for node in self.main_nodes:
            self.relay_message(node, self.create_message(contentTopic=self.test_content_topic))

    def test_retrieve_messages_without_subscribing_via_api(self):
        self.setup_main_relay_nodes(
            cluster_id=self.auto_cluster, content_topic=self.test_content_topic, num_shards_in_network=self.num_shards_in_network
        )
        try:
            self.check_published_message_reaches_relay_peer(content_topic=self.test_content_topic)
            if self.node2.is_nwaku():
                pass
            else:
                raise AssertionError("Retrieving messages without subscribing worked!!!")
        except Exception as ex:
            assert "Failed to publish: Node not subscribed to topic" in str(ex)

    def test_subscribe_and_publish_on_another_content_topic_from_same_shard(self):
        self.setup_main_relay_nodes(
            cluster_id=self.auto_cluster, content_topic=self.test_content_topic, num_shards_in_network=self.num_shards_in_network
        )
        self.subscribe_main_relay_nodes(content_topics=["/newsService/1.0/weekly/protobuf"])
        self.check_published_message_reaches_relay_peer(content_topic="/newsService/1.0/weekly/protobuf")
        self.check_published_message_reaches_relay_peer(content_topic=self.test_content_topic)

    def test_subscribe_and_publish_on_another_content_topic_from_another_shard(self):
        self.setup_main_relay_nodes(
            cluster_id=self.auto_cluster, content_topic=self.test_content_topic, num_shards_in_network=self.num_shards_in_network
        )
        self.subscribe_main_relay_nodes(content_topics=["/toychat/2/huilong/proto"])
        self.check_published_message_reaches_relay_peer(content_topic="/toychat/2/huilong/proto")
        self.check_published_message_reaches_relay_peer(content_topic=self.test_content_topic)

    def test_publish_on_not_subscribed_content_topic_works(self):
        self.setup_main_relay_nodes(
            cluster_id=self.auto_cluster, content_topic=self.test_content_topic, num_shards_in_network=self.num_shards_in_network
        )
        self.subscribe_main_relay_nodes(content_topics=[self.test_content_topic])
        for node in self.main_nodes:
            self.relay_message(node, self.create_message(contentTopic="/toychat/2/huilong/proto"))

    def test_cant_retrieve_messages_on_not_subscribed_content_topic(self):
        self.setup_main_relay_nodes(
            cluster_id=self.auto_cluster, content_topic=self.test_content_topic, num_shards_in_network=self.num_shards_in_network
        )
        self.subscribe_main_relay_nodes(content_topics=[self.test_content_topic])
        self.check_published_message_doesnt_reach_relay_peer(content_topic="/toychat/2/huilong/proto")

    @pytest.mark.parametrize("content_topic_list", [CONTENT_TOPICS_SHARD_0, CONTENT_TOPICS_DIFFERENT_SHARDS])
    def test_subscribe_via_api_to_new_content_topics(self, content_topic_list):
        self.setup_main_relay_nodes(
            cluster_id=self.auto_cluster, num_shards_in_network=self.num_shards_in_network, content_topic=content_topic_list[:1]
        )
        self.subscribe_main_relay_nodes(content_topics=content_topic_list[1:])
        for content_topic in content_topic_list[1:]:
            self.check_published_message_reaches_relay_peer(content_topic=content_topic)

    def test_subscribe_one_by_one_to_different_content_topics_and_send_messages(self):
        self.setup_main_relay_nodes(
            cluster_id=self.auto_cluster, content_topic=self.test_content_topic, num_shards_in_network=self.num_shards_in_network
        )
        for content_topic in CONTENT_TOPICS_DIFFERENT_SHARDS + CONTENT_TOPICS_SHARD_0:
            self.subscribe_main_relay_nodes(content_topics=[content_topic])
            self.check_published_message_reaches_relay_peer(content_topic=content_topic)

    @pytest.mark.smoke
    @pytest.mark.parametrize("content_topic_list", [CONTENT_TOPICS_SHARD_0, CONTENT_TOPICS_DIFFERENT_SHARDS])
    def test_unsubscribe_from_some_content_topics(self, content_topic_list):
        self.setup_main_relay_nodes(
            cluster_id=self.auto_cluster, content_topic=self.test_content_topic, num_shards_in_network=self.num_shards_in_network
        )
        self.subscribe_main_relay_nodes(content_topics=content_topic_list)
        for content_topic in content_topic_list:
            self.check_published_message_reaches_relay_peer(content_topic=content_topic)
        self.unsubscribe_main_relay_nodes(content_topics=content_topic_list[:3])
        for content_topic in content_topic_list[:3]:
            self.check_published_message_doesnt_reach_relay_peer(content_topic=content_topic)
        for content_topic in content_topic_list[3:]:
            self.check_published_message_reaches_relay_peer(content_topic=content_topic)

    @pytest.mark.smoke
    def test_unsubscribe_from_all_content_topics(self):
        self.setup_main_relay_nodes(
            cluster_id=self.auto_cluster, content_topic=self.test_content_topic, num_shards_in_network=self.num_shards_in_network
        )
        self.subscribe_main_relay_nodes(content_topics=CONTENT_TOPICS_DIFFERENT_SHARDS)
        for content_topic in CONTENT_TOPICS_DIFFERENT_SHARDS:
            self.check_published_message_reaches_relay_peer(content_topic=content_topic)
        self.unsubscribe_main_relay_nodes(content_topics=CONTENT_TOPICS_DIFFERENT_SHARDS)
        for content_topic in CONTENT_TOPICS_DIFFERENT_SHARDS:
            self.check_published_message_doesnt_reach_relay_peer(content_topic=content_topic)

    def test_unsubscribe_from_all_content_topics_one_by_one(self):
        self.setup_main_relay_nodes(
            cluster_id=self.auto_cluster, content_topic=self.test_content_topic, num_shards_in_network=self.num_shards_in_network
        )
        self.subscribe_main_relay_nodes(content_topics=CONTENT_TOPICS_DIFFERENT_SHARDS)
        for content_topic in CONTENT_TOPICS_DIFFERENT_SHARDS:
            self.check_published_message_reaches_relay_peer(content_topic=content_topic)
        for content_topic in CONTENT_TOPICS_DIFFERENT_SHARDS:
            self.unsubscribe_main_relay_nodes(content_topics=[content_topic])
        for content_topic in CONTENT_TOPICS_DIFFERENT_SHARDS:
            self.check_published_message_doesnt_reach_relay_peer(content_topic=content_topic)

    @pytest.mark.smoke
    def test_resubscribe_to_unsubscribed_content_topics(self):
        self.setup_main_relay_nodes(
            cluster_id=self.auto_cluster, content_topic=self.test_content_topic, num_shards_in_network=self.num_shards_in_network
        )
        self.subscribe_main_relay_nodes(content_topics=CONTENT_TOPICS_DIFFERENT_SHARDS)
        for content_topic in CONTENT_TOPICS_DIFFERENT_SHARDS:
            self.check_published_message_reaches_relay_peer(content_topic=content_topic)
        self.unsubscribe_main_relay_nodes(content_topics=CONTENT_TOPICS_DIFFERENT_SHARDS)
        for content_topic in CONTENT_TOPICS_DIFFERENT_SHARDS:
            self.check_published_message_doesnt_reach_relay_peer(content_topic=content_topic)
        self.subscribe_main_relay_nodes(content_topics=CONTENT_TOPICS_DIFFERENT_SHARDS)
        for content_topic in CONTENT_TOPICS_DIFFERENT_SHARDS:
            self.check_published_message_reaches_relay_peer(content_topic=content_topic)

    def test_unsubscribe_from_non_subscribed_content_topics(self):
        self.setup_main_relay_nodes(
            cluster_id=self.auto_cluster, content_topic=self.test_content_topic, num_shards_in_network=self.num_shards_in_network
        )
        self.unsubscribe_main_relay_nodes(content_topics=CONTENT_TOPICS_DIFFERENT_SHARDS)
        for content_topic in CONTENT_TOPICS_DIFFERENT_SHARDS:
            self.check_published_message_doesnt_reach_relay_peer(content_topic=content_topic)

    @pytest.mark.parametrize("content_topic_list", [CONTENT_TOPICS_SHARD_0, CONTENT_TOPICS_DIFFERENT_SHARDS])
    def test_publish_on_multiple_content_topics_and_only_after_fetch_them(self, content_topic_list):
        self.setup_main_relay_nodes(
            cluster_id=self.auto_cluster, content_topic=self.test_content_topic, num_shards_in_network=self.num_shards_in_network
        )
        self.subscribe_main_relay_nodes(content_topics=content_topic_list)
        for content_topic in content_topic_list:
            self.relay_message(self.node1, self.create_message(payload=to_base64(content_topic), contentTopic=content_topic))
        delay(0.1)
        for content_topic in content_topic_list:
            get_messages_response = self.retrieve_relay_message(self.node2, content_topic=content_topic)
            assert get_messages_response, f"Peer NODE_2 couldn't find any messages"
            assert len(get_messages_response) == 1, f"Expected 1 message but got {len(get_messages_response)}"
            assert get_messages_response[0]["contentTopic"] == content_topic
            assert get_messages_response[0]["payload"] == to_base64(content_topic)
