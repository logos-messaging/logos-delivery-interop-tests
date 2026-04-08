import pytest
from src.env_vars import NODE_2
from src.libs.common import delay, to_base64
from src.libs.custom_logger import get_custom_logger
from src.steps.sharding import StepsSharding
from src.test_data import PUBSUB_TOPICS_SAME_CLUSTER

logger = get_custom_logger(__name__)


class TestRelayStaticSharding(StepsSharding):
    def test_retrieve_messages_without_subscribing_via_api(self):
        self.setup_main_relay_nodes(pubsub_topic=self.test_pubsub_topic)
        try:
            self.check_published_message_reaches_relay_peer(pubsub_topic=self.test_pubsub_topic)
            if self.node2.is_nwaku():
                pass
            else:
                raise AssertionError("Retrieving messages without subscribing worked!!!")
        except Exception as ex:
            assert "no subscription found for pubsubTopic" in str(ex)

    def test_subscribe_and_publish_on_another_shard(self):
        self.setup_main_relay_nodes(pubsub_topic=self.test_pubsub_topic)
        self.subscribe_main_relay_nodes(pubsub_topics=["/waku/2/rs/2/1"])
        self.check_published_message_reaches_relay_peer(pubsub_topic="/waku/2/rs/2/1")
        try:
            self.check_published_message_reaches_relay_peer(pubsub_topic=self.test_pubsub_topic)
            if self.node2.is_nwaku():
                pass
            else:
                raise AssertionError("Retrieving messages without subscribing worked!!!")
        except Exception as ex:
            assert "no subscription found for pubsubTopic" in str(ex)

    def test_cant_publish_on_not_subscribed_shard(self):
        self.setup_main_relay_nodes(pubsub_topic=self.test_pubsub_topic)
        self.subscribe_main_relay_nodes(pubsub_topics=[self.test_pubsub_topic])
        self.check_publish_fails_on_not_subscribed_pubsub_topic("/waku/2/rs/2/1")

    def test_subscribe_via_api_to_new_pubsub_topics(self):
        self.setup_main_relay_nodes(pubsub_topic=PUBSUB_TOPICS_SAME_CLUSTER[:1])
        self.subscribe_main_relay_nodes(pubsub_topics=PUBSUB_TOPICS_SAME_CLUSTER[1:])
        for pubsub_topic in PUBSUB_TOPICS_SAME_CLUSTER[1:]:
            self.check_published_message_reaches_relay_peer(pubsub_topic=pubsub_topic)

    def test_subscribe_one_by_one_to_different_pubsub_topics_and_send_messages(self):
        self.setup_main_relay_nodes(cluster_id=self.auto_cluster, pubsub_topic=self.test_pubsub_topic)
        for pubsub_topic in PUBSUB_TOPICS_SAME_CLUSTER:
            self.subscribe_main_relay_nodes(pubsub_topics=[pubsub_topic])
            self.check_published_message_reaches_relay_peer(pubsub_topic=pubsub_topic)

    @pytest.mark.smoke
    def test_unsubscribe_from_some_pubsub_topics(self):
        self.setup_main_relay_nodes(cluster_id=self.auto_cluster, pubsub_topic=PUBSUB_TOPICS_SAME_CLUSTER)
        self.subscribe_main_relay_nodes(pubsub_topics=PUBSUB_TOPICS_SAME_CLUSTER)
        for pubsub_topic in PUBSUB_TOPICS_SAME_CLUSTER:
            self.check_published_message_reaches_relay_peer(pubsub_topic=pubsub_topic)
        self.unsubscribe_main_relay_nodes(pubsub_topics=PUBSUB_TOPICS_SAME_CLUSTER[:3])
        for pubsub_topic in PUBSUB_TOPICS_SAME_CLUSTER[:3]:
            self.check_publish_fails_on_not_subscribed_pubsub_topic(pubsub_topic)
        for pubsub_topic in PUBSUB_TOPICS_SAME_CLUSTER[3:]:
            self.check_published_message_reaches_relay_peer(pubsub_topic=pubsub_topic)

    @pytest.mark.smoke
    def test_unsubscribe_from_all_pubsub_topics(self):
        self.setup_main_relay_nodes(cluster_id=self.auto_cluster, pubsub_topic=PUBSUB_TOPICS_SAME_CLUSTER)
        self.subscribe_main_relay_nodes(pubsub_topics=PUBSUB_TOPICS_SAME_CLUSTER)
        for pubsub_topic in PUBSUB_TOPICS_SAME_CLUSTER:
            self.check_published_message_reaches_relay_peer(pubsub_topic=pubsub_topic)
        self.unsubscribe_main_relay_nodes(pubsub_topics=PUBSUB_TOPICS_SAME_CLUSTER)
        for pubsub_topic in PUBSUB_TOPICS_SAME_CLUSTER:
            self.check_publish_fails_on_not_subscribed_pubsub_topic(pubsub_topic)

    def test_unsubscribe_from_all_pubsub_topics_one_by_one(self):
        self.setup_main_relay_nodes(cluster_id=self.auto_cluster, pubsub_topic=self.test_pubsub_topic)
        self.subscribe_main_relay_nodes(pubsub_topics=PUBSUB_TOPICS_SAME_CLUSTER)
        for pubsub_topic in PUBSUB_TOPICS_SAME_CLUSTER:
            self.check_published_message_reaches_relay_peer(pubsub_topic=pubsub_topic)
        for pubsub_topic in PUBSUB_TOPICS_SAME_CLUSTER:
            self.unsubscribe_main_relay_nodes(pubsub_topics=[pubsub_topic])
        for pubsub_topic in PUBSUB_TOPICS_SAME_CLUSTER:
            self.check_publish_fails_on_not_subscribed_pubsub_topic(pubsub_topic)

    def test_resubscribe_to_unsubscribed_pubsub_topics(self):
        self.setup_main_relay_nodes(cluster_id=self.auto_cluster, pubsub_topic=self.test_pubsub_topic)
        self.subscribe_main_relay_nodes(pubsub_topics=PUBSUB_TOPICS_SAME_CLUSTER)
        for pubsub_topic in PUBSUB_TOPICS_SAME_CLUSTER:
            self.check_published_message_reaches_relay_peer(pubsub_topic=pubsub_topic)
        self.unsubscribe_main_relay_nodes(pubsub_topics=PUBSUB_TOPICS_SAME_CLUSTER)
        for pubsub_topic in PUBSUB_TOPICS_SAME_CLUSTER:
            self.check_publish_fails_on_not_subscribed_pubsub_topic(pubsub_topic)
        self.subscribe_main_relay_nodes(pubsub_topics=PUBSUB_TOPICS_SAME_CLUSTER)
        for pubsub_topic in PUBSUB_TOPICS_SAME_CLUSTER:
            self.check_published_message_reaches_relay_peer(pubsub_topic=pubsub_topic)

    def test_unsubscribe_from_non_subscribed_pubsub_topics(self):
        self.setup_main_relay_nodes(cluster_id=self.auto_cluster, pubsub_topic=self.test_pubsub_topic)
        self.unsubscribe_main_relay_nodes(pubsub_topics=PUBSUB_TOPICS_SAME_CLUSTER)
        for pubsub_topic in PUBSUB_TOPICS_SAME_CLUSTER:
            self.check_publish_fails_on_not_subscribed_pubsub_topic(pubsub_topic)

    def test_publish_on_multiple_pubsub_topics_and_only_after_fetch_them(self):
        self.setup_main_relay_nodes(cluster_id=self.auto_cluster, pubsub_topic=self.test_pubsub_topic)
        self.subscribe_main_relay_nodes(pubsub_topics=PUBSUB_TOPICS_SAME_CLUSTER)
        for pubsub_topic in PUBSUB_TOPICS_SAME_CLUSTER:
            self.relay_message(self.node1, self.create_message(payload=to_base64(pubsub_topic)), pubsub_topic=pubsub_topic)
        delay(0.1)
        for pubsub_topic in PUBSUB_TOPICS_SAME_CLUSTER:
            get_messages_response = self.retrieve_relay_message(self.node2, pubsub_topic=pubsub_topic)
            assert get_messages_response, f"Peer NODE_2 couldn't find any messages"
            assert len(get_messages_response) == 1, f"Expected 1 message but got {len(get_messages_response)}"
            assert get_messages_response[0]["payload"] == to_base64(pubsub_topic)
