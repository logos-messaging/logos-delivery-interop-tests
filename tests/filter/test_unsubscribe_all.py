import pytest
from src.test_data import SAMPLE_INPUTS, VALID_PUBSUB_TOPICS
from src.steps.filter import StepsFilter
from random import choice


@pytest.mark.usefixtures("setup_main_relay_node", "setup_main_filter_node")
class TestFilterUnSubscribeAll(StepsFilter):
    @pytest.mark.waku_test_fleet
    def test_filter_unsubscribe_all_from_few_content_topics(self):
        content_topics = [input["value"] for input in SAMPLE_INPUTS[:5]]
        self.wait_for_subscriptions_on_main_nodes(content_topics)
        for content_topic in content_topics:
            self.check_published_message_reaches_filter_peer(self.create_message(contentTopic=content_topic))
        self.delete_all_filter_subscriptions({"requestId": "1"})
        for content_topic in content_topics:
            self.check_publish_without_filter_subscription(self.create_message(contentTopic=content_topic))

    def test_filter_unsubscribe_all_from_90_content_topics(self):
        first_list = [str(i) for i in range(1, 31)]
        second_list = [str(i) for i in range(31, 61)]
        third_list = [str(i) for i in range(61, 91)]
        self.wait_for_subscriptions_on_main_nodes(first_list)
        self.wait_for_subscriptions_on_main_nodes(second_list)
        self.wait_for_subscriptions_on_main_nodes(third_list)
        self.check_published_message_reaches_filter_peer(self.create_message(contentTopic=choice(first_list)))
        self.check_published_message_reaches_filter_peer(self.create_message(contentTopic=choice(second_list)))
        self.check_published_message_reaches_filter_peer(self.create_message(contentTopic=choice(third_list)))
        self.delete_all_filter_subscriptions({"requestId": "1"})
        self.check_publish_without_filter_subscription(self.create_message(contentTopic=choice(first_list)))
        self.check_publish_without_filter_subscription(self.create_message(contentTopic=choice(second_list)))
        self.check_publish_without_filter_subscription(self.create_message(contentTopic=choice(third_list)))

    @pytest.mark.waku_test_fleet
    def test_filter_unsubscribe_all_from_multiple_pubsub_topics(self):
        for pubsub_topic in VALID_PUBSUB_TOPICS:
            content_topic = pubsub_topic
            self.wait_for_subscriptions_on_main_nodes([content_topic], pubsub_topic)
            self.check_published_message_reaches_filter_peer(self.create_message(contentTopic=content_topic), pubsub_topic=pubsub_topic)
        self.delete_all_filter_subscriptions({"requestId": "1"})
        for pubsub_topic in VALID_PUBSUB_TOPICS:
            content_topic = pubsub_topic
            self.check_publish_without_filter_subscription(self.create_message(contentTopic=content_topic), pubsub_topic=pubsub_topic)

    def test_filter_unsubscribe_all_on_peer_with_no_subscription(self):
        try:
            self.delete_all_filter_subscriptions({"requestId": "1"})
            raise AssertionError("Unsubscribe all on peer without subscriptions worked!!!")
        except Exception as ex:
            if self.node2.is_nwaku():
                assert "Not Found" in str(ex) and "peer has no subscriptions" in str(ex)
            else:
                raise NotImplementedError("Not implemented for this node type")

    def test_filter_unsubscribe_all_with_invalid_request_id(self, subscribe_main_nodes):
        try:
            self.delete_all_filter_subscriptions({"requestId": 1})
            raise AssertionError("Unsubscribe all with invalid request id worked!!!")
        except Exception as ex:
            assert "Bad Request" in str(ex)

    def test_filter_unsubscribe_all_with_extra_field(self, subscribe_main_nodes):
        try:
            self.delete_all_filter_subscriptions({"requestId": 1, "extraField": "extraValue"})
            raise AssertionError("Unsubscribe all with extra field worked!!!")
        except Exception as ex:
            assert "Bad Request" in str(ex)
