import pytest
from src.test_data import SAMPLE_INPUTS
from src.steps.filter import StepsFilter


@pytest.mark.usefixtures("setup_main_relay_node", "setup_main_filter_node", "subscribe_main_nodes")
class TestFilterUnSubscribe(StepsFilter):
    @pytest.mark.waku_test_fleet
    def test_filter_unsubscribe_from_single_content_topic(self):
        self.check_published_message_reaches_filter_peer()
        self.delete_filter_subscription({"requestId": "1", "contentFilters": [self.test_content_topic], "pubsubTopic": self.test_pubsub_topic})
        self.check_publish_without_filter_subscription()

    @pytest.mark.waku_test_fleet
    def test_filter_unsubscribe_from_all_subscribed_content_topics(self):
        content_topics = [input["value"] for input in SAMPLE_INPUTS[:2]]
        self.wait_for_subscriptions_on_main_nodes(content_topics)
        self.check_published_message_reaches_filter_peer(self.create_message(contentTopic=content_topics[1]))
        self.delete_filter_subscription({"requestId": "1", "contentFilters": content_topics, "pubsubTopic": self.test_pubsub_topic})
        self.check_publish_without_filter_subscription(self.create_message(contentTopic=content_topics[1]))

    def test_filter_unsubscribe_from_some_of_the_subscribed_content_topics(self):
        content_topics = [input["value"] for input in SAMPLE_INPUTS[:2]]
        self.wait_for_subscriptions_on_main_nodes(content_topics)
        self.check_published_message_reaches_filter_peer(self.create_message(contentTopic=content_topics[1]))
        self.delete_filter_subscription({"requestId": "1", "contentFilters": content_topics[:1], "pubsubTopic": self.test_pubsub_topic})
        self.check_published_message_reaches_filter_peer(self.create_message(contentTopic=content_topics[1]))
        self.check_publish_without_filter_subscription(self.create_message(contentTopic=content_topics[0]))

    @pytest.mark.waku_test_fleet
    def test_filter_unsubscribe_from_pubsub_topics(self):
        self.wait_for_subscriptions_on_main_nodes([self.test_content_topic], self.test_pubsub_topic)
        self.wait_for_subscriptions_on_main_nodes([self.second_content_topic], self.second_pubsub_topic)
        self.check_published_message_reaches_filter_peer(self.create_message(contentTopic=self.test_content_topic), self.test_pubsub_topic)
        self.check_published_message_reaches_filter_peer(self.create_message(contentTopic=self.second_content_topic), self.second_pubsub_topic)
        self.delete_filter_subscription({"requestId": "1", "contentFilters": [self.test_content_topic], "pubsubTopic": self.test_pubsub_topic})
        self.check_publish_without_filter_subscription()
        self.check_published_message_reaches_filter_peer(self.create_message(contentTopic=self.second_content_topic), self.second_pubsub_topic)
        self.delete_filter_subscription({"requestId": "1", "contentFilters": [self.second_content_topic], "pubsubTopic": self.second_pubsub_topic})
        self.check_publish_without_filter_subscription()
        self.check_publish_without_filter_subscription(self.create_message(contentTopic=self.second_content_topic), self.second_pubsub_topic)

    def test_filter_unsubscribe_from_non_existing_content_topic(self):
        try:
            self.delete_filter_subscription(
                {"requestId": "1", "contentFilters": [self.second_content_topic], "pubsubTopic": self.test_pubsub_topic},
                "",
            )
        except Exception as ex:
            assert "Not Found" in str(ex) and "peer has no subscriptions" in str(ex)
        self.check_published_message_reaches_filter_peer()

    def test_filter_unsubscribe_from_non_existing_pubsub_topic(self):
        try:
            self.delete_filter_subscription(
                {"requestId": "1", "contentFilters": [self.test_pubsub_topic], "pubsubTopic": self.second_pubsub_topic}, status="can't unsubscribe"
            )
            if self.node2.is_nwaku():
                raise AssertionError("Unsubscribe with non existing pubsub topic worked!!!")
            else:
                raise NotImplementedError("Not implemented for this node type")
        except Exception as ex:
            assert "Not Found" in str(ex) and "peer has no subscriptions" in str(ex)
        self.check_published_message_reaches_filter_peer()

    def test_filter_unsubscribe_from_101_content_topics(self):
        try:
            _101_content_topics = [str(i) for i in range(101)]
            self.delete_filter_subscription({"requestId": "1", "contentFilters": _101_content_topics, "pubsubTopic": self.test_pubsub_topic})
            raise AssertionError("Unsubscribe from more than 100 content topics worked!!!")
        except Exception as ex:
            if self.node2.is_nwaku():
                assert "exceeds maximum content topics: 100" in str(ex)
            else:
                raise NotImplementedError("Not implemented for this node type")

    def test_filter_unsubscribe_with_no_content_topic(self):
        try:
            self.delete_filter_subscription({"requestId": "1", "pubsubTopic": self.test_pubsub_topic})
            raise AssertionError("Unsubscribe with no content topics worked!!!")
        except Exception as ex:
            assert "Bad Request" in str(ex)

    def test_filter_unsubscribe_with_content_topic_string_instead_of_list(self):
        try:
            self.delete_filter_subscription({"requestId": "1", "contentFilters": self.test_content_topic, "pubsubTopic": self.test_pubsub_topic})
            raise AssertionError("Unsubscribe with invalid content topics worked!!!")
        except Exception as ex:
            assert "Bad Request" in str(ex)

    def test_filter_unsubscribe_with_no_pubsub_topic(self):
        try:
            self.delete_filter_subscription({"requestId": "1", "contentFilters": self.test_content_topic})
            raise AssertionError("Unsubscribe with no pubsub topic worked!!!")
        except Exception as ex:
            assert "Bad Request" in str(ex)

    def test_filter_unsubscribe_with_pubsub_topic_string_instead_of_list(self):
        try:
            self.delete_filter_subscription({"requestId": "1", "contentFilters": self.test_content_topic, "pubsubTopic": self.test_pubsub_topic})
            raise AssertionError("Unsubscribe with invalid pubsub topic worked!!!")
        except Exception as ex:
            assert "Bad Request" in str(ex)

    def test_filter_unsubscribe_with_very_large_request_id(self):
        self.check_published_message_reaches_filter_peer()
        self.delete_filter_subscription(
            {
                "requestId": "12345678901234567890123456789012345678901234567890",
                "contentFilters": [self.test_content_topic],
                "pubsubTopic": self.test_pubsub_topic,
            }
        )
        self.check_publish_without_filter_subscription()

    def test_filter_unsubscribe_with_no_request_id(self):
        try:
            self.delete_filter_subscription(
                {"contentFilters": [self.test_content_topic], "pubsubTopic": self.test_pubsub_topic}, status="can't unsubscribe"
            )
            if self.node2.is_nwaku():
                raise AssertionError("Unsubscribe with no request id worked!!!")
            else:
                raise NotImplementedError("Not implemented for this node type")
        except Exception as ex:
            assert "Bad Request" in str(ex)

    def test_filter_unsubscribe_with_invalid_request_id(self):
        try:
            self.delete_filter_subscription({"requestId": 1, "contentFilters": [self.test_content_topic], "pubsubTopic": self.test_pubsub_topic})
            raise AssertionError("Unsubscribe with invalid request id worked!!!")
        except Exception as ex:
            assert "Bad Request" in str(ex)

    def test_filter_unsubscribe_with_extra_field(self):
        try:
            self.delete_filter_subscription(
                {"requestId": "1", "contentFilters": [self.test_content_topic], "pubsubTopic": self.test_pubsub_topic, "extraField": "extraValue"}
            )
            if self.node2.is_nwaku():
                raise AssertionError("Unsubscribe with extra field worked!!!")
            else:
                raise NotImplementedError("Not implemented for this node type")
        except Exception as ex:
            assert "Bad Request" in str(ex)

    def test_filter_resubscribe_to_unsubscribed_topics(self):
        self.check_published_message_reaches_filter_peer()
        self.delete_filter_subscription({"requestId": "1", "contentFilters": [self.test_content_topic], "pubsubTopic": self.test_pubsub_topic})
        self.check_publish_without_filter_subscription()
        self.wait_for_subscriptions_on_main_nodes([self.test_content_topic], self.test_pubsub_topic)
        self.check_published_message_reaches_filter_peer()
