import pytest
from src.libs.custom_logger import get_custom_logger
from src.test_data import INVALID_CONTENT_TOPICS, SAMPLE_INPUTS, VALID_PUBSUB_TOPICS
from src.steps.filter import StepsFilter

logger = get_custom_logger(__name__)


@pytest.mark.usefixtures("setup_main_relay_node", "setup_main_filter_node")
class TestFilterSubscribeUpdate(StepsFilter):
    @pytest.mark.waku_test_fleet
    def test_filter_update_subscription_add_a_new_content_topic(self):
        self.wait_for_subscriptions_on_main_nodes([self.test_content_topic], pubsub_topic=self.test_pubsub_topic)
        self.update_filter_subscription({"requestId": "1", "contentFilters": [self.second_content_topic], "pubsubTopic": self.test_pubsub_topic})
        self.check_published_message_reaches_filter_peer(self.create_message(contentTopic=self.test_content_topic))
        self.check_published_message_reaches_filter_peer(self.create_message(contentTopic=self.second_content_topic))

    def test_filter_update_subscription_add_30_new_content_topics(self):
        self.wait_for_subscriptions_on_main_nodes([self.test_content_topic], pubsub_topic=self.test_pubsub_topic)
        self.update_filter_subscription(
            {"requestId": "1", "contentFilters": [input["value"] for input in SAMPLE_INPUTS[:30]], "pubsubTopic": self.test_pubsub_topic}
        )
        self.check_published_message_reaches_filter_peer(self.create_message(contentTopic=self.test_content_topic))
        failed_content_topics = []
        for content_topic in SAMPLE_INPUTS[:30]:
            logger.debug(f'Running test with content topic {content_topic["description"]}')
            message = self.create_message(contentTopic=content_topic["value"])
            try:
                self.check_published_message_reaches_filter_peer(message)
            except Exception as ex:
                logger.error(f'ContentTopic {content_topic["description"]} failed: {str(ex)}')
                failed_content_topics.append(content_topic)
        assert not failed_content_topics, f"ContentTopics failed: {failed_content_topics}"

    def test_filter_update_subscription_add_101_new_content_topics(self, subscribe_main_nodes):
        try:
            _101_content_topics = [str(i) for i in range(101)]
            self.update_filter_subscription({"requestId": "1", "contentFilters": _101_content_topics, "pubsubTopic": self.test_pubsub_topic})
            raise AssertionError("Subscribe with more than 100 content topics worked!!!")
        except Exception as ex:
            assert "Bad Request" in str(ex)

    @pytest.mark.waku_test_fleet
    def test_filter_update_subscription_refresh_existing(self):
        self.wait_for_subscriptions_on_main_nodes([self.test_content_topic], pubsub_topic=self.test_pubsub_topic)
        self.update_filter_subscription({"requestId": "1", "contentFilters": [self.test_content_topic], "pubsubTopic": self.test_pubsub_topic})
        self.check_published_message_reaches_filter_peer(self.create_message(contentTopic=self.test_content_topic))

    def test_filter_update_subscription_add_a_new_pubsub_topic(self):
        self.wait_for_subscriptions_on_main_nodes([self.test_content_topic], pubsub_topic=self.test_pubsub_topic)
        self.update_filter_subscription(
            {"requestId": "1", "contentFilters": [self.test_content_topic, self.second_content_topic], "pubsubTopic": VALID_PUBSUB_TOPICS[4]}
        )
        self.add_new_relay_subscription(VALID_PUBSUB_TOPICS[4:5])
        self.check_published_message_reaches_filter_peer(
            self.create_message(contentTopic=self.test_content_topic), pubsub_topic=self.test_pubsub_topic
        )
        self.check_published_message_reaches_filter_peer(
            self.create_message(contentTopic=self.test_content_topic), pubsub_topic=VALID_PUBSUB_TOPICS[4]
        )
        self.check_published_message_reaches_filter_peer(
            self.create_message(contentTopic=self.second_content_topic), pubsub_topic=VALID_PUBSUB_TOPICS[4]
        )

    def test_filter_update_subscription_with_no_pubsub_topic(self, subscribe_main_nodes):
        try:
            self.update_filter_subscription({"requestId": "1", "contentFilters": [self.second_content_topic]})
            # raise AssertionError("Subscribe with no pubusub topics worked!!!")  commented until https://github.com/waku-org/nwaku/issues/2315 is fixed
        except Exception as ex:
            assert "Bad Request" in str(ex)

    def test_filter_update_subscription_with_pubsub_topic_list_instead_of_string(self, subscribe_main_nodes):
        try:
            self.update_filter_subscription({"requestId": "1", "contentFilters": [self.test_content_topic], "pubsubTopic": [self.test_pubsub_topic]})
            raise AssertionError(f"Subscribe with invalid pubusub topics worked!!!")
        except Exception as ex:
            assert "Bad Request" in str(ex)

    def test_filter_update_subscription_with_no_content_topic(self, subscribe_main_nodes):
        try:
            self.update_filter_subscription({"requestId": "1", "pubsubTopic": self.test_pubsub_topic})
            raise AssertionError("Subscribe with no content topics worked!!!")
        except Exception as ex:
            assert "Bad Request" in str(ex)

    def test_filter_update_subscription_with_invalid_content_topic_format(self, subscribe_main_nodes):
        success_content_topics = []
        for content_topic in INVALID_CONTENT_TOPICS:
            logger.debug(f'Running test with contetn topic {content_topic["description"]}')
            try:
                self.update_filter_subscription({"requestId": "1", "contentFilters": [content_topic], "pubsubTopic": self.test_pubsub_topic})
                success_content_topics.append(content_topic)
            except Exception as ex:
                assert "Bad Request" in str(ex) or "Internal Server Error" in str(ex)
        assert not success_content_topics, f"Invalid Content topics that didn't failed: {success_content_topics}"

    def test_filter_update_subscription_with_no_request_id(self, subscribe_main_nodes):
        try:
            self.update_filter_subscription({"contentFilters": [self.test_content_topic], "pubsubTopic": self.test_pubsub_topic})
            raise AssertionError("Subscribe with no request id worked!!!")
        except Exception as ex:
            assert "Bad Request" in str(ex)

    def test_filter_update_subscription_with_invalid_request_id(self, subscribe_main_nodes):
        try:
            self.update_filter_subscription({"requestId": 1, "contentFilters": [self.test_content_topic], "pubsubTopic": self.test_pubsub_topic})
            raise AssertionError("Subscribe with invalid request id worked!!!")
        except Exception as ex:
            assert "Bad Request" in str(ex)

    def test_filter_update_subscription_with_extra_field(self, subscribe_main_nodes):
        try:
            self.update_filter_subscription(
                {"requestId": "1", "contentFilters": [self.test_content_topic], "pubsubTopic": self.test_pubsub_topic, "extraField": "extraValue"}
            )
            raise AssertionError("Subscribe with extra field worked!!!")
        except Exception as ex:
            assert "Bad Request" in str(ex)
