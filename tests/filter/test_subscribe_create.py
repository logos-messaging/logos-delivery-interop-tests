import pytest
from uuid import uuid4
from src.env_vars import NODE_1, NODE_2
from src.libs.custom_logger import get_custom_logger
from src.test_data import INVALID_CONTENT_TOPICS, SAMPLE_INPUTS, VALID_PUBSUB_TOPICS
from src.steps.filter import StepsFilter

logger = get_custom_logger(__name__)


@pytest.mark.usefixtures("setup_main_relay_node", "setup_main_filter_node")
class TestFilterSubscribeCreate(StepsFilter):
    @pytest.mark.waku_test_fleet
    def test_filter_subscribe_to_single_topics(self):
        self.wait_for_subscriptions_on_main_nodes([self.test_content_topic])
        self.check_published_message_reaches_filter_peer()

    def test_filter_subscribe_to_multiple_pubsub_topic_from_same_cluster(self):
        failed_pubsub_topics = []
        for pubsub_topic in VALID_PUBSUB_TOPICS:
            content_topic = pubsub_topic
            logger.debug(f"Running test with pubsub topic: {pubsub_topic}")
            try:
                self.wait_for_subscriptions_on_main_nodes([content_topic], pubsub_topic)
                message = self.create_message(contentTopic=content_topic)
                self.check_published_message_reaches_filter_peer(message, pubsub_topic=pubsub_topic)
            except Exception as ex:
                logger.error(f"PubsubTopic {pubsub_topic} failed: {str(ex)}")
                failed_pubsub_topics.append(pubsub_topic)
        assert not failed_pubsub_topics, f"PubsubTopics failed: {failed_pubsub_topics}"

    def test_filter_subscribe_to_pubsub_topic_from_another_cluster_id(self):
        self.wait_for_subscriptions_on_main_nodes([self.test_content_topic], pubsub_topic=self.another_cluster_pubsub_topic)
        self.check_published_message_reaches_filter_peer(pubsub_topic=self.another_cluster_pubsub_topic)

    def test_filter_subscribe_to_pubsub_topics_from_multiple_clusters(self):
        pubsub_topic_list = [self.test_pubsub_topic, self.another_cluster_pubsub_topic, self.second_pubsub_topic]
        failed_pubsub_topics = []
        for pubsub_topic in pubsub_topic_list:
            content_topic = pubsub_topic
            logger.debug(f"Running test with pubsub topic: {pubsub_topic}")
            try:
                self.wait_for_subscriptions_on_main_nodes([content_topic], pubsub_topic)
                message = self.create_message(contentTopic=content_topic)
                self.check_published_message_reaches_filter_peer(message, pubsub_topic=pubsub_topic)
            except Exception as ex:
                logger.error(f"PubsubTopic {pubsub_topic} failed: {str(ex)}")
                failed_pubsub_topics.append(pubsub_topic)
        assert not failed_pubsub_topics, f"PubsubTopics failed: {failed_pubsub_topics}"

    @pytest.mark.waku_test_fleet
    def test_filter_subscribe_to_100_content_topics_in_one_call(self):
        failed_content_topics = []
        _100_content_topics = [str(i) for i in range(100)]
        self.wait_for_subscriptions_on_main_nodes(_100_content_topics)
        for content_topic in _100_content_topics:
            message = self.create_message(contentTopic=content_topic)
            try:
                self.check_published_message_reaches_filter_peer(message)
            except Exception as ex:
                logger.error(f"ContentTopic {content_topic} failed: {str(ex)}")
                failed_content_topics.append(content_topic)
        assert not failed_content_topics, f"ContentTopics failed: {failed_content_topics}"

    def test_filter_subscribe_to_29_content_topics_in_separate_calls(self, subscribe_main_nodes):
        # subscribe_main_nodes already consumed 1 slot; make 29 more = 30 total, all must succeed
        _29_content_topics = [str(i) for i in range(29)]
        for content_topic in _29_content_topics:
            self.create_filter_subscription({"requestId": str(uuid4()), "contentFilters": [content_topic], "pubsubTopic": self.test_pubsub_topic})
        failed_content_topics = []
        for content_topic in _29_content_topics:
            logger.debug(f"Running test with content topic {content_topic}")
            message = self.create_message(contentTopic=content_topic)
            try:
                self.check_published_message_reaches_filter_peer(message)
            except Exception as ex:
                logger.error(f"ContentTopic {content_topic} failed: {str(ex)}")
                failed_content_topics.append(content_topic)
        assert not failed_content_topics, f"ContentTopics failed: {failed_content_topics}"
        # Rate limit is a token bucket (30/min); keep calling beyond 30 until one is denied
        rate_limited = False
        for extra in range(1, 20):
            try:
                self.create_filter_subscription(
                    {"requestId": str(uuid4()), "contentFilters": [f"extra_{extra}"], "pubsubTopic": self.test_pubsub_topic}
                )
                logger.debug(f"Extra subscribe call #{extra} succeeded")
            except Exception as ex:
                assert "subscription failed" in str(ex) or "rate limit exceeded" in str(ex), f"Unexpected error on extra call #{extra}: {ex}"
                logger.info(f"Rate limit hit on extra call #{extra}: {ex}")
                rate_limited = True
                break
        assert rate_limited, "Rate limit was not triggered on any call beyond 30"

    def test_filter_subscribe_to_101_content_topics(self, subscribe_main_nodes):
        try:
            _101_content_topics = [str(i) for i in range(101)]
            self.create_filter_subscription({"requestId": "1", "contentFilters": _101_content_topics, "pubsubTopic": self.test_pubsub_topic})
            raise AssertionError("Subscribe with more than 100 content topics worked!!!")
        except Exception as ex:
            assert "Bad Request" in str(ex)

    @pytest.mark.waku_test_fleet
    def test_filter_subscribe_refresh(self):
        for _ in range(2):
            self.wait_for_subscriptions_on_main_nodes([self.test_content_topic])
            self.check_published_message_reaches_filter_peer()

    def test_filter_subscribe_with_multiple_overlapping_content_topics(self):
        self.wait_for_subscriptions_on_main_nodes([input["value"] for input in SAMPLE_INPUTS[:3]])
        self.wait_for_subscriptions_on_main_nodes([input["value"] for input in SAMPLE_INPUTS[1:4]])
        for content_topic in SAMPLE_INPUTS[:4]:
            message = self.create_message(contentTopic=content_topic["value"])
            self.check_published_message_reaches_filter_peer(message)

    def test_filter_subscribe_with_no_pubsub_topic(self, subscribe_main_nodes):
        try:
            self.create_filter_subscription({"requestId": "1", "contentFilters": [self.test_content_topic]})
            # raise AssertionError("Subscribe with no pubusub topics worked!!!") commented until https://github.com/waku-org/nwaku/issues/2315 is fixed
        except Exception as ex:
            assert "Bad Request" in str(ex) or "timed out" in str(ex)

    def test_filter_subscribe_with_invalid_pubsub_topic_format(self, subscribe_main_nodes):
        try:
            self.create_filter_subscription({"requestId": "1", "contentFilters": [self.test_content_topic], "pubsubTopic": [self.test_pubsub_topic]})
            raise AssertionError("Subscribe with invalid pubusub topics worked!!!")
        except Exception as ex:
            assert "Bad Request" in str(ex)

    def test_filter_subscribe_with_no_content_topic(self, subscribe_main_nodes):
        try:
            self.create_filter_subscription({"requestId": "1", "pubsubTopic": self.test_pubsub_topic})
            if self.node2.is_nwaku():
                raise AssertionError("Subscribe with extra field worked!!!")
            else:
                raise NotImplementedError("Not implemented for this node type")
        except Exception as ex:
            assert "Bad Request" in str(ex)

    def test_filter_subscribe_with_invalid_content_topic_format(self, subscribe_main_nodes):
        success_content_topics = []
        for content_topic in INVALID_CONTENT_TOPICS:
            logger.debug(f'Running test with contetn topic {content_topic["description"]}')
            try:
                self.create_filter_subscription({"requestId": "1", "contentFilters": [content_topic], "pubsubTopic": self.test_pubsub_topic})
                success_content_topics.append(content_topic)
            except Exception as ex:
                assert "Bad Request" in str(ex) or "Internal Server Error" in str(ex)
        assert not success_content_topics, f"Invalid Content topics that didn't failed: {success_content_topics}"

    def test_filter_subscribe_with_no_request_id(self, subscribe_main_nodes):
        try:
            self.create_filter_subscription({"contentFilters": [self.test_content_topic], "pubsubTopic": self.test_pubsub_topic})
            raise AssertionError("Subscribe with no request id worked!!!")
        except Exception as ex:
            assert "Bad Request" in str(ex)

    def test_filter_subscribe_with_invalid_request_id(self, subscribe_main_nodes):
        try:
            self.create_filter_subscription({"requestId": 1, "contentFilters": [self.test_content_topic], "pubsubTopic": self.test_pubsub_topic})
            raise AssertionError("Subscribe with invalid request id worked!!!")
        except Exception as ex:
            assert "Bad Request" in str(ex)

    @pytest.mark.waku_test_fleet
    def test_filter_subscribe_with_extra_field(self, subscribe_main_nodes):
        try:
            self.create_filter_subscription(
                {"requestId": "1", "contentFilters": [self.test_content_topic], "pubsubTopic": self.test_pubsub_topic, "extraField": "extraValue"}
            )
            if self.node2.is_nwaku():
                raise AssertionError("Subscribe with extra field worked!!!")
            else:
                raise NotImplementedError("Not implemented for this node type")
        except Exception as ex:
            assert "Bad Request" in str(ex)
