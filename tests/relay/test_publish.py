import pytest
from src.env_vars import NODE_1, NODE_2
from src.libs.custom_logger import get_custom_logger
from time import time
from src.libs.common import delay, to_base64
from src.steps.relay import StepsRelay
from src.test_data import INVALID_CONTENT_TOPICS, INVALID_PAYLOADS, SAMPLE_INPUTS, SAMPLE_TIMESTAMPS, VALID_PUBSUB_TOPICS
from src.node.waku_message import WakuMessage

logger = get_custom_logger(__name__)


@pytest.mark.usefixtures("setup_main_relay_nodes", "subscribe_main_relay_nodes", "relay_warm_up")
class TestRelayPublish(StepsRelay):
    @pytest.mark.waku_test_fleet
    def test_publish_with_valid_payloads(self):
        failed_payloads = []
        for payload in SAMPLE_INPUTS:
            logger.debug(f'Running test with payload {payload["description"]}')
            message = self.create_message(payload=to_base64(payload["value"]))
            try:
                self.check_published_message_reaches_relay_peer(message)
            except Exception as e:
                logger.error(f'Payload {payload["description"]} failed: {str(e)}')
                failed_payloads.append(payload["description"])
        assert not failed_payloads, f"Payloads failed: {failed_payloads}"

    def test_publish_with_invalid_payloads(self):
        success_payloads = []
        for payload in INVALID_PAYLOADS:
            logger.debug(f'Running test with payload {payload["description"]}')
            message = self.create_message(payload=payload["value"])
            try:
                self.node1.send_relay_message(message, self.test_pubsub_topic)
                success_payloads.append(payload)
            except Exception as ex:
                assert "Bad Request" in str(ex) or "Internal Server Error" in str(ex)
        assert not success_payloads, f"Invalid Payloads that didn't failed: {success_payloads}"

    def test_publish_with_missing_payload(self):
        message = {"contentTopic": self.test_content_topic, "timestamp": int(time() * 1e9)}
        try:
            self.node1.send_relay_message(message, self.test_pubsub_topic)
            raise AssertionError("Publish with missing payload worked!!!")
        except Exception as ex:
            assert "Bad Request" in str(ex) or "Internal Server Error" in str(ex)

    @pytest.mark.waku_test_fleet
    def test_publish_with_payload_less_than_150_kb(self):
        payload_length = 1024 * 100  # after encoding to base64 this will be close to 150KB
        logger.debug(f"Running test with payload length of {payload_length} bytes")
        message = self.create_message(payload=to_base64("a" * (payload_length)))
        self.check_published_message_reaches_relay_peer(message, message_propagation_delay=2)

    def test_publish_with_payload_equal_or_more_150_kb(self):
        for payload_length in [1024 * 200, 1024 * 1024, 1024 * 1024 * 10]:
            logger.debug(f"Running test with payload length of {payload_length} bytes")
            message = self.create_message(payload=to_base64("a" * (payload_length)))
            try:
                self.check_published_message_reaches_relay_peer(message, message_propagation_delay=2)
                raise AssertionError("Message with payload > 1MB was received")
            except Exception as ex:
                assert "couldn't find any messages" in str(ex) or "Bad Request" in str(ex) or "Internal Server Error" in str(ex)

    @pytest.mark.waku_test_fleet
    def test_publish_with_valid_content_topics(self):
        failed_content_topics = []
        for content_topic in SAMPLE_INPUTS:
            logger.debug(f'Running test with content topic {content_topic["description"]}')
            message = self.create_message(contentTopic=content_topic["value"])
            try:
                self.check_published_message_reaches_relay_peer(message)
            except Exception as e:
                logger.error(f'ContentTopic {content_topic["description"]} failed: {str(e)}')
                failed_content_topics.append(content_topic)
        assert not failed_content_topics, f"ContentTopics failed: {failed_content_topics}"

    def test_publish_with_invalid_content_topics(self):
        success_content_topics = []
        for content_topic in INVALID_CONTENT_TOPICS:
            logger.debug(f'Running test with contetn topic {content_topic["description"]}')
            message = self.create_message(contentTopic=content_topic["value"])
            try:
                self.node1.send_relay_message(message, self.test_pubsub_topic)
                success_content_topics.append(content_topic)
            except Exception as ex:
                assert "Bad Request" in str(ex) or "Internal Server Error" in str(ex)
        assert not success_content_topics, f"Invalid Content topics that didn't failed: {success_content_topics}"

    def test_publish_with_missing_content_topic(self):
        message = {"payload": to_base64(self.test_payload), "timestamp": int(time() * 1e9)}
        try:
            self.node1.send_relay_message(message, self.test_pubsub_topic)
            raise AssertionError("Publish with missing content_topic worked!!!")
        except Exception as ex:
            assert "Bad Request" in str(ex) or "Internal Server Error" in str(ex)

    @pytest.mark.waku_test_fleet
    def test_publish_on_multiple_pubsub_topics(self):
        self.ensure_relay_subscriptions_on_nodes(self.main_nodes, VALID_PUBSUB_TOPICS)
        failed_pubsub_topics = []
        for pubsub_topic in VALID_PUBSUB_TOPICS:
            logger.debug(f"Running test with pubsub topic {pubsub_topic}")
            try:
                self.check_published_message_reaches_relay_peer(pubsub_topic=pubsub_topic)
            except Exception as e:
                logger.error(f"PubusubTopic {pubsub_topic} failed: {str(e)}")
                failed_pubsub_topics.append(pubsub_topic)
        assert not failed_pubsub_topics, f"PubusubTopic failed: {failed_pubsub_topics}"

    def test_message_published_on_different_pubsub_topic_is_not_retrieved(self):
        self.ensure_relay_subscriptions_on_nodes(self.main_nodes, VALID_PUBSUB_TOPICS)
        self.node1.send_relay_message(self.create_message(), VALID_PUBSUB_TOPICS[0])
        delay(0.1)
        messages = self.node2.get_relay_messages(VALID_PUBSUB_TOPICS[1])
        assert not messages, "Message was retrieved on wrong pubsub_topic"

    def test_publish_on_non_subscribed_pubsub_topic(self):
        try:
            self.check_published_message_reaches_relay_peer(pubsub_topic=VALID_PUBSUB_TOPICS[4])
            raise AssertionError("Publish on unsubscribed pubsub_topic worked!!!")
        except Exception as ex:
            assert "Bad Request" in str(ex) or "Internal Server Error" in str(ex)

    @pytest.mark.waku_test_fleet
    def test_publish_with_valid_timestamps(self):
        failed_timestamps = []
        for timestamp in SAMPLE_TIMESTAMPS:
            if self.node1.type() in timestamp["valid_for"]:
                logger.debug(f'Running test with timestamp {timestamp["description"]}')
                message = self.create_message(timestamp=timestamp["value"])
                try:
                    self.check_published_message_reaches_relay_peer(message)
                except Exception as ex:
                    logger.error(f'Timestamp {timestamp["description"]} failed: {str(ex)}')
                    failed_timestamps.append(timestamp)
        assert not failed_timestamps, f"Timestamps failed: {failed_timestamps}"

    def test_publish_with_invalid_timestamps(self):
        success_timestamps = []
        for timestamp in SAMPLE_TIMESTAMPS:
            if self.node1.type() not in timestamp["valid_for"]:
                logger.debug(f'Running test with timestamp {timestamp["description"]}')
                message = self.create_message(timestamp=timestamp["value"])
                try:
                    self.check_published_message_reaches_relay_peer(message)
                    success_timestamps.append(timestamp)
                except Exception as e:
                    pass
        assert not success_timestamps, f"Invalid Timestamps that didn't failed: {success_timestamps}"

    @pytest.mark.waku_test_fleet
    def test_publish_with_no_timestamp(self):
        message = {"payload": to_base64(self.test_payload), "contentTopic": self.test_content_topic}
        self.check_published_message_reaches_relay_peer(message)

    @pytest.mark.waku_test_fleet
    def test_publish_with_valid_version(self):
        self.check_published_message_reaches_relay_peer(self.create_message(version=10))

    def test_publish_with_invalid_version(self):
        try:
            self.check_published_message_reaches_relay_peer(self.create_message(version=2.1))
            raise AssertionError("Publish with invalid version worked!!!")
        except Exception as ex:
            assert "Bad Request" in str(ex)

    def test_publish_with_valid_meta(self):
        self.check_published_message_reaches_relay_peer(self.create_message(meta=to_base64(self.test_payload)))

    def test_publish_with_invalid_meta(self):
        try:
            self.check_published_message_reaches_relay_peer(self.create_message(meta=self.test_payload))
            raise AssertionError("Publish with invalid meta worked!!!")
        except Exception as ex:
            assert "Bad Request" in str(ex)

    @pytest.mark.waku_test_fleet
    def test_publish_with_ephemeral(self):
        failed_ephemeral = []
        for ephemeral in [True, False]:
            logger.debug(f"Running test with Ephemeral {ephemeral}")
            try:
                self.check_published_message_reaches_relay_peer(self.create_message(ephemeral=ephemeral))
            except Exception as e:
                logger.error(f"Massage with Ephemeral {ephemeral} failed: {str(e)}")
                failed_ephemeral.append(ephemeral)
        assert not failed_ephemeral, f"Ephemeral that failed: {failed_ephemeral}"

    def test_publish_with_extra_field(self):
        try:
            self.check_published_message_reaches_relay_peer(self.create_message(extraField="extraValue"))
            if self.node1.is_nwaku():
                raise AssertionError("Relay publish with extra field worked!!!")
            else:
                raise NotImplementedError("Not implemented for this node type")
        except Exception as ex:
            assert "Bad Request" in str(ex)

    def test_publish_and_retrieve_duplicate_message(self):
        message = self.create_message()
        self.check_published_message_reaches_relay_peer(message)
        try:
            self.check_published_message_reaches_relay_peer(message)
            raise AssertionError("Duplicate message was retrieved twice")
        except Exception as ex:
            assert "couldn't find any messages" in str(ex)

    def test_publish_while_peer_is_paused(self):
        message = self.create_message()
        self.node2.pause()
        self.node1.send_relay_message(message, self.test_pubsub_topic)
        self.node2.unpause()
        get_messages_response = self.node2.get_relay_messages(self.test_pubsub_topic)
        assert get_messages_response, "Peer node couldn't find any messages"
        waku_message = WakuMessage(get_messages_response)
        waku_message.assert_received_message(message)

    def test_publish_after_node_pauses_and_pauses(self):
        self.check_published_message_reaches_relay_peer()
        self.node1.pause()
        self.node1.unpause()
        self.check_published_message_reaches_relay_peer(self.create_message(payload=to_base64("M1")))
        self.node2.pause()
        self.node2.unpause()
        self.check_published_message_reaches_relay_peer(self.create_message(payload=to_base64("M2")))

    @pytest.mark.flaky(reruns=5)
    def test_publish_after_node1_restarts(self):
        self.check_published_message_reaches_relay_peer()
        self.node1.restart()
        self.node1.ensure_ready()
        self.subscribe_and_publish_with_retry(self.main_nodes, [self.test_pubsub_topic])

    def test_publish_after_node2_restarts(self):
        self.check_published_message_reaches_relay_peer()
        self.node2.restart()
        self.node2.ensure_ready()
        self.ensure_relay_subscriptions_on_nodes(self.main_nodes, [self.test_pubsub_topic])
        self.wait_for_published_message_to_reach_relay_peer()

    @pytest.mark.skip(reason="waiting for https://github.com/waku-org/nwaku/issues/3444 resolution")
    @pytest.mark.flaky(reruns=5)
    def test_publish_and_retrieve_100_messages(self):
        num_messages = 100  # if increase this number make sure to also increase rest-relay-cache-capacity flag
        for index in range(num_messages):
            message = self.create_message(payload=to_base64(f"M_{index}"))
            self.node1.send_relay_message(message, self.test_pubsub_topic)
        delay(1)
        messages = self.node2.get_relay_messages(self.test_pubsub_topic)
        assert len(messages) == num_messages
        for index, message in enumerate(messages):
            assert message["payload"] == to_base64(
                f"M_{index}"
            ), f'Incorrect payload at index: {index}. Published {to_base64(f"M_{index}")} Received {message["payload"]}'
