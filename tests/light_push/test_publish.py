import pytest

from src.libs.custom_logger import get_custom_logger
from time import time
from src.libs.common import delay, to_base64
from src.steps.light_push import StepsLightPush
from src.test_data import (
    INVALID_CONTENT_TOPICS,
    INVALID_PAYLOADS,
    PUBSUB_TOPICS_WRONG_FORMAT,
    SAMPLE_INPUTS,
    SAMPLE_TIMESTAMPS,
    VALID_PUBSUB_TOPICS,
    get_sample_timestamps,
)

logger = get_custom_logger(__name__)


class TestLightPushPublish(StepsLightPush):
    @pytest.fixture(scope="function", autouse=True)
    def light_push_publish_setup(self, light_push_setup):
        self.setup_first_receiving_node()
        self.setup_second_receiving_node(lightpush="false", relay="true")
        self.setup_first_lightpush_node()
        self.subscribe_to_pubsub_topics_via_relay()

    @pytest.mark.waku_test_fleet
    def test_light_push_with_valid_payloads(self):
        failed_payloads = []
        for payload in SAMPLE_INPUTS:
            logger.debug(f'Running test with payload {payload["description"]}')
            message = self.create_message(payload=to_base64(payload["value"]))
            try:
                self.check_light_pushed_message_reaches_receiving_peer(message=message)
            except Exception as e:
                logger.error(f'Payload {payload["description"]} failed: {str(e)}')
                failed_payloads.append(payload["description"])
        assert not failed_payloads, f"Payloads failed: {failed_payloads}"

    def test_light_push_with_invalid_payloads(self):
        success_payloads = []
        for payload in INVALID_PAYLOADS:
            logger.debug(f'Running test with payload {payload["description"]}')
            payload = self.create_payload(message=self.create_message(payload=payload["value"]))
            try:
                self.light_push_node1.send_light_push_message(payload)
                success_payloads.append(payload)
            except Exception as ex:
                assert "Bad Request" in str(ex) or "missing Payload field" in str(ex)
        assert not success_payloads, f"Invalid Payloads that didn't failed: {success_payloads}"

    def test_light_push_with_missing_payload(self):
        message = {"contentTopic": self.test_content_topic, "timestamp": int(time() * 1e9)}
        try:
            self.light_push_node1.send_light_push_message(self.create_payload(message=message))
            raise AssertionError("Light push with missing payload worked!!!")
        except Exception as ex:
            assert "Bad Request" in str(ex) or "missing Payload field" in str(ex)

    def test_light_push_with_payload_less_than_150_kb(self):
        payload_length = 1024 * 140
        logger.debug(f"Running test with payload length of {payload_length} bytes")
        message = self.create_message(payload=to_base64("a" * (payload_length)))
        self.check_light_pushed_message_reaches_receiving_peer(message=message)

    def test_light_push_with_payload_of_150_kb(self):
        payload_length = 1024 * 150
        logger.debug(f"Running test with payload length of {payload_length} bytes")
        message = self.create_message(payload=to_base64("a" * (payload_length)))
        try:
            self.check_light_pushed_message_reaches_receiving_peer(message=message, message_propagation_delay=2)
            raise AssertionError("Message with payload of 150kb was received")
        except Exception as ex:
            assert "Message size exceeded maximum of 153600 bytes" in str(ex)

    def test_light_push_with_payload_of_1_MB(self):
        payload_length = 1024 * 1024
        logger.debug(f"Running test with payload length of {payload_length} bytes")
        message = self.create_message(payload=to_base64("a" * (payload_length)))
        try:
            self.check_light_pushed_message_reaches_receiving_peer(message=message, message_propagation_delay=2)
            raise AssertionError("Message with payload > 1MB was received")
        except Exception as ex:
            assert "Message size exceeded maximum of 153600 bytes" in str(ex)

    @pytest.mark.waku_test_fleet
    def test_light_push_with_valid_content_topics(self):
        failed_content_topics = []
        for content_topic in SAMPLE_INPUTS:
            logger.debug(f'Running test with content topic {content_topic["description"]}')
            message = self.create_message(contentTopic=content_topic["value"])
            try:
                self.check_light_pushed_message_reaches_receiving_peer(message=message)
            except Exception as e:
                logger.error(f'ContentTopic {content_topic["description"]} failed: {str(e)}')
                failed_content_topics.append(content_topic)
        assert not failed_content_topics, f"ContentTopics failed: {failed_content_topics}"

    def test_light_push_with_invalid_content_topics(self):
        success_content_topics = []
        for content_topic in INVALID_CONTENT_TOPICS:
            logger.debug(f'Running test with contetn topic {content_topic["description"]}')
            message = self.create_message(contentTopic=content_topic["value"])
            try:
                self.check_light_pushed_message_reaches_receiving_peer(message=message)
                success_content_topics.append(content_topic)
            except Exception as ex:
                assert "Bad Request" in str(ex) or "missing ContentTopic field" in str(ex)
        assert not success_content_topics, f"Invalid Content topics that didn't failed: {success_content_topics}"

    def test_light_push_with_missing_content_topic(self):
        message = {"payload": to_base64(self.test_payload), "timestamp": int(time() * 1e9)}
        try:
            self.light_push_node1.send_light_push_message(self.create_payload(message=message))
            raise AssertionError("Light push with missing content_topic worked!!!")
        except Exception as ex:
            assert "Bad Request" in str(ex) or "missing ContentTopic field" in str(ex)

    def test_light_push_on_multiple_pubsub_topics(self):
        self.subscribe_to_pubsub_topics_via_relay(pubsub_topics=VALID_PUBSUB_TOPICS)
        failed_pubsub_topics = []
        for pubsub_topic in VALID_PUBSUB_TOPICS:
            logger.debug(f"Running test with pubsub topic {pubsub_topic}")
            try:
                self.check_light_pushed_message_reaches_receiving_peer(pubsub_topic=pubsub_topic)
            except Exception as e:
                logger.error(f"PubusubTopic {pubsub_topic} failed: {str(e)}")
                failed_pubsub_topics.append(pubsub_topic)
        assert not failed_pubsub_topics, f"PubusubTopic failed: {failed_pubsub_topics}"

    def test_message_light_pushed_on_different_pubsub_topic_is_not_retrieved(self):
        self.subscribe_to_pubsub_topics_via_relay(pubsub_topics=VALID_PUBSUB_TOPICS)
        payload = self.create_payload(pubsub_topic=VALID_PUBSUB_TOPICS[0])
        self.light_push_node1.send_light_push_message(payload)
        delay(0.1)
        messages = self.receiving_node1.get_relay_messages(VALID_PUBSUB_TOPICS[1])
        assert not messages, "Message was retrieved on wrong pubsub_topic"

    def test_light_push_on_non_subscribed_pubsub_topic(self):
        try:
            self.check_light_pushed_message_reaches_receiving_peer(pubsub_topic=VALID_PUBSUB_TOPICS[1])
            raise AssertionError("Light push on unsubscribed pubsub_topic worked!!!")
        except Exception as ex:
            assert "not_published_to_any_peer" in str(ex)

    def test_light_push_with_invalid_pubsub_topics(self):
        success_content_topics = []
        for pubsub_topic in PUBSUB_TOPICS_WRONG_FORMAT:
            logger.debug(f"Running test with pubsub topic {pubsub_topic}")
            try:
                self.check_light_pushed_message_reaches_receiving_peer(pubsub_topic=pubsub_topic["value"])
                success_content_topics.append(pubsub_topic)
            except Exception as ex:
                assert "Bad Request" in str(ex)
        assert not success_content_topics, f"Invalid Content topics that didn't failed: {success_content_topics}"

    def test_light_push_with_missing_pubsub_topics(self):
        try:
            self.light_push_node1.send_light_push_message({"message": self.create_message()})
        except Exception as ex:
            assert "not_published_to_any_peer" in str(ex) or "timeout" in str(ex)

    @pytest.mark.waku_test_fleet
    def test_light_push_with_valid_timestamps(self):
        failed_timestamps = []
        for timestamp in get_sample_timestamps():
            if self.light_push_node1.type() in timestamp["valid_for"]:
                logger.debug(f'Running test with timestamp {timestamp["description"]}')
                message = self.create_message(timestamp=timestamp["value"])
                try:
                    self.check_light_pushed_message_reaches_receiving_peer(message=message)
                except Exception as ex:
                    logger.error(f'Timestamp {timestamp["description"]} failed: {str(ex)}')
                    failed_timestamps.append(timestamp)
        assert not failed_timestamps, f"Timestamps failed: {failed_timestamps}"

    def test_light_push_with_invalid_timestamps(self):
        success_timestamps = []
        for timestamp in SAMPLE_TIMESTAMPS:
            if self.light_push_node1.type() not in timestamp["valid_for"]:
                logger.debug(f'Running test with timestamp {timestamp["description"]}')
                message = self.create_message(timestamp=timestamp["value"])
                try:
                    self.check_light_pushed_message_reaches_receiving_peer(message=message)
                    success_timestamps.append(timestamp)
                except Exception as e:
                    pass
        assert not success_timestamps, f"Invalid Timestamps that didn't failed: {success_timestamps}"

    def test_light_push_with_no_timestamp(self):
        message = {"payload": to_base64(self.test_payload), "contentTopic": self.test_content_topic}
        self.check_light_pushed_message_reaches_receiving_peer(message=message)

    def test_light_push_with_valid_version(self):
        self.check_light_pushed_message_reaches_receiving_peer(message=self.create_message(version=10))

    def test_light_push_with_invalid_version(self):
        try:
            self.check_light_pushed_message_reaches_receiving_peer(message=self.create_message(version=2.1))
            raise AssertionError("Light push with invalid version worked!!!")
        except Exception as ex:
            assert "Bad Request" in str(ex)

    @pytest.mark.waku_test_fleet
    def test_light_push_with_valid_meta(self):
        self.check_light_pushed_message_reaches_receiving_peer(message=self.create_message(meta=to_base64(self.test_payload)))

    def test_light_push_with_invalid_meta(self):
        try:
            self.check_light_pushed_message_reaches_receiving_peer(message=self.create_message(meta=self.test_payload))
            raise AssertionError("Light push with invalid meta worked!!!")
        except Exception as ex:
            assert "Bad Request" in str(ex)

    def test_light_push_with_with_large_meta(self):
        meta_l = 1024 * 1
        try:
            self.check_light_pushed_message_reaches_receiving_peer(message=self.create_message(meta=to_base64("a" * (meta_l))))
        except Exception as ex:
            assert '(kind: InvalidLengthField, field: "meta")' in str(ex) or "invalid length for Meta field" in str(ex)

    @pytest.mark.waku_test_fleet
    def test_light_push_with_ephemeral(self):
        failed_ephemeral = []
        for ephemeral in [True, False]:
            logger.debug(f"Running test with Ephemeral {ephemeral}")
            try:
                self.check_light_pushed_message_reaches_receiving_peer(message=self.create_message(ephemeral=ephemeral))
            except Exception as e:
                logger.error(f"Light push message with Ephemeral {ephemeral} failed: {str(e)}")
                failed_ephemeral.append(ephemeral)
        assert not failed_ephemeral, f"Ephemeral that failed: {failed_ephemeral}"

    @pytest.mark.waku_test_fleet
    def test_light_push_with_extra_field(self):
        try:
            self.check_light_pushed_message_reaches_receiving_peer(message=self.create_message(extraField="extraValue"))
            if self.light_push_node1.is_nwaku():
                raise AssertionError("Relay publish with extra field worked!!!")
            else:
                raise NotImplementedError("Not implemented for this node type")
        except Exception as ex:
            assert "Bad Request" in str(ex)

    def test_light_push_and_retrieve_duplicate_message(self):
        message = self.create_message()
        self.check_light_pushed_message_reaches_receiving_peer(message=message)
        try:
            self.check_light_pushed_message_reaches_receiving_peer(message=message)
        except Exception as ex:
            assert "not_published_to_any_peer" in str(ex)

    def test_light_push_while_peer_is_paused(self):
        message = self.create_message()
        self.receiving_node1.stop()
        try:
            self.light_push_node1.send_light_push_message(self.create_payload(message=message))
            raise AssertionError("Push with peer stopped worked!!")
        except Exception as ex:
            assert "Failed to request a message push: dial_failure" in str(ex) or "lightpush error" in str(ex)

    def test_light_push_after_node_pauses_and_pauses(self):
        self.check_light_pushed_message_reaches_receiving_peer()
        self.light_push_node1.pause()
        self.light_push_node1.unpause()
        self.check_light_pushed_message_reaches_receiving_peer()
        self.receiving_node1.pause()
        self.receiving_node1.unpause()
        self.check_light_pushed_message_reaches_receiving_peer()

    def test_light_push_after_light_push_node_restarts(self):
        self.check_light_pushed_message_reaches_receiving_peer()
        self.light_push_node1.restart()
        self.light_push_node1.ensure_ready()
        self.check_light_pushed_message_reaches_receiving_peer()

    def test_light_push_after_receiving_node_restarts(self):
        self.check_light_pushed_message_reaches_receiving_peer()
        self.receiving_node1.restart()
        self.receiving_node1.ensure_ready()
        self.subscribe_and_light_push_with_retry()

    @pytest.mark.skip(reason="waiting for https://github.com/waku-org/nwaku/issues/3444 resolution")
    def test_light_push_and_retrieve_100_messages(self):
        num_messages = 100  # if increase this number make sure to also increase rest-relay-cache-capacity flag
        for index in range(num_messages):
            message = self.create_message(payload=to_base64(f"M_{index}"))
            self.light_push_node1.send_light_push_message(self.create_payload(message=message))
        delay(1)
        messages = self.receiving_node1.get_relay_messages(self.test_pubsub_topic)
        assert len(messages) == num_messages
        for index, message in enumerate(messages):
            assert message["payload"] == to_base64(
                f"M_{index}"
            ), f'Incorrect payload at index: {index}. Published {to_base64(f"M_{index}")} Received {message["payload"]}'
