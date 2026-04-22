import pytest
from src.env_vars import NODE_1, NODE_2
from src.libs.common import delay, to_base64
from src.libs.custom_logger import get_custom_logger
from src.test_data import SAMPLE_INPUTS, SAMPLE_TIMESTAMPS
from src.steps.filter import StepsFilter

logger = get_custom_logger(__name__)


# here we will also implicitly test filter push, see: https://rfc.vac.dev/spec/12/#messagepush
@pytest.mark.usefixtures("setup_main_relay_node", "setup_main_filter_node", "subscribe_main_nodes")
class TestFilterGetMessages(StepsFilter):
    @pytest.mark.smoke
    @pytest.mark.waku_test_fleet
    def test_filter_get_message_with_valid_payloads(self):
        failed_payloads = []
        for payload in SAMPLE_INPUTS:
            logger.debug(f'Running test with payload {payload["description"]}')
            message = self.create_message(payload=to_base64(payload["value"]))
            try:
                self.check_published_message_reaches_filter_peer(message)
            except Exception as e:
                logger.error(f'Payload {payload["description"]} failed: {str(e)}')
                failed_payloads.append(payload["description"])
        assert not failed_payloads, f"Payloads failed: {failed_payloads}"

    @pytest.mark.waku_test_fleet
    def test_filter_get_message_with_valid_timestamps(self):
        failed_timestamps = []
        for timestamp in SAMPLE_TIMESTAMPS:
            if self.node1.type() in timestamp["valid_for"]:
                logger.debug(f'Running test with timestamp {timestamp["description"]}')
                message = self.create_message(timestamp=timestamp["value"])
                try:
                    self.check_published_message_reaches_filter_peer(message)
                except Exception as ex:
                    logger.error(f'Timestamp {timestamp["description"]} failed: {str(ex)}')
                    failed_timestamps.append(timestamp)
        assert not failed_timestamps, f"Timestamps failed: {failed_timestamps}"

    @pytest.mark.waku_test_fleet
    def test_filter_get_message_with_version(self):
        self.check_published_message_reaches_filter_peer(self.create_message(version=10))

    @pytest.mark.waku_test_fleet
    def test_filter_get_message_with_meta(self):
        self.check_published_message_reaches_filter_peer(self.create_message(meta=to_base64(self.test_payload)))

    @pytest.mark.waku_test_fleet
    def test_filter_get_message_with_ephemeral(self):
        failed_ephemeral = []
        for ephemeral in [True, False]:
            logger.debug(f"Running test with Ephemeral {ephemeral}")
            try:
                self.check_published_message_reaches_filter_peer(self.create_message(ephemeral=ephemeral))
            except Exception as e:
                logger.error(f"Massage with Ephemeral {ephemeral} failed: {str(e)}")
                failed_ephemeral.append(ephemeral)
        assert not failed_ephemeral, f"Ephemeral that failed: {failed_ephemeral}"

    @pytest.mark.waku_test_fleet
    def test_filter_get_message_with_extra_field(self):
        try:
            self.check_published_message_reaches_filter_peer(self.create_message(extraField="extraValue"))
            if self.node1.is_nwaku():
                raise AssertionError("Relay publish with extra field worked!!!")
            else:
                raise NotImplementedError("Not implemented for this node type")
        except Exception as ex:
            assert "Bad Request" in str(ex)

    def test_filter_get_message_duplicate_message(self):
        message = self.create_message()
        self.check_published_message_reaches_filter_peer(message)
        try:
            self.check_published_message_reaches_filter_peer(message)
            raise AssertionError("Duplicate message was retrieved twice")
        except Exception as ex:
            assert "couldn't find any messages" in str(ex)

    def test_filter_get_message_after_node_pauses_and_pauses(self):
        self.check_published_message_reaches_filter_peer()
        self.node1.pause()
        self.node1.unpause()
        self.check_published_message_reaches_filter_peer(self.create_message(payload=to_base64("M1")))
        self.node2.pause()
        self.node2.unpause()
        self.check_published_message_reaches_filter_peer(self.create_message(payload=to_base64("M2")))

    def test_filter_get_message_after_node1_restarts(self):
        self.check_published_message_reaches_filter_peer()
        self.node1.restart()
        self.node1.ensure_ready()
        delay(2)
        self.wait_for_subscriptions_on_main_nodes([self.test_content_topic])
        self.check_published_message_reaches_filter_peer()

    def test_filter_get_message_after_node2_restarts(self):
        self.check_published_message_reaches_filter_peer()
        self.node2.restart()
        self.node2.ensure_ready()
        delay(2)
        self.wait_for_subscriptions_on_main_nodes([self.test_content_topic])
        self.check_published_message_reaches_filter_peer()

    @pytest.mark.flaky(reruns=5)
    def test_filter_get_50_messages(self):
        num_messages = 50
        for index in range(num_messages):
            message = self.create_message(payload=to_base64(f"M_{index}"))
            self.node1.send_relay_message(message, self.test_pubsub_topic)
            delay(0.01)
        delay(1)
        filter_messages = self.get_filter_messages(content_topic=self.test_content_topic, pubsub_topic=self.test_pubsub_topic, node=self.node2)
        assert len(filter_messages) == num_messages
        for index, message in enumerate(filter_messages):
            assert message["payload"] == to_base64(
                f"M_{index}"
            ), f'Incorrect payload at index: {index}. Published {to_base64(f"M_{index}")} Received {message["payload"]}'

    def test_filter_get_message_with_150_kb_payload(self):
        payload_length = 1024 * 100  # after encoding to base64 this will be close to 150KB
        message = self.create_message(payload=to_base64("a" * (payload_length)))
        self.check_published_message_reaches_filter_peer(message, message_propagation_delay=2)
