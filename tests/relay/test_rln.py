import math
import random
from time import time
import pytest

from src.env_vars import NODE_1, NODE_2, ADDITIONAL_NODES
from src.libs.common import delay, to_base64
from src.libs.custom_logger import get_custom_logger
from src.steps.relay import StepsRelay
from src.steps.rln import StepsRLN
from src.test_data import SAMPLE_INPUTS

logger = get_custom_logger(__name__)


@pytest.mark.xdist_group(name="RLN serial tests")
class TestRelayRLN(StepsRLN, StepsRelay):
    SAMPLE_INPUTS_RLN = SAMPLE_INPUTS + SAMPLE_INPUTS + SAMPLE_INPUTS

    @pytest.mark.smoke
    def test_valid_payloads_lightpush_at_spam_rate(self, pytestconfig):
        message_limit = 1
        epoch_sec = 1
        rln_state = self.register_rln_relay_nodes(2, [])
        pytestconfig.cache.set(
            "keystore-prefixes",
            {
                "keystore_prefixes": rln_state["keystore_prefixes"],
                "rln_membership_indexes": rln_state["rln_membership_indexes"],
            },
        )
        self.setup_first_rln_relay_node(lightpush="true", rln_relay_user_message_limit=message_limit, rln_relay_epoch_sec=epoch_sec)
        self.setup_second_rln_lightpush_node(rln_relay_user_message_limit=message_limit, rln_relay_epoch_sec=epoch_sec)
        self.subscribe_main_relay_nodes()
        start = math.trunc(time())
        for i, payload in enumerate(SAMPLE_INPUTS[:5]):
            logger.debug(f'Running test with payload {payload["description"]}')
            message = self.create_message(payload=to_base64(payload["value"]))
            try:
                logger.debug(f"Sending message No. #{i + 1}")
                now = math.trunc(time())
                self.publish_message(message=message, sender=self.light_push_node2, use_lightpush=True)
                if i > message_limit and (now - start) <= epoch_sec:
                    raise AssertionError("Publish with RLN enabled at spam rate worked!!!")
            except Exception as e:
                error_str = str(e)
                assert "RLN validation failed" in error_str or "NonceLimitReached" in error_str
                if "NonceLimitReached" in error_str:
                    assert "503" in error_str, f"Expected HTTP 503 for NonceLimitReached, got: {error_str}"

    def test_valid_payloads_at_slow_rate(self, pytestconfig):
        message_limit = 20
        rln_state = self.register_rln_relay_nodes(2, [])
        pytestconfig.cache.set(
            "keystore-prefixes",
            {
                "keystore_prefixes": rln_state["keystore_prefixes"],
                "rln_membership_indexes": rln_state["rln_membership_indexes"],
            },
        )
        self.setup_main_rln_relay_nodes(rln_relay_user_message_limit=message_limit, rln_relay_epoch_sec=600)
        self.subscribe_main_relay_nodes()
        failed_payloads = []
        for i, payload in enumerate(self.SAMPLE_INPUTS_RLN):
            logger.debug(f'Running test with payload {payload["description"]}')
            message = self.create_message(payload=to_base64(payload["value"]))
            try:
                logger.debug(f"Sending message No. #{i + 1}")
                self.check_published_message_reaches_relay_peer(message, message_propagation_delay=0.2)
            except Exception as e:
                logger.error(f'Payload {payload["description"]} failed: {str(e)}')
                failed_payloads.append(payload["description"])
            delay(1)
            assert not failed_payloads, f"Payloads failed: {failed_payloads}"
            if i == message_limit - 1:
                break

    @pytest.mark.smoke
    def test_valid_payloads_at_spam_rate(self, pytestconfig):
        message_limit = 20
        epoch_sec = 600
        self.register_rln_relay_nodes(
            0,
            pytestconfig.cache.get("keystore-prefixes", {"keystore_prefixes": [], "rln_membership_indexes": []}),
        )
        self.setup_main_rln_relay_nodes(rln_relay_user_message_limit=message_limit, rln_relay_epoch_sec=epoch_sec)
        self.subscribe_main_relay_nodes()
        start = math.trunc(time())
        for i, payload in enumerate(self.SAMPLE_INPUTS_RLN):
            logger.debug(f'Running test with payload {payload["description"]}')
            message = self.create_message(payload=to_base64(payload["value"]))
            try:
                logger.debug(f"Sending message No. #{i + 1}")
                now = math.trunc(time())
                self.publish_message(message)
                if i > message_limit and (now - start) <= epoch_sec:
                    raise AssertionError("Publish with RLN enabled at spam rate worked!!!")
            except Exception as e:
                error_str = str(e)
                assert "RLN validation failed" in error_str or "NonceLimitReached" in error_str
                if "NonceLimitReached" in error_str:
                    assert "500" in error_str, f"Expected HTTP 500 for NonceLimitReached, got: {error_str}"

    def test_valid_payload_at_variable_rate(self, pytestconfig):
        self.register_rln_relay_nodes(
            0,
            pytestconfig.cache.get("keystore-prefixes", {"keystore_prefixes": [], "rln_membership_indexes": []}),
        )
        self.setup_main_rln_relay_nodes(rln_relay_user_message_limit=1, rln_relay_epoch_sec=1)
        self.subscribe_main_relay_nodes()
        payload_desc = SAMPLE_INPUTS[0]["description"]
        payload = to_base64(SAMPLE_INPUTS[0]["value"])
        previous = math.trunc(time())
        for i in range(0, 10):
            logger.debug(f"Running test with payload {payload_desc}")
            message = self.create_message(payload=payload)
            try:
                if i % 2 == 1:  # every odd iteration is sent slowly
                    delay(1 + 1)
                now = math.trunc(time())
                logger.debug(f"Message sent at timestamp {now}")
                logger.debug(f"Sending message No. #{i + 1}")
                self.publish_message(message)
                if i > 0 and (now - previous) == 0:
                    raise AssertionError("Publish with RLN enabled at spam rate worked!!!")
                else:
                    previous = now
            except Exception as e:
                error_str = str(e)
                assert "RLN validation failed" in error_str or "NonceLimitReached" in error_str
                if "NonceLimitReached" in error_str:
                    assert "500" in error_str, f"Expected HTTP 500 for NonceLimitReached, got: {error_str}"

    def test_valid_payloads_random_epoch_at_slow_rate(self, pytestconfig):
        epoch_sec = random.randint(2, 5)
        self.register_rln_relay_nodes(
            0,
            pytestconfig.cache.get("keystore-prefixes", {"keystore_prefixes": [], "rln_membership_indexes": []}),
        )
        self.setup_main_rln_relay_nodes(rln_relay_user_message_limit=1, rln_relay_epoch_sec=epoch_sec)
        self.subscribe_main_relay_nodes()
        failed_payloads = []
        for payload in SAMPLE_INPUTS[:5]:
            logger.debug(f'Running test with payload {payload["description"]}')
            message = self.create_message(payload=to_base64(payload["value"]))
            try:
                self.check_published_message_reaches_relay_peer(message, message_propagation_delay=0.2)
            except Exception as e:
                logger.error(f'Payload {payload["description"]} failed: {str(e)}')
                failed_payloads.append(payload["description"])
            delay(epoch_sec)
            assert not failed_payloads, f"Payloads failed: {failed_payloads}"

    def test_valid_payloads_random_user_message_limit(self, pytestconfig):
        user_message_limit = random.randint(2, 4)
        self.register_rln_relay_nodes(
            0,
            pytestconfig.cache.get("keystore-prefixes", {"keystore_prefixes": [], "rln_membership_indexes": []}),
        )
        self.setup_main_rln_relay_nodes(rln_relay_user_message_limit=user_message_limit, rln_relay_epoch_sec=1)
        self.subscribe_main_relay_nodes()
        failed_payloads = []
        for payload in SAMPLE_INPUTS[:user_message_limit]:
            logger.debug(f'Running test with payload {payload["description"]}')
            message = self.create_message(payload=to_base64(payload["value"]))
            try:
                self.publish_message(message)
            except Exception as e:
                logger.error(f'Payload {payload["description"]} failed: {str(e)}')
                failed_payloads.append(payload["description"])
            assert not failed_payloads, f"Payloads failed: {failed_payloads}"

    @pytest.mark.timeout(600)
    def test_valid_payloads_dynamic_at_spam_rate(self, pytestconfig):
        message_limit = 100
        epoch_sec = 600
        rln_state = self.register_rln_relay_nodes(2, [])
        pytestconfig.cache.set(
            "keystore-prefixes",
            {
                "keystore_prefixes": rln_state["keystore_prefixes"],
                "rln_membership_indexes": rln_state["rln_membership_indexes"],
            },
        )
        self.setup_main_rln_relay_nodes(
            rln_relay_user_message_limit=message_limit,
            rln_relay_epoch_sec=epoch_sec,
            rln_relay_dynamic="true",
            wait_for_node_sec=600,
        )
        self.subscribe_main_relay_nodes()
        start = math.trunc(time())
        for i, payload in enumerate(self.SAMPLE_INPUTS_RLN):
            logger.debug(f'Running test with payload {payload["description"]}')
            message = self.create_message(payload=to_base64(payload["value"]))
            try:
                logger.debug(f"Sending message No. #{i + 1}")
                now = math.trunc(time())
                self.publish_message(message)
                if i > message_limit and (now - start) <= epoch_sec:
                    raise AssertionError("Publish with RLN enabled at spam rate worked!!!")
            except Exception as e:
                error_str = str(e)
                assert "RLN validation failed" in error_str or "NonceLimitReached" in error_str
                if "NonceLimitReached" in error_str:
                    assert "500" in error_str, f"Expected HTTP 500 for NonceLimitReached, got: {error_str}"

    @pytest.mark.timeout(600)
    def test_valid_payloads_dynamic_at_slow_rate(self, pytestconfig):
        message_limit = 100
        rln_state = self.register_rln_relay_nodes(2, [])
        pytestconfig.cache.set(
            "keystore-prefixes",
            {
                "keystore_prefixes": rln_state["keystore_prefixes"],
                "rln_membership_indexes": rln_state["rln_membership_indexes"],
            },
        )
        self.setup_main_rln_relay_nodes(
            rln_relay_user_message_limit=message_limit,
            rln_relay_epoch_sec=600,
            rln_relay_dynamic="true",
            wait_for_node_sec=600,
        )
        self.subscribe_main_relay_nodes()
        failed_payloads = []
        for i, payload in enumerate(self.SAMPLE_INPUTS_RLN):
            logger.debug(f'Running test with payload {payload["description"]}')
            message = self.create_message(payload=to_base64(payload["value"]))
            try:
                logger.debug(f"Sending message No. #{i + 1}")
                self.check_published_message_reaches_relay_peer(message, message_propagation_delay=0.2)
            except Exception as e:
                logger.error(f'Payload {payload["description"]} failed: {str(e)}')
                failed_payloads.append(payload["description"])
            delay(1)
            assert not failed_payloads, f"Payloads failed: {failed_payloads}"
            if i == message_limit - 1:
                break

    def test_valid_payloads_n1_with_rln_n2_without_rln_at_spam_rate(self, pytestconfig):
        message_limit = 1
        epoch_sec = 1
        self.register_rln_relay_nodes(
            0,
            pytestconfig.cache.get("keystore-prefixes", {"keystore_prefixes": [], "rln_membership_indexes": []}),
        )
        self.setup_first_rln_relay_node(rln_relay_user_message_limit=message_limit, rln_relay_epoch_sec=epoch_sec)
        self.setup_second_relay_node()
        self.subscribe_main_relay_nodes()
        start = math.trunc(time())
        for i, payload in enumerate(SAMPLE_INPUTS[:5]):
            logger.debug(f'Running test with payload {payload["description"]}')
            message = self.create_message(payload=to_base64(payload["value"]))
            try:
                now = math.trunc(time())
                self.publish_message(message)
                if i > message_limit and (now - start) <= epoch_sec:
                    raise AssertionError("Publish with RLN enabled at spam rate worked!!!")
            except Exception as e:
                error_str = str(e)
                assert "RLN validation failed" in error_str or "NonceLimitReached" in error_str
                if "NonceLimitReached" in error_str:
                    assert "500" in error_str, f"Expected HTTP 500 for NonceLimitReached, got: {error_str}"

    def test_valid_payloads_with_optional_nodes_at_slow_rate(self, pytestconfig):
        rln_state = self.register_rln_relay_nodes(5, [])
        pytestconfig.cache.set(
            "keystore-prefixes",
            {
                "keystore_prefixes": rln_state["keystore_prefixes"],
                "rln_membership_indexes": rln_state["rln_membership_indexes"],
            },
        )
        self.setup_main_rln_relay_nodes(rln_relay_user_message_limit=1, rln_relay_epoch_sec=1)
        self.setup_optional_rln_relay_nodes(rln_relay_user_message_limit=1, rln_relay_epoch_sec=1)
        self.subscribe_main_relay_nodes()
        self.subscribe_optional_relay_nodes()
        failed_payloads = []
        for i, payload in enumerate(SAMPLE_INPUTS):
            logger.debug(f'Running test with payload {payload["description"]}')
            message = self.create_message(payload=to_base64(payload["value"]))
            try:
                logger.debug(f"Sending message No. #{i + 1}")
                self.check_published_message_reaches_relay_peer(message, message_propagation_delay=0.2)
            except Exception as e:
                logger.error(f'Payload {payload["description"]} failed: {str(e)}')
                failed_payloads.append(payload["description"])
            delay(1)
            assert not failed_payloads, f"Payloads failed: {failed_payloads}"

    def test_valid_payloads_with_optional_nodes_at_spam_rate(self, pytestconfig):
        self.register_rln_relay_nodes(
            0,
            pytestconfig.cache.get("keystore-prefixes", {"keystore_prefixes": [], "rln_membership_indexes": []}),
        )
        self.setup_main_rln_relay_nodes(rln_relay_user_message_limit=1, rln_relay_epoch_sec=1)
        self.setup_optional_rln_relay_nodes(rln_relay_user_message_limit=1, rln_relay_epoch_sec=1)
        self.subscribe_main_relay_nodes()
        self.subscribe_optional_relay_nodes()
        previous = math.trunc(time())
        for i, payload in enumerate(SAMPLE_INPUTS[:5]):
            logger.debug(f'Running test with payload {payload["description"]}')
            message = self.create_message(payload=to_base64(payload["value"]))
            try:
                logger.debug(f"Sending message No. #{i + 1}")
                now = math.trunc(time())
                self.publish_message(message)
                if i > 0 and (now - previous) == 0:
                    raise AssertionError("Publish with RLN enabled at spam rate worked!!!")
                else:
                    previous = now
            except Exception as e:
                error_str = str(e)
                assert "RLN validation failed" in error_str or "NonceLimitReached" in error_str
                if "NonceLimitReached" in error_str:
                    assert "500" in error_str, f"Expected HTTP 500 for NonceLimitReached, got: {error_str}"
