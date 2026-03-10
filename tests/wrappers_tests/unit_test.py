import inspect
import pytest
from result import Ok
from src.libs.custom_logger import get_custom_logger
from src.steps.wrappers_setup import NodeStub
from src.node import wrappers_manager

# from wrapper_setup import NodeWrapper

logger = get_custom_logger(__name__)


class TestWrappersManager:
    @pytest.fixture(scope="function", autouse=True)
    def wrapper_setup(self):
        logger.debug(f"Running setup")
        self.node = NodeForTest()

    def test_wrapper_send_message(self):
        message = {
            "contentTopic": "/test/1/chat/proto",
            "payload": "SGVsbG8=",
            "ephemeral": False,
        }

        result = wrappers_manager.wrapper_send_message(self.node, message, timeout_s=5.0)

        assert result == Ok(1)
        assert self.node.last_message == message
        assert self.node.last_timeout == 5.0

    def test_wrapper_get_available_node_info_ids(self):
        result = wrappers_manager.wrapper_get_available_node_info_ids(self.node, timeout_s=6.0)

        assert result == Ok(2)
