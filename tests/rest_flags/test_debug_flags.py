import pytest
from src.env_vars import NODE_1, NODE_2, STRESS_ENABLED
from src.libs.common import delay
from src.libs.custom_logger import get_custom_logger
from src.node.waku_node import WakuNode
from src.steps.filter import StepsFilter
from src.steps.light_push import StepsLightPush
from src.steps.relay import StepsRelay
from src.steps.store import StepsStore
import re

logger = get_custom_logger(__name__)

"""
These tests make sure thst REST flags related to debug acting as expected 
"""


class TestDebugFlags(StepsFilter, StepsStore, StepsRelay, StepsLightPush):
    @pytest.fixture(scope="function", autouse=True)
    def nodes(self):
        self.node1 = WakuNode(NODE_2, f"node1_{self.test_id}")

    def test_verify_node_version2(self):
        self.node1.start(relay="true")
        node1_version = self.node1.get_version()
        logger.debug(f"version of created node is {node1_version}")
        assert re.match(r"^v0\.(3[5-9])(?:[.\-]|$)", node1_version), f"expected v0.35–v0.39, got {node1_version}"

    def test_verify_node_info(self):
        self.node1.start(relay="true")
        info = self.node1.get_info()
        logger.debug(f"node info: {info}")
        assert info["enrUri"] == self.node1.get_enr_uri(), "node enruri doesn't match"
        assert self.node1.get_multiaddr_with_id() in info["listenAddresses"], "node address doesn't match"

    def test_get_debug_version_is_string(self):
        self.node1.start(relay="true")
        dbg_version = self.node1.get_debug_version()
        logger.debug(f"debug version returned: {dbg_version}")
        assert isinstance(dbg_version, str) and dbg_version.strip() != "", "Expected /debug/v1/version to return a non-empty string"
