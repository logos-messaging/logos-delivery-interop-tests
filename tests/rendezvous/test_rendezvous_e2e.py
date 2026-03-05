import pytest
from src.env_vars import NODE_1, NODE_2, STRESS_ENABLED
from src.libs.common import delay
from src.libs.custom_logger import get_custom_logger
from src.node.waku_node import WakuNode
from src.steps.filter import StepsFilter
from src.steps.light_push import StepsLightPush
from src.steps.relay import StepsRelay
from src.steps.store import StepsStore

logger = get_custom_logger(__name__)

"""

This tests will cover rendezvous protocol e2e scenarios 

"""


class TestE2E(StepsRelay):
    @pytest.fixture(scope="function", autouse=True)
    def nodes(self):
        self.node1 = WakuNode(NODE_2, f"node1_{self.test_id}")
        self.node2 = WakuNode(NODE_1, f"node2_{self.test_id}")
        self.node3 = WakuNode(NODE_2, f"node3_{self.test_id}")

    def test_basic_rendezvous_register_and_discover(self):
        self.node1.start(rendezvous="true", relay="true")
        delay(5)
        self.node2.start(rendezvous="true", relay="true", discv5_bootstrap_node=self.node1.get_enr_uri())
        self.node1.set_relay_subscriptions([self.test_pubsub_topic])
        self.node2.set_relay_subscriptions([self.test_pubsub_topic])
        self.wait_for_autoconnection([self.node1, self.node2], hard_wait=30)
        self.node3.start(rendezvous="true", relay="true")
        self.node2.add_peers([self.node3.get_multiaddr_with_id()])
        delay(60)
        discovered = self.node3.get_peers()
        logger.debug(f"Node3 peers count is : {len(discovered)}")
        assert len(discovered) > 0, "No peers discovered via Rendezvous"
