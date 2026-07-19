import pytest

from src.env_vars import NODE_1, NODE_2
from src.libs.custom_logger import get_custom_logger
from src.node.waku_node import WakuNode
from src.steps.filter import StepsFilter
from src.steps.light_push import StepsLightPush
from src.steps.relay import StepsRelay
from src.steps.store import StepsStore
from tenacity import retry, stop_after_delay, wait_fixed

logger = get_custom_logger(__name__)


class TestDiscv5(StepsRelay, StepsFilter, StepsStore, StepsLightPush):
    @pytest.mark.smoke
    def running_a_node(self, image, **kwargs):
        node = WakuNode(image, f"node{len(self.main_nodes) + 1}_{self.test_id}")
        node.start(**kwargs)
        return node

    @retry(stop=stop_after_delay(70), wait=wait_fixed(1), reraise=True)
    def wait_for_published_message_to_be_stored(self):
        self.publish_message()
        self.check_published_message_is_stored([self.store_node1], page_size=5, ascending="true")

    @retry(stop=stop_after_delay(70), wait=wait_fixed(1), reraise=True)
    def wait_for_lightpushed_message_to_be_stored(self):
        self.check_light_pushed_message_reaches_receiving_peer(peer_list=[self.receiving_node1, self.receiving_node2])

    @pytest.mark.smoke
    def test_relay(self):
        self.node1 = self.running_a_node(NODE_1, relay="true")
        self.node2 = self.running_a_node(NODE_2, relay="true", discv5_bootstrap_node=self.node1.get_enr_uri())
        self.main_nodes = [self.node1, self.node2]
        self.ensure_relay_subscriptions_on_nodes(self.main_nodes, [self.test_pubsub_topic])
        self.wait_for_published_message_to_reach_relay_peer()

    @pytest.mark.smoke
    def test_filter(self):
        self.node1 = self.running_a_node(NODE_1, relay="true", filter="true")
        self.node2 = self.running_a_node(
            NODE_2, relay="false", discv5_bootstrap_node=self.node1.get_enr_uri(), filternode=self.node1.get_multiaddr_with_id()
        )
        self.main_nodes = [self.node2]
        self.wait_for_subscriptions_on_main_nodes([self.test_content_topic])
        self.check_published_message_reaches_filter_peer()

    def test_store(self):
        self.publishing_node1 = self.running_a_node(NODE_1, relay="true", store="true")
        self.store_node1 = self.running_a_node(
            NODE_2,
            relay="true",
            store="true",
            discv5_bootstrap_node=self.publishing_node1.get_enr_uri(),
            storenode=self.publishing_node1.get_multiaddr_with_id(),
        )
        self.main_nodes = [self.publishing_node1, self.store_node1]
        self.subscribe_to_pubsub_topics_via_relay(self.main_nodes)
        self.wait_for_published_message_to_be_stored()

    @pytest.mark.smoke
    def test_lightpush(self):
        self.receiving_node1 = self.running_a_node(NODE_1, lightpush="true", relay="true")
        self.receiving_node2 = self.running_a_node(NODE_1, lightpush="false", relay="true", discv5_bootstrap_node=self.receiving_node1.get_enr_uri())
        self.light_push_node1 = self.running_a_node(
            NODE_2,
            lightpush="true",
            relay="true",
            discv5_bootstrap_node=self.receiving_node1.get_enr_uri(),
            lightpushnode=self.receiving_node1.get_multiaddr_with_id(),
        )
        self.subscribe_to_pubsub_topics_via_relay([self.receiving_node1, self.receiving_node2])
        self.wait_for_lightpushed_message_to_be_stored()
