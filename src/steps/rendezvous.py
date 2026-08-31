import allure
from tenacity import retry, stop_after_delay, wait_fixed

from src.env_vars import NODE_1, NODE_2
from src.libs.custom_logger import get_custom_logger
from src.node.waku_node import WakuNode, peer_info2id
from src.steps.relay import StepsRelay

logger = get_custom_logger(__name__)

# Rendezvous discovery only surfaces peers whose advertised record carries a mix
# key, so registrant nodes must run with mix enabled. Discovery is disabled on
# every node except through rendezvous itself (discv5 / peer-exchange are turned
# off) so that a discovered peer can only have been learned via rendezvous.


class StepsRendezvous(StepsRelay):
    @allure.step
    def setup_rendezvous_point(self, **kwargs):
        # Central node acting as the rendezvous server: registrants advertise on
        # it and discoverers query it. It is the only shared point of contact.
        self.rendezvous_point = WakuNode(NODE_1, f"rzv_point_{self.test_id}")
        self.rendezvous_point.start(relay="true", rendezvous="true", discv5_discovery="false", peer_exchange="false", **kwargs)
        self.rendezvous_multiaddr = self.rendezvous_point.get_multiaddr_with_id()
        return self.rendezvous_point

    @allure.step
    def setup_registrant_node(self, name, **kwargs):
        # Mix-enabled node: its advertised rendezvous record carries a mix key,
        # which is what makes it discoverable by other nodes via rendezvous.
        node = WakuNode(NODE_2, f"{name}_{self.test_id}")
        node.start(relay="true", rendezvous="true", mix="true", discv5_discovery="false", peer_exchange="false", **kwargs)
        self.add_node_peer(node, [self.rendezvous_multiaddr])
        return node

    @allure.step
    def setup_discovering_node(self, name, **kwargs):
        # Node that learns about registrants purely through rendezvous discovery.
        node = WakuNode(NODE_2, f"{name}_{self.test_id}")
        node.start(relay="true", rendezvous="true", discv5_discovery="false", peer_exchange="false", **kwargs)
        self.add_node_peer(node, [self.rendezvous_multiaddr])
        return node

    @allure.step
    @retry(stop=stop_after_delay(90), wait=wait_fixed(5), reraise=True)
    def wait_for_rendezvous_discovery(self, node, expected_ids):
        peer_store_ids = {peer_info2id(peer, node.is_nwaku()) for peer in node.get_peers()}
        missing = set(expected_ids) - peer_store_ids
        logger.debug(f"Rendezvous peer store for {node._image_name}: {peer_store_ids}, still missing: {missing}")
        assert not missing, f"Peers not yet discovered via rendezvous: {missing}"
        return peer_store_ids
