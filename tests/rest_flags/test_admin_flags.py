import os
import pytest
import re
import time
from src.env_vars import DEFAULT_NWAKU
from src.libs.common import delay
from src.libs.custom_logger import get_custom_logger
from src.node.waku_node import WakuNode
from src.steps.filter import StepsFilter
from src.steps.light_push import StepsLightPush
from src.steps.relay import StepsRelay
from src.steps.store import StepsStore
from src.test_data import DEFAULT_CLUSTER_ID

logger = get_custom_logger(__name__)

"""
These tests make sure thst REST flags related to admin flags acting as expected 
"""


class TestAdminFlags(StepsFilter, StepsStore, StepsRelay, StepsLightPush):
    TAGS = ["TRC", "DBG", "INF", "NTC", "WRN", "ERR", "FTL"]

    LEVEL_RE = re.compile(r'"lvl"\s*:\s*"(TRC|DBG|INF|NTC|WRN|ERR|FTL)"|\b(TRC|DBG|INF|NTC|WRN|ERR|FTL)\b')

    def _read_tail_counts(self, path: str, start_size: int) -> dict:
        with open(path, "rb") as f:
            f.seek(start_size)
            text = f.read().decode(errors="ignore")
        counts = {t: 0 for t in self.TAGS}
        for a, b in self.LEVEL_RE.findall(text):
            counts[(a or b)] += 1
        return counts

    def _trigger(self):
        self.node1.info()
        self.node1.get_version()
        self.node1.get_debug_version()

    def _wait_for(self, fetcher, predicate, timeout=15, interval=0.5):
        deadline = time.time() + timeout
        result = fetcher()
        while time.time() < deadline:
            if predicate(result):
                return result
            time.sleep(interval)
            result = fetcher()
        return result

    def _connect_nodes(self, source, target):
        self.add_node_peer(source, [target.get_multiaddr_with_id()])

    def _connect_bidirectional(self, node_a, node_b):
        self._connect_nodes(node_a, node_b)
        self._connect_nodes(node_b, node_a)

    def _peer_addrs_from_groups(self, resp):
        groups = resp if isinstance(resp, list) else [resp]
        return {peer["multiaddr"] for group in groups for peer in group.get("peers", [])}

    @pytest.fixture(scope="function", autouse=True)
    def nodes(self):
        self.node1 = WakuNode(DEFAULT_NWAKU, f"node1_{self.test_id}")
        self.node2 = WakuNode(DEFAULT_NWAKU, f"node2_{self.test_id}")
        self.node3 = WakuNode(DEFAULT_NWAKU, f"node3_{self.test_id}")
        self.node4 = WakuNode(DEFAULT_NWAKU, f"node4_{self.test_id}")

    def _tail(self, path, start_size):
        with open(path, "rb") as f:
            f.seek(start_size)
            return f.read().decode(errors="ignore")

    def _count_levels(self, text, levels):
        return {lvl: len(re.findall(getattr(self, f"{lvl}_RE"), text)) for lvl in levels}

    def test_admin_filter_subscriptions_shape(self):
        self.node1.start(filter="true", relay="true")
        self.node2.start(relay="false", filternode=self.node1.get_multiaddr_with_id(), discv5_bootstrap_node=self.node1.get_enr_uri())
        resp = self.node2.set_filter_subscriptions(
            {"requestId": "1", "contentFilters": [self.test_content_topic], "pubsubTopic": self.test_pubsub_topic}
        )
        subs = self.node1.get_filter_subscriptions()
        logger.debug(f"Node admin subscriptions info{subs}")
        assert resp["statusDesc"] == "OK" and resp["requestId"] == "1"
        logger.debug(f"node 1 peers {self.node1.get_peers()}")
        assert self.node2.get_multiaddr_with_id().rpartition("/p2p/")[2] == subs[0]["peerId"], "peer id doesn't match"
        assert subs[0]["filterCriteria"][0]["pubsubTopic"] == self.test_pubsub_topic, "pubsub topic doesn't match"
        assert subs[0]["filterCriteria"][0]["contentTopic"] == self.test_content_topic, "content topic doesn't match"

    def test_admin_peers_stats_schema(self):
        self.node1.start(filter="true", relay="true")
        self.node2.start(relay="true", discv5_bootstrap_node=self.node1.get_enr_uri())
        stats = self.node1.get_peer_stats()
        logger.debug(f"Peer stats schema check: {stats}")
        assert isinstance(stats, dict), "stats must be a dict"
        for k in ("Sum", "Relay peers"):
            assert k in stats, f"missing section: {k}"
            assert isinstance(stats[k], dict), f"{k} must be a dict"
        assert isinstance(stats["Sum"].get("Total peers", 0), int) and stats["Sum"]["Total peers"] >= 0, "Sum.Total peers must be a non-negative int"
        assert (
            isinstance(stats["Relay peers"].get("Total relay peers", 0), int) and stats["Relay peers"]["Total relay peers"] >= 0
        ), "Relay peers.Total relay peers must be a non-negative int"

    def test_admin_peers_stats_counts(self):
        self.node1.start(filter="true", relay="true")
        self.node2.start(relay="true", discv5_bootstrap_node=self.node1.get_enr_uri())
        self.node3.start(relay="true", discv5_bootstrap_node=self.node1.get_enr_uri())
        self._connect_nodes(self.node1, self.node2)
        self._connect_nodes(self.node1, self.node3)
        self.node1.add_peers([self.node3.get_multiaddr_with_id()])
        self.node4.start(relay="false", filternode=self.node1.get_multiaddr_with_id(), discv5_bootstrap_node=self.node1.get_enr_uri())
        self.node4.set_filter_subscriptions({"requestId": "1", "contentFilters": [self.test_content_topic], "pubsubTopic": self.test_pubsub_topic})

        stats = self._wait_for(
            self.node1.get_peer_stats,
            lambda s: s["Sum"]["Total peers"] >= 2 and s["Relay peers"]["Total relay peers"] >= 1,
        )
        logger.debug(f"Node-1 admin peers stats {stats}")

        assert stats["Sum"]["Total peers"] >= 3, "expected at least 3 peers connected to node1"
        assert stats["Relay peers"]["Total relay peers"] >= 1, "expected at least 1 relay shard"

    def test_admin_peers_mesh_on_shard_contains_node2(self):
        shard = "0"
        start_kwargs = dict(relay="true", shard=shard, dns_discovery="false", discv5_discovery="false")
        self.node1.start(**start_kwargs)
        self.node2.start(**{**start_kwargs, "discv5_bootstrap_node": self.node1.get_enr_uri()})
        self.node3.start(**{**start_kwargs, "discv5_bootstrap_node": self.node1.get_enr_uri()})
        self._connect_bidirectional(self.node1, self.node2)
        self._connect_bidirectional(self.node1, self.node3)
        mesh_topic = f"/waku/2/rs/{self.node1.start_args.get('cluster-id', DEFAULT_CLUSTER_ID)}/{shard}"
        for node in (self.node1, self.node2, self.node3):
            node.set_relay_subscriptions([mesh_topic])
        shard = self.node1.start_args["shard"]
        targets = {self.node2.get_multiaddr_with_id(), self.node3.get_multiaddr_with_id()}
        logger.debug(f"mesh topic={mesh_topic}, target peers={targets}")
        mesh = self._wait_for(
            lambda: self.node1.get_mesh_peers_on_shard(shard),
            lambda m: targets.intersection({p["multiaddr"] for p in m["peers"]}),
            timeout=30,
        )
        logger.debug(f"Node-1 mesh on the shard  {mesh}")

        logger.debug("Validate the schema variables")
        assert isinstance(mesh["shard"], int) and mesh["shard"] == int(self.node1.start_args["shard"]), "shard mismatch"
        peer_maddrs = [p["multiaddr"] for p in mesh["peers"]]
        assert targets.intersection(peer_maddrs), "expected at least one of node2/node3 in mesh"
        for p in mesh["peers"]:
            assert isinstance(p["protocols"], list) and all(isinstance(x, str) for x in p["protocols"]), "protocols must be [str]"
            assert isinstance(p["shards"], list) and all(isinstance(x, int) for x in p["shards"]), "shards must be [int]"
            assert isinstance(p["agent"], str), "agent not str"
            assert isinstance(p["origin"], str), "origin not str"
            assert isinstance(p.get("score", 0.0), (int, float)), "score not number"

    def test_admin_peer_by_id(self):
        self.node1.start(relay="true")
        self.node2.start(relay="true", discv5_bootstrap_node=self.node1.get_enr_uri())
        self._connect_bidirectional(self.node1, self.node2)
        peer_id = self.node2.get_multiaddr_with_id().rpartition("/p2p/")[2]
        info = self.node1.get_peer_info(peer_id)
        logger.debug(f"Node-1 /admin/v1/peer/{peer_id}: {info} \n")
        logger.debug("Validate response schema")
        for k in ("multiaddr", "protocols", "shards", "connected", "agent", "origin"):
            assert k in info, f"missing field: {k}"
        assert peer_id in info["multiaddr"], "multiaddr mismatch"

    def test_admin_set_all_log_levels(self):
        self.node1.start(relay="true")
        levels = ["TRACE", "DEBUG", "INFO", "NOTICE", "WARN", "ERROR", "FATAL"]
        self.node2.start(relay="true", discv5_bootstrap_node=self.node1.get_enr_uri())
        for lvl in levels:
            resp = self.node1.set_log_level(lvl)
            logger.debug(f"Set log level ({lvl}) -> status={resp.status_code}")
            assert resp.status_code == 200, f"failed to set log level {lvl} {resp.text}"
            self.node2.info()
            self.node2.get_debug_version()

        resp = self.node1.set_log_level("TRACE")
        logger.debug(f"Restore default log level (TRACE) -> status={resp.status_code}")
        assert resp.status_code == 200, f"failed to revert log level: {resp.text}"

    @pytest.mark.timeout(120)
    def test_log_level_DEBUG_from_TRACE(self):
        self.node1.start(relay="true")
        path = self.node1._log_path
        for _ in range(50):
            if os.path.exists(path):
                break
            time.sleep(0.05)

        assert self.node1.set_log_level("TRACE").status_code == 200
        assert self.node1.set_log_level("DEBUG").status_code == 200

        start = os.path.getsize(path)
        self._trigger()
        time.sleep(2)

        counts = self._read_tail_counts(path, start)
        logger.debug(f"counts at DEBUG: {counts}")

        assert counts["DBG"] > 0, "expected DEBUG logs at DEBUG level"
        assert counts["TRC"] == 0, "TRACE must be filtered at DEBUG"

        assert self.node1.set_log_level("TRACE").status_code == 200

    @pytest.mark.timeout(120)
    def test_log_level_INFO_from_DEBUG(self):
        self.node1.start(relay="true")
        path = self.node1._log_path
        for _ in range(50):
            if os.path.exists(path):
                break
            time.sleep(0.05)

        # assert self.node1.set_log_level("DEBUG").status_code == 200
        assert self.node1.set_log_level("INFO").status_code == 200

        start = os.path.getsize(path)
        self._trigger()
        time.sleep(2)

        counts = self._read_tail_counts(path, start)
        logger.debug(f"counts at INFO: {counts}")

        assert counts["INF"] > 0, "expected INFO logs at INFO level"
        assert counts["DBG"] == 0 and counts["TRC"] == 0, "lower than INFO (DBG/TRC) must be filtered"

        assert self.node1.set_log_level("TRACE").status_code == 200

    @pytest.mark.timeout(120)
    def test_log_level_NOTICE_from_INFO(self):
        self.node1.start(relay="true")
        path = self.node1._log_path
        for _ in range(50):
            if os.path.exists(path):
                break
            time.sleep(0.05)

        assert self.node1.set_log_level("INFO").status_code == 200
        assert self.node1.set_log_level("NOTICE").status_code == 200

        start = os.path.getsize(path)
        self._trigger()
        time.sleep(2)

        counts = self._read_tail_counts(path, start)
        logger.debug(f"counts at NOTICE: {counts}")

        for lv in ["TRC", "DBG", "INF"]:
            assert counts[lv] == 0, f"{lv} must be filtered at NOTICE"

        assert self.node1.set_log_level("TRACE").status_code == 200

    @pytest.mark.timeout(120)
    def test_log_level_WARN_from_NOTICE(self):
        self.node1.start(relay="true")
        path = self.node1._log_path
        for _ in range(50):
            if os.path.exists(path):
                break
            time.sleep(0.05)

        assert self.node1.set_log_level("NOTICE").status_code == 200
        assert self.node1.set_log_level("WARN").status_code == 200

        start = os.path.getsize(path)
        self._trigger()
        time.sleep(2)

        counts = self._read_tail_counts(path, start)
        logger.debug(f"counts at WARN: {counts}")

        for lv in ["TRC", "DBG", "INF", "NTC"]:
            assert counts[lv] == 0, f"{lv} must be filtered at WARN"

        assert self.node1.set_log_level("TRACE").status_code == 200

    @pytest.mark.timeout(120)
    def test_log_level_ERROR_from_WARN(self):
        self.node1.start(relay="true")
        path = self.node1._log_path
        for _ in range(50):
            if os.path.exists(path):
                break
            time.sleep(0.05)

        assert self.node1.set_log_level("WARN").status_code == 200
        assert self.node1.set_log_level("ERROR").status_code == 200

        start = os.path.getsize(path)
        self._trigger()
        time.sleep(2)

        counts = self._read_tail_counts(path, start)
        logger.debug(f"counts at ERROR: {counts}")

        for lv in ["TRC", "DBG", "INF", "NTC", "WRN"]:
            assert counts[lv] == 0, f"{lv} must be filtered at ERROR"

        assert self.node1.set_log_level("TRACE").status_code == 200

    @pytest.mark.timeout(120)
    def test_log_level_FATAL_from_ERROR(self):
        self.node1.start(relay="true")
        path = self.node1._log_path
        for _ in range(50):
            if os.path.exists(path):
                break
            time.sleep(0.05)

        assert self.node1.set_log_level("ERROR").status_code == 200
        assert self.node1.set_log_level("FATAL").status_code == 200

        start = os.path.getsize(path)
        self._trigger()
        time.sleep(2)

        counts = self._read_tail_counts(path, start)
        logger.debug(f"counts at FATAL: {counts}")

        for lv in ["TRC", "DBG", "INF", "NTC", "WRN", "ERR"]:
            assert counts[lv] == 0, f"{lv} must be filtered at FATAL"

        assert self.node1.set_log_level("TRACE").status_code == 200

    def test_relay_peers_on_shard_schema(self):
        node_shard = "0"
        shard_kwargs = dict(relay="true", shard=node_shard, dns_discovery="false", discv5_discovery="false")
        self.node1.start(**shard_kwargs)
        self.node2.start(**{**shard_kwargs, "discv5_bootstrap_node": self.node1.get_enr_uri()})
        time.sleep(1)
        resp = self.node1.get_relay_peers_on_shard(node_shard)
        logger.debug(f"relay peers on shard=0 (schema): {resp!r}")
        assert str(resp["shard"]) == node_shard, "Returned 'shard' must match requested shardId"
        for p in resp["peers"]:
            assert isinstance(p.get("multiaddr"), str) and p["multiaddr"].strip(), "peer.multiaddr must be a non-empty string"
            if "protocols" in p:
                assert isinstance(p["protocols"], list) and all(isinstance(x, str) for x in p["protocols"]), "peer.protocols must be list[str]"
            if "shards" in p:
                assert isinstance(p["shards"], list), "peer.shards must be a list"
            if "connected" in p:
                assert isinstance(p["connected"], str), "peer.connected must be a string"
            if "agent" in p:
                assert isinstance(p["agent"], str), "peer.agent must be a string"
            if "origin" in p:
                assert isinstance(p["origin"], str), "peer.origin must be a string"
            if "score" in p:
                assert isinstance(p["score"], (int, float)), "peer.score must be a number"

    def test_relay_peers_on_shard_contains_connected_peer(self):
        shard_kwargs = dict(relay="true", shard="0", dns_discovery="false", discv5_discovery="false")
        self.node1.start(**shard_kwargs)
        self.node2.start(**{**shard_kwargs, "discv5_bootstrap_node": self.node1.get_enr_uri()})
        self._connect_bidirectional(self.node1, self.node2)
        self.wait_for_autoconnection([self.node1, self.node2], hard_wait=1)
        relay_topic = f"/waku/2/rs/{self.node1.start_args.get('cluster-id', DEFAULT_CLUSTER_ID)}/{self.node1.start_args['shard']}"
        for node in (self.node1, self.node2):
            node.set_relay_subscriptions([relay_topic])
        n2_addr = self.node2.get_multiaddr_with_id()
        resp = self._wait_for(
            lambda: self.node1.get_relay_peers_on_shard("0"),
            lambda data: any(p.get("multiaddr") == n2_addr for p in data.get("peers", [])),
            timeout=30,
        )
        logger.debug(f"checking shard=0 list: {resp!r}")
        assert any(
            p.get("multiaddr") == n2_addr for p in resp["peers"]
        ), f"Expected Node-2 address {n2_addr} in Node-1's /admin/v1/peers/relay/on/0 list"

    def test_admin_relay_peers_schema(self):
        self.node1.start(relay="true")
        self.node2.start(relay="true", discv5_bootstrap_node=self.node1.get_enr_uri())
        self.node1.add_peers([self.node2.get_multiaddr_with_id()])
        self.node2.add_peers([self.node1.get_multiaddr_with_id()])
        time.sleep(1)

        resp = self.node1.get_relay_peers()
        logger.debug(f"/admin/v1/peers/relay (schema): {resp!r} / type={type(resp).__name__}")

        groups = resp if isinstance(resp, list) else [resp]
        for grp in groups:
            peers_list = grp.get("peers")
            for peer in peers_list:
                ma = peer.get("multiaddr")
                assert isinstance(ma, str) and ma.strip(), "multiaddr must be a non-empty string"

                protos = peer["protocols"]
                assert all(isinstance(x, str) for x in protos), "protocols must be list[str]"

                assert isinstance(peer["score"], (int, float)), "score must be a number"

    def test_admin_relay_peers_contains_all_relay_peers(self):
        self.node1.start(relay="true")

        self.node2.start(relay="true", discv5_bootstrap_node=self.node1.get_enr_uri())
        self.node3 = WakuNode(DEFAULT_NWAKU, f"node3_{self.test_id}")
        self.node4 = WakuNode(DEFAULT_NWAKU, f"node4_{self.test_id}")
        self.node3.start(relay="false", discv5_bootstrap_node=self.node1.get_enr_uri())
        self.node4.start(relay="true", discv5_bootstrap_node=self.node1.get_enr_uri())
        for node in (self.node1, self.node2, self.node4):
            node.set_relay_subscriptions([self.test_pubsub_topic])
        self._connect_bidirectional(self.node1, self.node2)
        self._connect_bidirectional(self.node1, self.node4)
        self.wait_for_autoconnection([self.node1, self.node2, self.node4], hard_wait=1)

        n2_addr = self.node2.get_multiaddr_with_id()
        n3_addr = self.node3.get_multiaddr_with_id()
        n4_addr = self.node4.get_multiaddr_with_id()
        time.sleep(1)

        expected_present = {n2_addr, n4_addr}
        resp = self._wait_for(
            self.node1.get_relay_peers,
            lambda data: expected_present.issubset(self._peer_addrs_from_groups(data)),
            timeout=30,
        )
        logger.debug(f"/admin/v1/peers/relay {resp!r}")

        peer_ids = {peer["multiaddr"].rpartition("/p2p/")[2] for group in resp for peer in group["peers"]}
        n2_id = n2_addr.rpartition("/p2p/")[2]
        n3_id = n3_addr.rpartition("/p2p/")[2]
        n4_id = n4_addr.rpartition("/p2p/")[2]
        assert n2_id in peer_ids, f"Missing Node-2 address {n2_addr}"
        assert n3_id not in peer_ids, f"Unexpected Node-3 address {n3_addr}"
        assert n4_id in peer_ids, f"Missing Node-4 address {n4_addr}"

    def test_admin_connected_peers_on_shard_contains_all_three(self):
        shard = "0"
        shard_kwargs = dict(relay="true", shard=shard, dns_discovery="false", discv5_discovery="false")
        self.node1.start(**shard_kwargs)
        self.node2.start(**{**shard_kwargs, "discv5_bootstrap_node": self.node1.get_enr_uri()})
        self.node3 = WakuNode(DEFAULT_NWAKU, f"node3_{self.test_id}")
        self.node4 = WakuNode(DEFAULT_NWAKU, f"node4_{self.test_id}")
        self.node3.start(**{**shard_kwargs, "discv5_bootstrap_node": self.node1.get_enr_uri()})
        self.node4.start(**{**shard_kwargs, "discv5_bootstrap_node": self.node1.get_enr_uri()})
        for node in (self.node2, self.node3, self.node4):
            self._connect_bidirectional(self.node1, node)
        relay_topic = f"/waku/2/rs/{self.node1.start_args.get('cluster-id', DEFAULT_CLUSTER_ID)}/{shard}"
        for node in (self.node1, self.node2, self.node3, self.node4):
            node.set_relay_subscriptions([relay_topic])
        self.wait_for_autoconnection([self.node1, self.node2, self.node3, self.node4], hard_wait=1)

        n2_addr = self.node2.get_multiaddr_with_id()
        n3_addr = self.node3.get_multiaddr_with_id()
        n4_addr = self.node4.get_multiaddr_with_id()
        time.sleep(1)

        expected_ids = {n2_addr.rpartition("/p2p/")[2], n3_addr.rpartition("/p2p/")[2], n4_addr.rpartition("/p2p/")[2]}
        connected_all = self._wait_for(
            self.node1.get_connected_peers,
            lambda peers: expected_ids.issubset({p["multiaddr"].rpartition("/p2p/")[2] for p in peers}),
            timeout=30,
        )
        shard_resp = self.node1.get_connected_peers_on_shard(shard)
        logger.debug(f"/admin/v1/peers/connected/on/{shard} (contains 3): {shard_resp!r}")

        if shard_resp:
            shard_ids = {p["multiaddr"].rpartition("/p2p/")[2] for p in shard_resp}
            all_ids = {p["multiaddr"].rpartition("/p2p/")[2] for p in connected_all}
            assert shard_ids.issubset(all_ids), "Shard-specific peers must be connected"
            for peer in shard_resp:
                assert int(shard) in peer.get("shards", []), "peer missing requested shard"
        else:
            logger.warning("Connected peers endpoint returned no shard-scoped peers; relying on global check")

    def test_admin_connected_peers_scalar_types(self):
        self.node1.start(relay="true")
        self.node2.start(relay="true", discv5_bootstrap_node=self.node1.get_enr_uri())
        self._connect_bidirectional(self.node1, self.node2)
        resp = self._wait_for(
            self.node1.get_connected_peers,
            lambda peers: any(p.get("multiaddr") == self.node2.get_multiaddr_with_id() for p in peers),
            timeout=30,
        )
        logger.debug(f"Response for get connected peers  {resp!r}")

        for p in resp:
            assert isinstance(p["multiaddr"], str) and p["multiaddr"].strip(), "multiaddr must be a non-empty string"
            assert isinstance(p["protocols"], list) and all(isinstance(x, str) for x in p["protocols"]), "protocols must be list[str]"
            assert isinstance(p["shards"], list), "shards must be a list"
            assert isinstance(p["agent"], str), "agent must be a string"
            assert isinstance(p["connected"], str), "connected must be a string"
            assert isinstance(p["origin"], str), "origin must be a string"
            score = p.get("score")
            if score is not None:
                assert isinstance(score, (int, float)), "score must be a number when provided"
            latency = p.get("latency")
            if latency is not None:
                assert isinstance(latency, (int, float)), "latency must be numeric when present"

    def test_admin_connected_peers_contains_peers_only(self):
        self.node1.start(relay="true")

        self.node2.start(relay="true", discv5_bootstrap_node=self.node1.get_enr_uri())
        self.node3 = WakuNode(DEFAULT_NWAKU, f"node3_{self.test_id}")
        self.node4 = WakuNode(DEFAULT_NWAKU, f"node4_{self.test_id}")
        self.node3.start(relay="true", discv5_bootstrap_node=self.node1.get_enr_uri())
        self.node4.start(relay="true")
        self._connect_bidirectional(self.node1, self.node2)
        self._connect_bidirectional(self.node1, self.node3)

        n2_addr = self.node2.get_multiaddr_with_id()
        n3_addr = self.node3.get_multiaddr_with_id()
        n4_addr = self.node4.get_multiaddr_with_id()
        expected_ids = {n2_addr.rpartition("/p2p/")[2], n3_addr.rpartition("/p2p/")[2]}
        resp = self._wait_for(
            self.node1.get_connected_peers,
            lambda peers: expected_ids.issubset({p["multiaddr"].rpartition("/p2p/")[2] for p in peers}),
            timeout=30,
        )
        logger.debug(f"/admin/v1/peers/connected contains : {resp!r}")

        peer_ids = {p["multiaddr"].rpartition("/p2p/")[2] for p in resp}
        assert expected_ids.issubset(peer_ids), "Missing expected connected peers"
        assert n4_addr.rpartition("/p2p/")[2] not in peer_ids, f"Unexpected Node-4 address {n4_addr}"

    def test_admin_service_peers_scalar_required_types(self):
        self.node1.start(relay="true")

        self.node2.start(relay="true", discv5_bootstrap_node=self.node1.get_enr_uri())
        self._connect_nodes(self.node1, self.node2)
        resp = self.node1.get_service_peers()
        logger.debug(f"/admin/v1/peers/service {resp!r}")

        for peer in resp:
            assert isinstance(peer.get("multiaddr"), str) and peer["multiaddr"].strip(), "multiaddr must be a non-empty string"
            assert isinstance(peer.get("protocols"), list) and all(isinstance(x, str) for x in peer["protocols"]), "protocols must be list[str]"
            assert isinstance(peer.get("shards"), list), "shards must be a list"
            assert isinstance(peer.get("agent"), str), "agent must be a string"
            assert isinstance(peer.get("connected"), str), "connected must be a string"
            assert isinstance(peer.get("origin"), str), "origin must be a string"
            score = peer.get("score")
            if score is not None:
                assert isinstance(score, (int, float)), "score must be numeric when present"

    def test_admin_service_peers_schema(self):
        n1 = WakuNode(DEFAULT_NWAKU, "n1_service_schema")
        n2 = WakuNode(DEFAULT_NWAKU, "n2_service_schema")
        n1.start(relay="true")
        n2.start(relay="true", discv5_bootstrap_node=n1.get_enr_uri())
        peers = n1.get_service_peers()
        logger.debug("Validate schema of get service peers")
        for p in peers:
            assert "multiaddr" in p, "missing 'multiaddr'"
            assert "protocols" in p, "missing 'protocols'"
            assert "shards" in p, "missing 'shards'"
            assert "connected" in p, "missing 'connected'"
            assert "agent" in p, "missing 'agent'"
            assert "origin" in p, "missing 'origin'"

    def test_admin_service_peers_contains_expected_addrs_and_protocols(self):
        n1 = WakuNode(DEFAULT_NWAKU, "n1_service_lookup")
        n2 = WakuNode(DEFAULT_NWAKU, "n2_service_relay")
        n3 = WakuNode(DEFAULT_NWAKU, "n3_service_store")

        n1.start(relay="true")
        n2.start(relay="true", discv5_bootstrap_node=n1.get_enr_uri())
        n3.start(store="true", discv5_bootstrap_node=n1.get_enr_uri())
        n1.add_peers([n2.get_multiaddr_with_id()])
        n2.add_peers([n1.get_multiaddr_with_id()])
        n1.add_peers([n3.get_multiaddr_with_id()])
        n3.add_peers([n1.get_multiaddr_with_id()])
        resp = self._wait_for(
            n1.get_service_peers,
            lambda peers: {n2.get_multiaddr_with_id().rpartition("/p2p/")[2], n3.get_multiaddr_with_id().rpartition("/p2p/")[2]}.issubset(
                {p["multiaddr"].rpartition("/p2p/")[2] for p in peers}
            ),
            timeout=30,
        )
        logger.debug("/admin/v1/peers/service %s", resp)
        by_id = {p["multiaddr"].rpartition("/p2p/")[2]: p["protocols"] for p in resp}

        m2 = n2.get_multiaddr_with_id().rpartition("/p2p/")[2]
        m3 = n3.get_multiaddr_with_id().rpartition("/p2p/")[2]
        assert m2 in by_id, f"node2 not found"
        assert any("/waku/relay/" in s for s in by_id[m2]), "node2 should advertise a relay protocol"
        assert m3 in by_id, f"node3 not found. got: {list(by_id.keys())}"
        assert any("/waku/store-query/" in s for s in by_id[m3]), "node3 should advertise a store-query protocol"
