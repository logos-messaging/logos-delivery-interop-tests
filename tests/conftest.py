# -*- coding: utf-8 -*-
"""
Root pytest configuration for the logos-delivery interop test suite.

Fleet bootstrap – hybrid local+fleet
--------------------------------------------------
Every local Docker node spawned by a test is patched at start() time so
that it connects to a live waku.test fleet peer as a static peer, and
discovers all remaining fleet peers through the published ENR DNS tree.

Bootstrap assignment by node creation order (mirrors config-n*.toml files):
  NODE1 (1st started) → config-n1.toml  → node-01.do-ams3.waku.test.status.im
  NODE2 (2nd started) → config-n2.toml  → node-01.gc-us-central1-a.waku.test.status.im
  additional nodes    → FLEET_PRIMARY_MULTIADDR (Amsterdam, same as NODE1)

Direct bootstrap coupling between NODE1 and NODE2 is suppressed:
  * ``discv5_bootstrap_node`` kwargs that point to a local node's ENR are
    stripped; fleet DNS discovery (dns_discovery_url) replaces them so that
    each node bootstraps independently from its assigned fleet peer rather
    than from another local container.

Tests still retain full access to local nodes (REST API calls, add_peers,
store/filter/lightpush service calls) – only the initial discv5 bootstrap
link between local nodes is removed.

Fleet node information (addresses, peer IDs, ENR tree URL) is stored in
``src/env_vars.py`` (FLEET_NODES, FLEET_N1_MULTIADDR, FLEET_N2_MULTIADDR,
FLEET_PRIMARY_MULTIADDR, FLEET_DNS_DISCOVERY_URL)

Activation (opt-in, disabled by default):
  pytest <any-test-path> --fleet -v
  FLEET_BOOTSTRAP=true pytest <any-test-path> -v

"""
import inspect
import glob
import random
import string
from src.libs.custom_logger import get_custom_logger
import os
import pytest
from datetime import datetime
from time import time
from uuid import uuid4
from src.libs.common import attach_allure_file, gen_step_id
import src.env_vars as env_vars
from src.env_vars import FLEET_PRIMARY_MULTIADDR, FLEET_DNS_DISCOVERY_URL, FLEET_N1_MULTIADDR, FLEET_N2_MULTIADDR
from src.data_storage import DS
from src.postgres_setup import start_postgres, stop_postgres
from src.test_data import FLEET_CLUSTER_ID, FLEET_PUBSUB_TOPICS, PUBSUB_TOPICS_RLN

logger = get_custom_logger(__name__)


def pytest_addoption(parser):
    """Register the --fleet command-line option."""
    parser.addoption(
        "--fleet",
        action="store_true",
        default=False,
        help=(
            "Bootstrap every local nwaku Docker node against the live waku.test "
            "fleet (node-01.do-ams3 / gc-us-central1-a / ac-cn-hongkong-c). "
            "Also activatable via FLEET_BOOTSTRAP=true env var."
        ),
    )


def _fleet_bootstrap_enabled(config) -> bool:
    """Return True when fleet bootstrap should be activated.

    Activation priority (first match wins):
      1. ``--fleet`` CLI flag passed to pytest
      2. ``FLEET_BOOTSTRAP=true`` environment variable
    """
    if config.getoption("--fleet", default=False):
        return True
    return os.getenv("FLEET_BOOTSTRAP", "false").lower() == "true"


def _append_fleet_kwarg(kwargs: dict, key: str, value: str) -> None:
    """Add *value* to the kwargs entry *key*, creating a list when needed."""
    existing = kwargs.get(key)
    if existing is None:
        kwargs[key] = value
    elif isinstance(existing, list):
        if value not in existing:
            kwargs[key] = existing + [value]
    else:
        if existing != value:
            kwargs[key] = [existing, value]


@pytest.fixture(scope="session")
def fleet_rln_state(request):
    """Register 2 RLN memberships once per test session when ``--fleet`` is active.

    The on-disk keystore directories created here are reused by every test in
    the session so that the expensive blockchain registration only happens once.

    Yields a dict with keys:
        ``keystore_prefixes``      – list[str] of random 4-char directory prefixes
        ``rln_membership_indexes`` – list[int | None] returned by register_rln()

    An empty dict (both lists empty) is yielded when fleet bootstrap is not
    active or when ``RLN_CREDENTIALS`` is not set.
    """
    if not _fleet_bootstrap_enabled(request.config):
        yield {"keystore_prefixes": [], "rln_membership_indexes": []}
        return

    from src.node.waku_node import WakuNode
    from src.env_vars import RLN_CREDENTIALS, DEFAULT_NWAKU

    if not RLN_CREDENTIALS:
        logger.info("Fleet RLN: RLN_CREDENTIALS not set – nodes will start without RLN")
        yield {"keystore_prefixes": [], "rln_membership_indexes": []}
        return

    state: dict = {"keystore_prefixes": [], "rln_membership_indexes": []}
    try:
        for i in range(2):
            prefix = "".join(random.choices(string.ascii_lowercase, k=4))
            node = WakuNode(DEFAULT_NWAKU, f"rln_reg_{i + 1}_{gen_step_id()}")
            membership_index = node.register_rln(
                rln_keystore_prefix=prefix,
                rln_creds_source=RLN_CREDENTIALS,
                rln_creds_id=str(i + 1),
            )
            state["keystore_prefixes"].append(prefix)
            state["rln_membership_indexes"].append(membership_index)
        logger.info(
            "Fleet RLN: registered %d memberships – indexes=%s  prefixes=%s",
            len(state["rln_membership_indexes"]),
            state["rln_membership_indexes"],
            state["keystore_prefixes"],
        )
    except BaseException as ex:
        logger.error("Fleet RLN: registration failed – aborting test session: %s", ex)
        pytest.exit(f"Fleet RLN registration failed – aborting session: {ex}", returncode=1)

    yield state


@pytest.fixture(autouse=True)
def patch_waku_node_start(request, monkeypatch, fleet_rln_state):
    """Monkey-patch WakuNode.start() to bootstrap every local node from the
    waku.test fleet before the test body runs.

    Active only when ``--fleet`` is passed to pytest or ``FLEET_BOOTSTRAP=true``
    is set. By default the patch is a no-op so all existing tests are unaffected.

    The patch is transparent to existing tests:
    - Any ``staticnode`` kwarg already provided is preserved; the fleet
      multiaddr is *appended* as an additional entry.
    - ``dns_discovery`` and ``dns_discovery_url`` are set only if the caller
      has not already supplied them (``setdefault`` semantics).
    - When ``fleet_rln_state`` contains registered credentials AND the caller
      has not provided explicit RLN args, RLN credentials are injected
      automatically so that the node can participate in the fleet's
      RLN-protected relay.
    """
    if not _fleet_bootstrap_enabled(request.config):
        logger.info("Fleet bootstrap inactive – pass --fleet (or set FLEET_BOOTSTRAP=true) " "to connect local nodes to the waku.test fleet")
        yield
        return

    from src.node.waku_node import WakuNode
    from src.env_vars import RLN_CREDENTIALS

    original_start = WakuNode.start

    def fleet_joined_start(self, wait_for_node_sec=20, use_wrapper=False, **kwargs):
        logger.debug("fleet_joined_start: injecting waku.test bootstrap args into WakuNode.start()")

        # Escape-hatch: callers that set skip_fleet_peering=True (e.g. lightpush client
        # nodes that have no RLN membership) bypass all fleet bootstrap injection so
        # they do NOT join the fleet relay mesh.  discv5_bootstrap_node is still stripped
        # to prevent accidental local-node coupling.  All other kwargs are forwarded as-is.
        if kwargs.pop("skip_fleet_peering", False):
            if "discv5_bootstrap_node" in kwargs:
                del kwargs["discv5_bootstrap_node"]
            logger.debug(
                "fleet_joined_start: skip_fleet_peering=True – bypassing fleet bootstrap " "for this node (no fleet staticnode / shard injected)"
            )
            return original_start(self, wait_for_node_sec=wait_for_node_sec, use_wrapper=use_wrapper, **kwargs)

        # Determine which fleet peer to connect to based on node creation order
        # within the current test (DS.waku_nodes is reset to [] before each test).
        # The append to DS.waku_nodes happens inside _start_docker/_start_wrapper,
        # *after* this function returns, so len() here reflects the count of nodes
        # already fully started.
        node_index = len(DS.waku_nodes)
        if node_index == 0:
            # First node started → NODE1 → mirrors config-n1.toml
            fleet_multiaddr = FLEET_N1_MULTIADDR  # node-01.do-ams3.waku.test.status.im
            logger.debug("fleet_joined_start: NODE1 – bootstrapping from config-n1.toml (%s)", fleet_multiaddr)
        elif node_index == 1:
            # Second node started → NODE2 → mirrors config-n2.toml
            fleet_multiaddr = FLEET_N2_MULTIADDR  # node-01.gc-us-central1-a.waku.test.status.im
            logger.debug("fleet_joined_start: NODE2 – bootstrapping from config-n2.toml (%s)", fleet_multiaddr)
        else:
            # Additional nodes fall back to the primary (Amsterdam) fleet peer
            fleet_multiaddr = FLEET_PRIMARY_MULTIADDR
            logger.debug("fleet_joined_start: additional node %d – bootstrapping from primary (%s)", node_index, fleet_multiaddr)

        _append_fleet_kwarg(kwargs, "staticnode", fleet_multiaddr)
        kwargs.setdefault("dns_discovery", "true")
        kwargs.setdefault("dns_discovery_url", FLEET_DNS_DISCOVERY_URL)
        # Align local node cluster and shards with the fleet node configs
        # (config-n1.toml / config-n2.toml both use cluster-id=1, shards 0-7).
        kwargs.setdefault("cluster_id", FLEET_CLUSTER_ID)
        kwargs.setdefault("shard", list(range(8)))

        # Inject session-level RLN credentials into nodes that don't already
        # carry explicit RLN args (i.e. the regular waku_test_fleet tests that
        # are not themselves RLN tests).  Uses the same node_index as the fleet
        # multiaddr assignment so NODE1 gets creds-id=1 and NODE2 gets creds-id=2.
        # Only inject into nodes with relay enabled – filter/lightpush/store service
        # nodes run without relay and nwaku rejects rln-relay when WakuRelay is not mounted.
        if fleet_rln_state["keystore_prefixes"] and kwargs.get("rln_creds_source") is None:
            if str(kwargs.get("relay", "")).lower() == "true":
                if node_index < len(fleet_rln_state["keystore_prefixes"]):
                    kwargs["rln_creds_source"] = RLN_CREDENTIALS
                    kwargs["rln_creds_id"] = str(node_index + 1)
                    kwargs["rln_keystore_prefix"] = fleet_rln_state["keystore_prefixes"][node_index]
                    kwargs["rln_relay_membership_index"] = str(fleet_rln_state["rln_membership_indexes"][node_index])
                    kwargs.setdefault("rln_relay_user_message_limit", "300")
                    logger.debug(
                        "fleet_joined_start: injected session RLN for node %d – prefix=%s  index=%s  user_message_limit=300",
                        node_index,
                        kwargs["rln_keystore_prefix"],
                        kwargs["rln_relay_membership_index"],
                    )
            else:
                logger.debug(
                    "fleet_joined_start: skipping RLN injection for node %d – relay not enabled (relay=%r)",
                    node_index,
                    kwargs.get("relay"),
                )

        # Strip any local-node discv5 bootstrap ENR so that each node bootstraps
        # independently from its assigned fleet peer rather than from another local
        # container.  The fleet DNS tree (dns_discovery_url) replaces it.
        if "discv5_bootstrap_node" in kwargs:
            logger.debug(
                "fleet_joined_start: dropping local discv5_bootstrap_node=%s " "(fleet DNS discovery replaces it)",
                kwargs["discv5_bootstrap_node"],
            )
            del kwargs["discv5_bootstrap_node"]

        logger.debug(
            "fleet_joined_start: staticnode=%s  dns_discovery_url=%s",
            kwargs.get("staticnode"),
            kwargs.get("dns_discovery_url"),
        )
        return original_start(self, wait_for_node_sec=wait_for_node_sec, use_wrapper=use_wrapper, **kwargs)

    monkeypatch.setattr(WakuNode, "start", fleet_joined_start)
    logger.info(
        "Fleet bootstrap patch active – NODE1→%s  NODE2→%s  (additional nodes→%s)  dns_discovery_url=%s",
        FLEET_N1_MULTIADDR,
        FLEET_N2_MULTIADDR,
        FLEET_PRIMARY_MULTIADDR,
        FLEET_DNS_DISCOVERY_URL,
    )
    yield


@pytest.fixture(scope="function", autouse=True)
def skip_fleet_test_without_rln(request, fleet_rln_state):
    """Skip tests marked @pytest.mark.waku_test_fleet when no RLN keystore is
    available for the current session.

    When fleet bootstrap is active but RLN credentials were not set (or
    on-chain registration failed), local nodes cannot join the fleet relay mesh
    (which enforces RLN), so every fleet-marked test would ERROR instead of
    giving useful signal.  An explicit skip with a clear reason is cleaner.
    """
    if not _fleet_bootstrap_enabled(request.config):
        return
    if not request.node.get_closest_marker("waku_test_fleet"):
        return
    if not fleet_rln_state.get("keystore_prefixes"):
        pytest.skip("Skipping fleet test: RLN keystore not available " "(RLN_CREDENTIALS not set or on-chain registration failed)")


@pytest.fixture(autouse=True)
def patch_fleet_cluster_config(request, monkeypatch):
    """When --fleet is active, override every step-class pubsub-topic attribute and
    any module-level VALID_PUBSUB_TOPICS reference used in @pytest.mark.waku_test_fleet
    tests so that local Docker nodes use cluster-id=1, shards 0-7 – matching the
    fleet node configs (config-n1.toml / config-n2.toml).

    Without this patch the step classes default to VALID_PUBSUB_TOPICS (cluster-id
    198) which the fleet nodes do not subscribe to, so no cross-fleet data flow
    would actually be exercised.
    """
    if not _fleet_bootstrap_enabled(request.config):
        yield
        return

    from src.steps.relay import StepsRelay
    from src.steps.filter import StepsFilter
    from src.steps.light_push import StepsLightPush
    from src.steps.store import StepsStore
    from src.steps.rln import StepsRLN
    import tests.relay.test_publish as _relay_publish_mod

    # Step-class attributes: each class has test_pubsub_topic set to a cluster-198
    # topic.  Override them to the matching cluster-1 shard.
    #   StepsRelay  → VALID_PUBSUB_TOPICS[1]  → FLEET_PUBSUB_TOPICS[1]  (/waku/2/rs/1/1)
    #   StepsFilter → VALID_PUBSUB_TOPICS[1]  → FLEET_PUBSUB_TOPICS[1]
    #               second_pubsub_topic is VALID_PUBSUB_TOPICS[2] → FLEET_PUBSUB_TOPICS[2]
    #   StepsLightPush → VALID_PUBSUB_TOPICS[0] → FLEET_PUBSUB_TOPICS[0] (/waku/2/rs/1/0)
    #   StepsStore     → VALID_PUBSUB_TOPICS[0] → FLEET_PUBSUB_TOPICS[0]
    #   StepsRLN    → PUBSUB_TOPICS_RLN[0] (/waku/2/rs/198/0) → FLEET_PUBSUB_TOPICS[0] (/waku/2/rs/1/0)
    monkeypatch.setattr(StepsRelay, "test_pubsub_topic", FLEET_PUBSUB_TOPICS[1])
    monkeypatch.setattr(StepsFilter, "test_pubsub_topic", FLEET_PUBSUB_TOPICS[1])
    monkeypatch.setattr(StepsFilter, "second_pubsub_topic", FLEET_PUBSUB_TOPICS[2])
    monkeypatch.setattr(StepsLightPush, "test_pubsub_topic", FLEET_PUBSUB_TOPICS[0])
    monkeypatch.setattr(StepsStore, "test_pubsub_topic", FLEET_PUBSUB_TOPICS[0])
    monkeypatch.setattr(StepsRLN, "test_pubsub_topic", FLEET_PUBSUB_TOPICS[0])

    # tests/relay/test_publish.py::test_publish_on_multiple_pubsub_topics has a
    # @pytest.mark.waku_test_fleet marker and iterates over the module-level
    # VALID_PUBSUB_TOPICS import directly.  Patch that binding so the test uses
    # cluster-1 topics instead.
    monkeypatch.setattr(_relay_publish_mod, "VALID_PUBSUB_TOPICS", FLEET_PUBSUB_TOPICS)

    # ── Light-push client topology fix ──────────────────────────────────────────
    # In fleet mode the 3rd node started by light-push tests (light_push_node1,
    # node_index=2) has relay=true but NO RLN membership (only 2 memberships are
    # registered in fleet_rln_state).  Connecting to a fleet peer that enforces
    # rln-relay with no credentials causes nwaku to crash, producing the
    # ConnectionResetError(54) seen in the ERROR lines.
    #
    # Fix: replace setup_lightpush_node with a fleet-aware version that
    #   1. routes lightpush requests to FLEET_N1_MULTIADDR (Amsterdam fleet node,
    #      confirmed lightpush=true in config-n1.toml) so the fleet relay network
    #      delivers messages to fleet-connected receiving_node1/node2.
    #   2. starts the client with relay=false so no RLN membership is needed.
    #   3. does NOT add the client to main_receiving_nodes (relay=false); the
    #      assertion peers remain receiving_node1 and receiving_node2 only.
    def _fleet_setup_lightpush_node(self, image, node_index, **kwargs):
        from src.node.waku_node import WakuNode

        node = WakuNode(image, f"lightpush_node{node_index}_{self.test_id}")
        fleet_kwargs = dict(kwargs)
        # Force relay=false so the node runs as a pure lightpush *client* (caller).
        # This means:
        #   - No relay protocol is mounted → no RLN membership required.
        #   - The node dials FLEET_N1_MULTIADDR via the lightpush protocol to publish
        #     messages; the fleet relay network then delivers them to the fleet-connected
        #     receiving_node1 / receiving_node2.
        # skip_fleet_peering prevents the bootstrap patch from also injecting a fleet
        # staticnode + RLN creds (which would fail for the same reason).
        # Pre-set cluster_id and shard so the pubsub topic subscriptions issued by the
        # test body match FLEET_PUBSUB_TOPICS.
        fleet_kwargs["relay"] = "false"
        fleet_kwargs["skip_fleet_peering"] = True
        fleet_kwargs.setdefault("cluster_id", FLEET_CLUSTER_ID)
        fleet_kwargs.setdefault("shard", list(range(8)))
        node.start(lightpushnode=FLEET_N1_MULTIADDR, **fleet_kwargs)
        # relay=false → do NOT add to main_receiving_nodes; assertion peers are
        # receiving_node1 and receiving_node2 only.
        self.add_node_peer(node, self.multiaddr_list)
        logger.debug(
            "fleet _fleet_setup_lightpush_node: node %d started with relay=false, " "skip_fleet_peering=True, lightpushnode=%s",
            node_index,
            FLEET_N1_MULTIADDR,
        )
        return node

    monkeypatch.setattr(StepsLightPush, "setup_lightpush_node", _fleet_setup_lightpush_node)

    logger.info(
        "Fleet cluster patch active – pubsub topics overridden to cluster-id=%s "
        "(shards 0-7, e.g. test_pubsub_topic=%s  rln_test_pubsub_topic=%s); "
        "StepsLightPush.setup_lightpush_node overridden to use fleet relay %s",
        FLEET_CLUSTER_ID,
        FLEET_PUBSUB_TOPICS[1],
        FLEET_PUBSUB_TOPICS[0],
        FLEET_N1_MULTIADDR,
    )
    yield


# See https://docs.pytest.org/en/latest/example/simple.html#making-test-result-information-available-in-fixtures
@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_makereport(item):
    outcome = yield
    rep = outcome.get_result()
    if rep.when == "call":
        setattr(item, "rep_call", rep)
        return rep
    return None


@pytest.fixture(scope="session", autouse=True)
def set_allure_env_variables():
    yield
    if os.path.isdir("allure-results") and not os.path.isfile(os.path.join("allure-results", "environment.properties")):
        logger.debug(f"Running fixture teardown: {inspect.currentframe().f_code.co_name}")
        with open(os.path.join("allure-results", "environment.properties"), "w") as outfile:
            for attribute_name in dir(env_vars):
                if attribute_name.isupper():
                    attribute_value = getattr(env_vars, attribute_name)
                    outfile.write(f"{attribute_name}={attribute_value}\n")


@pytest.fixture(scope="function", autouse=False)
def start_postgres_container():
    pg_container = start_postgres()
    yield
    stop_postgres(pg_container)


@pytest.fixture(scope="function", autouse=True)
def test_id(request):
    # setting up an unique test id to be used where needed
    logger.debug(f"Running fixture setup: {inspect.currentframe().f_code.co_name}")
    request.cls.test_id = f"{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}__{str(uuid4())}"


@pytest.fixture(scope="function", autouse=True)
def test_setup(request, test_id):
    logger.debug(f"Running test: {request.node.name} with id: {request.cls.test_id}")
    yield
    logger.debug(f"Running fixture teardown: {inspect.currentframe().f_code.co_name}")
    for file in glob.glob(os.path.join(env_vars.DOCKER_LOG_DIR, "*")):
        if os.path.getmtime(file) < time() - 3600:
            logger.debug(f"Deleting old log file: {file}")
            try:
                os.remove(file)
            except:
                logger.error("Could not delete file")


@pytest.fixture(scope="function", autouse=True)
def attach_logs_on_fail(request):
    yield
    if env_vars.RUNNING_IN_CI and hasattr(request.node, "rep_call") and request.node.rep_call.failed:
        logger.debug(f"Running fixture teardown: {inspect.currentframe().f_code.co_name}")
        logger.debug("Test failed, attempting to attach logs to the allure reports")
        for file in glob.glob(os.path.join(env_vars.DOCKER_LOG_DIR, "*" + request.cls.test_id + "*")):
            attach_allure_file(file)


@pytest.fixture(scope="function", autouse=True)
def close_open_nodes(attach_logs_on_fail):
    DS.waku_nodes = []
    yield
    logger.debug(f"Running fixture teardown: {inspect.currentframe().f_code.co_name}")
    crashed_containers = []
    for node in DS.waku_nodes:
        try:
            node.stop()
        except Exception as ex:
            if "No such container" in str(ex):
                crashed_containers.append(node.image)
            logger.error(f"Failed to stop container because of error {ex}")
    assert not crashed_containers, f"Containers {crashed_containers} crashed during the test!!!"


@pytest.fixture(scope="function", autouse=True)
def check_waku_log_errors():
    yield
    logger.debug(f"Running fixture teardown: {inspect.currentframe().f_code.co_name}")
    for node in DS.waku_nodes:
        node.check_waku_log_errors()
