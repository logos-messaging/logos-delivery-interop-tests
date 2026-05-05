# -*- coding: utf-8 -*-
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
from src.test_data import FLEET_CLUSTER_ID, FLEET_PUBSUB_TOPICS, PUBSUB_TOPICS_RLN, VALID_PUBSUB_TOPICS
from src.test_config import PubsubConfig

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
    """Return True when fleet bootstrap should be activated."""

    if config.getoption("--fleet", default=False):
        return True
    return os.getenv("FLEET_BOOTSTRAP", "false").lower() == "true"


@pytest.fixture(scope="session")
def fleet_rln_state(request):
    """Register 2 RLN memberships once per test session when ``--fleet`` is active."""
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


@pytest.fixture(scope="session")
def pubsub_cfg(request) -> PubsubConfig:
    """Return the pubsub-topic configuration for the current session."""

    if _fleet_bootstrap_enabled(request.config):
        return PubsubConfig(
            relay_test_topic=FLEET_PUBSUB_TOPICS[1],
            filter_test_topic=FLEET_PUBSUB_TOPICS[1],
            filter_second_topic=FLEET_PUBSUB_TOPICS[2],
            lightpush_test_topic=FLEET_PUBSUB_TOPICS[0],
            store_test_topic=FLEET_PUBSUB_TOPICS[0],
            rln_test_topic=FLEET_PUBSUB_TOPICS[0],
            all_topics=FLEET_PUBSUB_TOPICS,
        )
    return PubsubConfig(
        relay_test_topic=VALID_PUBSUB_TOPICS[1],
        filter_test_topic=VALID_PUBSUB_TOPICS[1],
        filter_second_topic=VALID_PUBSUB_TOPICS[2],
        lightpush_test_topic=VALID_PUBSUB_TOPICS[0],
        store_test_topic=VALID_PUBSUB_TOPICS[0],
        rln_test_topic=PUBSUB_TOPICS_RLN[0],
        all_topics=VALID_PUBSUB_TOPICS,
    )


@pytest.fixture(scope="session", autouse=True)
def configure_fleet_bootstrap(request, fleet_rln_state):
    """Register ``FleetBootstrapConfig`` as ``WakuNode._pre_start_hook`` for the session."""

    if not _fleet_bootstrap_enabled(request.config):
        logger.info("Fleet bootstrap inactive – pass --fleet (or set FLEET_BOOTSTRAP=true) " "to connect local nodes to the waku.test fleet")
        yield
        return

    from src.node.fleet_waku_node import FleetBootstrapConfig
    from src.node.waku_node import WakuNode

    cfg = FleetBootstrapConfig(fleet_rln_state=fleet_rln_state)
    WakuNode._pre_start_hook = cfg.prepare_start_kwargs
    logger.info(
        "Fleet bootstrap active – NODE1→%s  NODE2→%s  (additional nodes→%s)  dns_discovery_url=%s",
        FLEET_N1_MULTIADDR,
        FLEET_N2_MULTIADDR,
        FLEET_PRIMARY_MULTIADDR,
        FLEET_DNS_DISCOVERY_URL,
    )
    yield
    WakuNode._pre_start_hook = None


@pytest.fixture(scope="function", autouse=True)
def skip_fleet_test_without_rln(request, fleet_rln_state):
    """Skip tests marked @pytest.mark.waku_test_fleet when no RLN keystore is
    available for the current session.
    """
    if not _fleet_bootstrap_enabled(request.config):
        return
    if not request.node.get_closest_marker("waku_test_fleet"):
        return
    if not fleet_rln_state.get("keystore_prefixes"):
        pytest.skip("Skipping fleet test: RLN keystore not available " "(RLN_CREDENTIALS not set or on-chain registration failed)")


@pytest.fixture(scope="session", autouse=True)
def configure_fleet_cluster(request, pubsub_cfg):
    """Apply fleet cluster configuration to step classes when ``--fleet`` is active."""

    if not _fleet_bootstrap_enabled(request.config):
        yield
        return

    from src.steps.relay import StepsRelay
    from src.steps.filter import StepsFilter
    from src.steps.light_push import StepsLightPush
    from src.steps.store import StepsStore
    from src.steps.rln import StepsRLN
    import tests.relay.test_publish as _relay_publish_mod

    # Override step-class topic attributes with fleet cluster-1 topics.
    StepsRelay.test_pubsub_topic = pubsub_cfg.relay_test_topic
    StepsFilter.test_pubsub_topic = pubsub_cfg.filter_test_topic
    StepsFilter.second_pubsub_topic = pubsub_cfg.filter_second_topic
    StepsLightPush.test_pubsub_topic = pubsub_cfg.lightpush_test_topic
    StepsStore.test_pubsub_topic = pubsub_cfg.store_test_topic
    StepsRLN.test_pubsub_topic = pubsub_cfg.rln_test_topic

    # tests/relay/test_publish.py::test_publish_on_multiple_pubsub_topics iterates
    # over the module-level VALID_PUBSUB_TOPICS import directly; rebind it.
    _relay_publish_mod.VALID_PUBSUB_TOPICS = pubsub_cfg.all_topics

    def _fleet_setup_lightpush_node(self, image, node_index, **kwargs):
        from src.node.waku_node import WakuNode

        node = WakuNode(image, f"lightpush_node{node_index}_{self.test_id}")
        fleet_kwargs = dict(kwargs)
        fleet_kwargs["relay"] = "false"
        fleet_kwargs["lightpush"] = "false"
        fleet_kwargs["skip_fleet_peering"] = True
        fleet_kwargs.setdefault("cluster_id", FLEET_CLUSTER_ID)
        fleet_kwargs.setdefault("shard", list(range(8)))

        lightpush_service_addr = self.multiaddr_list[0]
        node.start(lightpushnode=lightpush_service_addr, **fleet_kwargs)
        self.add_node_peer(node, self.multiaddr_list)
        logger.debug(
            "fleet _fleet_setup_lightpush_node: node %d started with relay=false, " "skip_fleet_peering=True, lightpushnode=%s",
            node_index,
            lightpush_service_addr,
        )
        return node

    StepsLightPush.setup_lightpush_node = _fleet_setup_lightpush_node
    StepsLightPush.default_message_propagation_delay = 0.5

    logger.info(
        "Fleet cluster config active – pubsub topics overridden to cluster-id=%s "
        "(shards 0-7, e.g. relay_test_topic=%s  rln_test_topic=%s); "
        "StepsLightPush.setup_lightpush_node overridden to use receiving_node1 as "
        "lightpush service (fleet-peered with RLN membership #1; messages relay "
        "through fleet mesh to receiving_node2 peered with %s)",
        FLEET_CLUSTER_ID,
        pubsub_cfg.relay_test_topic,
        pubsub_cfg.rln_test_topic,
        FLEET_N2_MULTIADDR,
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
