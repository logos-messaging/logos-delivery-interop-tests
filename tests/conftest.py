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
from src.libs.custom_logger import get_custom_logger
import os
import pytest
from datetime import datetime
from time import time
from uuid import uuid4
from src.libs.common import attach_allure_file
import src.env_vars as env_vars
from src.env_vars import FLEET_PRIMARY_MULTIADDR, FLEET_DNS_DISCOVERY_URL, FLEET_N1_MULTIADDR, FLEET_N2_MULTIADDR
from src.data_storage import DS
from src.postgres_setup import start_postgres, stop_postgres

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


@pytest.fixture(autouse=True)
def patch_waku_node_start(request, monkeypatch):
    """Monkey-patch WakuNode.start() to bootstrap every local node from the
    waku.test fleet before the test body runs.

    Active only when ``--fleet`` is passed to pytest or ``FLEET_BOOTSTRAP=true``
    is set. By default the patch is a no-op so all existing tests are unaffected.

    The patch is transparent to existing tests:
    - Any ``staticnode`` kwarg already provided is preserved; the fleet
      multiaddr is *appended* as an additional entry.
    - ``dns_discovery`` and ``dns_discovery_url`` are set only if the caller
      has not already supplied them (``setdefault`` semantics).
    """
    if not _fleet_bootstrap_enabled(request.config):
        logger.info("Fleet bootstrap inactive – pass --fleet (or set FLEET_BOOTSTRAP=true) " "to connect local nodes to the waku.test fleet")
        yield
        return

    from src.node.waku_node import WakuNode

    original_start = WakuNode.start

    def fleet_joined_start(self, wait_for_node_sec=20, use_wrapper=False, **kwargs):
        logger.debug("fleet_joined_start: injecting waku.test bootstrap args into WakuNode.start()")

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
