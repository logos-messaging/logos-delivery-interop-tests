"""Fleet bootstrap configuration for WakuNode.

When fleet bootstrap is active (``--fleet`` CLI flag or ``FLEET_BOOTSTRAP=true``
env var), an instance of :class:`FleetBootstrapConfig` is assigned to
``WakuNode._pre_start_hook``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from src.libs.custom_logger import get_custom_logger
from src.data_storage import DS
from src.env_vars import (
    FLEET_N1_MULTIADDR,
    FLEET_N2_MULTIADDR,
    FLEET_PRIMARY_MULTIADDR,
    FLEET_DNS_DISCOVERY_URL,
    RLN_CREDENTIALS,
)
from src.test_data import FLEET_CLUSTER_ID

if TYPE_CHECKING:
    from src.node.waku_node import WakuNode

logger = get_custom_logger(__name__)


def _append_fleet_kwarg(kwargs: dict, key: str, value: Any) -> None:
    """Append *value* to the kwargs entry *key*, creating a list when needed."""
    existing = kwargs.get(key)
    if existing is None:
        kwargs[key] = value
    elif isinstance(existing, list):
        if value not in existing:
            kwargs[key] = existing + [value]
    else:
        if existing != value:
            kwargs[key] = [existing, value]


@dataclass
class FleetBootstrapConfig:
    """Holds fleet session state and implements the pre-start kwargs injection.

    One instance is created per pytest session when fleet bootstrap is active.
    It is registered as ``WakuNode._pre_start_hook`` so that every call to
    ``WakuNode.start()`` automatically receives fleet bootstrap arguments.

    Bootstrap assignment by node creation order (mirrors config-n*.toml files):
      - NODE1 (1st started) → FLEET_N1_MULTIADDR (node-01.do-ams3)
      - NODE2 (2nd started) → FLEET_N2_MULTIADDR (node-01.gc-us-central1-a)
      - additional nodes    → FLEET_PRIMARY_MULTIADDR (Amsterdam, same as NODE1)
    """

    fleet_rln_state: dict

    def prepare_start_kwargs(self, node: "WakuNode", kwargs: dict) -> dict:
        """Inject fleet bootstrap arguments into *kwargs* before node start."""

        logger.debug("FleetBootstrapConfig.prepare_start_kwargs: injecting waku.test bootstrap args")

        if kwargs.pop("skip_fleet_peering", False):
            kwargs.pop("discv5_bootstrap_node", None)
            logger.debug(
                "FleetBootstrapConfig: skip_fleet_peering=True – " "bypassing fleet bootstrap for this node (no fleet staticnode / shard injected)"
            )
            return kwargs

        # Determine which fleet peer to connect to based on node creation order
        # within the current test (DS.waku_nodes is reset to [] before each test).
        node_index = len(DS.waku_nodes)
        if node_index == 0:
            fleet_multiaddr = FLEET_N1_MULTIADDR
            logger.debug(
                "FleetBootstrapConfig: NODE1 – bootstrapping from config-n1.toml (%s)",
                fleet_multiaddr,
            )
        elif node_index == 1:
            fleet_multiaddr = FLEET_N2_MULTIADDR
            logger.debug(
                "FleetBootstrapConfig: NODE2 – bootstrapping from config-n2.toml (%s)",
                fleet_multiaddr,
            )
        else:
            fleet_multiaddr = FLEET_PRIMARY_MULTIADDR
            logger.debug(
                "FleetBootstrapConfig: additional node %d – bootstrapping from primary (%s)",
                node_index,
                fleet_multiaddr,
            )

        _append_fleet_kwarg(kwargs, "staticnode", fleet_multiaddr)
        kwargs.setdefault("dns_discovery", "true")
        kwargs.setdefault("dns_discovery_url", FLEET_DNS_DISCOVERY_URL)
        kwargs.setdefault("cluster_id", FLEET_CLUSTER_ID)
        kwargs.setdefault("shard", list(range(8)))

        # Inject session-level RLN credentials into relay enabled nodes that
        # don't already carry explicit RLN args.
        rln_prefixes = self.fleet_rln_state.get("keystore_prefixes", [])
        if rln_prefixes and kwargs.get("rln_creds_source") is None:
            if str(kwargs.get("relay", "")).lower() == "true":
                if node_index < len(rln_prefixes):
                    kwargs["rln_creds_source"] = RLN_CREDENTIALS
                    kwargs["rln_creds_id"] = str(node_index + 1)
                    kwargs["rln_keystore_prefix"] = rln_prefixes[node_index]
                    kwargs["rln_relay_membership_index"] = str(self.fleet_rln_state["rln_membership_indexes"][node_index])
                    kwargs.setdefault("rln_relay_user_message_limit", "300")
                    logger.debug(
                        "FleetBootstrapConfig: injected session RLN for node %d – " "prefix=%s  index=%s  user_message_limit=300",
                        node_index,
                        kwargs["rln_keystore_prefix"],
                        kwargs["rln_relay_membership_index"],
                    )
            else:
                logger.debug(
                    "FleetBootstrapConfig: skipping RLN injection for node %d – " "relay not enabled (relay=%r)",
                    node_index,
                    kwargs.get("relay"),
                )

        # Strip any local-node discv5 bootstrap ENR so that each node bootstraps
        # independently from its assigned fleet peer rather than from another
        # local container.  The fleet DNS tree (dns_discovery_url) replaces it.
        if "discv5_bootstrap_node" in kwargs:
            logger.debug(
                "FleetBootstrapConfig: dropping local discv5_bootstrap_node=%s " "(fleet DNS discovery replaces it)",
                kwargs["discv5_bootstrap_node"],
            )
            del kwargs["discv5_bootstrap_node"]

        logger.debug(
            "FleetBootstrapConfig: staticnode=%s  dns_discovery_url=%s",
            kwargs.get("staticnode"),
            kwargs.get("dns_discovery_url"),
        )
        return kwargs
