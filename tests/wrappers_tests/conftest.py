import socket
import pytest
from src.test_data import DEFAULT_CLUSTER_ID


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def build_node_config(**overrides):
    config = {
        "logLevel": "DEBUG",
        "listenAddress": "0.0.0.0",
        "tcpPort": _free_port(),
        "discv5UdpPort": _free_port(),
        "restPort": _free_port(),
        "restAddress": "0.0.0.0",
        "clusterId": DEFAULT_CLUSTER_ID,
        "relay": True,
        "store": True,
        "filter": False,
        "lightpush": False,
        "peerExchange": False,
        "discv5Discovery": False,
    }
    config.update(overrides)
    return config


@pytest.fixture
def node_config():
    return build_node_config()
