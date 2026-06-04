import re
import pytest
from src.steps.common import StepsCommon
from src.libs.custom_logger import get_custom_logger
from src.node.wrappers_manager import WrapperManager
from src.node.wrapper_helpers import (
    EventCollector,
    create_message_bindings,
    get_node_multiaddr,
    wait_for_propagated,
)
from tests.wrappers_tests.conftest import build_node_config

logger = get_custom_logger(__name__)

PROPAGATED_TIMEOUT_S = 30.0

# Matches the /tcp/<port>/ segment in a libp2p multiaddr.
TCP_PORT_RE = re.compile(r"/tcp/(\d+)/")


def _extract_tcp_port(multiaddr: str) -> int:
    match = TCP_PORT_RE.search(multiaddr)
    assert match, f"multiaddr missing /tcp/<port>/ segment: {multiaddr!r}"
    return int(match.group(1))


class TestWrapperAutoPortAllocation(StepsCommon):
    """Corner case: port 0 triggers auto-port allocation.

    Tracks logos-messaging/logos-delivery#3828. Per that PR, auto-port is
    opt-in (caller passes 0 explicitly) and only applies to tcpPort,
    discv5UdpPort and webSocketPort.
    """

    def test_auto_port_starts_node_with_tcp_and_discv5_zero(self):
        config = build_node_config(tcpPort=0, discv5UdpPort=0)

        result = WrapperManager.create_and_start(config=config)
        assert result.is_ok(), f"create_and_start failed with tcpPort=0, discv5UdpPort=0: " f"{result.err()}"

        with result.ok_value as node:
            multiaddr = get_node_multiaddr(node)
            tcp_port = _extract_tcp_port(multiaddr)

            assert tcp_port != 0, f"multiaddr still reports tcp port 0; auto-port did not " f"happen. multiaddr={multiaddr!r}"
            assert 1024 <= tcp_port <= 65535, f"auto-allocated tcp port out of range: {tcp_port} " f"(multiaddr={multiaddr!r})"

    def test_auto_port_node_can_propagate_message(self):
        # End-to-end: two nodes, sender uses auto-port for tcp + discv5.
        # restPort stays concrete because REST does not support auto-port.
        sender_collector = EventCollector()
        sender_config = build_node_config(tcpPort=0, discv5UdpPort=0)

        sender_result = WrapperManager.create_and_start(
            config=sender_config,
            event_cb=sender_collector.event_callback,
        )
        assert sender_result.is_ok(), f"sender start failed: {sender_result.err()}"

        with sender_result.ok_value as sender:
            sender_addr = get_node_multiaddr(sender)

            peer_config = build_node_config(
                tcpPort=0,
                discv5UdpPort=0,
                staticnodes=[sender_addr],
            )
            peer_result = WrapperManager.create_and_start(config=peer_config)
            assert peer_result.is_ok(), f"peer start failed: {peer_result.err()}"

            with peer_result.ok_value:
                message = create_message_bindings()
                send_result = sender.send_message(message=message)
                assert send_result.is_ok(), f"send failed: {send_result.err()}"

                request_id = send_result.ok_value
                assert request_id, "send returned empty RequestId"

                propagated = wait_for_propagated(sender_collector, request_id, PROPAGATED_TIMEOUT_S)
                assert propagated is not None, f"no message_propagated with auto-allocated ports. " f"Events: {sender_collector.events}"

    @pytest.mark.parametrize("port_field", ["tcpPort", "discv5UdpPort"])
    def test_auto_port_per_field(self, port_field):
        # Each auto-port-capable field set to 0 in isolation. restPort and
        # metricsServerPort are intentionally excluded (see class docstring).
        config = build_node_config(**{port_field: 0})

        result = WrapperManager.create_and_start(config=config)
        assert result.is_ok(), f"create_and_start failed with {port_field}=0: {result.err()}"

        with result.ok_value as node:
            multiaddr = get_node_multiaddr(node)
            tcp_port = _extract_tcp_port(multiaddr)
            assert tcp_port != 0, f"tcp port is 0 in multiaddr with {port_field}=0; " f"multiaddr={multiaddr!r}"
