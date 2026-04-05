import pytest
from src.node.wrappers_manager import WrapperManager


@pytest.mark.smoke
class TestLogosDeliveryLifecycle:
    def test_create_and_start_node(self, node_config):
        result = WrapperManager.create_and_start(config=node_config)
        assert result.is_ok(), f"Failed to create and start node: {result.err()}"
        node = result.ok_value

        stop_result = node.stop_and_destroy()
        assert stop_result.is_ok(), f"Failed to stop and destroy node: {stop_result.err()}"

    def test_create_node_without_starting(self, node_config):
        result = WrapperManager.create(config=node_config)
        assert result.is_ok(), f"Failed to create node: {result.err()}"
        node = result.ok_value

        start_result = node.start_node()
        assert start_result.is_ok(), f"Failed to start node: {start_result.err()}"

        stop_result = node.stop_and_destroy()
        assert stop_result.is_ok(), f"Failed to stop and destroy node: {stop_result.err()}"

    def test_stop_node_without_destroy(self, node_config):
        result = WrapperManager.create_and_start(config=node_config)
        assert result.is_ok(), f"Failed to create and start node: {result.err()}"
        node = result.ok_value

        stop_result = node.stop_node()
        assert stop_result.is_ok(), f"Failed to stop node: {stop_result.err()}"

        destroy_result = node.destroy()
        assert destroy_result.is_ok(), f"Failed to destroy node: {destroy_result.err()}"
