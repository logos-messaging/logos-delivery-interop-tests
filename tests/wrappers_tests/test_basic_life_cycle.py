import pytest
from src.node.wrappers_manager import WrapperManager


@pytest.mark.smoke
class TestLogosDeliveryLifecycle:
    def _create_started_node(self, node_config):
        result = WrapperManager.create_and_start(config=node_config)
        assert result.is_ok(), f"Failed to create and start node: {result.err()}"
        return result.ok_value

    def test_create_and_start_node(self, node_config):
        node = self._create_started_node(node_config)

        stop_result = node.stop_and_destroy()
        assert stop_result.is_ok(), f"Failed to stop and destroy node: {stop_result.err()}"

    def test_stop_node_without_destroy(self, node_config):
        node = self._create_started_node(node_config)

        try:
            stop_result = node.stop_node()
            assert stop_result.is_ok(), f"Failed to stop node: {stop_result.err()}"
        finally:
            destroy_result = node.destroy()
            assert destroy_result.is_ok(), f"Failed to destroy node: {destroy_result.err()}"
