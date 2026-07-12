import pytest
from src.node.wrappers_manager import WrapperManager

CHANNEL_ID = "rc01-channel"
CONTENT_TOPIC = "/test/1/channel/proto"
SENDER_ID = "rc01-sender"


@pytest.mark.smoke
class TestChannelLifecycle:
    def test_rc01_create_channel_duplicate_rejected(self, node_config):
        """RC01: create a channel; a duplicate create with the same id is rejected.

        The reliable channel manager is mounted automatically for a Core-mode
        node, so no store / --reliability is needed. No events are expected.
        """
        create_node_result = WrapperManager.create_and_start(config=node_config)
        assert create_node_result.is_ok(), f"Failed to create and start node: {create_node_result.err()}"
        node = create_node_result.ok_value

        try:
            create_result = node.channel_create(CHANNEL_ID, CONTENT_TOPIC, SENDER_ID)
            assert create_result.is_ok(), f"channel_create failed: {create_result.err()}"
            assert create_result.ok_value == CHANNEL_ID, f"channel_create returned unexpected id: {create_result.ok_value!r}"

            duplicate_result = node.channel_create(CHANNEL_ID, CONTENT_TOPIC, SENDER_ID)
            assert duplicate_result.is_err(), f"duplicate channel_create must fail, got Ok({duplicate_result.ok_value!r})"
            assert f"channel already exists: {CHANNEL_ID}" in duplicate_result.err(), f"unexpected error message: {duplicate_result.err()!r}"
        finally:
            node.stop_and_destroy()
