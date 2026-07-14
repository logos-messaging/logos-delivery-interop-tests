import pytest
from src.node.wrappers_manager import WrapperManager
from src.node.wrapper_helpers import EventCollector, create_message_bindings

CHANNEL_ID = "rc01-channel"
CONTENT_TOPIC = "/test/1/channel/proto"
SENDER_ID = "rc01-sender"

UNKNOWN_CHANNEL_ID = "rc02-unknown-channel"


@pytest.mark.smoke
class TestChannelLifecycle:
    def test_rc01_create_channel_duplicate_rejected(self, node_config):
        """RC01: create a channel; a duplicate create with the same id is rejected.

        The reliable channel manager is mounted automatically for a Core-mode
        node, so no store / --reliability is needed. No events are expected.
        """
        node_config.update({"mode": "Core"})

        collector = EventCollector()
        create_node_result = WrapperManager.create_and_start(config=node_config, event_cb=collector.event_callback)
        assert create_node_result.is_ok(), f"Failed to create and start node: {create_node_result.err()}"
        node = create_node_result.ok_value

        try:
            create_result = node.channel_create(CHANNEL_ID, CONTENT_TOPIC, SENDER_ID)
            assert create_result.is_ok(), f"channel_create failed: {create_result.err()}"
            assert create_result.ok_value == CHANNEL_ID, f"channel_create returned unexpected id: {create_result.ok_value!r}"

            duplicate_result = node.channel_create(CHANNEL_ID, CONTENT_TOPIC, SENDER_ID)
            assert duplicate_result.is_err(), f"duplicate channel_create must fail, got Ok({duplicate_result.ok_value!r})"
            assert f"channel already exists: {CHANNEL_ID}" in duplicate_result.err(), f"unexpected error message: {duplicate_result.err()!r}"

            assert collector.events == [], f"expected no events, got: {collector.events}"
        finally:
            node.stop_and_destroy()

    def test_rc02_send_on_unknown_channel_rejected(self, node_config):
        """RC02: channel_send() to an id that was never created is rejected.

        The send must Err with "unknown channel: <id>" and emit no events.
        """
        node_config.update({"mode": "Core"})

        collector = EventCollector()
        create_node_result = WrapperManager.create_and_start(config=node_config, event_cb=collector.event_callback)
        assert create_node_result.is_ok(), f"Failed to create and start node: {create_node_result.err()}"
        node = create_node_result.ok_value

        try:
            send_result = node.channel_send(UNKNOWN_CHANNEL_ID, create_message_bindings())
            assert send_result.is_err(), f"channel_send on unknown channel must fail, got Ok({send_result.ok_value!r})"
            assert f"unknown channel: {UNKNOWN_CHANNEL_ID}" in send_result.err(), f"unexpected error message: {send_result.err()!r}"

            assert collector.events == [], f"expected no events, got: {collector.events}"
        finally:
            node.stop_and_destroy()
