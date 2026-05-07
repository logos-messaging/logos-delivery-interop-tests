import pytest
from src.env_vars import NODE_2
from src.steps.store import StepsStore


class TestRunningNodes(StepsStore):
    def test_main_node_relay_and_store__peer_relay_and_store(self):
        self.setup_first_publishing_node(store="true", relay="true")
        self.setup_first_store_node(store="true", relay="true")
        self.subscribe_to_pubsub_topics_via_relay()
        self.publish_message()
        self.check_published_message_is_stored(page_size=5, ascending="true")

    def test_main_node_relay_and_store__peer_only_store(self):
        self.setup_first_publishing_node(store="true", relay="true")
        self.setup_first_store_node(store="true", relay="false")
        self.subscribe_to_pubsub_topics_via_relay()
        self.publish_message()
        self.check_store_returns_empty_response()

    def test_main_node_relay_and_store__peer_only_relay(self):
        self.setup_first_publishing_node(store="true", relay="true")
        self.setup_first_store_node(store="false", relay="true")
        self.subscribe_to_pubsub_topics_via_relay()
        self.publish_message()
        self.check_published_message_is_stored(page_size=5, ascending="true")

    def test_main_node_relay_and_store__peer_neither_relay_nor_store(self):
        self.setup_first_publishing_node(store="true", relay="true")
        self.setup_first_store_node(store="false", relay="false")
        self.subscribe_to_pubsub_topics_via_relay()
        self.publish_message()
        self.check_published_message_is_stored(page_size=5, ascending="true")

    def test_main_node_only_relay__peer_relay_and_store(self):
        self.setup_first_publishing_node(store="false", relay="true")
        self.setup_first_store_node(store="true", relay="true")
        self.subscribe_to_pubsub_topics_via_relay()
        self.publish_message()
        self.check_published_message_is_stored(page_size=5, ascending="true")

    def test_main_node_only_relay__peer_only_store(self):
        self.setup_first_publishing_node(store="false", relay="true")
        self.setup_first_store_node(store="true", relay="false")
        self.subscribe_to_pubsub_topics_via_relay()
        self.publish_message()
        self.check_store_returns_empty_response()

    def test_main_node_only_relay__peer_only_relay(self):
        self.setup_first_publishing_node(store="false", relay="true")
        self.setup_first_store_node(store="false", relay="true")
        self.subscribe_to_pubsub_topics_via_relay()
        self.publish_message()
        try:
            self.check_published_message_is_stored(page_size=5, ascending="true")
        except Exception as ex:
            assert "failed to negotiate protocol: protocols not supported" in str(ex) or "PEER_DIAL_FAILURE" in str(ex)

    @pytest.mark.smoke
    def test_store_lightpushed_message(self):
        self.setup_first_publishing_node(store="true", relay="true", lightpush="true")
        self.setup_second_publishing_node(store="false", relay="true")
        self.setup_first_store_node(store="false", relay="true", lightpush="true", lightpushnode=self.multiaddr_list[0])
        self.subscribe_to_pubsub_topics_via_relay()
        self.publish_message(via="lightpush", sender=self.store_node1)
        self.check_published_message_is_stored(page_size=5, ascending="true")

    @pytest.mark.smoke
    def test_store_with_filter(self):
        self.setup_first_publishing_node(store="true", relay="true", filter="true")
        self.setup_first_store_node(store="false", relay="false", filter="true")
        self.subscribe_to_pubsub_topics_via_relay()
        self.publish_message()
        self.check_published_message_is_stored(page_size=5, ascending="true")
