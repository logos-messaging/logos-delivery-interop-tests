import pytest
from src.env_vars import NODE_1
from src.libs.common import delay
from src.steps.light_push import StepsLightPush


class TestMultipleNodes(StepsLightPush):
    def test_2_receiving_nodes__relay_node1_forwards_lightpushed_message_to_relay_node2(self):
        self.setup_first_receiving_node(lightpush="true", relay="true")
        self.setup_second_receiving_node(lightpush="false", relay="true")
        self.setup_first_lightpush_node(lightpush="true", relay="true")
        self.subscribe_to_pubsub_topics_via_relay()
        self.check_light_pushed_message_reaches_receiving_peer(sender=self.light_push_node1)

    def test_2_receiving_nodes__relay_node1_forwards_lightpushed_message_to_filter_node2(self):
        self.setup_first_receiving_node(lightpush="true", relay="true", filter="true")
        self.setup_second_receiving_node(lightpush="false", relay="false", filternode=self.receiving_node1.get_multiaddr_with_id())
        self.setup_first_lightpush_node(lightpush="true", relay="true")
        helper_node = self.start_receiving_node(NODE_1, node_index=4, lightpush="false", relay="true")
        self.subscribe_to_pubsub_topics_via_relay(node=[self.receiving_node1, helper_node])
        self.subscribe_to_pubsub_topics_via_filter(node=self.receiving_node2)
        self.check_light_pushed_message_reaches_receiving_peer(sender=self.light_push_node1)
        get_messages_response = self.receiving_node2.get_filter_messages(self.test_content_topic)
        assert len(get_messages_response) == 1, "Lightpushed message was not relayed to the filter node"

    @pytest.mark.skip(reason=" test has m=no meaning now as relay = false won't work , moght be used in future if relay = false work again")
    def test_2_lightpush_nodes_and_2_receiving_nodes(self):
        self.setup_first_receiving_node(lightpush="true", relay="true")
        self.setup_second_receiving_node(lightpush="false", relay="true")
        self.setup_first_lightpush_node(lightpush="true", relay="false")
        self.setup_second_lightpush_node(lightpush="true", relay="false")
        self.subscribe_to_pubsub_topics_via_relay()
        self.check_light_pushed_message_reaches_receiving_peer(sender=self.light_push_node1)
        self.check_light_pushed_message_reaches_receiving_peer(sender=self.light_push_node2)

    def test_combination_of_different_nodes(self):
        self.setup_first_receiving_node(lightpush="true", relay="true", filter="true")
        self.setup_second_receiving_node(lightpush="false", relay="false", filternode=self.receiving_node1.get_multiaddr_with_id())
        self.setup_second_lightpush_node(lightpush="true", relay="true")
        self.subscribe_to_pubsub_topics_via_relay(node=self.receiving_node1)
        self.subscribe_to_pubsub_topics_via_relay(node=self.light_push_node2)
        self.subscribe_to_pubsub_topics_via_filter(node=self.receiving_node2)
        delay(1)
        self.check_light_pushed_message_reaches_receiving_peer(sender=self.light_push_node2)
        get_messages_response = self.receiving_node2.get_filter_messages(self.test_content_topic)
        assert len(get_messages_response) == 1, "Lightpushed message was not relayed to the filter node"

    def test_multiple_receiving_nodes(self):
        self.setup_first_receiving_node(lightpush="true", relay="true")
        self.setup_additional_receiving_nodes()
        self.setup_first_lightpush_node(lightpush="true", relay="true")
        self.subscribe_to_pubsub_topics_via_relay()
        self.check_light_pushed_message_reaches_receiving_peer(sender=self.light_push_node1)

    def test_multiple_lightpush_nodes(self):
        self.setup_first_receiving_node(lightpush="true", relay="true")
        self.setup_second_receiving_node(lightpush="false", relay="true")
        self.setup_first_lightpush_node(lightpush="true", relay="true")
        self.setup_additional_lightpush_nodes()
        self.subscribe_to_pubsub_topics_via_relay()
        self.check_light_pushed_message_reaches_receiving_peer(sender=self.light_push_node1)
        for node in self.additional_lightpush_nodes:
            self.check_light_pushed_message_reaches_receiving_peer(sender=node)
