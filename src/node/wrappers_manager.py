from pathlib import Path
import sys

WRAPPER_DIR = Path(__file__).resolve().parents[2] / "third_party" / "logos-delivery-python-bindings" / "waku"
sys.path.insert(0, str(WRAPPER_DIR))

# from wrapper import NodeWrapper


def wrapper_create_node(config, event_cb=None, timeout_s=20.0):
    return NodeWrapper.create_node(
        config=config,
        event_cb=event_cb,
        timeout_s=timeout_s,
    )


def wrapper_create_and_start_node(config, event_cb=None, timeout_s=20.0):
    return NodeWrapper.create_and_start(
        config=config,
        event_cb=event_cb,
        timeout_s=timeout_s,
    )


def wrapper_stop_node(node, timeout_s=20.0):
    return node.stop_node(timeout_s=timeout_s)


def wrapper_destroy_node(node, timeout_s=20.0):
    return node.destroy(timeout_s=timeout_s)


def wrapper_stop_and_destroy_node(node, timeout_s=20.0):
    return node.stop_and_destroy(timeout_s=timeout_s)


def wrapper_subscribe(node, content_topic, timeout_s=20.0):
    return node.subscribe_content_topic(
        content_topic=content_topic,
        timeout_s=timeout_s,
    )


def wrapper_unsubscribe(node, content_topic, timeout_s=20.0):
    return node.unsubscribe_content_topic(
        content_topic=content_topic,
        timeout_s=timeout_s,
    )
