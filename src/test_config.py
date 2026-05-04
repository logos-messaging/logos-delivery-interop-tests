"""Test session configuration objects.

These dataclasses carry configuration that varies between fleet and
non-fleet test runs.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class PubsubConfig:
    """Named pubsub-topic slots for a test session.

    A *default* instance uses ``VALID_PUBSUB_TOPICS`` / ``PUBSUB_TOPICS_RLN``
    (cluster-id 198).  A *fleet* instance uses ``FLEET_PUBSUB_TOPICS``
    (cluster-id 1, shards 0-7).
    """

    relay_test_topic: str
    filter_test_topic: str
    filter_second_topic: str
    lightpush_test_topic: str
    store_test_topic: str
    rln_test_topic: str
    all_topics: List[str]
