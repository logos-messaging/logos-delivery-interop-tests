"""Test session configuration objects.

These dataclasses carry configuration that varies between fleet and
non-fleet test runs.  Fixtures in ``tests/conftest.py`` build and
provide the appropriate instance; step classes and tests consume them
via fixture injection rather than through hardcoded class attributes or
``monkeypatch``.
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

    Attributes:
        relay_test_topic:      Primary topic used by ``StepsRelay`` tests.
        filter_test_topic:     Primary topic used by ``StepsFilter`` tests.
        filter_second_topic:   Secondary topic used by multi-topic filter tests.
        lightpush_test_topic:  Topic used by ``StepsLightPush`` tests.
        store_test_topic:      Topic used by ``StepsStore`` tests.
        rln_test_topic:        Topic used by ``StepsRLN`` tests.
        all_topics:            Full ordered topic list (used where a module-level
                               ``VALID_PUBSUB_TOPICS`` reference is iterated).
    """

    relay_test_topic: str
    filter_test_topic: str
    filter_second_topic: str
    lightpush_test_topic: str
    store_test_topic: str
    rln_test_topic: str
    all_topics: List[str]
