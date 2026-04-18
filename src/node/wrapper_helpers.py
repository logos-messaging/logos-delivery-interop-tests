from __future__ import annotations

import json
import threading
import time
from typing import Optional


class EventCollector:
    """Thread-safe collector for async node events.

    Pass `collector.event_callback` as the `event_cb` argument to
    WrapperManager.create_and_start().  Every event fired by the library
    is decoded from JSON and appended to `self.events`.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.events: list[dict] = []

    def event_callback(self, ret: int, raw: bytes) -> None:
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception:
            payload = {"_raw": raw.decode("utf-8", errors="replace"), "_ret": ret}

        with self._lock:
            self.events.append(payload)

    def get_events_for_request(self, request_id: str) -> list[dict]:
        with self._lock:
            return [e for e in self.events if e.get("requestId") == request_id]


# eventType values emitted by liblogosdelivery (node_api.nim:106–124)
EVENT_PROPAGATED = "message_propagated"
EVENT_SENT = "message_sent"
EVENT_ERROR = "message_error"


def is_propagated_event(event: dict) -> bool:
    return event.get("eventType") == EVENT_PROPAGATED


def is_sent_event(event: dict) -> bool:
    return event.get("eventType") == EVENT_SENT


def is_error_event(event: dict) -> bool:
    return event.get("eventType") == EVENT_ERROR


def wait_for_event(
    collector: EventCollector,
    request_id: str,
    predicate,
    timeout_s: float,
    poll_interval_s: float = 0.5,
) -> Optional[dict]:
    """Poll until an event matching `predicate` arrives for `request_id`,
    or until `timeout_s` elapses.  Returns the matching event or None.
    """
    deadline = time.monotonic() + timeout_s

    while time.monotonic() < deadline:
        for event in collector.get_events_for_request(request_id):
            if predicate(event):
                return event
        time.sleep(poll_interval_s)

    return None


def wait_for_propagated(collector: EventCollector, request_id: str, timeout_s: float) -> Optional[dict]:
    return wait_for_event(collector, request_id, is_propagated_event, timeout_s)


def wait_for_sent(collector: EventCollector, request_id: str, timeout_s: float) -> Optional[dict]:
    return wait_for_event(collector, request_id, is_sent_event, timeout_s)


def wait_for_error(collector: EventCollector, request_id: str, timeout_s: float) -> Optional[dict]:
    return wait_for_event(collector, request_id, is_error_event, timeout_s)


def get_node_multiaddr(node) -> str:
    """Return the first TCP multiaddr (with peer-id) from a WrapperManager node."""
    result = node.get_node_info_raw("MyMultiaddresses")
    if result.is_err():
        raise RuntimeError(f"get_node_info_raw failed: {result.err()}")

    addr = result.ok_value.strip()
    if not addr or not addr.startswith("/"):
        raise RuntimeError(f"Unexpected multiaddr format: {addr!r}")

    return addr
