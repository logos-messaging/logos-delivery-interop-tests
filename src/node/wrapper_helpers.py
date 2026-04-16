import json
import threading
import time


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


def is_propagated_event(event: dict) -> bool:
    return "Propagated" in event.get("eventType", "")


def is_sent_event(event: dict) -> bool:
    return "Sent" in event.get("eventType", "")


def is_error_event(event: dict) -> bool:
    return "Error" in event.get("eventType", "")


def wait_for_event(
    collector: EventCollector,
    request_id: str,
    predicate,
    timeout_s: float,
    poll_interval_s: float = 0.5,
) -> dict | None:
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


def wait_for_propagated(collector: EventCollector, request_id: str, timeout_s: float) -> dict | None:
    return wait_for_event(collector, request_id, is_propagated_event, timeout_s)


def wait_for_sent(collector: EventCollector, request_id: str, timeout_s: float) -> dict | None:
    return wait_for_event(collector, request_id, is_sent_event, timeout_s)


def wait_for_error(collector: EventCollector, request_id: str, timeout_s: float) -> dict | None:
    return wait_for_event(collector, request_id, is_error_event, timeout_s)


def get_node_multiaddr(node) -> str:
    """Return the first TCP multiaddr (with peer-id) from a WrapperManager node.

    Uses the existing get_available_node_info_ids / get_node_info APIs on
    WrapperManager.  Raises RuntimeError if the address cannot be resolved.
    """
    ids_result = node.get_available_node_info_ids()
    if ids_result.is_err():
        raise RuntimeError(f"get_available_node_info_ids failed: {ids_result.err()}")

    ids = ids_result.ok_value
    if not ids:
        raise RuntimeError("No node-info IDs returned")

    info_result = node.get_node_info(ids[0])
    if info_result.is_err():
        raise RuntimeError(f"get_node_info failed: {info_result.err()}")

    info = info_result.ok_value

    for key in ("listenAddresses", "multiaddrs", "addresses"):
        addresses = info.get(key)
        if addresses:
            return addresses[0]

    raise RuntimeError(f"Could not find a listen address in node info: {info}")
