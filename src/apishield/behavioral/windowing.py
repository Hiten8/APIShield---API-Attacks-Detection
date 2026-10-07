"""Group JSONL events into sessions and cut event-count rolling windows."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

DEFAULT_WINDOW_SIZE = 16
DEFAULT_TRAIN_STRIDE = 8
DEFAULT_INFER_STRIDE = 4
DEFAULT_IDLE_GAP_S = 60.0
DEFAULT_MIN_INFER_EVENTS = 4


def parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    if not isinstance(value, str):
        raise TypeError(f"Unsupported timestamp type: {type(value)!r}")
    text = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def event_delta_seconds(previous: dict[str, Any], current: dict[str, Any]) -> float:
    delta = (
        parse_timestamp(current["timestamp"]) - parse_timestamp(previous["timestamp"])
    ).total_seconds()
    return max(delta, 0.0)


@dataclass
class EventWindow:
    session_id: str
    stream_index: int
    window_index: int
    y: int
    attack_type: str
    events: list[dict[str, Any]] = field(default_factory=list)
    deltas: list[float] = field(default_factory=list)

    @property
    def size(self) -> int:
        return len(self.events)


def group_sessions(
    events: Iterable[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        session_id = event.get("session_id")
        if not session_id:
            raise ValueError("Event is missing session_id")
        grouped[str(session_id)].append(event)

    for session_id, rows in grouped.items():
        grouped[session_id] = sorted(rows, key=lambda row: parse_timestamp(row["timestamp"]))
    return dict(grouped)


def split_on_idle_gap(
    events: list[dict[str, Any]],
    *,
    idle_gap_s: float = DEFAULT_IDLE_GAP_S,
) -> list[list[dict[str, Any]]]:
    if not events:
        return []
    streams: list[list[dict[str, Any]]] = [[events[0]]]
    for previous, current in zip(events, events[1:]):
        if event_delta_seconds(previous, current) > idle_gap_s:
            streams.append([current])
        else:
            streams[-1].append(current)
    return streams


def slice_stream(
    events: list[dict[str, Any]],
    *,
    window_size: int = DEFAULT_WINDOW_SIZE,
    stride: int = DEFAULT_TRAIN_STRIDE,
) -> list[list[dict[str, Any]]]:
    """
    Cut a compact event stream into windows of at most ``window_size``.

    Streams shorter than N become a single window (no padding).
    """

    if window_size < 1:
        raise ValueError("window_size must be >= 1")
    if stride < 1:
        raise ValueError("stride must be >= 1")
    n = len(events)
    if n == 0:
        return []
    if n <= window_size:
        return [list(events)]

    starts = list(range(0, n - window_size + 1, stride))
    last_start = n - window_size
    if starts[-1] != last_start:
        starts.append(last_start)
    return [events[start : start + window_size] for start in starts]


def window_deltas(events: list[dict[str, Any]]) -> list[float]:
    if len(events) < 2:
        return []
    return [
        event_delta_seconds(previous, current)
        for previous, current in zip(events, events[1:])
    ]


def windows_from_session(
    session_id: str,
    events: list[dict[str, Any]],
    *,
    y: int,
    attack_type: str,
    window_size: int = DEFAULT_WINDOW_SIZE,
    stride: int = DEFAULT_TRAIN_STRIDE,
    idle_gap_s: float = DEFAULT_IDLE_GAP_S,
) -> list[EventWindow]:
    ordered = sorted(events, key=lambda row: parse_timestamp(row["timestamp"]))
    windows: list[EventWindow] = []
    for stream_index, stream in enumerate(split_on_idle_gap(ordered, idle_gap_s=idle_gap_s)):
        for window_index, slice_events in enumerate(
            slice_stream(stream, window_size=window_size, stride=stride)
        ):
            windows.append(
                EventWindow(
                    session_id=session_id,
                    stream_index=stream_index,
                    window_index=window_index,
                    y=y,
                    attack_type=attack_type,
                    events=slice_events,
                    deltas=window_deltas(slice_events),
                )
            )
    return windows


def windows_from_labeled_events(
    events: Iterable[dict[str, Any]],
    *,
    y: int,
    attack_type: str,
    window_size: int = DEFAULT_WINDOW_SIZE,
    stride: int = DEFAULT_TRAIN_STRIDE,
    idle_gap_s: float = DEFAULT_IDLE_GAP_S,
) -> list[EventWindow]:
    windows: list[EventWindow] = []
    for session_id, session_events in group_sessions(events).items():
        windows.extend(
            windows_from_session(
                session_id,
                session_events,
                y=y,
                attack_type=attack_type,
                window_size=window_size,
                stride=stride,
                idle_gap_s=idle_gap_s,
            )
        )
    return windows
