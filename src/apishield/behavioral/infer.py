"""Online rolling-window session scorer."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import torch

from apishield.behavioral.graphs import EndpointResolver, encode_window, to_pyg_data
from apishield.behavioral.metrics import sigmoid
from apishield.behavioral.model import WindowGNN
from apishield.behavioral.windowing import (
    DEFAULT_INFER_STRIDE,
    DEFAULT_MIN_INFER_EVENTS,
    DEFAULT_WINDOW_SIZE,
    EventWindow,
    event_delta_seconds,
    parse_timestamp,
    window_deltas,
)


@dataclass
class SessionScore:
    session_id: str
    session_score: float
    flagged: bool
    window_scores: list[float] = field(default_factory=list)
    window_count: int = 0


@dataclass
class StreamUpdate:
    """One scored rolling window after a live event."""

    session_id: str
    event_index: int
    path: str
    method: str
    buffer_len: int
    window_score: float
    session_score: float
    flagged: bool
    first_flag: bool
    window_count: int


class RollingSessionScorer:
    """
    Append events per session_id. Score the last min(N, len) events every
    ``stride`` events (and on finalize). Session score is the max window score.
    """

    def __init__(
        self,
        model: WindowGNN,
        resolver: EndpointResolver,
        *,
        threshold: float,
        window_size: int = DEFAULT_WINDOW_SIZE,
        stride: int = DEFAULT_INFER_STRIDE,
        min_events: int = DEFAULT_MIN_INFER_EVENTS,
        idle_gap_s: float = 60.0,
        device: str | torch.device = "cpu",
    ) -> None:
        self.model = model
        self.resolver = resolver
        self.threshold = threshold
        self.window_size = window_size
        self.stride = stride
        self.min_events = min_events
        self.idle_gap_s = idle_gap_s
        self.device = torch.device(device)
        self.model.to(self.device)
        self.model.eval()
        self._buffers: dict[str, list[dict[str, Any]]] = {}
        self._scores: dict[str, list[float]] = {}

    def reset(self) -> None:
        self._buffers.clear()
        self._scores.clear()

    def push(self, event: dict[str, Any], *, end_of_session: bool = False) -> SessionScore | None:
        session_id = str(event.get("session_id") or "")
        if not session_id:
            raise ValueError("Event is missing session_id")

        buffer = self._buffers.setdefault(session_id, [])
        if (
            self.idle_gap_s > 0
            and buffer
            and event_delta_seconds(buffer[-1], event) > self.idle_gap_s
        ):
            self._flush_score(session_id, buffer, force=True)
            print(
                f"[idle-reset] session={session_id} gap>{self.idle_gap_s}s "
                "rolling window buffer cleared",
                flush=True,
            )
            buffer = []
            self._buffers[session_id] = buffer

        buffer.append(event)
        should_score = len(buffer) >= self.min_events and (
            end_of_session or len(buffer) % self.stride == 0
        )
        if should_score:
            self._flush_score(session_id, buffer, force=False)
        return self.snapshot(session_id) if should_score else None

    def apply_event(
        self,
        event: dict[str, Any],
        *,
        event_index: int,
        previously_flagged: bool = False,
    ) -> StreamUpdate | None:
        """Push one live event; return an update only when a window is scored."""

        snapshot = self.push(event)
        if snapshot is None or not snapshot.window_scores:
            return None
        return StreamUpdate(
            session_id=snapshot.session_id,
            event_index=event_index,
            path=str(event.get("path") or ""),
            method=str(event.get("method") or ""),
            buffer_len=len(self._buffers.get(snapshot.session_id) or []),
            window_score=snapshot.window_scores[-1],
            session_score=snapshot.session_score,
            flagged=snapshot.flagged,
            first_flag=snapshot.flagged and not previously_flagged,
            window_count=snapshot.window_count,
        )

    def finalize(self, session_id: str) -> SessionScore:
        buffer = self._buffers.get(session_id) or []
        if len(buffer) >= self.min_events:
            self._flush_score(session_id, buffer, force=True)
        return self.snapshot(session_id)

    def snapshot(self, session_id: str) -> SessionScore:
        scores = self._scores.get(session_id) or []
        session_score = max(scores) if scores else 0.0
        return SessionScore(
            session_id=session_id,
            session_score=session_score,
            flagged=session_score >= self.threshold if scores else False,
            window_scores=list(scores),
            window_count=len(scores),
        )

    def score_event_list(
        self,
        session_id: str,
        events: list[dict[str, Any]],
        *,
        y: int = 0,
        attack_type: str = "unknown",
    ) -> SessionScore:
        ordered = sorted(events, key=lambda row: parse_timestamp(row["timestamp"]))
        for event in ordered:
            self.push(event)
        return self.finalize(session_id)

    def _flush_score(
        self,
        session_id: str,
        buffer: list[dict[str, Any]],
        *,
        force: bool,
    ) -> None:
        if len(buffer) < self.min_events and not force:
            return
        if not buffer:
            return
        slice_events = buffer[-self.window_size :]
        if len(slice_events) < self.min_events:
            return
        window = EventWindow(
            session_id=session_id,
            stream_index=0,
            window_index=len(self._scores.get(session_id) or []),
            y=0,
            attack_type="online",
            events=slice_events,
            deltas=window_deltas(slice_events),
        )
        graph = encode_window(window, self.resolver)
        data = to_pyg_data(graph)
        data.batch = torch.zeros(data.x.size(0), dtype=torch.long)
        data = data.to(self.device)
        with torch.no_grad():
            logit = float(self.model(data).reshape(-1)[0].cpu())
        score = sigmoid(logit)
        self._scores.setdefault(session_id, []).append(score)


def load_rolling_scorer(
    checkpoint_path: str | Path,
    threshold_path: str | Path,
    spec_path: str | Path,
    *,
    stride: int | None = None,
    window_size: int | None = None,
    min_events: int | None = None,
    idle_gap_s: float | None = None,
    device: str | torch.device = "cpu",
) -> RollingSessionScorer:
    """Load a trained checkpoint + τ and return a live rolling scorer."""

    import json

    from apishield.conformance.openapi_loader import OpenAPILoader

    ckpt = torch.load(Path(checkpoint_path), map_location="cpu", weights_only=False)
    tau = float(json.loads(Path(threshold_path).read_text(encoding="utf-8"))["tau"])
    spec = OpenAPILoader().load(spec_path)
    resolver = EndpointResolver(spec)
    model = WindowGNN(
        vocab_size=len(ckpt["vocab"]),
        hidden_dim=int(ckpt.get("hidden_dim") or 64),
        dropout=float(ckpt.get("dropout") or 0.2),
    )
    model.load_state_dict(ckpt["model_state"])
    return RollingSessionScorer(
        model,
        resolver,
        threshold=tau,
        window_size=int(window_size or ckpt.get("window_size") or DEFAULT_WINDOW_SIZE),
        stride=int(
            stride
            if stride is not None
            else ckpt.get("infer_stride") or DEFAULT_INFER_STRIDE
        ),
        min_events=int(
            min_events or ckpt.get("min_infer_events") or DEFAULT_MIN_INFER_EVENTS
        ),
        idle_gap_s=float(idle_gap_s if idle_gap_s is not None else 60.0),
        device=device,
    )
