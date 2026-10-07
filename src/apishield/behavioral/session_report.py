"""Batch session reports: train-style windows (N=16, stride=8) → JSON."""

from __future__ import annotations

from typing import Any

import torch

from apishield.behavioral.graphs import EndpointResolver, WindowGraph, encode_window, to_pyg_data
from apishield.behavioral.metrics import sigmoid
from apishield.behavioral.model import WindowGNN
from apishield.behavioral.windowing import (
    DEFAULT_IDLE_GAP_S,
    DEFAULT_TRAIN_STRIDE,
    DEFAULT_WINDOW_SIZE,
    group_sessions,
    windows_from_session,
)


def predict_window_score(
    model: WindowGNN,
    graph: WindowGraph,
    *,
    device: str | torch.device = "cpu",
) -> float:
    device_t = torch.device(device)
    model.to(device_t)
    model.eval()
    data = to_pyg_data(graph)
    data.batch = torch.zeros(data.x.size(0), dtype=torch.long)
    data = data.to(device_t)
    with torch.no_grad():
        logit = float(model(data).reshape(-1)[0].cpu())
    return sigmoid(logit)


def score_sessions_to_report(
    events: list[dict[str, Any]],
    model: WindowGNN,
    resolver: EndpointResolver,
    *,
    tau: float,
    window_size: int = DEFAULT_WINDOW_SIZE,
    stride: int = DEFAULT_TRAIN_STRIDE,
    idle_gap_s: float = DEFAULT_IDLE_GAP_S,
    device: str | torch.device = "cpu",
) -> dict[str, Any]:
    """
    Group JSONL events by session_id, cut the same windows used for training,
    score each window, emit one object per session.
    """

    sessions_out: list[dict[str, Any]] = []
    grouped = group_sessions(events)
    for session_id, session_events in grouped.items():
        windows = windows_from_session(
            session_id,
            session_events,
            y=0,
            attack_type="unlabeled",
            window_size=window_size,
            stride=stride,
            idle_gap_s=idle_gap_s,
        )
        window_scores = [
            predict_window_score(
                model,
                encode_window(window, resolver),
                device=device,
            )
            for window in windows
        ]
        max_score = max(window_scores) if window_scores else 0.0
        first = session_events[0] if session_events else {}
        sessions_out.append(
            {
                "session_id": session_id,
                "user_id": first.get("user_id"),
                "event_count": len(session_events),
                "window_count": len(window_scores),
                "max_attack_score": max_score,
                "flagged": bool(window_scores) and max_score >= tau,
                "window_scores": window_scores,
            }
        )

    sessions_out.sort(key=lambda row: str(row["session_id"]))
    return {
        "tau": tau,
        "window_size": window_size,
        "stride": stride,
        "idle_gap_s": idle_gap_s,
        "session_count": len(sessions_out),
        "flagged_count": sum(1 for row in sessions_out if row["flagged"]),
        "sessions": sessions_out,
    }
