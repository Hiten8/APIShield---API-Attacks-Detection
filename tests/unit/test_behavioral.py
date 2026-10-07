"""Unit tests for rolling-window graphs, labels, splits, and (optional) GNN bits."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from apishield.behavioral.graphs import EndpointResolver, encode_window
from apishield.behavioral.labels import label_from_path
from apishield.behavioral.metrics import average_precision, choose_threshold, roc_auc
from apishield.behavioral.splits import split_session_ids
from apishield.behavioral.windowing import (
    EventWindow,
    slice_stream,
    split_on_idle_gap,
    windows_from_session,
)

MINI_SPEC = {
    "paths": {
        "/identity/api/auth/login": {"post": {}},
        "/workshop/api/shop/products": {"get": {}},
        "/workshop/api/shop/orders": {"post": {}},
        "/workshop/api/shop/orders/all": {"get": {}},
        "/workshop/api/shop/orders/{order_id}": {"get": {}, "put": {}},
        "/workshop/api/management/users/all": {"get": {}},
        "/workshop/api/mechanic/": {"get": {}},
        "/workshop/api/mechanic/service_requests": {"get": {}},
        "/workshop/api/mechanic/mechanic_report": {"get": {}},
    }
}


def _ts(seconds: int) -> str:
    return (
        datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc) + timedelta(seconds=seconds)
    ).isoformat().replace("+00:00", "Z")


def _event(session: str, index: int, method: str, path: str, status: int = 200) -> dict:
    return {
        "event_id": f"{session}-{index}",
        "timestamp": _ts(index),
        "user_id": "u1",
        "session_id": session,
        "method": method,
        "path": path,
        "endpoint": path,
        "response_status": status,
        "target_service": "crapi",
    }


def test_labels_come_from_filename_not_status():
    y, kind = label_from_path("data/raw/shop_workshop_bfla.jsonl")
    assert y == 1
    assert kind == "bfla"
    y, kind = label_from_path("shop_sessions.jsonl")
    assert y == 0
    assert kind == "normal_shop"


def test_slice_stream_short_session_is_one_window():
    events = [_event("s", i, "GET", "/workshop/api/shop/products") for i in range(5)]
    slices = slice_stream(events, window_size=16, stride=8)
    assert len(slices) == 1
    assert len(slices[0]) == 5


def test_slice_stream_rolls_with_stride_and_covers_tail():
    events = [_event("s", i, "GET", "/x") for i in range(20)]
    slices = slice_stream(events, window_size=16, stride=8)
    assert [len(item) for item in slices] == [16, 16]
    assert slices[0][0]["event_id"] == "s-0"
    assert slices[1][0]["event_id"] == "s-4"


def test_idle_gap_splits_stream():
    events = [
        _event("s", 0, "GET", "/a"),
        _event("s", 1, "GET", "/b"),
        _event("s", 90, "GET", "/c"),
    ]
    streams = split_on_idle_gap(events, idle_gap_s=60)
    assert len(streams) == 2
    assert [e["path"] for e in streams[0]] == ["/a", "/b"]
    assert [e["path"] for e in streams[1]] == ["/c"]


def test_template_collapse_merges_order_ids():
    resolver = EndpointResolver(MINI_SPEC)
    events = [
        _event("s", 0, "POST", "/identity/api/auth/login"),
        _event("s", 1, "GET", "/workshop/api/shop/orders/8"),
        _event("s", 2, "GET", "/workshop/api/shop/orders/26"),
        _event("s", 3, "GET", "/workshop/api/shop/orders/20"),
    ]
    window = EventWindow(
        session_id="s",
        stream_index=0,
        window_index=0,
        y=1,
        attack_type="enumeration",
        events=events,
        deltas=[1.0, 0.2, 0.1],
    )
    graph = encode_window(window, resolver)
    order_nodes = [n for n in graph.nodes if "orders/{order_id}" in n.key]
    assert len(order_nodes) == 1
    assert order_nodes[0].visit_count == 3
    key, template, _vid = resolver.resolve("GET", "/workshop/api/shop/orders/99")
    assert template == "/workshop/api/shop/orders/{order_id}"
    static, static_t, _ = resolver.resolve("GET", "/workshop/api/shop/orders/all")
    assert static_t == "/workshop/api/shop/orders/all"
    self_loops = [e for e in graph.edges if e.src == e.dst]
    assert self_loops
    assert self_loops[0].count == 2


def test_bfla_window_contains_privileged_nodes():
    resolver = EndpointResolver(MINI_SPEC)
    events = [
        _event("s", 0, "POST", "/identity/api/auth/login"),
        _event("s", 1, "GET", "/workshop/api/shop/orders/all"),
        _event("s", 2, "GET", "/workshop/api/management/users/all"),
        _event("s", 3, "GET", "/workshop/api/mechanic/"),
        _event("s", 4, "GET", "/workshop/api/mechanic/mechanic_report", 400),
    ]
    windows = windows_from_session(
        "s",
        events,
        y=1,
        attack_type="bfla",
        window_size=16,
        stride=8,
    )
    assert len(windows) == 1
    graph = encode_window(windows[0], resolver)
    keys = {node.key for node in graph.nodes}
    assert "GET /workshop/api/management/users/all" in keys
    assert any("mechanic" in key for key in keys)


def test_split_does_not_leak_session_ids():
    sessions = []
    for kind in ("normal_shop", "enumeration", "bfla"):
        for i in range(10):
            sessions.append((f"{kind}-{i}", kind))
    assignment = split_session_ids(sessions, seed=42)
    assert len(assignment) == 30
    inverted: dict[str, set[str]] = {"train": set(), "val": set(), "test": set()}
    for session_id, split in assignment.items():
        inverted[split].add(session_id)
    assert inverted["train"].isdisjoint(inverted["val"])
    assert inverted["train"].isdisjoint(inverted["test"])
    assert inverted["val"].isdisjoint(inverted["test"])
    for kind in ("normal_shop", "enumeration", "bfla"):
        kinds = [assignment[f"{kind}-{i}"] for i in range(10)]
        assert "train" in kinds
        assert "val" in kinds
        assert "test" in kinds


def test_metrics_and_threshold():
    y = [0, 0, 1, 1]
    scores = [0.1, 0.2, 0.8, 0.9]
    assert roc_auc(y, scores) == 1.0
    assert average_precision(y, scores) == 1.0
    chosen = choose_threshold(y, scores, target_fpr=0.05)
    assert chosen["tau"] > 0.2


def test_infer_session_score_is_max_window(monkeypatch):
    torch = pytest.importorskip("torch")
    pytest.importorskip("torch_geometric")
    from apishield.behavioral.infer import RollingSessionScorer
    from apishield.behavioral.model import WindowGNN

    resolver = EndpointResolver(MINI_SPEC)
    model = WindowGNN(vocab_size=resolver.vocab_size)

    values = [0.0, 4.0, 1.0, 1.0, 1.0]
    logits = iter(values)

    def fake_forward(_self, _data):
        return torch.tensor([next(logits)], dtype=torch.float)

    monkeypatch.setattr(WindowGNN, "forward", fake_forward)
    scorer = RollingSessionScorer(
        model,
        resolver,
        threshold=0.5,
        window_size=4,
        stride=2,
        min_events=4,
    )
    events = [
        _event("s", i, "GET", "/workshop/api/shop/orders/all") for i in range(8)
    ]
    for event in events:
        scorer.push(event)
    result = scorer.finalize("s")
    assert result.window_count >= 1
    assert result.session_score == max(result.window_scores)
    assert result.flagged is True


def test_apply_event_can_flag_before_session_ends(monkeypatch):
    torch = pytest.importorskip("torch")
    pytest.importorskip("torch_geometric")
    from apishield.behavioral.infer import RollingSessionScorer
    from apishield.behavioral.model import WindowGNN

    resolver = EndpointResolver(MINI_SPEC)
    model = WindowGNN(vocab_size=resolver.vocab_size)
    # Stay below τ for first scored window, then jump above.
    logits = iter([-4.0, 6.0, 6.0, 6.0, 6.0])

    def fake_forward(_self, _data):
        return torch.tensor([next(logits)], dtype=torch.float)

    monkeypatch.setattr(WindowGNN, "forward", fake_forward)
    scorer = RollingSessionScorer(
        model,
        resolver,
        threshold=0.5,
        window_size=4,
        stride=1,
        min_events=4,
    )
    flagged_at = None
    previously = False
    for i in range(8):
        update = scorer.apply_event(
            _event("s", i, "GET", f"/workshop/api/shop/orders/{i+1}"),
            event_index=i + 1,
            previously_flagged=previously,
        )
        if update is None:
            continue
        if update.first_flag:
            flagged_at = update.event_index
            previously = True
    assert flagged_at is not None
    assert flagged_at < 8
    assert scorer.snapshot("s").flagged is True


def test_gine_forward_on_batched_graphs():
    torch = pytest.importorskip("torch")
    pytest.importorskip("torch_geometric")
    from torch_geometric.loader import DataLoader

    from apishield.behavioral.graphs import to_pyg_data
    from apishield.behavioral.model import WindowGNN

    resolver = EndpointResolver(MINI_SPEC)
    events_a = [
        _event("a", i, "GET", f"/workshop/api/shop/orders/{i+1}") for i in range(6)
    ]
    events_b = [
        _event("b", 0, "POST", "/identity/api/auth/login"),
        _event("b", 1, "GET", "/workshop/api/management/users/all"),
    ]
    graphs = []
    for session, events, y, kind in (
        ("a", events_a, 1, "enumeration"),
        ("b", events_b, 1, "bfla"),
    ):
        windows = windows_from_session(
            session, events, y=y, attack_type=kind, window_size=16, stride=8
        )
        graphs.append(encode_window(windows[0], resolver))
    loader = DataLoader([to_pyg_data(g) for g in graphs], batch_size=2)
    model = WindowGNN(vocab_size=resolver.vocab_size)
    batch = next(iter(loader))
    logits = model(batch)
    assert logits.shape[0] == 2
    assert batch.y.numel() == 2
    assert batch.graph_attr.size(0) == 2


def test_session_report_collects_window_scores(monkeypatch):
    pytest.importorskip("torch")
    pytest.importorskip("torch_geometric")
    from apishield.behavioral.model import WindowGNN
    from apishield.behavioral.session_report import score_sessions_to_report

    resolver = EndpointResolver(MINI_SPEC)
    model = WindowGNN(vocab_size=resolver.vocab_size)
    scores = iter([0.2, 0.9, 0.4])

    monkeypatch.setattr(
        "apishield.behavioral.session_report.predict_window_score",
        lambda *args, **kwargs: next(scores),
    )
    events = [
        _event("sess-a", i, "GET", f"/workshop/api/shop/orders/{i+1}")
        for i in range(20)
    ]
    events.extend(
        [
            _event("sess-b", i, "GET", "/workshop/api/shop/orders/all")
            for i in range(5)
        ]
    )
    report = score_sessions_to_report(
        events,
        model,
        resolver,
        tau=0.5,
        window_size=16,
        stride=8,
    )
    by_id = {row["session_id"]: row for row in report["sessions"]}
    assert by_id["sess-a"]["event_count"] == 20
    assert by_id["sess-a"]["window_count"] == 2
    assert by_id["sess-a"]["window_scores"] == [0.2, 0.9]
    assert by_id["sess-a"]["max_attack_score"] == 0.9
    assert by_id["sess-a"]["flagged"] is True
    assert by_id["sess-b"]["event_count"] == 5
    assert by_id["sess-b"]["window_count"] == 1
    assert by_id["sess-b"]["flagged"] is False
    assert report["session_count"] == 2

