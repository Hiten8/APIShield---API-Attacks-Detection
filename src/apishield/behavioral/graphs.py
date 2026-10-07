"""Encode an event window as an OpenAPI-template transition graph."""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from typing import Any

from apishield.behavioral.windowing import EventWindow
from apishield.conformance.path_matcher import OpenAPIPathMatcher

HTTP_METHODS = frozenset(
    {"get", "post", "put", "patch", "delete", "head", "options"}
)
UNKNOWN_KEY = "UNKNOWN"


def log1p_clamp(value: float) -> float:
    return math.log1p(max(value, 0.0))


def node_key(method: str, template: str) -> str:
    return f"{method.upper()} {template}"


class EndpointResolver:
    """Map a concrete request to (METHOD, OpenAPI template) and a vocab index."""

    def __init__(self, specification: dict[str, Any]) -> None:
        self.paths = specification.get("paths") or {}
        if not isinstance(self.paths, dict):
            raise ValueError("OpenAPI specification is missing a paths object.")
        self.matcher = OpenAPIPathMatcher()
        self.vocab: dict[str, int] = {UNKNOWN_KEY: 0}
        self._build_vocab()

    def _build_vocab(self) -> None:
        for template, item in self.paths.items():
            if not isinstance(item, dict):
                continue
            for method, body in item.items():
                if method.lower() not in HTTP_METHODS:
                    continue
                if not isinstance(body, dict):
                    continue
                key = node_key(method, template)
                if key not in self.vocab:
                    self.vocab[key] = len(self.vocab)

    @property
    def vocab_size(self) -> int:
        return len(self.vocab)

    def resolve(self, method: str, path: str) -> tuple[str, str, int]:
        match = self.matcher.find_match(path, self.paths)
        if match is None:
            return UNKNOWN_KEY, UNKNOWN_KEY, self.vocab[UNKNOWN_KEY]
        template, _params = match
        key = node_key(method, template)
        index = self.vocab.get(key, self.vocab[UNKNOWN_KEY])
        if key not in self.vocab:
            key = UNKNOWN_KEY
            template = UNKNOWN_KEY
        return key, template, index


@dataclass
class GraphNode:
    key: str
    vocab_id: int
    visit_count: int
    mean_dt_in: float
    min_dt_in: float
    error_fraction: float


@dataclass
class GraphEdge:
    src: int
    dst: int
    count: int
    mean_dt: float
    min_dt: float


@dataclass
class WindowGraph:
    session_id: str
    attack_type: str
    y: int
    window_index: int
    stream_index: int
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)
    graph_attr: list[float] = field(default_factory=list)
    node_keys: list[str] = field(default_factory=list)

    def to_record(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "attack_type": self.attack_type,
            "y": self.y,
            "window_index": self.window_index,
            "stream_index": self.stream_index,
            "node_keys": self.node_keys,
            "nodes": [asdict(node) for node in self.nodes],
            "edges": [asdict(edge) for edge in self.edges],
            "graph_attr": self.graph_attr,
        }


def _local_index(key_to_local: dict[str, int], key: str) -> int:
    if key not in key_to_local:
        key_to_local[key] = len(key_to_local)
    return key_to_local[key]


def encode_window(window: EventWindow, resolver: EndpointResolver) -> WindowGraph:
    events = window.events
    deltas = window.deltas
    key_to_local: dict[str, int] = {}
    local_meta: dict[int, dict[str, Any]] = {}

    resolved: list[tuple[str, int]] = []
    for event in events:
        key, _template, vocab_id = resolver.resolve(
            str(event.get("method") or "GET"),
            str(event.get("path") or ""),
        )
        local = _local_index(key_to_local, key)
        resolved.append((key, local))
        meta = local_meta.setdefault(
            local,
            {
                "key": key,
                "vocab_id": vocab_id,
                "visits": 0,
                "inbound_dts": [],
                "statuses": [],
            },
        )
        meta["visits"] += 1
        status = event.get("response_status")
        meta["statuses"].append(status)

    edge_agg: dict[tuple[int, int], list[float]] = defaultdict(list)
    for index, delta in enumerate(deltas):
        _src_key, src = resolved[index]
        _dst_key, dst = resolved[index + 1]
        edge_agg[(src, dst)].append(delta)
        local_meta[dst]["inbound_dts"].append(delta)

    nodes: list[GraphNode] = []
    node_keys = [""] * len(key_to_local)
    for local, meta in sorted(local_meta.items()):
        inbound = meta["inbound_dts"]
        statuses = [s for s in meta["statuses"] if isinstance(s, int)]
        errors = sum(1 for status in statuses if status >= 400)
        mean_dt = sum(inbound) / len(inbound) if inbound else 0.0
        min_dt = min(inbound) if inbound else 0.0
        error_fraction = (errors / len(statuses)) if statuses else 0.0
        node_keys[local] = meta["key"]
        nodes.append(
            GraphNode(
                key=meta["key"],
                vocab_id=int(meta["vocab_id"]),
                visit_count=int(meta["visits"]),
                mean_dt_in=mean_dt,
                min_dt_in=min_dt,
                error_fraction=error_fraction,
            )
        )

    edges: list[GraphEdge] = []
    max_self_loop = 0
    all_dts = list(deltas)
    for (src, dst), dts in edge_agg.items():
        count = len(dts)
        if src == dst:
            max_self_loop = max(max_self_loop, count)
        edges.append(
            GraphEdge(
                src=src,
                dst=dst,
                count=count,
                mean_dt=sum(dts) / count,
                min_dt=min(dts),
            )
        )

    mean_dt = sum(all_dts) / len(all_dts) if all_dts else 0.0
    min_dt = min(all_dts) if all_dts else 0.0
    graph_attr = [
        log1p_clamp(float(len(events))),
        log1p_clamp(mean_dt),
        log1p_clamp(min_dt),
        log1p_clamp(float(len(nodes))),
        log1p_clamp(float(max_self_loop)),
    ]

    return WindowGraph(
        session_id=window.session_id,
        attack_type=window.attack_type,
        y=window.y,
        window_index=window.window_index,
        stream_index=window.stream_index,
        nodes=nodes,
        edges=edges,
        graph_attr=graph_attr,
        node_keys=node_keys,
    )


def window_graph_from_record(record: dict[str, Any]) -> WindowGraph:
    nodes = [
        GraphNode(
            key=row["key"],
            vocab_id=int(row["vocab_id"]),
            visit_count=int(row["visit_count"]),
            mean_dt_in=float(row["mean_dt_in"]),
            min_dt_in=float(row["min_dt_in"]),
            error_fraction=float(row["error_fraction"]),
        )
        for row in record.get("nodes") or []
    ]
    edges = [
        GraphEdge(
            src=int(row["src"]),
            dst=int(row["dst"]),
            count=int(row["count"]),
            mean_dt=float(row["mean_dt"]),
            min_dt=float(row["min_dt"]),
        )
        for row in record.get("edges") or []
    ]
    return WindowGraph(
        session_id=str(record["session_id"]),
        attack_type=str(record["attack_type"]),
        y=int(record["y"]),
        window_index=int(record.get("window_index") or 0),
        stream_index=int(record.get("stream_index") or 0),
        nodes=nodes,
        edges=edges,
        graph_attr=[float(v) for v in (record.get("graph_attr") or [])],
        node_keys=list(record.get("node_keys") or [node.key for node in nodes]),
    )


def node_feature_row(node: GraphNode) -> list[float]:
    return [
        log1p_clamp(float(node.visit_count)),
        log1p_clamp(node.mean_dt_in),
        log1p_clamp(node.min_dt_in),
        float(node.error_fraction),
    ]


def edge_feature_row(edge: GraphEdge) -> list[float]:
    return [
        log1p_clamp(float(edge.count)),
        log1p_clamp(edge.mean_dt),
        log1p_clamp(edge.min_dt),
    ]


def to_pyg_data(graph: WindowGraph):
    """Convert a WindowGraph to torch_geometric.data.Data (imports torch lazily)."""

    import torch
    from torch_geometric.data import Data

    if not graph.nodes:
        raise ValueError("Cannot encode an empty window graph.")

    class WindowData(Data):
        def __cat_dim__(self, key, value, *args, **kwargs):
            if key in {"graph_attr", "y"}:
                return None
            return super().__cat_dim__(key, value, *args, **kwargs)

        def __inc__(self, key, value, *args, **kwargs):
            if key in {"graph_attr", "y", "n_id"}:
                return 0
            return super().__inc__(key, value, *args, **kwargs)

    vocab_ids = torch.tensor([node.vocab_id for node in graph.nodes], dtype=torch.long)
    x = torch.tensor(
        [node_feature_row(node) for node in graph.nodes],
        dtype=torch.float,
    )
    if graph.edges:
        edge_index = torch.tensor(
            [[edge.src for edge in graph.edges], [edge.dst for edge in graph.edges]],
            dtype=torch.long,
        )
        edge_attr = torch.tensor(
            [edge_feature_row(edge) for edge in graph.edges],
            dtype=torch.float,
        )
    else:
        edge_index = torch.zeros((2, 0), dtype=torch.long)
        edge_attr = torch.zeros((0, 3), dtype=torch.float)

    data = WindowData(
        x=x,
        n_id=vocab_ids,
        edge_index=edge_index,
        edge_attr=edge_attr,
        y=torch.tensor([float(graph.y)], dtype=torch.float),
        graph_attr=torch.tensor(graph.graph_attr, dtype=torch.float).unsqueeze(0),
        num_nodes=len(graph.nodes),
    )
    data.session_id = graph.session_id  # type: ignore[attr-defined]
    data.attack_type = graph.attack_type  # type: ignore[attr-defined]
    return data
