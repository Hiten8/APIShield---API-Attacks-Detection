"""
Build rolling event windows and endpoint-transition graphs from raw JSONL.

Example:
  python scripts/build_behavioral_windows.py
  python scripts/build_behavioral_windows.py --dump-graph-samples 8
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from apishield.behavioral.graphs import EndpointResolver, encode_window
from apishield.behavioral.labels import label_from_path
from apishield.behavioral.windowing import (
    DEFAULT_IDLE_GAP_S,
    DEFAULT_TRAIN_STRIDE,
    DEFAULT_WINDOW_SIZE,
    group_sessions,
    windows_from_session,
)
from apishield.conformance.openapi_loader import OpenAPILoader


DEFAULT_SPEC = ROOT / "targets" / "crAPI-main" / "openapi-spec" / "crapi-openapi-spec.json"
DEFAULT_RAW = ROOT / "data" / "raw"
DEFAULT_OUTPUT = ROOT / "data" / "processed" / "windows.jsonl"
DEFAULT_GRAPHS = ROOT / "data" / "graphs"

DEFAULT_FILES = [
    "shop_sessions.jsonl",
    "vehicle_sessions.jsonl",
    "shop_order_enumeration.jsonl",
    "shop_order_flooder.jsonl",
    "shop_order_bola.jsonl",
    "shop_workshop_bfla.jsonl",
]


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def session_length_stats(sessions: dict[str, list[dict[str, Any]]]) -> dict[str, float]:
    lengths = [len(events) for events in sessions.values()]
    if not lengths:
        return {"n": 0}
    ordered = sorted(lengths)
    return {
        "n": float(len(ordered)),
        "min": float(ordered[0]),
        "median": float(statistics.median(ordered)),
        "max": float(ordered[-1]),
    }


def dump_networkx_sample(graph, path: Path) -> None:
    import networkx as nx

    g = nx.DiGraph()
    for index, node in enumerate(graph.nodes):
        g.add_node(index, key=node.key, visits=node.visit_count)
    for edge in graph.edges:
        g.add_edge(
            edge.src,
            edge.dst,
            count=edge.count,
            mean_dt=round(edge.mean_dt, 4),
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    nx.write_gml(g, path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build labelled window graphs from raw traffic JSONL."
    )
    parser.add_argument("--raw-dir", type=Path, default=DEFAULT_RAW)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--spec", type=Path, default=DEFAULT_SPEC)
    parser.add_argument("--window-size", type=int, default=DEFAULT_WINDOW_SIZE)
    parser.add_argument("--stride", type=int, default=DEFAULT_TRAIN_STRIDE)
    parser.add_argument("--idle-gap", type=float, default=DEFAULT_IDLE_GAP_S)
    parser.add_argument(
        "--dump-graph-samples",
        type=int,
        default=0,
        help="Write this many NetworkX GML samples under data/graphs/",
    )
    parser.add_argument("--graphs-dir", type=Path, default=DEFAULT_GRAPHS)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if not args.spec.exists():
        raise FileNotFoundError(f"OpenAPI spec not found: {args.spec}")

    spec = OpenAPILoader().load(args.spec)
    resolver = EndpointResolver(spec)
    print(f"Loaded spec vocab_size={resolver.vocab_size} from {args.spec}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    type_counts: Counter[str] = Counter()
    window_count = 0
    samples_written = 0

    with args.output.open("w", encoding="utf-8") as out:
        for filename in DEFAULT_FILES:
            path = args.raw_dir / filename
            if not path.exists():
                print(f"  skip missing {path}")
                continue
            y, attack_type = label_from_path(path)
            events = load_jsonl(path)
            sessions = group_sessions(events)
            stats = session_length_stats(sessions)
            print(
                f"{filename}: sessions={int(stats.get('n', 0))} "
                f"len min/med/max="
                f"{stats.get('min')}/{stats.get('median')}/{stats.get('max')} "
                f"y={y} type={attack_type}"
            )
            if attack_type.startswith("normal") and stats.get("median", 16) < 10:
                print(
                    "  note: median normal session length is << 16; "
                    "consider --window-size 12 if graphs look padded with cover."
                )
            for session_id, session_events in sessions.items():
                for window in windows_from_session(
                    session_id,
                    session_events,
                    y=y,
                    attack_type=attack_type,
                    window_size=args.window_size,
                    stride=args.stride,
                    idle_gap_s=args.idle_gap,
                ):
                    graph = encode_window(window, resolver)
                    out.write(json.dumps(graph.to_record()) + "\n")
                    window_count += 1
                    type_counts[attack_type] += 1
                    if samples_written < args.dump_graph_samples:
                        dump_networkx_sample(
                            graph,
                            args.graphs_dir
                            / f"{attack_type}_{session_id[:8]}_{window.window_index}.gml",
                        )
                        samples_written += 1

    print(f"\nWrote {window_count} windows -> {args.output}")
    print("by type:", dict(type_counts))


if __name__ == "__main__":
    main()
