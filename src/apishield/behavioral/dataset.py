"""Load processed window graphs and convert them to PyG Data objects."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Iterator

from apishield.behavioral.graphs import WindowGraph, to_pyg_data, window_graph_from_record
from apishield.behavioral.splits import SplitName, split_session_ids


def load_window_records(path: str | Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records


def records_to_graphs(records: Iterable[dict[str, Any]]) -> list[WindowGraph]:
    return [window_graph_from_record(record) for record in records]


def assign_splits(
    records: list[dict[str, Any]],
    *,
    seed: int = 42,
) -> dict[str, SplitName]:
    pairs = [
        (str(record["session_id"]), str(record["attack_type"]))
        for record in records
    ]
    return split_session_ids(pairs, seed=seed)


def partition_records(
    records: list[dict[str, Any]],
    assignment: dict[str, SplitName],
) -> dict[SplitName, list[dict[str, Any]]]:
    buckets: dict[SplitName, list[dict[str, Any]]] = {
        "train": [],
        "val": [],
        "test": [],
    }
    for record in records:
        split = assignment[str(record["session_id"])]
        buckets[split].append(record)
    return buckets


def pyg_dataset(records: Iterable[dict[str, Any]]) -> list[Any]:
    return [to_pyg_data(window_graph_from_record(record)) for record in records]


def iter_jsonl(path: str | Path) -> Iterator[dict[str, Any]]:
    with Path(path).open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                yield json.loads(line)
