"""Session-id train/val/test splits stratified by attack_type."""

from __future__ import annotations

import random
from collections import defaultdict
from typing import Iterable, Literal

SplitName = Literal["train", "val", "test"]


def split_session_ids(
    sessions: Iterable[tuple[str, str]],
    *,
    seed: int = 42,
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
) -> dict[str, SplitName]:
    """
    Map session_id -> split.

    ``sessions`` is iterable of (session_id, attack_type). All windows of a
    session share this assignment. Stratified by attack_type.
    """

    by_type: dict[str, list[str]] = defaultdict(list)
    seen: set[str] = set()
    for session_id, attack_type in sessions:
        if session_id in seen:
            continue
        seen.add(session_id)
        by_type[attack_type].append(session_id)

    rng = random.Random(seed)
    assignment: dict[str, SplitName] = {}

    for _attack_type, ids in sorted(by_type.items()):
        shuffled = list(ids)
        rng.shuffle(shuffled)
        n = len(shuffled)
        if n == 1:
            assignment[shuffled[0]] = "train"
            continue
        n_train = max(1, int(round(n * train_ratio)))
        n_val = int(round(n * val_ratio))
        if n >= 3:
            n_train = min(n_train, n - 2)
            n_val = max(1, min(n_val, n - n_train - 1))
        elif n == 2:
            n_train = 1
            n_val = 1
        n_train = max(1, min(n_train, n))
        n_val = max(0, min(n_val, n - n_train))
        train_ids = shuffled[:n_train]
        val_ids = shuffled[n_train : n_train + n_val]
        test_ids = shuffled[n_train + n_val :]
        for session_id in train_ids:
            assignment[session_id] = "train"
        for session_id in val_ids:
            assignment[session_id] = "val"
        for session_id in test_ids:
            assignment[session_id] = "test"

    return assignment
