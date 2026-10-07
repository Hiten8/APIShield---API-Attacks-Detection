"""Map traffic JSONL files to binary labels and attack-type metadata."""

from __future__ import annotations

from pathlib import Path


NORMAL_TYPES = frozenset({"normal_shop", "normal_vehicle"})

DEFAULT_FILE_LABELS: dict[str, tuple[int, str]] = {
    "shop_sessions.jsonl": (0, "normal_shop"),
    "vehicle_sessions.jsonl": (0, "normal_vehicle"),
    "shop_order_enumeration.jsonl": (1, "enumeration"),
    "shop_order_flooder.jsonl": (1, "flooder"),
    "shop_order_bola.jsonl": (1, "bola"),
    "shop_workshop_bfla.jsonl": (1, "bfla"),
}


def label_from_path(path: str | Path) -> tuple[int, str]:
    """
    Return (y, attack_type) from the source filename.

    Labels come from which generator wrote the file, never from HTTP status.
    """

    name = Path(path).name
    if name not in DEFAULT_FILE_LABELS:
        raise ValueError(
            f"Unknown traffic file {name!r}. "
            f"Expected one of: {sorted(DEFAULT_FILE_LABELS)}"
        )
    return DEFAULT_FILE_LABELS[name]


def is_attack_type(attack_type: str) -> bool:
    return attack_type not in NORMAL_TYPES
