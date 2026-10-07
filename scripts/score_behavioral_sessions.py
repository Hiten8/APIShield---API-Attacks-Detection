"""
Score every session in a JSONL file with train-style rolling windows.

N=16, stride=8 (same as training). Writes one JSON object with an array of
sessions: event_count, max_attack_score, and every window score.

A file with a single session is the same interface.

Example:
  python scripts/score_behavioral_sessions.py --input data/raw/shop_order_enumeration.jsonl
  python scripts/score_behavioral_sessions.py --input data/raw/shop_sessions.jsonl --output data/processed/session_scores.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from apishield.behavioral.infer import load_rolling_scorer
from apishield.behavioral.session_report import score_sessions_to_report
from apishield.behavioral.windowing import (
    DEFAULT_IDLE_GAP_S,
    DEFAULT_TRAIN_STRIDE,
    DEFAULT_WINDOW_SIZE,
)


DEFAULT_CKPT = ROOT / "data" / "processed" / "behavioral_gnn.pt"
DEFAULT_THRESHOLD = ROOT / "data" / "processed" / "threshold.json"
DEFAULT_SPEC = (
    ROOT / "targets" / "crAPI-main" / "openapi-spec" / "crapi-openapi-spec.json"
)
DEFAULT_OUTPUT = ROOT / "data" / "processed" / "session_scores.json"


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue
            payload = json.loads(text)
            if not isinstance(payload, dict):
                raise ValueError(f"Line {line_number} is not a JSON object")
            rows.append(payload)
    return rows


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Batch-score sessions in a JSONL file. "
            "Output JSON lists max attack score and all window scores per session."
        )
    )
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--checkpoint", type=Path, default=DEFAULT_CKPT)
    parser.add_argument("--threshold", type=Path, default=DEFAULT_THRESHOLD)
    parser.add_argument("--spec", type=Path, default=DEFAULT_SPEC)
    parser.add_argument("--window-size", type=int, default=DEFAULT_WINDOW_SIZE)
    parser.add_argument("--stride", type=int, default=DEFAULT_TRAIN_STRIDE)
    parser.add_argument("--idle-gap", type=float, default=DEFAULT_IDLE_GAP_S)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if not args.checkpoint.exists():
        raise FileNotFoundError(
            f"Checkpoint not found: {args.checkpoint}. "
            "Train first with scripts/train_behavioral_gnn.py"
        )
    events = load_jsonl(args.input)
    if not events:
        raise ValueError(f"No events in {args.input}")

    scorer = load_rolling_scorer(
        args.checkpoint,
        args.threshold,
        args.spec,
    )
    report = score_sessions_to_report(
        events,
        scorer.model,
        scorer.resolver,
        tau=scorer.threshold,
        window_size=args.window_size,
        stride=args.stride,
        idle_gap_s=args.idle_gap,
        device=scorer.device,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(
        f"wrote {args.output} sessions={report['session_count']} "
        f"flagged={report['flagged_count']} "
        f"N={report['window_size']} stride={report['stride']}"
    )


if __name__ == "__main__":
    main()
