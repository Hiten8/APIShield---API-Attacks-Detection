"""
Stream API events into the trained rolling-window GNN (live / middleware-shaped).

Each JSON line is one request. After every scored window the CLI prints what
the model thinks *so far* — so an enumeration burst can flag before the
session ends.

Examples:
  python scripts/score_behavioral_stream.py --input data/raw/shop_order_enumeration.jsonl
  python scripts/score_behavioral_stream.py --input data/raw/shop_order_enumeration.jsonl --stride 1
  Get-Content data\\raw\\shop_order_enumeration.jsonl | python scripts/score_behavioral_stream.py --input -
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterable, TextIO

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from apishield.behavioral.infer import (
    RollingSessionScorer,
    StreamUpdate,
    load_rolling_scorer,
)


DEFAULT_CKPT = ROOT / "data" / "processed" / "behavioral_gnn.pt"
DEFAULT_THRESHOLD = ROOT / "data" / "processed" / "threshold.json"
DEFAULT_SPEC = (
    ROOT / "targets" / "crAPI-main" / "openapi-spec" / "crapi-openapi-spec.json"
)


def iter_jsonl(handle: TextIO) -> Iterable[dict[str, Any]]:
    for line_number, line in enumerate(handle, start=1):
        text = line.strip()
        if not text:
            continue
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON on line {line_number}: {exc}") from exc
        if not isinstance(payload, dict):
            raise ValueError(f"Line {line_number} is not a JSON object")
        yield payload


def format_update(update: StreamUpdate) -> str:
    tag = "FLAG" if update.flagged else "ok"
    if update.first_flag:
        tag = "FLAG*"
    return (
        f"[{tag}] session={update.session_id} "
        f"event={update.event_index} "
        f"{update.method} {update.path} "
        f"buf={update.buffer_len} "
        f"window={update.window_score:.3f} "
        f"session_max={update.session_score:.3f} "
        f"windows={update.window_count}"
    )


def stream_events(
    scorer: RollingSessionScorer,
    events: Iterable[dict[str, Any]],
    *,
    only_flags: bool = False,
    session_id: str | None = None,
) -> list[StreamUpdate]:
    updates: list[StreamUpdate] = []
    flagged: set[str] = set()
    seen_sessions: set[str] = set()

    for index, event in enumerate(events, start=1):
        sid = str(event.get("session_id") or "")
        if not sid:
            raise ValueError(f"Event {index} is missing session_id")
        if session_id is not None and sid != session_id:
            continue
        session_id_used = sid
        seen_sessions.add(session_id_used)
        update = scorer.apply_event(
            event,
            event_index=index,
            previously_flagged=session_id_used in flagged,
        )
        if update is None:
            continue
        if update.flagged:
            flagged.add(session_id_used)
        if only_flags and not update.flagged:
            continue
        updates.append(update)
        print(format_update(update), flush=True)

    for session_id in sorted(seen_sessions):
        before = scorer.snapshot(session_id)
        final = scorer.finalize(session_id)
        if final.window_count == before.window_count:
            continue
        update = StreamUpdate(
            session_id=session_id,
            event_index=-1,
            path="(eof)",
            method="",
            buffer_len=len(scorer._buffers.get(session_id) or []),
            window_score=(
                final.window_scores[-1] if final.window_scores else 0.0
            ),
            session_score=final.session_score,
            flagged=final.flagged,
            first_flag=final.flagged and session_id not in flagged,
            window_count=final.window_count,
        )
        if update.flagged:
            flagged.add(session_id)
        if only_flags and not update.flagged:
            continue
        updates.append(update)
        print(format_update(update), flush=True)

    print(
        f"done sessions={len(seen_sessions)} "
        f"flagged={len(flagged)} scored_windows={len(updates)}",
        flush=True,
    )
    return updates


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Feed live (or replayed) JSONL events into the GNN. "
            "Prints a line whenever a rolling window is scored."
        )
    )
    parser.add_argument(
        "--input",
        default="-",
        help="JSONL file of APIEvent objects, or '-' for stdin",
    )
    parser.add_argument("--checkpoint", type=Path, default=DEFAULT_CKPT)
    parser.add_argument("--threshold", type=Path, default=DEFAULT_THRESHOLD)
    parser.add_argument("--spec", type=Path, default=DEFAULT_SPEC)
    parser.add_argument(
        "--stride",
        type=int,
        default=1,
        help=(
            "Score every Nth event after min_events (default 1 = after every "
            "request, so enumeration can flag mid-burst). Training used 4."
        ),
    )
    parser.add_argument(
        "--min-events",
        type=int,
        default=4,
        help="Do not score until the session has this many events (default 4).",
    )
    parser.add_argument(
        "--only-flags",
        action="store_true",
        help="Print only windows that are at/above tau",
    )
    parser.add_argument(
        "--session-id",
        default=None,
        help="Only score this session_id (for testing one session event-by-event).",
    )
    parser.add_argument(
        "--first-session",
        action="store_true",
        help="Use the session_id of the first event (easy one-session replay).",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="Write scored window updates as JSON (array of objects).",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if not args.checkpoint.exists():
        raise FileNotFoundError(
            f"Checkpoint not found: {args.checkpoint}. "
            "Train first with scripts/train_behavioral_gnn.py"
        )
    if not args.threshold.exists():
        raise FileNotFoundError(f"Threshold file not found: {args.threshold}")

    scorer = load_rolling_scorer(
        args.checkpoint,
        args.threshold,
        args.spec,
        stride=args.stride,
        min_events=args.min_events,
    )
    print(
        f"loaded model tau={scorer.threshold:.3f} "
        f"N={scorer.window_size} stride={scorer.stride} "
        f"min_events={scorer.min_events}",
        flush=True,
    )

    session_filter = args.session_id
    source = sys.stdin if args.input == "-" else None

    def run(handle: TextIO) -> None:
        locked = session_filter
        filtered = iter_jsonl(handle)
        if args.first_session and locked is None:
            buffered: list[dict[str, Any]] = []
            for event in filtered:
                locked = str(event.get("session_id") or "")
                print(f"streaming session_id={locked}", flush=True)
                buffered.append(event)
                break
            def chained():
                yield from buffered
                for event in filtered:
                    yield event
            events = chained()
        else:
            events = filtered
        if locked:
            print(f"filter session_id={locked}", flush=True)
        updates = stream_events(
            scorer,
            events,
            only_flags=args.only_flags,
            session_id=locked,
        )
        if args.json_out is not None:
            payload = [update.__dict__ for update in updates]
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(
                json.dumps(payload, indent=2),
                encoding="utf-8",
            )
            print(f"wrote {args.json_out}", flush=True)

    if source is not None:
        run(source)
        return
    with Path(args.input).open("r", encoding="utf-8") as handle:
        run(handle)


if __name__ == "__main__":
    main()
