"""
Live GNN proxy in front of crAPI.

Send traffic to this process (default http://localhost:8090) instead of
crAPI :8888. Each request is forwarded unchanged, then scored event-by-event.

  python scripts/run_live_gnn_proxy.py
  curl http://localhost:8090/identity/api/auth/login ...
  curl http://localhost:8090/apishield/sessions
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import uvicorn

from apishield.behavioral.infer import load_rolling_scorer
from apishield.behavioral.live_proxy import create_live_app


DEFAULT_CKPT = ROOT / "data" / "processed" / "behavioral_gnn.pt"
DEFAULT_THRESHOLD = ROOT / "data" / "processed" / "threshold.json"
DEFAULT_SPEC = (
    ROOT / "targets" / "crAPI-main" / "openapi-spec" / "crapi-openapi-spec.json"
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Proxy live HTTP to crAPI and score each request with the GNN."
    )
    parser.add_argument("--target", default="http://localhost:8888", help="crAPI base URL")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--checkpoint", type=Path, default=DEFAULT_CKPT)
    parser.add_argument("--threshold", type=Path, default=DEFAULT_THRESHOLD)
    parser.add_argument("--spec", type=Path, default=DEFAULT_SPEC)
    parser.add_argument(
        "--stride",
        type=int,
        default=1,
        help="Score after every Nth event (default 1 = every request after min_events).",
    )
    parser.add_argument("--min-events", type=int, default=4)
    parser.add_argument(
        "--idle-gap",
        type=float,
        default=0.0,
        help=(
            "Seconds of silence before the rolling buffer is cleared "
            "(0 = never; training used 60s which is too short for Postman)."
        ),
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if not args.checkpoint.exists():
        raise FileNotFoundError(
            f"Checkpoint not found: {args.checkpoint}. "
            "Train first with scripts/train_behavioral_gnn.py"
        )
    scorer = load_rolling_scorer(
        args.checkpoint,
        args.threshold,
        args.spec,
        stride=args.stride,
        min_events=args.min_events,
        idle_gap_s=args.idle_gap,
    )
    app = create_live_app(scorer, target_base_url=args.target)
    print(
        f"APIShield live GNN proxy -> {args.target} "
        f"listen http://{args.host}:{args.port} "
        f"tau={scorer.threshold:.3f} N={scorer.window_size} "
        f"stride={scorer.stride} idle_gap={scorer.idle_gap_s}s",
        flush=True,
    )
    print(
        f"Point clients at this port instead of crAPI. "
        f"Status: http://127.0.0.1:{args.port}/apishield/sessions",
        flush=True,
    )
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
