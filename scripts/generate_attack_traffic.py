"""
Generate shop attack traffic for APIShield behavioural training.

Example:
  python scripts/generate_attack_traffic.py --num-sessions 5 --attack enumeration
  python scripts/generate_attack_traffic.py --num-sessions 5 --attack flooder
  python scripts/generate_attack_traffic.py --num-sessions 10 --attack bola --max-targets 5
  python scripts/generate_attack_traffic.py --num-sessions 10 --attack bfla
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from apishield.traffic.attacks import (
    collect_order_ownership,
    run_order_bola_attack,
    run_order_enumeration_attack,
    run_order_flooder_attack,
    run_workshop_bfla_attack,
)


DEFAULT_LOGINS = ROOT.parent / "test_logins.json"
DEFAULT_ENUM_OUTPUT = ROOT / "data" / "raw" / "shop_order_enumeration_2.jsonl"
DEFAULT_FLOOD_OUTPUT = ROOT / "data" / "raw" / "shop_order_flooder_2.jsonl"
DEFAULT_BOLA_OUTPUT = ROOT / "data" / "raw" / "shop_order_bola_2.jsonl"
DEFAULT_BFLA_OUTPUT = ROOT / "data" / "raw" / "shop_workshop_bfla_2.jsonl"
DEFAULT_OWNERSHIP_OUTPUT = ROOT / "data" / "raw" / "order_ownership_2.json"


def load_logins(path: Path) -> list[dict[str, str]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    logins = payload.get("logins")

    if not isinstance(logins, list) or not logins:
        raise ValueError(f"No logins found in {path}")

    users: list[dict[str, str]] = []
    for entry in logins:
        if not isinstance(entry, dict):
            continue
        email = entry.get("email")
        password = entry.get("password")
        name = entry.get("name") or email
        if not email or not password:
            raise ValueError(f"Login entry missing email/password: {entry}")
        users.append(
            {
                "name": str(name),
                "email": str(email),
                "password": str(password),
            }
        )

    if not users:
        raise ValueError(f"No valid login entries in {path}")

    return users


def _users_by_name(users: list[dict[str, str]]) -> dict[str, dict[str, str]]:
    return {user["name"]: user for user in users}


def _ownership_index(
    ownership: dict,
) -> dict[str, list[int]]:
    result: dict[str, list[int]] = {}
    users = ownership.get("users") or {}
    for user_id, info in users.items():
        if not isinstance(info, dict):
            continue
        ids = info.get("order_ids") or []
        cleaned: list[int] = []
        for oid in ids:
            try:
                cleaned.append(int(oid))
            except (TypeError, ValueError):
                continue
        result[str(user_id)] = cleaned
    return result


def _build_bola_access_plan(
    selected_victims: list[dict[str, str]],
    owned: dict[str, list[int]],
    *,
    traversal: str,
) -> list[tuple[str, int]]:
    """
    Build (victim_user_id, order_id) access plan.

    ordered: victim-by-victim, then each victim's objects in list order
    random: all objects from selected victims, then shuffled
    """

    plan: list[tuple[str, int]] = []
    for victim in selected_victims:
        victim_id = victim["name"]
        for order_id in owned.get(victim_id, []):
            plan.append((victim_id, order_id))

    if not plan:
        return plan

    if traversal == "random":
        random.shuffle(plan)
    # ordered: keep blocks as appended (user → user, object → object)

    return plan


async def run_bola_sessions(
    users: list[dict[str, str]],
    *,
    num_sessions: int,
    max_targets: int,
    base_url: str,
    bola_output: Path,
    ownership_output: Path,
    delay_scale: float,
) -> None:
    if len(users) < 2:
        raise ValueError("BOLA requires at least 2 users in the logins file.")

    if max_targets < 1:
        raise ValueError("--max-targets / n must be >= 1")

    # n = max victim *accounts*. Attacker cannot be a victim.
    max_other_accounts = len(users) - 1
    if max_targets > max_other_accounts:
        raise ValueError(
            f"--max-targets n={max_targets} is greater than the number of "
            f"other accounts available as victims ({max_other_accounts}). "
            f"Reduce n or add more users to logins."
        )

    print("Collecting per-user order ownership...")
    ownership = await collect_order_ownership(
        users,
        base_url=base_url,
        ownership_path=ownership_output,
        delay_scale=delay_scale,
    )
    owned = _ownership_index(ownership)
    print(f"  ownership saved -> {ownership_output}")

    for user in users:
        count = len(owned.get(user["name"], []))
        print(f"  {user['name']}: {count} order(s)")

    victims_with_orders = [
        user for user in users if owned.get(user["name"])
    ]
    if not victims_with_orders:
        raise RuntimeError(
            "No user has any orders. Create orders first "
            "(normal shop / flooder traffic), then rerun BOLA."
        )

    print(
        f"Running {num_sessions} BOLA session(s); "
        f"max victim accounts n={max_targets} "
        f"(x accounts in 1..n each session)..."
    )

    by_name = _users_by_name(users)

    for session_index in range(num_sessions):
        attacker = users[session_index % len(users)]

        candidate_victims = [
            user
            for user in victims_with_orders
            if user["name"] != attacker["name"]
        ]
        if not candidate_victims:
            raise RuntimeError(
                f"No victim with orders available for attacker={attacker['name']}"
            )

        # x = number of victim *accounts* this session.
        x = random.randint(1, max_targets)
        x = min(x, len(candidate_victims))

        selected_victims = random.sample(candidate_victims, x)
        traversal = random.choice(["ordered", "random"])
        access_plan = _build_bola_access_plan(
            selected_victims,
            owned,
            traversal=traversal,
        )
        if not access_plan:
            raise RuntimeError(
                "Selected victims have no order IDs to access."
            )

        victim_names = [victim["name"] for victim in selected_victims]
        print(
            f"\n[session {session_index + 1}/{num_sessions}] "
            f"attacker={attacker['name']} "
            f"victim_accounts={victim_names} "
            f"(x={x}, n={max_targets}) "
            f"objects={len(access_plan)} traversal={traversal}"
        )

        events = await run_order_bola_attack(
            attacker=by_name[attacker["name"]],
            access_plan=access_plan,
            base_url=base_url,
            output_path=bola_output,
            delay_scale=delay_scale,
            skip_probability=0.05,
            traversal=traversal,
        )
        print(f"  order BOLA: {len(events)} events -> {bola_output}")


async def run_sessions(
    users: list[dict[str, str]],
    *,
    num_sessions: int,
    attack: str,
    base_url: str,
    enum_output: Path,
    flood_output: Path,
    bola_output: Path,
    bfla_output: Path,
    ownership_output: Path,
    delay_scale: float,
    max_targets: int | None,
) -> None:
    run_enum = attack in {"enumeration", "both"}
    run_flood = attack in {"flooder", "both"}
    run_bola = attack == "bola"
    run_bfla = attack == "bfla"

    if run_bola:
        if max_targets is None:
            raise ValueError("--max-targets is required when --attack bola")
        await run_bola_sessions(
            users,
            num_sessions=num_sessions,
            max_targets=max_targets,
            base_url=base_url,
            bola_output=bola_output,
            ownership_output=ownership_output,
            delay_scale=delay_scale,
        )
        return

    if run_bfla:
        print(
            f"Running {num_sessions} BFLA session(s) "
            f"across {len(users)} user(s)..."
        )
        for session_index in range(num_sessions):
            user = users[session_index % len(users)]
            print(
                f"\n[session {session_index + 1}/{num_sessions}] "
                f"user={user['name']} email={user['email']}"
            )
            events = await run_workshop_bfla_attack(
                email=user["email"],
                password=user["password"],
                user_id=user["name"],
                base_url=base_url,
                output_path=bfla_output,
                delay_scale=delay_scale,
            )
            print(f"  workshop BFLA: {len(events)} events -> {bfla_output}")
        return

    print(
        f"Running {num_sessions} session(s) "
        f"(attack={attack}) across {len(users)} user(s)..."
    )

    for session_index in range(num_sessions):
        user = users[session_index % len(users)]
        user_id = user["name"]

        print(
            f"\n[session {session_index + 1}/{num_sessions}] "
            f"user={user_id} email={user['email']}"
        )

        if run_enum:
            events = await run_order_enumeration_attack(
                email=user["email"],
                password=user["password"],
                user_id=user_id,
                base_url=base_url,
                output_path=enum_output,
                delay_scale=delay_scale,
            )
            print(
                f"  order enumeration: {len(events)} events -> {enum_output}"
            )

        if run_flood:
            events = await run_order_flooder_attack(
                email=user["email"],
                password=user["password"],
                user_id=user_id,
                base_url=base_url,
                output_path=flood_output,
                delay_scale=delay_scale,
            )
            print(
                f"  order flooder: {len(events)} events -> {flood_output}"
            )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Generate shop attack traffic "
            "(enumeration / flooder / bola / bfla) into JSONL for GNN training."
        )
    )
    parser.add_argument(
        "--num-sessions",
        type=int,
        required=True,
        help="How many times to run the selected attack workflow(s).",
    )
    parser.add_argument(
        "--attack",
        choices=["enumeration", "flooder", "both", "bola", "bfla"],
        default="both",
        help="Which attack(s) to generate (default: both).",
    )
    parser.add_argument(
        "--max-targets",
        type=int,
        default=None,
        help=(
            "BOLA only: maximum victim *accounts* per session (n). "
            "Each session samples x victim accounts uniformly from 1..n, "
            "then accesses their owned orders (ordered or random walk). "
            "Errors if n > number of other users available as victims."
        ),
    )
    parser.add_argument(
        "--logins",
        type=Path,
        default=DEFAULT_LOGINS,
        help=f"Path to logins JSON (default: {DEFAULT_LOGINS})",
    )
    parser.add_argument(
        "--base-url",
        default="http://localhost:8888",
        help="crAPI base URL",
    )
    parser.add_argument(
        "--enum-output",
        type=Path,
        default=DEFAULT_ENUM_OUTPUT,
        help="JSONL output for order enumeration",
    )
    parser.add_argument(
        "--flood-output",
        type=Path,
        default=DEFAULT_FLOOD_OUTPUT,
        help="JSONL output for order flooder",
    )
    parser.add_argument(
        "--bola-output",
        type=Path,
        default=DEFAULT_BOLA_OUTPUT,
        help="JSONL output for order BOLA",
    )
    parser.add_argument(
        "--bfla-output",
        type=Path,
        default=DEFAULT_BFLA_OUTPUT,
        help="JSONL output for workshop BFLA",
    )
    parser.add_argument(
        "--ownership-output",
        type=Path,
        default=DEFAULT_OWNERSHIP_OUTPUT,
        help="JSON file for per-user owned order IDs (BOLA)",
    )
    parser.add_argument(
        "--delay-scale",
        type=float,
        default=1.0,
        help=(
            "Scale attack delays (default 1.0). "
            "Attack gaps stay in a small band (~0.05–0.8s before scaling)."
        ),
    )
    return parser


async def async_main(args: argparse.Namespace) -> None:
    if args.num_sessions < 1:
        raise ValueError("--num-sessions must be >= 1")

    users = load_logins(args.logins)
    print(f"Loaded {len(users)} login(s) from {args.logins}")

    await run_sessions(
        users,
        num_sessions=args.num_sessions,
        attack=args.attack,
        base_url=args.base_url,
        enum_output=args.enum_output,
        flood_output=args.flood_output,
        bola_output=args.bola_output,
        bfla_output=args.bfla_output,
        ownership_output=args.ownership_output,
        delay_scale=args.delay_scale,
        max_targets=args.max_targets,
    )

    print("\nDone.")
    if args.attack in {"enumeration", "both"}:
        print(f"  enumeration: {args.enum_output}")
    if args.attack in {"flooder", "both"}:
        print(f"  flooder:     {args.flood_output}")
    if args.attack == "bola":
        print(f"  bola:        {args.bola_output}")
        print(f"  ownership:   {args.ownership_output}")
    if args.attack == "bfla":
        print(f"  bfla:        {args.bfla_output}")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
