"""
Generate normal-user traffic for APIShield using crAPI.

Example:
  python scripts/generate_normal_traffic.py --num-sessions 5 --delay-scale 0.05
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from apishield.traffic.provision import VehicleProvisioner
from apishield.traffic.workflows import (
    run_shop_browse_workflow,
    run_vehicle_tracking_workflow,
)


DEFAULT_LOGINS = ROOT.parent / "test_logins.json"
DEFAULT_SHOP_OUTPUT = ROOT / "data" / "raw" / "shop_sessions.jsonl"
DEFAULT_VEHICLE_OUTPUT = ROOT / "data" / "raw" / "vehicle_sessions.jsonl"


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


async def provision_all(
    users: list[dict[str, str]],
    *,
    base_url: str,
    mailhog_url: str,
) -> None:
    provisioner = VehicleProvisioner(
        base_url=base_url,
        mailhog_url=mailhog_url,
    )

    print("Provisioning vehicles...")
    for user in users:
        result = await provisioner.ensure_vehicle(
            user["email"],
            user["password"],
        )
        print(
            f"  {result.get('email')}: {result.get('status')}"
            f" (vehicles={result.get('vehicle_count', 0)})"
        )
        if result.get("status") in {
            "resend_failed",
            "mail_credentials_not_found",
            "add_vehicle_failed",
        }:
            raise RuntimeError(
                f"Failed to provision vehicle for {user['email']}: {result}"
            )


async def run_sessions(
    users: list[dict[str, str]],
    *,
    num_sessions: int,
    base_url: str,
    shop_output: Path,
    vehicle_output: Path,
    delay_scale: float,
) -> None:
    print(
        f"Running {num_sessions} session(s) for each workflow "
        f"across {len(users)} user(s)..."
    )

    for session_index in range(num_sessions):
        user = users[session_index % len(users)]
        user_id = user["name"]

        print(
            f"\n[session {session_index + 1}/{num_sessions}] "
            f"user={user_id} email={user['email']}"
        )

        shop_events = await run_shop_browse_workflow(
            email=user["email"],
            password=user["password"],
            user_id=user_id,
            base_url=base_url,
            output_path=shop_output,
            delay_scale=delay_scale,
        )
        print(
            f"  shop workflow: {len(shop_events)} events "
            f"-> {shop_output}"
        )

        vehicle_events = await run_vehicle_tracking_workflow(
            email=user["email"],
            password=user["password"],
            user_id=user_id,
            base_url=base_url,
            output_path=vehicle_output,
            delay_scale=delay_scale,
        )
        print(
            f"  vehicle workflow: {len(vehicle_events)} events "
            f"-> {vehicle_output}"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Provision crAPI vehicles if needed, then generate normal "
            "shop/vehicle workflow traffic into separate JSONL files."
        )
    )
    parser.add_argument(
        "--num-sessions",
        type=int,
        required=True,
        help="How many times to run each workflow (shop and vehicle).",
    )
    parser.add_argument(
        "--logins",
        type=Path,
        default=DEFAULT_LOGINS,
        help=f"Path to test_logins.json (default: {DEFAULT_LOGINS})",
    )
    parser.add_argument(
        "--base-url",
        default="http://localhost:8888",
        help="crAPI base URL",
    )
    parser.add_argument(
        "--mailhog-url",
        default="http://localhost:8025",
        help="MailHog API base URL",
    )
    parser.add_argument(
        "--shop-output",
        type=Path,
        default=DEFAULT_SHOP_OUTPUT,
        help="JSONL output for shop workflow events",
    )
    parser.add_argument(
        "--vehicle-output",
        type=Path,
        default=DEFAULT_VEHICLE_OUTPUT,
        help="JSONL output for vehicle workflow events",
    )
    parser.add_argument(
        "--delay-scale",
        type=float,
        default=1.0,
        help=(
            "Scale human delays (1.0 = realistic, 0.05 = fast demo). "
            "Default: 1.0"
        ),
    )
    parser.add_argument(
        "--skip-provision",
        action="store_true",
        help="Skip vehicle claim step (assume vehicles already exist).",
    )
    return parser


async def async_main(args: argparse.Namespace) -> None:
    if args.num_sessions < 1:
        raise ValueError("--num-sessions must be >= 1")

    users = load_logins(args.logins)
    print(f"Loaded {len(users)} login(s) from {args.logins}")

    if not args.skip_provision:
        await provision_all(
            users,
            base_url=args.base_url,
            mailhog_url=args.mailhog_url,
        )
    else:
        print("Skipping vehicle provisioning.")

    await run_sessions(
        users,
        num_sessions=args.num_sessions,
        base_url=args.base_url,
        shop_output=args.shop_output,
        vehicle_output=args.vehicle_output,
        delay_scale=args.delay_scale,
    )

    print("\nDone.")
    print(f"  shop sessions:    {args.shop_output}")
    print(f"  vehicle sessions: {args.vehicle_output}")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
