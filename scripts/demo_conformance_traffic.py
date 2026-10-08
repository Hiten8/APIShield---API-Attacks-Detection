"""
Replay generated JSONL traffic through APIShield's OpenAPI validator.

This is an offline replay: it does NOT send requests to crAPI. It evaluates
the recorded request fields against the OpenAPI contract. Request rate,
sequence, order-ID enumeration, and quantity variation are not behavioral
signals for this validator.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

# Make `src/` importable when run from the repository root, without requiring
# an editable install.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if SRC_DIR.exists():
    sys.path.insert(0, str(SRC_DIR))

from apishield.ingestion.models import APIEvent
from apishield.conformance.validator import OpenAPIValidator


DEFAULT_SPEC = Path("targets/crAPI-main/openapi-spec/crapi-openapi-spec.json")
DEFAULT_FILES = [
    Path("shop_order_enumeration.jsonl"),
    Path("shop_order_flooder.jsonl"),
]


def load_jsonl(path: Path) -> list[APIEvent]:
    events: list[APIEvent] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, start=1):
            if not raw.strip():
                continue
            try:
                payload = json.loads(raw)
                events.append(APIEvent.model_validate(payload))
            except Exception as exc:
                raise ValueError(f"{path}:{line_number}: could not parse APIEvent: {exc}") from exc
    return events


def violation_value(violation: Any, field: str, default: str = "-") -> str:
    value = getattr(violation, field, None)
    if value is None:
        return default
    return getattr(value, "value", str(value))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, default=DEFAULT_SPEC,
                        help="Path to crAPI OpenAPI JSON specification")
    parser.add_argument("--files", nargs="+", type=Path, default=DEFAULT_FILES,
                        help="One or more JSONL traffic files")
    parser.add_argument("--show-clean", action="store_true",
                        help="Print every conformant event (can produce lengthy output)")
    args = parser.parse_args()

    spec_path = args.spec if args.spec.is_absolute() else PROJECT_ROOT / args.spec
    if not spec_path.is_file():
        print(f"ERROR: OpenAPI spec not found: {spec_path}", file=sys.stderr)
        print("Pass its location with --spec.", file=sys.stderr)
        return 2

    try:
        with spec_path.open("r", encoding="utf-8") as handle:
            specification = json.load(handle)
        validator = OpenAPIValidator(specification)
    except Exception as exc:
        print(f"ERROR loading OpenAPI specification: {exc}", file=sys.stderr)
        return 2

    print("=" * 76)
    print(" APIShield | OpenAPI Conformance Replay")
    print("=" * 76)
    print(f"Spec: {spec_path}")
    print("Mode: offline JSONL replay; no HTTP requests are sent")
    print("Note: frequency/sequence/quantity patterns are not conformance checks.")
    print()

    overall = Counter()
    files_ok = True

    for supplied_path in args.files:
        path = supplied_path if supplied_path.is_absolute() else Path.cwd() / supplied_path
        if not path.is_file():
            print(f"ERROR: traffic file not found: {path}", file=sys.stderr)
            files_ok = False
            continue

        try:
            events = load_jsonl(path)
        except Exception as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            files_ok = False
            continue

        valid_count = 0
        invalid_count = 0
        finding_counts: Counter[str] = Counter()
        sessions: set[str] = set()
        users: set[str] = set()

        print("-" * 76)
        print(f"FILE: {path.name} | events: {len(events)}")

        for event in events:
            if event.session_id:
                sessions.add(event.session_id)
            if event.user_id:
                users.add(event.user_id)

            result = validator.validate(event)
            if result.valid:
                valid_count += 1
                if args.show_clean:
                    print(f"  PASS  {event.method.upper():6} {event.path}")
                continue

            invalid_count += 1
            violations = getattr(result, "violations", []) or []
            for violation in violations:
                kind = violation_value(violation, "violation_type", "UNKNOWN")
                finding_counts[kind] += 1
                overall[kind] += 1

            print(f"  FINDING {event.method.upper():6} {event.path}")
            print(f"    HTTP status: {event.response_status if event.response_status is not None else 'not recorded'}")
            for violation in violations:
                kind = violation_value(violation, "violation_type", "UNKNOWN")
                location = violation_value(violation, "location")
                severity = violation_value(violation, "severity", "unspecified")
                parameter = getattr(violation, "parameter", None)
                suffix = f" | parameter={parameter}" if parameter else ""
                message = getattr(violation, "message", "")
                print(f"    - {kind} | location={location} | severity={severity}{suffix}")
                if message:
                    print(f"      {message}")

        print()
        print(f"  Users: {len(users)} | Sessions: {len(sessions)}")
        print(f"  Conformant events: {valid_count}")
        print(f"  Events with findings: {invalid_count}")
        print(f"  Total violations: {sum(finding_counts.values())}")
        if finding_counts:
            print("  Violation types:")
            for kind, count in sorted(finding_counts.items()):
                print(f"    {kind}: {count}")
        else:
            print("  Violation types: none")
        print()

    print("=" * 76)
    print("OVERALL")
    print("=" * 76)
    print(f"Violation instances: {sum(overall.values())}")
    if overall:
        for kind, count in sorted(overall.items()):
            print(f"  {kind}: {count}")
    else:
        print("No OpenAPI conformance violations found in the processed traffic.")

    print()
    print("INTERPRETATION")
    print("A conformant result means the recorded request fields passed this")
    print("validator's implemented contract checks—not that the behavior is safe.")
    print("Rapid order-ID traversal and repeated/variable-quantity ordering can")
    print("remain conformant; detecting those patterns belongs to behavioral")
    print("analysis. Conversely, any findings printed above are contract findings.")
    return 0 if files_ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
