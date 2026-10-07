# Scoring interfaces

Three ways to run the trained GNN. All load
`data/processed/behavioral_gnn.pt` and `data/processed/threshold.json` (τ ≈
0.5088) plus the crAPI OpenAPI spec.

Run commands from the repo root (`APIShield---API-Attacks-Detection`).

| Interface | Script | Input | Window | Stride | Idle gap |
|---|---|---|---|---|---|
| Batch sessions | `score_behavioral_sessions.py` | JSONL file | last-16 slices as in train | **8** | **60 s** |
| Stream / replay | `score_behavioral_stream.py` | JSONL or stdin | last 16 of buffer | **1** | 60 s (scorer default) |
| Live proxy | `run_live_gnn_proxy.py` | real HTTP → crAPI | last 16 of buffer | **1** | **0** (default) |

`session_score = max(window scores)`. `FLAG*` = first time that session
crosses τ.

---

## 1. Batch JSONL (`score_behavioral_sessions.py`)

Scores **every session** in a file with train-style windows (N=16, stride=8).
Writes one JSON: `session_count`, `flagged_count`, per-session
`max_attack_score` and `window_scores`.

```text
python scripts/score_behavioral_sessions.py --input data/raw/shop_sessions2.jsonl --output data/processed/normal_testing.json

python scripts/score_behavioral_sessions.py --input data/raw/shop_order_enumeration_2.jsonl --output data/processed/Enumeration_testing.json
```

Useful flags: `--checkpoint`, `--threshold`, `--spec`, `--window-size`,
`--stride`, `--idle-gap`.

This is the interface used for the confirmation-set tables in `results.md`.

---

## 2. Stream JSONL (`score_behavioral_stream.py`)

Feeds events **one line at a time** so a burst can flag **before** EOF.
Prints a line whenever a window is scored.

```text
python scripts/score_behavioral_stream.py --input data/raw/shop_order_enumeration_2.jsonl

python scripts/score_behavioral_stream.py --input data/raw/shop_order_enumeration_2.jsonl --only-flags

python scripts/score_behavioral_stream.py --input data/raw/shop_sessions2.jsonl --first-session

Get-Content data\raw\shop_order_enumeration_2.jsonl | python scripts/score_behavioral_stream.py --input -
```

| Flag | Meaning |
|---|---|
| `--stride 1` | default; score after every event once `min_events` is met |
| `--min-events 4` | no score until 4 events |
| `--only-flags` | print FLAG lines only |
| `--session-id <uuid>` | one session |
| `--first-session` | lock to the first event’s `session_id` |
| `--json-out path` | dump updates as JSON |

Log line shape:

```text
[ok]    session=… event=5 GET /workshop/api/shop/orders/all buf=5 window=0.32 session_max=0.32 windows=2
[FLAG*] session=… event=9 GET /workshop/api/shop/orders/12 buf=9 window=0.73 session_max=0.73 windows=6
```

---

## 3. Live reverse proxy (`run_live_gnn_proxy.py`)

ASGI process listens on **:8090**, forwards each request unchanged to crAPI
**:8888**, then scores the captured event.

```text
python scripts/run_live_gnn_proxy.py
```

Point the React app / Postman at `http://localhost:8090` instead of `:8888`.

| Flag | Default | Notes |
|---|---|---|
| `--target` | `http://localhost:8888` | crAPI |
| `--port` | 8090 | listen |
| `--stride` | 1 | every request after min_events |
| `--min-events` | 4 | |
| `--idle-gap` | **0** | 60 s would wipe slow Postman / browse pauses |

**Session key** (`live_session.py`), in order:

1. header `X-APIShield-Session`
2. JWT `email` / `sub` from `Authorization: Bearer`
3. client IP (login has no JWT yet — login and later calls can be **two**
   keys: `127.0.0.1` then `yamada@example.com`)

Control endpoints (not forwarded to crAPI, not scored):

```text
GET http://localhost:8090/apishield/health
GET http://localhost:8090/apishield/sessions
```

`/apishield/sessions` returns current `session_max` / flagged state for live
keys.

---

## Pipeline (build + train, not scoring)

Needed once before any of the three interfaces:

```text
python scripts/build_behavioral_windows.py
python scripts/train_behavioral_gnn.py
```

`build_behavioral_windows.py` reads the **original** raw files listed in
`DEFAULT_FILES` (not the `*_2.jsonl` confirmation captures) and writes
`data/processed/windows.jsonl`.
