# Scripts and algorithms

This document describes each executable under `scripts/`, what it is for, and
the algorithms it drives. Implementation lives in `src/apishield/`; scripts are
thin CLIs that wire paths, defaults, and I/O.

Run commands from the repository root (`APIShield---API-Attacks-Detection`).

---

## End-to-end pipelines

**Behavioural (GNN) — offline**

```text
generate_normal_traffic.py  ──┐
generate_attack_traffic.py  ──┼──► data/raw/*.jsonl
                              │
build_behavioral_windows.py ──┼──► data/processed/windows.jsonl
                              │
train_behavioral_gnn.py     ──┼──► behavioral_gnn.pt, threshold.json
                              │
score_behavioral_sessions.py ─┴──► per-session JSON reports
score_behavioral_stream.py  ───────► event-by-event stdout (replay)
```

**Live (conformance + GNN)**

```text
run_live_gnn_proxy.py  ──► :8090 proxy ──► crAPI :8888
                              │
                              ├── OpenAPIValidator (per request)
                              └── RollingSessionScorer (per request)
```

**Conformance-only replay (no GNN, no HTTP)**

```text
demo_conformance_traffic.py  ──► validate stored JSONL against OpenAPI spec
```

---

## Script reference

| Script | Role | Main outputs |
|---|---|---|
| `generate_normal_traffic.py` | Legitimate crAPI sessions | `shop_sessions*.jsonl`, `vehicle_sessions.jsonl` |
| `generate_attack_traffic.py` | Attack sessions (enum, flooder, BOLA, BFLA) | `shop_order_*.jsonl`, ownership JSON for BOLA |
| `build_behavioral_windows.py` | Windowing + graph encoding for training | `windows.jsonl`, optional `.gml` samples |
| `train_behavioral_gnn.py` | Train binary GINE, pick τ, evaluate hold-out | `behavioral_gnn.pt`, `threshold.json` |
| `score_behavioral_sessions.py` | Batch score all sessions in a JSONL file | Session report JSON |
| `score_behavioral_stream.py` | Replay JSONL as a live stream | Stdout lines per scored window |
| `run_live_gnn_proxy.py` | HTTP proxy + conformance + GNN | Headers, `/apishield/calls`, logs |
| `demo_conformance_traffic.py` | Offline OpenAPI check on JSONL | Console summary of violations |

---

## Traffic generation

### `generate_normal_traffic.py`

**Role.** Drive two stochastic **normal-user workflows** against a running crAPI
instance and append `APIEvent` rows to JSONL.

**Algorithms / behaviour.**

1. **Vehicle provisioning** (unless `--skip-provision`): for each login in
   `test_logins.json`, `VehicleProvisioner.ensure_vehicle` claims a vehicle via
   MailHog so the vehicle workflow has data.
2. For `--num-sessions` iterations, rotate users and run:
   - **Shop browse** (`NormalUserWorkflows.run_shop_browse_workflow`): login →
     products → optional refreshes → optional order → `orders/all` → optional
     own order detail → optional misclick. Delays are drawn from bands
     (MISCLICK, NAV, SCAN, READ, THINK) and scaled by `--delay-scale`.
   - **Vehicle tracking** (`run_vehicle_tracking_workflow`): login → dashboard →
     vehicles → location → optional refresh / resend / misclick.
3. **Early quit** after successful login with probability 0.10 (normal only).

**Default outputs:** `data/raw/shop_sessions2.jsonl`, `data/raw/vehicle_sessions.jsonl`
(configurable). See `fastview/traffic-generators.md` for probabilities.

---

### `generate_attack_traffic.py`

**Role.** Generate **OpenAPI-valid** attack traffic so the conformance branch
stays quiet while call graphs look anomalous.

**Algorithms / behaviour.**

- **Enumeration / flooder / BFLA:** loop `--num-sessions` times, round-robin
  users, call `ShopAttackWorkflows` in `attacks.py` (skeleton + randomised
  parameters; tight delay band 0.05–0.80 s × `delay-scale`).
- **BOLA:**
  1. `collect_order_ownership`: each user logs in and pages `GET orders/all` →
     `order_ownership*.json`.
  2. Per session: pick attacker, sample `x` victim accounts (1…`--max-targets`),
     build `access_plan` of foreign `(victim, order_id)` pairs, optional ordered
     vs random traversal, then `run_order_bola_attack` (GET/PUT/return with
     skip probability 0.05).

**CLI:** `--attack enumeration | flooder | bola | bfla | both`. BOLA requires
`--max-targets`.

---

## Dataset construction

### `build_behavioral_windows.py`

**Role.** Turn raw JSONL into labelled **window graphs** for training.

**Algorithms / behaviour.**

For each file in `DEFAULT_FILES` (six training corpora under `data/raw/`):

1. **Labelling** (`labels.label_from_path`): binary `y` and `attack_type` from
   **filename only** (not HTTP status).
2. **Session grouping** (`windowing.group_sessions`): group by `session_id`,
   sort by timestamp.
3. **Idle split** (`split_on_idle_gap`, default 60 s): gaps longer than the
   threshold start a new sub-stream within the same session.
4. **Rolling windows** (`slice_stream`): window size **N = 16**, stride **8**;
   streams shorter than N become one window; last window always covers the
   final N events.
5. **Graph encoding** (`graphs.encode_window`):
   - Resolve each event to `(METHOD, OpenAPI template)` via `EndpointResolver`.
   - Nodes: visit counts, inbound Δt stats, error fraction.
   - Edges: consecutive transitions with count and Δt (self-loops on repeated
     templates).
   - Graph attributes: `log1p` of event count, mean/min Δt, node count, max
     self-loop count.

Each window is one JSON line in `data/processed/windows.jsonl`. Optional
`--dump-graph-samples` writes NetworkX GML under `data/graphs/`.

---

## Training

### `train_behavioral_gnn.py`

**Role.** Train `WindowGNN`, select decision threshold τ, report hold-out metrics,
save checkpoint.

**Algorithms / behaviour.**

1. **Load** `windows.jsonl` → PyG `Data` objects (`dataset.py`).
2. **Split** (`assign_splits` / `split_session_ids`): stratified by
   `attack_type`, **70 / 15 / 15** train/val/test by **session_id** (seed 42).
   All windows from one session share one split.
3. **Training:**
   - Model: 2-layer **GINE** (edge-aware GIN), node embedding + numeric
     features, global mean/max pool + graph extras → binary logit.
   - Loss: `BCEWithLogitsLoss` with `pos_weight` from class balance.
   - Optimizer: Adam; **WeightedRandomSampler** inverse to `attack_type`
     frequency on train windows.
   - Early stopping on **validation window PR-AUC** (patience 8); restore best
     weights.
4. **Threshold** (`metrics.choose_threshold` on validation session scores):
   among score values that appear in val data, pick τ with **maximum F1** subject
   to **FPR ≤ 0.05** (`max_f1_fpr_cap`); else global max F1.
5. **Test evaluation:** session-level PR-AUC / ROC-AUC; recall by attack type
   at τ; write `threshold.json`.
6. **Checkpoint:** `model_state`, vocab, `hidden_dim`, `dropout`, `window_size`,
   default infer stride / `min_infer_events`.

**Defaults:** CPU, 50 epochs max, batch 32, hidden 64, dropout 0.2.

---

## Inference (offline)

### `score_behavioral_sessions.py`

**Role.** Score **every session** in one JSONL file the same way as training
windowing (not the live rolling buffer).

**Algorithms / behaviour.**

1. Load checkpoint + τ via `load_rolling_scorer` (model only; scoring uses
   `session_report.score_sessions_to_report`).
2. `group_sessions` → `windows_from_session` with **N = 16, stride = 8,
   idle_gap = 60 s**.
3. Each window: `encode_window` → `predict_window_score` (forward pass,
   sigmoid).
4. Per session: `max_attack_score = max(window_scores)`, `flagged` if ≥
   τ.

Writes a single JSON object: `sessions[]`, `session_count`, `flagged_count`,
metadata (τ, N, stride).

---

### `score_behavioral_stream.py`

**Role.** Simulate **middleware-style** scoring: one event at a time, print when
a window is scored (useful for time-to-detect on enumeration).

**Algorithms / behaviour.**

Uses `RollingSessionScorer` (`infer.py`):

- Per `session_id`, append events to a buffer.
- Optional **idle reset** (default 60 s from loader; CLI does not override unless
  extended): clear buffer if gap exceeds idle.
- When `len(buffer) ≥ min_events` (default 4) and `len(buffer) % stride == 0`
  (default **stride 1**), score **`buffer[-N:]`** as one graph.
- `session_score = max(window scores)`; `StreamUpdate` printed with `FLAG*`
  on first crossing of τ.

Supports stdin, `--only-flags`, `--session-id`, `--first-session`, `--json-out`.

---

## Live deployment

### `run_live_gnn_proxy.py`

**Role.** Start uvicorn on **:8090**; forward HTTP to crAPI; run **both**
branches on each proxied call.

**Algorithms / behaviour.**

1. Load OpenAPI spec → `OpenAPIValidator`.
2. Load GNN + τ → `RollingSessionScorer` with **stride 1**, **idle_gap 0**,
   **min_events 4** (defaults).
3. `LiveGnnProxy.proxy`: httpx forward request unchanged; build `APIEvent`
   (including JSON body parse for conformance).
4. **Conformance branch:** `validator.validate(event)` → valid flag, matched
   template, violation list (path match prefers static segments over `{param}`;
   parameter and body checks via `ParameterChecker` / `RequestBodyChecker`).
5. **GNN branch:** `scorer.apply_event` as in stream mode.
6. Attach `X-APIShield-*` headers; ring buffer of last 200 calls at
   `GET /apishield/calls`; session aggregates at `GET /apishield/sessions`.

Session key: `X-APIShield-Session`, else JWT email/sub, else client IP.

---

## Conformance demo

### `demo_conformance_traffic.py`

**Role.** **Offline** validation of recorded traffic: no HTTP, no GNN.

**Algorithms / behaviour.**

For each JSONL file, parse `APIEvent` rows and run `OpenAPIValidator.validate`
(same logic as live). Print per-event findings and file-level counts by
violation type.

Explicitly does **not** use rate, sequence, or enumeration patterns—those are
behavioural signals. Attack generators are designed to be conformant so this
script often reports few findings on attack JSONL; it is still useful for
malformed or spec-drift traffic.

---

## Shared library concepts (used by multiple scripts)

| Module | Algorithm / idea |
|---|---|
| `conformance/path_matcher.py` | Segment-wise template match; prefer more static segments |
| `conformance/validator.py` | Path → method → params → JSON body schema |
| `behavioral/windowing.py` | Session group, idle split, stride windows, Δt on edges |
| `behavioral/graphs.py` | Template collapse, transition graph, PyG features |
| `behavioral/model.py` | `WindowGNN` (GINE × 2, binary head) |
| `behavioral/infer.py` | `RollingSessionScorer`, `load_rolling_scorer` |
| `behavioral/metrics.py` | PR-AUC, ROC-AUC, F1, FPR, `choose_threshold` |
| `behavioral/splits.py` | Stratified session-id split |
| `traffic/workflows.py` / `attacks.py` | Stochastic HTTP workflows for data generation |

---

## Typical command order

**First-time behavioural pipeline**

```text
python scripts/generate_normal_traffic.py --num-sessions 50 --delay-scale 0.05
python scripts/generate_attack_traffic.py --num-sessions 30 --attack both
python scripts/generate_attack_traffic.py --num-sessions 50 --attack bola --max-targets 5
python scripts/generate_attack_traffic.py --num-sessions 50 --attack bfla
python scripts/build_behavioral_windows.py
python scripts/train_behavioral_gnn.py
```

**Evaluate new JSONL (frozen model)**

```text
python scripts/score_behavioral_sessions.py --input data/raw/shop_sessions2.jsonl --output data/processed/normal_testing.json
```

**Live demo**

```text
python scripts/run_live_gnn_proxy.py
```

**Conformance-only on files**

```text
python scripts/demo_conformance_traffic.py --files data/raw/shop_order_enumeration.jsonl
```

For interface flags and URLs, see `fastview/interfaces.md`. For generator
probabilities, see `fastview/traffic-generators.md`.
