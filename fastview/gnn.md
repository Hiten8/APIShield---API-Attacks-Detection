# Rolling-window GNN

The behavioural detector does **not** read a whole session as a sequence of
raw URLs. It **collapses** requests onto OpenAPI templates, **cuts** the
session into overlapping event windows, **encodes** each window as a directed
transition graph, then scores that graph with a **2-layer GINE**. A session is
flagged if the **max** window score ≥ τ.

Implementation: `src/apishield/behavioral/` (`windowing.py`, `graphs.py`,
`model.py`, `infer.py`).

---

## 1. From HTTP events to a session

Each JSONL line is one API event (`method`, `path`, `timestamp`,
`session_id`, status, …). Events with the same `session_id` are grouped and
sorted by time.

If two consecutive events are more than **idle_gap** seconds apart (training
default **60 s**), the session is split into separate streams. Live proxy
default idle gap is **0** (no split).

---

## 2. Rolling windows (flattening time)

A stream of *n* events is cut with:

- **window size N = 16** (at most 16 events per graph)
- **stride** = 8 at train / batch JSONL scoring; **1** for live / stream
- streams shorter than N become **one** window (no padding)

Starts are `0, stride, 2·stride, …` plus a final window that always covers
the **last N** events so the tail is not dropped.

Example, *n* = 20, N = 16, stride = 8:

| Window | Events |
|---|---|
| 0 | 1–16 |
| 1 | 9–24 → clipped to last 16 of the stream: **5–20** (last-start rule) |

Live scoring is slightly different: the buffer keeps the whole session (until
an idle reset), and each score uses only **`buffer[-16:]`** (the most recent
N events). That is the “rolling” view: as request 17 arrives, event 1 falls
out of the graph.

`min_events = 4` on live/stream: do not score until four requests exist.

**Session score** = max of all window scores for that `session_id`. Once a
window crosses τ, `session_max` stays high (sticky FLAG for that session).

Δt between consecutive events in the window is stored on **edges**
(`log1p(Δt)`). The model never sees object IDs (`/orders/8` and `/orders/99`
are the same node).

---

## 3. Template collapse → graph

Concrete path + method is mapped through the crAPI OpenAPI spec:

```text
GET /workshop/api/shop/orders/8  →  node "GET /workshop/api/shop/orders/{order_id}"
```

Unknown paths become `UNKNOWN`.

**Nodes** = distinct `(METHOD, template)` keys in the window.

**Edges** = consecutive calls. Repeating the same template creates a
**self-loop** (enumeration / flooder signature).

**Node features (4):** `log1p(visit_count)`, `log1p(mean inbound Δt)`,
`log1p(min inbound Δt)`, error fraction (HTTP ≥ 400).

**Edge features (3):** `log1p(count)`, `log1p(mean Δt)`, `log1p(min Δt)`.

**Graph extras (5), concatenated after pooling:**

`log1p` of event count, mean Δt, min Δt, number of nodes, **max self-loop
count**.

Vocab id of the OpenAPI operation is an **embedding**, added to the numeric
node vector.

---

## 4. Model: binary GINE (`WindowGNN`)

[GINE](https://arxiv.org/abs/1905.12265) is Graph Isomorphism Network with
**edge attributes** (needed because Δt and transition count live on edges).

```text
n_id embedding (hidden=64) + Linear(node numeric → 64)
edge_attr → 2-layer MLP → 64
GINEConv → ReLU → Dropout(0.2)
GINEConv → ReLU
global mean pool  ⊕  global max pool   → 128
concat graph_attr (5)                  → 133
MLP → 1 logit → sigmoid = attack score
```

Training (`scripts/train_behavioral_gnn.py`): CPU, Adam `1e-3`,
`BCEWithLogitsLoss` with pos_weight, **WeightedRandomSampler** by
`attack_type`, early stop on val PR-AUC (patience 8), seed 42. τ from
validation: highest F1 with FPR ≤ 0.05 (`max_f1_fpr_cap`).

Binary head only: shop-normal, vehicle-normal, enum, flooder, BOLA, BFLA all
share **y ∈ {0,1}**. Attack type is metadata for recall tables, not a
softmax class.

---

## 5. What the GNN can and cannot see

It **can** see: which OpenAPI operations appeared, how often, how fast (Δt),
self-loops, privileged templates (BFLA nodes), mixed vs hammered graphs.

It **cannot** see: whether order 8 belongs to this user (BOLA is flagged as
object-template hammering, like a short enum), cookies, or request bodies
beyond what status/error_fraction encodes.
