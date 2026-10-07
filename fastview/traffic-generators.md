# Traffic generators

All generators hit a live crAPI instance (default `http://localhost:8888`),
write **OpenAPI-valid** requests to JSONL, and label later by **filename**,
not status code. Passwords in bodies are redacted.

Logins: `../test_logins.json` relative to the repo (`--logins` to override).
crAPI must be up. Vehicle workflow also needs MailHog (`:8025`) unless
`--skip-provision`.

Code: `src/apishield/traffic/workflows.py` (normal),
`src/apishield/traffic/attacks.py` (attacks),
`scripts/generate_normal_traffic.py`, `scripts/generate_attack_traffic.py`.

---

## How to run

Default outputs currently append to the **confirmation** files (`*_2.jsonl`).
Pass `--*-output` if you want a different path.

**Normal** (shop **and** vehicle, `--num-sessions` times each, rotating users):

```text
python scripts/generate_normal_traffic.py --num-sessions 10 --delay-scale 1.0
python scripts/generate_normal_traffic.py --num-sessions 10 --delay-scale 0.05 --skip-provision --shop-output data/raw/shop_sessions2.jsonl
```

**Attacks** (one type per run; users rotate round-robin):

```text
python scripts/generate_attack_traffic.py --num-sessions 10 --attack enumeration --enum-output data/raw/shop_order_enumeration_2.jsonl
python scripts/generate_attack_traffic.py --num-sessions 10 --attack flooder --flood-output data/raw/shop_order_flooder_2.jsonl
python scripts/generate_attack_traffic.py --num-sessions 10 --attack bola --max-targets 5 --bola-output data/raw/shop_order_bola_2.jsonl
python scripts/generate_attack_traffic.py --num-sessions 10 --attack bfla --bfla-output data/raw/shop_workshop_bfla_2.jsonl
```

`--attack both` runs enumeration **and** flooder in the same loop.
`--delay-scale` multiplies sleeps (use `0.05` for a fast demo).
`--max-targets` is **required** for BOLA (max victim *accounts* per session).

---

## Shared timing

**Normal** delay bands (seconds, then × `delay_scale`). Floor 1 s unless
`delay_scale < 1`:

| Band | Range | Typical use |
|---|---|---|
| MISCLICK | 1–3 | accidental extra GET |
| NAV | 3–8 | move between pages |
| SCAN | 15–45 | glance at a list |
| READ | 60–180 | read dashboard / location |
| THINK | 20–90 | decide to buy / resend email |

**Attacks** use a tight band **0.05–0.80 s** × `delay_scale` (floor 0.02 s).
That Δt gap is a large part of what the GNN sees.

After **login**, every workflow may stop with **p = 0.10** (`EARLY_QUIT_PROBABILITY`)
on **normal only**. Attacks always continue if login is 200.

---

## Normal — shop browse

Skeleton (always, if login succeeds and no early quit):

```text
POST /identity/api/auth/login
→ GET /workshop/api/shop/products
→ [optional product refreshes]
→ [optional POST /orders + GET that order]
→ GET /workshop/api/shop/orders/all
→ [optional GET own /orders/{id}]
→ [optional products misclick]
```

| Random choice | Probability / range |
|---|---|
| Early quit after login | 0.10 |
| Extra `GET products` | uniform **0, 1, or 2** times |
| Place an order (`POST /orders`, qty=1, random catalog id) | **0.40** |
| After `orders/all`, open **one own** `GET /orders/{id}` | **0.55** if any own ids |
| Trailing products “misclick” | **0.15** |

---

## Normal — vehicle / dashboard

Skeleton:

```text
POST /identity/api/auth/login
→ GET /identity/api/v2/user/dashboard
→ GET /identity/api/v2/vehicle/vehicles
→ GET /identity/api/v2/vehicle/{uuid}/location   (one owned vehicle)
→ [one of: location refresh | resend_email | dashboard misclick | stop]
```

| Random choice | Probability |
|---|---|
| Early quit after login | 0.10 |
| No vehicles: bounce to dashboard | **0.30**, else stop |
| After location, `roll ~ U(0,1)` | |
| `roll < 0.50` | refresh **same** location |
| `0.50 ≤ roll < 0.65` | `POST .../vehicle/resend_email` |
| `0.65 ≤ roll < 0.85` | dashboard misclick |
| `roll ≥ 0.85` | stop |

---

## Attack A — order ID enumeration

Skeleton (always):

```text
login → optional light cover → many GET /workshop/api/shop/orders/{id}
        → optional mid-burst GET /orders/all
```

Status 200 / 403 / 404 are all kept.

| Random choice | Distribution |
|---|---|
| Cover | `none` / `products` / `orders_all` each **1/3** |
| ID mode | `foreign` or `mixed` each **1/2**. Mixed may force `orders/all` to learn owned ids, then insert **1–2** owned ids into the scan |
| Strategy | `sequential` / `random_sample` / `stride` each **1/3**. Stride ∈ {2, 3, 5} |
| Start id | uniform **1–50** |
| Burst length | uniform **15–80** |
| Mid-burst `orders/all` | **0.35** (at the midpoint of the id list) |

---

## Attack B — mass order flooding

Skeleton:

```text
login → optional GET products → many POST /workshop/api/shop/orders
      → optional follow-up
```

| Random choice | Distribution |
|---|---|
| Fetch products first | **0.75** (else product_id falls back to `1`) |
| POST count | uniform **10–40** |
| Product mode | `fixed` or `round_robin` each **1/2** |
| Quantity | uniform **1–3** |
| Follow-up | `none` / `GET orders/all` / `GET last created order` each **1/3** |

---

## Attack C — BOLA (foreign known orders)

**Not** ID guessing. First, `collect_order_ownership` logs every user in and
pages `GET /orders/all` into `order_ownership*.json`.

Each session:

1. Attacker = users\[session % n\].
2. Sample **x ~ Uniform(1, `--max-targets`)** other accounts that own orders.
3. `access_plan` = all of those victims’ order ids.
4. Traversal `ordered` or `random` each **1/2** (chosen in the script).
5. Workflow:

```text
login(attacker)
→ cover none | products | orders/all  (each 1/3)
→ for each (victim, order_id) in plan:
      skip this object with p = 0.05
      else GET /orders/{id}
      then maybe PUT /orders/{id} or POST return_order
→ trailing GET /orders/all with p = 0.40
```

| Random choice | Distribution |
|---|---|
| Mutate mode (whole session) | `get_only` / `get_put` / `get_return` each **1/3** |
| Skip an object | **0.05** |

The GNN still only sees `GET /orders/{order_id}` nodes — ownership is for
**dataset construction**, not a model feature.

---

## Attack D — workshop BFLA

Normal **shop** user hits privileged workshop/management routes. No mechanic
seed required.

```text
login
→ cover none | products | orders/all  (each 1/3)
→ k probes, k ~ Uniform(1, 4), sample k of the four kinds (no replacement)
→ trailing GET /orders/all with p = 0.40
```

| Probe | Request |
|---|---|
| `users_all` | `GET /workshop/api/management/users/all` , **1 or 2** pages (`limit=10`) |
| `mechanic_list` | `GET /workshop/api/mechanic/` once |
| `service_requests` | `GET /workshop/api/mechanic/service_requests` once |
| `mechanic_report` | `GET .../mechanic_report?report_id=` **1–3** ids sampled from 1–30 |

403/400 still count as events; the graph contains privileged **templates**.
