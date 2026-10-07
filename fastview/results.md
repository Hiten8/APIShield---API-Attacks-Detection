# Results (synthetic JSONL)

Two evaluations: (1) the session-id hold-out used at train time, (2) a later
generator replay scored with the **frozen** checkpoint and **τ = 0.5088**.

Scoring: last-16 events, stride 8, idle gap 60 s, `session_score = max(window
scores)`, flag iff score ≥ τ. Labels come from the **JSONL source file**, not
HTTP status.

---

## 1. Training and in-distribution testing

Traffic was captured against OWASP crAPI. Each session was cut into
OpenAPI-template transition graphs with **N = 16** events, **stride = 8**,
idle gap **60 s**.

**Corpus (before split)**

| Class | Sessions | Windows |
|---|---:|---:|
| Normal (shop) | 50 | 58 |
| Normal (vehicle) | 50 | 115 |
| Enumeration | 31 | 164 |
| Mass flooding | 30 | 94 |
| BOLA | 50 | 58 |
| BFLA | 50 | 50 |
| **Total** | **261** | **539** |

Windows: 173 benign, 366 attack.

**Split.** Session-id split, **stratified by `attack_type`**, seed **42**,
**70 / 15 / 15** (all windows of a session stay in one split):

| Split | Sessions | Windows |
|---|---:|---:|
| Train | 183 | 383 |
| Val | 41 | 89 |
| Test | 37 | 67 |

A binary GINE was trained on CPU. The decision threshold was chosen on
**validation** with `max_f1_fpr_cap`.

**Held-out test (`data/processed/threshold.json`)**

| Quantity | Value |
|---|---|
| τ | 0.5088 |
| Val F1 | 1.00 |
| Val FPR | 0.00 |
| Test session PR-AUC | 1.00 |
| Test session ROC-AUC | 1.00 |
| Test recall: enum / flooder / BOLA / BFLA | 1.00 each |

These metrics are on **unseen sessions from the same generators**, not a public
IDS corpus. Perfect AUROC means the generators are separable in graph space at
this τ; it is not a claim about arbitrary production traffic.

---

## 2. Fresh generator runs (confirmation set)

A second capture was run **after** training. The model and τ were **not**
updated. Session IDs in the score files do not appear in `windows.jsonl`.

Files:

- `data/processed/normal_testing.json`
- `data/processed/Enumeration_testing.json`
- `data/processed/Flooder_testing.json`
- `data/processed/Bola_testing.json`
- `data/processed/Bfla_testing.json`

**Per-class results**

| Traffic | Sessions | Flagged | Accuracy | Score min / med / max | Events (med, range) |
|---|---:|---:|---:|---|---|
| Normal (shop) | 10 | 0 | 100% | 0.270 / 0.351 / **0.477** | 5 (1–6) |
| Enumeration | 11 | 11 | 100% | **0.515** / 0.802 / 0.822 | 46 (3–79) |
| Mass flooding | 10 | 10 | 100% | 0.681 / 0.738 / 0.749 | 25 (12–38) |
| BOLA | 10 | 10 | 100% | 0.587 / 0.664 / 0.739 | 12.5 (4–28) |
| BFLA | 10 | 10 | 100% | 0.540 / 0.597 / 0.613 | 6 (5–8) |

**Aggregate (51 sessions):** TP = 41, TN = 10, FP = 0, FN = 0. Precision /
recall / FPR = **1.00 / 1.00 / 0.00**. Treat this as **session-level accuracy
on a confirmation set**, not a second ROC (n is small).

**Separation.** Normal scores stay **below τ** (max 0.477). Enumeration and
flooding sit well above it except one **3-event** enum session at **0.515**,
which still flags. BOLA and BFLA sit between flooding and τ; BFLA is the
tightest attack band (0.54–0.61) but all 10 sessions are ≥ 5 events.

**Caveats**

- Same generator family as training; this rules out “we scored the train
  file,” not “any unseen attack.”
- Confirmation **normal** is shop-only (`shop_sessions2.jsonl`);
  vehicle-normal was in training, not in this replay.
- Enumeration is **11** sessions (one extra short capture), not 10.
