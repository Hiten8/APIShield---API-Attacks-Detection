# APIShield

**APIShield** is a hybrid REST API security framework that combines **OpenAPI-aware conformance validation** with **graph-based behavioral anomaly detection**.

It addresses two complementary questions:

1. **Conformance:** Does the request match the documented OpenAPI contract?
2. **Behavior:** Does the observed API usage exhibit anomalous operational patterns?

The behavioral component represents API activity as rolling **API call graphs** and uses a two-layer **Graph Isomorphism Network with Edge features (GINE)** for binary anomaly detection.

## Key Features

- OpenAPI-based request conformance validation
- Detection of undocumented parameters and endpoints
- Detection of missing required parameters and invalid parameter types
- Request-body validation
- Rolling-window API call graphs
- OpenAPI operation-level graph abstraction
- Temporal edge features based on inter-request timing
- Two-layer GINE behavioral detector
- Session-level scoring using the maximum rolling-window score
- Batch, stream/replay, and live reverse-proxy detection
- Controlled generation of normal and attack traffic

## Architecture

```text
                         API Traffic
                              |
                              v
                     +----------------+
                     |  Event Capture  |
                     +----------------+
                              |
                    +---------+---------+
                    |                   |
                    v                   v
          +------------------+   +----------------------+
          | OpenAPI          |   | Behavioral Detection |
          | Conformance      |   | Branch               |
          +------------------+   +----------------------+
                    |                   |
                    |                   v
                    |          +----------------------+
                    |          | Rolling Event Windows|
                    |          +----------------------+
                    |                   |
                    |                   v
                    |          +----------------------+
                    |          | API Call Graphs      |
                    |          +----------------------+
                    |                   |
                    |                   v
                    |          +----------------------+
                    |          | GINE Model           |
                    |          +----------------------+
                    |                   |
                    v                   v
             Conformance         Behavioral Score
                Findings                |
                    |                   |
                    +---------+---------+
                              |
                              v
                       Security Decision
```

## OpenAPI Conformance Detection

The conformance branch uses the OpenAPI specification as the expected API contract. It identifies the applicable path template and HTTP operation and validates:

- Path parameters
- Query parameters
- Required parameters
- Parameter types
- Request-body structure and types
- Supported paths and HTTP methods

Example findings include undocumented query parameters, missing required parameters, invalid parameter types, invalid request bodies, unknown endpoints, and unsupported methods.

Conformance validation is deterministic and interpretable. A request can nevertheless be valid according to the API contract while exhibiting malicious behavior; this motivates the behavioral branch.

## Behavioral Detection

### Rolling API Call Graphs

API activity is grouped into overlapping event windows.

Current configuration:

- **Window size:** 16 events
- **Training/batch stride:** 8
- **Live/stream stride:** 1
- **Session score:** maximum score across the session windows

Concrete URLs are normalized to OpenAPI operation templates. For example:

```text
GET /workshop/api/shop/orders/8
GET /workshop/api/shop/orders/26
```

are represented as:

```text
GET /workshop/api/shop/orders/{order_id}
```

Each distinct `(HTTP method, operation)` is a graph node. Directed edges connect consecutive operations, and repeated operations create self-loops.

### Graph Features

**Node features**

1. `log1p(visit_count)`
2. `log1p(mean_inbound_delta_t)`
3. `log1p(min_inbound_delta_t)`
4. `error_fraction`

An OpenAPI operation identifier is also represented using an embedding.

**Edge features**

1. `log1p(transition_count)`
2. `log1p(mean_delta_t)`
3. `log1p(min_delta_t)`

**Graph features**

1. `log1p(event_count)`
2. `log1p(mean_delta_t)`
3. `log1p(min_delta_t)`
4. `log1p(number_of_nodes)`
5. `log1p(max_self_loop_count)`

The representation emphasizes operation-level structure, transition behavior, repetition, timing, and error behavior rather than directly using object identifiers.

## GINE Model

The behavioral detector is a two-layer GINE model:

```text
Operation ID Embedding + Node Numeric Features
                    |
                    v
             64-dim representation
                    |
                 GINEConv
                    |
                  ReLU
                    |
              Dropout(0.2)
                    |
                 GINEConv
                    |
                  ReLU
                    |
           Global Mean + Max Pool
                    |
              128 dimensions
                    |
        + 5 graph-level features
                    |
             133 dimensions
                    |
                   MLP
                    |
                 Logit
                    |
                Sigmoid
                    |
             Attack Score
```

The model performs binary classification:

```text
0 = Normal
1 = Attack
```

Attack categories are retained as scenario metadata rather than separate softmax classes.

Training uses Adam with learning rate `1e-3`, weighted binary cross-entropy, weighted sampling, validation PR-AUC for early stopping, and validation-based threshold selection with a false-positive-rate constraint.

## Traffic Generation

The evaluation environment uses **OWASP crAPI** as the target API.

### Normal scenarios

- Shop-user workflows
- Vehicle-related workflows

### Attack scenarios

- Enumeration
- Mass flooding
- Broken Object Level Authorization (BOLA)
- Broken Function Level Authorization (BFLA)

Traffic is stored as JSONL event data, with labels assigned according to the generation scenario rather than inferred from HTTP status codes.

## Runtime Modes

### Batch

Processes previously collected JSONL sessions using rolling windows.

Typical configuration:

```text
Window size: 16
Stride:      8
Idle gap:    60 seconds
```

### Stream / Replay

Processes events sequentially using a rolling buffer and scores new windows as events arrive.

### Live Reverse Proxy

The documented development configuration uses:

```text
APIShield proxy: http://localhost:8090
crAPI target:    http://localhost:8888
```

The live detector maintains the latest 16 events and evaluates behavioral graphs as requests arrive.

## Session Identification

For live traffic, the session key is resolved in this order:

1. `X-APIShield-Session`
2. JWT `email` / `sub`
3. Client IP address

## Evaluation Dataset

The documented corpus contains:

| Scenario | Sessions | Windows |
|---|---:|---:|
| Normal shop | 50 | 58 |
| Normal vehicle | 50 | 115 |
| Enumeration | 31 | 164 |
| Mass flooding | 30 | 94 |
| BOLA | 50 | 58 |
| BFLA | 50 | 50 |
| **Total** | **261** | **539** |

Session-level split:

- Training: 183 sessions / 383 windows
- Validation: 41 sessions / 89 windows
- Test: 37 sessions / 67 windows

## Reported Evaluation

The documented controlled evaluation selected a threshold of approximately `0.5088`.

Reported test results include:

- Session-level PR-AUC: `1.00`
- ROC-AUC: `1.00`
- Enumeration recall: `1.00`
- Mass flooding recall: `1.00`
- BOLA recall: `1.00`
- BFLA recall: `1.00`

A separate confirmation set contained 51 sessions:

- True positives: 41
- True negatives: 10
- False positives: 0
- False negatives: 0

These results apply to the controlled traffic used in the project and should not be interpreted as guaranteed performance on arbitrary production API traffic.

## Repository Structure

```text
src/
└── apishield/
    ├── behavioral/
    │   ├── windowing.py
    │   ├── graphs.py
    │   ├── model.py
    │   └── infer.py
    │
    └── conformance/
        ├── models.py
        ├── path_matcher.py
        ├── validator.py
        ├── parameter_checker.py
        └── body_checker.py

targets/
└── crAPI-main/
    └── openapi-spec/
        └── crapi-openapi-spec.json
```

Additional scripts support traffic generation, demonstrations, training, replay, and live proxy execution.

## Reproducibility

A typical experiment follows this sequence:

1. Start the local crAPI target.
2. Load the project OpenAPI specification.
3. Generate or collect API event logs.
4. Split sessions before creating overlapping windows.
5. Build rolling API call graphs.
6. Train the GINE behavioral model.
7. Select the threshold using validation data.
8. Evaluate on unseen sessions.
9. Optionally replay the event stream or use the live reverse proxy.

The exact commands and environment configuration should follow the scripts and configuration files included in the repository.

## Design Considerations

APIShield intentionally combines two security perspectives.

**Conformance is not the same as anomaly detection.** A request can be structurally valid while its sequence, frequency, timing, or transition pattern is suspicious.

**Behavioral detection is not a complete authorization oracle.** The current GINE model does not directly observe object ownership, complete authentication state, cookies, or full request-body semantics. It is therefore a complementary detection mechanism rather than a replacement for application-level authorization.


---

## First-Time Setup Guide

This section is intended for a new user setting up APIShield for the first time.

### 1. Clone the repository

Clone the APIShield repository and move into the repository root:

```bash
git clone <APIShield-repository-url>
cd APIShield---API-Attacks-Detection
```

All APIShield commands below are run from this repository root.

> If the repository directory has a different name after cloning, use that directory name instead.

### 2. Prepare the runtime environment

APIShield uses Python for the conformance, traffic-generation, graph-building, training, and scoring components.

Create and activate a Python virtual environment before installing the dependencies required by the repository:

```bash
python -m venv .venv
```

Activate it on Linux/macOS:

```bash
source .venv/bin/activate
```

On Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Install the Python dependencies using the dependency file provided in the repository. For example, if the repository contains `requirements.txt`:

```bash
pip install -r requirements.txt
```

If the project uses a different dependency-management file, follow the corresponding instructions included in the repository.

### 3. Start the crAPI target

APIShield's documented traffic generators and live proxy target a local **OWASP crAPI** instance.

The expected default target is:

```text
http://localhost:8888
```

Start the crAPI Docker environment supplied with the project and wait until the application is ready.

Before continuing, verify that the crAPI service is reachable at port `8888`.

The traffic generators require crAPI to be running. The vehicle workflow also uses MailHog on port `8025` unless `--skip-provision` is supplied.

### 4. Verify the OpenAPI specification

APIShield uses the crAPI OpenAPI specification to map concrete requests to operation templates.

The expected project path is:

```text
targets/crAPI-main/openapi-spec/crapi-openapi-spec.json
```

The same specification is used by the behavioral graph-processing pipeline and the conformance branch.

Do not replace the specification with a different API specification unless you also update the corresponding target and configuration.

### 5. Prepare test logins

The traffic-generation utilities use:

```text
test_logins.json
```

by default, relative to the repository.

If the login file is stored somewhere else, provide it explicitly using the generator's `--logins` option.

Do not commit real passwords, access tokens, or other credentials to GitHub.

### 6. Generate normal traffic

Once crAPI is running, generate normal shop and vehicle sessions:

```bash
python scripts/generate_normal_traffic.py \
    --num-sessions 10 \
    --delay-scale 1.0
```

For a faster demonstration, the documented setup also supports:

```bash
python scripts/generate_normal_traffic.py \
    --num-sessions 10 \
    --delay-scale 0.05 \
    --skip-provision \
    --shop-output data/raw/shop_sessions2.jsonl
```

The generators write OpenAPI-valid requests to JSONL files.

### 7. Generate attack traffic

Generate the attack scenarios individually.

#### Enumeration

```bash
python scripts/generate_attack_traffic.py \
    --num-sessions 10 \
    --attack enumeration \
    --enum-output data/raw/shop_order_enumeration_2.jsonl
```

#### Mass flooding

```bash
python scripts/generate_attack_traffic.py \
    --num-sessions 10 \
    --attack flooder \
    --flood-output data/raw/shop_order_flooder_2.jsonl
```

#### BOLA

`--max-targets` is required for the documented BOLA generator:

```bash
python scripts/generate_attack_traffic.py \
    --num-sessions 10 \
    --attack bola \
    --max-targets 5 \
    --bola-output data/raw/shop_order_bola_2.jsonl
```

#### BFLA

```bash
python scripts/generate_attack_traffic.py \
    --num-sessions 10 \
    --attack bfla \
    --bfla-output data/raw/shop_workshop_bfla_2.jsonl
```

The generators label traffic by the attack scenario rather than by HTTP status code. This is important because a malicious request can legitimately receive a `200`, `403`, `404`, or another response.

### 8. Build behavioral windows

Before training the GINE model, convert the raw behavioral events into rolling graph windows:

```bash
python scripts/build_behavioral_windows.py
```

The documented pipeline reads the original raw files listed in the script's `DEFAULT_FILES` configuration and writes:

```text
data/processed/windows.jsonl
```

The window configuration used by the training/batch pipeline is:

```text
Window size: 16
Stride:      8
Idle gap:    60 seconds
```

Sessions should be partitioned before overlapping windows are created so that windows from the same session do not leak across train, validation, and test sets.

### 9. Train the GINE model

Train the behavioral detector:

```bash
python scripts/train_behavioral_gnn.py
```

The documented training procedure uses CPU training, Adam with learning rate `1e-3`, weighted binary cross-entropy, weighted sampling, validation PR-AUC for early stopping, and validation-based threshold selection.

After successful training, the scoring interfaces expect the trained artifacts at:

```text
data/processed/behavioral_gnn.pt
data/processed/threshold.json
```

The selected threshold in the documented experiment is approximately:

```text
0.5088
```

### 10. Score a JSONL session file

For batch scoring:

```bash
python scripts/score_behavioral_sessions.py \
    --input data/raw/shop_order_enumeration_2.jsonl \
    --output data/processed/Enumeration_testing.json
```

The batch scorer uses train-style rolling windows:

```text
Window size: 16
Stride:      8
Idle gap:    60 seconds
```

Useful options include:

```text
--checkpoint
--threshold
--spec
--window-size
--stride
--idle-gap
```

### 11. Run stream/replay detection

To process a JSONL file event-by-event:

```bash
python scripts/score_behavioral_stream.py \
    --input data/raw/shop_order_enumeration_2.jsonl
```

To display only detections:

```bash
python scripts/score_behavioral_stream.py \
    --input data/raw/shop_order_enumeration_2.jsonl \
    --only-flags
```

The stream interface uses the latest 16 events and normally scores with stride 1 after the minimum number of events has been reached.

The documented default is:

```text
min_events = 4
stride = 1
idle_gap = 60 seconds
```

### 12. Run the live APIShield proxy

Start the live reverse proxy:

```bash
python scripts/run_live_gnn_proxy.py
```

By default:

```text
APIShield: http://localhost:8090
crAPI:    http://localhost:8888
```

Point the React application, Postman, or another authorized API client to:

```text
http://localhost:8090
```

instead of directly using port `8888`.

The live proxy:

1. Receives the API request.
2. Forwards it to crAPI.
3. Captures the resulting API event.
4. Adds the event to the session buffer.
5. Builds a graph from the latest 16 events.
6. Computes the behavioral score.
7. Maintains the maximum session score.

Useful live-proxy defaults are:

```text
--target http://localhost:8888
--port 8090
--stride 1
--min-events 4
--idle-gap 0
```

The live proxy also exposes control endpoints that are not forwarded to crAPI:

```text
GET http://localhost:8090/apishield/health
GET http://localhost:8090/apishield/sessions
```

The sessions endpoint reports the current `session_max` and flagged state for active session keys.

### 13. Understand live session identification

For live traffic, APIShield determines the session key in this order:

1. `X-APIShield-Session`
2. JWT `email` / `sub` from the `Authorization: Bearer` header
3. Client IP address

A login request does not yet contain a JWT, so a login and later authenticated requests can sometimes initially map to different keys unless an explicit `X-APIShield-Session` header is supplied.

For controlled experiments, using a stable session header can make session tracking easier.

### 14. Run the conformance component

The conformance branch uses the OpenAPI specification to validate requests against the documented contract.

The core implementation is located under:

```text
src/apishield/conformance/
```

including:

```text
models.py
path_matcher.py
validator.py
parameter_checker.py
body_checker.py
```

The project also includes a conformance demonstration script:

```text
demo_conformance_traffic.py
```

Use the repository's supplied demonstration/configuration when testing the conformance branch.

Typical findings demonstrated by the project include:

- Undocumented query parameters
- Invalid path parameter types
- Missing required parameters
- Invalid request-body types
- Unsupported methods / unknown endpoints

### 15. Recommended first successful test

For a first-time user, the easiest validation sequence is:

```text
1. Start crAPI
       ↓
2. Verify localhost:8888
       ↓
3. Activate the Python environment
       ↓
4. Generate a small normal dataset
       ↓
5. Generate a small enumeration dataset
       ↓
6. Build behavioral windows
       ↓
7. Train the GINE model
       ↓
8. Run the batch scorer
       ↓
9. Run the stream scorer
       ↓
10. Start the live proxy
       ↓
11. Send authorized requests through :8090
```

Start with a small number of sessions while validating the installation. Increase the dataset size only after the complete pipeline works.

### 16. Troubleshooting checklist

If APIShield does not work on the first run, check the following in order:

**crAPI is unavailable**

```text
Expected target: http://localhost:8888
```

Make sure the crAPI Docker environment is running before starting traffic generation or the live proxy.

**Missing model artifacts**

The scoring interfaces expect:

```text
data/processed/behavioral_gnn.pt
data/processed/threshold.json
```

Run the behavioral-window build and training steps before scoring.

**Wrong OpenAPI specification**

Verify:

```text
targets/crAPI-main/openapi-spec/crapi-openapi-spec.json
```

**No behavioral score appears**

For stream/live scoring, fewer than four events do not produce a score by default.

**Live proxy appears slow**

The documented live configuration uses `--idle-gap 0`. Do not increase the idle gap without understanding how it changes session splitting.

**Vehicle traffic generation fails**

The vehicle workflow requires MailHog on port `8025` unless `--skip-provision` is used.

**BOLA generation fails**

Make sure `--max-targets` is supplied and that the target crAPI instance contains the required account/order data.

**Session continuity looks incorrect**

Use an explicit `X-APIShield-Session` header for controlled live testing, or verify the JWT/session-key behavior described above.

### 17. Safety reminder

The attack generators intentionally produce security-testing traffic such as enumeration, flooding, BOLA, and BFLA patterns.

Run them only against the local crAPI instance or another system for which you have explicit authorization.

Never point these generators at a production API or a third-party service without permission.

## Security and Data Handling

Use the traffic generators only against systems for which you have explicit authorization.

Do not commit real credentials, tokens, secrets, or sensitive traffic logs to the repository. Generated examples should use controlled local test data.

## Research Context

APIShield is a research prototype for studying the combination of:

- API specification conformance
- Runtime API behavior
- Rolling call-graph representations
- Graph neural networks
- API attack detection

The central idea is to combine **what the API contract permits** with **how the API is actually used over time**.

## Citation

If you use APIShield in academic work, cite the associated research paper once its final publication details are available.

## Disclaimer

APIShield is an experimental security framework. Detection performance depends on the API specification, traffic characteristics, training data, and deployment environment. The reported evaluation uses controlled traffic and does not guarantee production-grade detection performance.
