# APIShield

APIShield is a cybersecurity project that combines **OpenAPI contract
conformance validation** with **behavioural anomaly detection** for API
traffic.

The project is being developed in two major branches:

1. **OpenAPI Conformance Validation**
2. **Behavioural Anomaly Detection using per-user API call graphs and GNNs**

At the current development checkpoint, the OpenAPI conformance branch has
been implemented and validated against a running OWASP crAPI deployment.

The behavioural/GNN branch has not yet been implemented.

---

## Current Project Status

### Completed

- Python project scaffold
- API event data model
- HTTP traffic client
- API request interception/event generation
- OpenAPI specification loading
- OpenAPI path matching
- OpenAPI parameter validation
- OpenAPI request-body validation
- OpenAPI conformance result modelling
- Conformance violation severity classification
- Integration with OWASP crAPI
- Real authenticated API traffic testing
- Real unauthenticated API traffic testing
- Real malformed API traffic testing
- Conformance attack test suite
- Path-matching regression handling
- Automated test suite

### Not Yet Implemented

- Normal-user traffic generator
- Behavioural dataset generation
- Per-user API call sequences
- Per-user call graphs
- Graph feature extraction
- GNN model
- Behavioural anomaly scoring
- Combined conformance + behavioural detection
- Final APIShield detection/decision pipeline

---

# Architecture

The overall project is designed around two complementary detection branches.

```text
                    API Traffic
                         |
                         v
                 +---------------+
                 |   APIShield   |
                 +---------------+
                         |
             +-----------+-----------+
             |                       |
             v                       v
    OpenAPI Conformance      Behavioural Analysis
         Branch                    Branch
             |                       |
             v                       v
     Contract Validation      Per-user Call Graph
             |                       |
             v                       v
      Conformance Result            GNN
                                     |
                                     v
                            Behavioural Anomaly

```

# OpenAPI Conformance Branch

The current branch receives API traffic as APIEvent objects and evaluates
the request against the target API's OpenAPI specification.

HTTP Request
     |
     v
Target API
     |
     v
APIEvent
     |
     v
OpenAPI Validator
     |
     +-------------------+
     |                   |
     v                   v
 Valid Request       Violations
                         |
                         v
                  Severity / Details


# APIEvent

APIShield represents observed API traffic using an APIEvent.

An event contains information such as:

event ID
timestamp
user ID
HTTP method
request path
resolved endpoint
query parameters
request body
response status
target service

Example:
{
    "event_id": "...",
    "timestamp": "...",
    "user_id": "crapi-test-user",
    "method": "GET",
    "path": "/workshop/api/shop/products",
    "endpoint": "/workshop/api/shop/products",
    "query_parameters": {},
    "request_body": null,
    "response_status": 200,
    "target_service": "crapi"
}

Authentication tokens are kept in memory by the traffic client and are not
stored inside the APIEvent.


# OpenAPI Specification

The current integration target is OWASP crAPI.

The project uses the crAPI OpenAPI specification:

targets/crAPI-main/openapi-spec/crapi-openapi-spec.json

The specification currently used by the integration tests is:

OpenAPI: 3.0.1
Title: OWASP crAPI API
Endpoints: 40

The specification defines a bearer authentication scheme using JWT.

# OpenAPI Path Matching

APIShield resolves incoming request paths against the OpenAPI paths.

The matcher supports parameterized paths such as:

/identity/api/v2/user/videos/{video_id}

and static paths such as:

/workshop/api/shop/orders/all

A specificity rule was added so that an exact/static path takes precedence
over a parameterized path.

For example:

/workshop/api/shop/orders/all

must be matched before:

/workshop/api/shop/orders/{order_id}

when the request path is:

/workshop/api/shop/orders/all

This prevents all from incorrectly being interpreted as an
order_id.

A regression test is included for this behaviour.

# Conformance Validation

The validator currently checks multiple aspects of an API request against
the OpenAPI specification.

These include:

endpoint/path matching
HTTP method validity
required parameters
parameter types
undocumented query parameters
request-body schema validation

The validator produces a structured conformance result containing:

valid
endpoint
method
violations

Each violation contains information such as:

violation type
message
parameter
location
expected type
actual value
severity
Severity

The current conformance implementation assigns severity based on the type
of contract violation.

The current tested examples include:

Violation	Severity
Undocumented query parameter	Medium
Invalid path parameter type	Medium
Missing required parameter	High
Invalid request body	High
Unsupported/undefined HTTP method	High

Severity is currently part of the conformance result and is intended to
provide a basic indication of the security relevance of a contract
violation.

# Real crAPI Integration

APIShield has been integrated with a running Dockerized crAPI deployment.

The integration tests communicate with crAPI over HTTP rather than using
only mocked responses.

The project has verified:

Authenticated traffic
TargetAPIClient
      |
      v
crAPI login
      |
      v
JWT
      |
      v
Authenticated API request
      |
      v
APIEvent
Unauthenticated traffic

The client also supports endpoints that do not require authentication.

When no JWT is present, the client does not add an Authorization header.

When a JWT is present, the client adds:

Authorization: Bearer <JWT>

Both behaviours have been tested against the real crAPI deployment.

# Conformance Attack Tests

The conformance branch has been tested against real crAPI traffic using
five attack scenarios.

## Attack 1 — Undocumented Query Parameter

A request is sent with a query parameter that is not declared in the
OpenAPI specification.

Example:

GET /workshop/api/shop/products?unexpected_parameter=attack-test

Expected result:

UNDOCUMENTED_PARAMETER
Severity: medium

## Attack 2 — Invalid Path Parameter Type

The OpenAPI specification defines:

video_id -> integer

The test sends a non-integer value:

GET /identity/api/v2/user/videos/not-an-integer

Expected result:

INVALID_PARAMETER_TYPE
Severity: medium

## Attack 3 — Missing Required Query Parameter

The OpenAPI specification defines required query parameters:

limit
offset

The test intentionally omits:

offset

Expected result:

MISSING_REQUIRED_PARAMETER
Parameter: offset
Location: query
Severity: high

This test also exposed and led to the correction of a path-matching
specificity issue involving:

/workshop/api/shop/orders/all

and:

/workshop/api/shop/orders/{order_id}

## Attack 4 — Invalid Request Body Type

The login request body defines:

email -> string
password -> string

The test intentionally sends an integer for email.

Example:

{
    "email": 12345,
    "password": "..."
}

Expected result:

INVALID_REQUEST_BODY
Location: body
Severity: high

This test also verified that the traffic client can send an
unauthenticated request to the login endpoint.

## Attack 5 — Unsupported HTTP Method

The OpenAPI specification defines operations for:

GET /workshop/api/shop/products
POST /workshop/api/shop/products

The test sends:

DELETE /workshop/api/shop/products

The target API returns:

405 Method Not Allowed

The APIShield conformance layer identifies this as a method-level contract
violation.

Current result:

UNKNOWN_ENDPOINT
Location: method
Severity: high

The violation message identifies that the HTTP method is not defined for
the endpoint.

# Testing

The project currently has a unit and integration test suite.

At the current checkpoint:

31 tests passed

The test suite covers:

API event models
request interception
middleware
normalization
OpenAPI loading
path matching
conformance validation
dataset-related components already implemented
crAPI OpenAPI integration
crAPI path matching
crAPI authenticated traffic
crAPI unauthenticated traffic
real conformance attack scenarios
traffic client authentication behaviour

Run the complete test suite with:

pytest

A successful run should report:

31 passed

The exact number may increase as new project functionality is added.

# Project Structure

The current project is organized approximately as follows:

APIShield/
│
├── src/
│   └── apishield/
│       │
│       ├── ingestion/
│       │   └── models.py
│       │
│       ├── conformance/
│       │   ├── body_checker.py
│       │   ├── parameter_checker.py
│       │   ├── path_matcher.py
│       │   ├── validator.py
│       │   └── ...
│       │
│       └── traffic/
│           ├── client.py
│           └── workflows.py
│
├── tests/
│   ├── unit/
│   └── integration/
│
├── targets/
│   └── crAPI-main/
│
├── data/
│   ├── raw/
│   ├── processed/
│   └── graphs/
│
├── pyproject.toml
├── .gitignore
└── README.md

The behavioural/GNN components will be added in subsequent development
phases.

# Environment

APIShield is currently developed and tested using Python 3.13.

A Python virtual environment is recommended.

Create the environment:

python -m venv .venv

Activate it on Windows:

.venv\Scripts\activate

Install the project dependencies according to pyproject.toml.

The project uses packages including:

FastAPI
HTTPX
Pydantic
JSON Schema
NetworkX
NumPy
Pandas
OpenAPI specification validation tooling
PyYAML
Uvicorn
python-dotenv
crAPI

The current integration target is OWASP crAPI running through Docker
Compose.

The crAPI deployment is used as a realistic API target for:

authenticated traffic
unauthenticated traffic
OpenAPI specification validation
malformed request testing
conformance attack testing

The target deployment should be running before executing tests that require
live crAPI traffic.

# Current Development Checkpoint

The OpenAPI conformance branch is currently considered the first completed
baseline of APIShield.

The following pipeline has been demonstrated:

Real crAPI Request
       |
       v
TargetAPIClient
       |
       v
APIEvent
       |
       v
OpenAPIPathMatcher
       |
       v
OpenAPIValidator
       |
       v
ConformanceResult
       |
       v
Violation + Severity

The branch has been validated using real requests against Dockerized crAPI.

# Next Development Phase

The next phase is the Behavioural / GNN branch.

The planned pipeline is:

Normal crAPI User Traffic
          |
          v
       APIEvents
          |
          v
    User Sequences
          |
          v
   Per-user Call Graphs
          |
          v
    Graph Features
          |
          v
         GNN
          |
          v
 Behavioural Anomaly Score

The behavioural branch will initially focus on generating legitimate,
normal-user API traffic.

The resulting traffic will form the basis for constructing per-user API
call graphs before introducing graph-based anomaly detection.

# CrAPI Setup

## Clone APIShield
git clone <YOUR-GITHUB-REPO-URL>
cd APIShield

## Create Python environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

## Install APIShield
python -m pip install --upgrade pip
pip install -e .

## Download OWASP crAPI
mkdir targets
cd targets
curl.exe -L -o crapi.zip https://github.com/OWASP/crAPI/archive/refs/heads/main.zip
tar -xf .\crapi.zip
cd ..

## Start crAPI with Docker
cd targets\crAPI-main\deploy\docker
docker compose pull
docker compose -f docker-compose.yml --compatibility up -d

## Return to APIShield
cd ..\..\..\..

## Run APIShield tests
pytest