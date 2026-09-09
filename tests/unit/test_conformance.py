from datetime import datetime, timezone
from pathlib import Path

from apishield.conformance.openapi_loader import OpenAPILoader
from apishield.conformance.validator import OpenAPIValidator
from apishield.ingestion.models import APIEvent

SPECIFICATION = Path("tests/fixtures/openapi/simple_api.yaml")

def create_validator() -> OpenAPIValidator:
    specification = OpenAPILoader().load(SPECIFICATION)

    return OpenAPIValidator(specification)

def test_valid_request_passes_conformance():
    validator = create_validator()

    event = APIEvent(
        event_id="event_001",
        timestamp=datetime.now(timezone.utc),
        user_id="user_001",
        method="GET",
        path="/api/users/123",
        endpoint="/api/users/{id}",
        query_parameters={
            "include": "profile",
        },
        response_status=200,
    )

    result = validator.validate(event)

    assert result.valid is True
    assert result.violations == []

def test_undocumented_query_parameter_is_detected():
    validator = create_validator()

    event = APIEvent(
        event_id="event_002",
        timestamp=datetime.now(timezone.utc),
        user_id="user_001",
        method="GET",
        path="/api/users/123",
        endpoint="/api/users/{id}",
        query_parameters={
            "include": "profile",
            "is_admin": "true",
        },
        response_status=200,
    )

    result = validator.validate(event)

    assert result.valid is False
    assert len(result.violations) == 1

    violation = result.violations[0]

    assert violation.violation_type.value == "undocumented_parameter"
    assert violation.parameter == "is_admin"
    assert violation.location == "query"

def test_invalid_parameter_type_is_detected():
    validator = create_validator()

    event = APIEvent(
        event_id="event_003",
        timestamp=datetime.now(timezone.utc),
        user_id="user_001",
        method="GET",
        path="/api/users/not-a-number",
        endpoint="/api/users/{id}",
        query_parameters={},
        response_status=200,
    )

    result = validator.validate(event)

    assert result.valid is False
    assert len(result.violations) == 1

    violation = result.violations[0]

    assert violation.violation_type.value == "invalid_parameter_type"
    assert violation.parameter == "id"
    assert violation.expected_type == "integer"

def test_unknown_endpoint_is_detected():
    validator = create_validator()

    event = APIEvent(
        event_id="event_004",
        timestamp=datetime.now(timezone.utc),
        user_id="user_001",
        method="GET",
        path="/api/admin/users",
        endpoint="/api/admin/users",
        query_parameters={},
        response_status=200,
    )

    result = validator.validate(event)

    assert result.valid is False

    assert (
        result.violations[0].violation_type.value
        == "unknown_endpoint"
    )

def test_valid_request_body_passes_conformance():
    validator = create_validator()

    event = APIEvent(
        event_id="event_005",
        timestamp=datetime.now(timezone.utc),
        user_id="user_001",
        method="POST",
        path="/api/users",
        endpoint="/api/users",
        request_body={
            "username": "alice",
            "email": "alice@example.com",
        },
        response_status=201,
    )

    result = validator.validate(event)

    assert result.valid is True
    assert result.violations == []

def test_undocumented_body_field_is_detected():
    validator = create_validator()

    event = APIEvent(
        event_id="event_006",
        timestamp=datetime.now(timezone.utc),
        user_id="user_001",
        method="POST",
        path="/api/users",
        endpoint="/api/users",
        request_body={
            "username": "alice",
            "email": "alice@example.com",
            "is_admin": True,
        },
        response_status=201,
    )

    result = validator.validate(event)

    assert result.valid is False
    assert len(result.violations) == 1

    violation = result.violations[0]

    assert (
        violation.violation_type.value
        == "invalid_request_body"
    )

    assert violation.parameter == "is_admin"
    assert violation.location == "body"

def test_missing_required_body_field_is_detected():
    validator = create_validator()

    event = APIEvent(
        event_id="event_007",
        timestamp=datetime.now(timezone.utc),
        user_id="user_001",
        method="POST",
        path="/api/users",
        endpoint="/api/users",
        request_body={
            "username": "alice",
        },
        response_status=201,
    )

    result = validator.validate(event)

    assert result.valid is False
    assert len(result.violations) == 1

    violation = result.violations[0]

    assert (
        violation.violation_type.value
        == "invalid_request_body"
    )