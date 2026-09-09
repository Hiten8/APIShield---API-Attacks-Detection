import json
from datetime import datetime, timezone
from pathlib import Path

from apishield.conformance.openapi_loader import OpenAPILoader
from apishield.conformance.validator import OpenAPIValidator
from apishield.ingestion.models import APIEvent


CRAPI_SPEC = Path(
    "targets/crAPI-main/openapi-spec/crapi-openapi-spec.json"
)


def create_validator() -> OpenAPIValidator:
    specification = OpenAPILoader().load(CRAPI_SPEC)

    return OpenAPIValidator(specification)


def test_real_crapi_endpoint_is_recognized():
    validator = create_validator()

    event = APIEvent(
        event_id="crapi-test-001",
        timestamp=datetime.now(timezone.utc),
        user_id="test-user",
        method="GET",
        path="/identity/api/v2/user/dashboard",
        endpoint="/identity/api/v2/user/dashboard",
        query_parameters={},
        response_status=200,
    )

    result = validator.validate(event)

    assert result.endpoint == "/identity/api/v2/user/dashboard"
    assert result.method == "GET"

    assert result.violations == []
    assert result.valid is True