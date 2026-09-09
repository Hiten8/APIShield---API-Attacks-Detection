import os
from pathlib import Path

import pytest
from dotenv import load_dotenv

from apishield.conformance.openapi_loader import OpenAPILoader
from apishield.conformance.validator import OpenAPIValidator
from apishield.traffic.client import TargetAPIClient


load_dotenv()


CRAPI_BASE_URL = "http://localhost:8888"

CRAPI_SPEC = Path(
    "targets/crAPI-main/openapi-spec/crapi-openapi-spec.json"
)


@pytest.mark.anyio
async def test_crapi_undocumented_query_parameter():
    """
    Send a real authenticated request to crAPI with an
    undocumented query parameter.

    The HTTP request itself may still succeed, but the
    APIShield OpenAPI conformance layer should flag the
    request as non-conformant.
    """

    email = os.environ.get("CRAPI_TEST_EMAIL")
    password = os.environ.get("CRAPI_TEST_PASSWORD")

    if not email or not password:
        pytest.skip(
            "CRAPI_TEST_EMAIL and CRAPI_TEST_PASSWORD are not configured."
        )

    # Load the real crAPI OpenAPI specification.
    specification = OpenAPILoader().load(CRAPI_SPEC)

    validator = OpenAPIValidator(specification)

    # Authenticate against the real crAPI instance.
    client = TargetAPIClient(
        base_url=CRAPI_BASE_URL,
        target_service="crapi",
    )

    await client.login(
        email=email,
        password=password,
        user_id="crapi-attack-test-user",
    )

    # Send a legitimate endpoint with an intentionally
    # undocumented query parameter.
    response, event = await client.request(
        "GET",
        "/workshop/api/shop/products",
        params={
            "unexpected_parameter": "attack-test",
        },
    )

    print(
        "HTTP status:",
        response.status_code,
    )

    print(
        "APIEvent:",
        event.model_dump(),
    )

    # We're testing whether APIShield identifies the
    # contract violation.
    result = validator.validate(event)

    print(
        "Conformance result:",
        result.model_dump(),
    )

    assert result.valid is False
    assert len(result.violations) > 0

@pytest.mark.anyio
async def test_crapi_invalid_path_parameter_type():
    """
    Send a real authenticated request with an invalid type for
    the video_id path parameter.
    """

    email = os.environ.get("CRAPI_TEST_EMAIL")
    password = os.environ.get("CRAPI_TEST_PASSWORD")

    if not email or not password:
        pytest.skip(
            "CRAPI_TEST_EMAIL and CRAPI_TEST_PASSWORD are not configured."
        )

    specification = OpenAPILoader().load(CRAPI_SPEC)
    validator = OpenAPIValidator(specification)

    client = TargetAPIClient(
        base_url=CRAPI_BASE_URL,
        target_service="crapi",
    )

    await client.login(
        email=email,
        password=password,
        user_id="crapi-invalid-type-test-user",
    )

    response, event = await client.request(
        "GET",
        "/identity/api/v2/user/videos/not-an-integer",
    )

    print(
        "HTTP status:",
        response.status_code,
    )

    print(
        "APIEvent:",
        event.model_dump(),
    )

    result = validator.validate(event)

    print(
        "Conformance result:",
        result.model_dump(),
    )

    assert result.valid is False
    assert len(result.violations) > 0

@pytest.mark.anyio
async def test_crapi_missing_required_query_parameter():
    """
    Send a real authenticated request to crAPI while omitting
    one of the required query parameters defined by OpenAPI.
    """

    email = os.environ.get("CRAPI_TEST_EMAIL")
    password = os.environ.get("CRAPI_TEST_PASSWORD")

    if not email or not password:
        pytest.skip(
            "CRAPI_TEST_EMAIL and CRAPI_TEST_PASSWORD are not configured."
        )

    specification = OpenAPILoader().load(CRAPI_SPEC)
    validator = OpenAPIValidator(specification)

    client = TargetAPIClient(
        base_url=CRAPI_BASE_URL,
        target_service="crapi",
    )

    await client.login(
        email=email,
        password=password,
        user_id="crapi-missing-parameter-test-user",
    )

    # 'offset' is intentionally omitted.
    response, event = await client.request(
        "GET",
        "/workshop/api/shop/orders/all",
        params={
            "limit": 30,
        },
    )

    print(
        "HTTP status:",
        response.status_code,
    )

    print(
        "APIEvent:",
        event.model_dump(),
    )

    result = validator.validate(event)

    print(
        "Conformance result:",
        result.model_dump(),
    )

    assert result.valid is False
    assert len(result.violations) > 0

    missing_parameter_violations = [
        violation
        for violation in result.violations
        if violation.violation_type.value
        == "missing_required_parameter"
    ]

    assert len(missing_parameter_violations) == 1

    violation = missing_parameter_violations[0]

    assert violation.parameter == "offset"
    assert violation.location == "query"
    assert violation.severity == "high"

@pytest.mark.anyio
async def test_crapi_invalid_request_body_type():
    """
    Send a real request to crAPI with an invalid JSON request-body
    type.

    The OpenAPI specification defines the login email field as a
    string. We intentionally send an integer instead.
    """

    email = os.environ.get("CRAPI_TEST_EMAIL")
    password = os.environ.get("CRAPI_TEST_PASSWORD")

    if not email or not password:
        pytest.skip(
            "CRAPI_TEST_EMAIL and CRAPI_TEST_PASSWORD are not configured."
        )

    specification = OpenAPILoader().load(CRAPI_SPEC)
    validator = OpenAPIValidator(specification)

    client = TargetAPIClient(
        base_url=CRAPI_BASE_URL,
        target_service="crapi",
    )

    # We do NOT need to log in here because the login endpoint
    # itself is intentionally being tested.

    response, event = await client.request(
        "POST",
        "/identity/api/auth/login",
        json={
            "email": 12345,
            "password": password,
        },
    )

    print(
        "HTTP status:",
        response.status_code,
    )

    print(
        "APIEvent:",
        event.model_dump(),
    )

    result = validator.validate(event)

    print(
        "Conformance result:",
        result.model_dump(),
    )

    assert result.valid is False
    assert len(result.violations) > 0

@pytest.mark.anyio
async def test_crapi_unsupported_http_method():
    """
    Send a request using an HTTP method that is not documented
    for an otherwise valid crAPI endpoint.

    The OpenAPI specification documents GET and POST for
    /workshop/api/shop/products, but not DELETE.
    """

    email = os.environ.get("CRAPI_TEST_EMAIL")
    password = os.environ.get("CRAPI_TEST_PASSWORD")

    if not email or not password:
        pytest.skip(
            "CRAPI_TEST_EMAIL and CRAPI_TEST_PASSWORD are not configured."
        )

    specification = OpenAPILoader().load(CRAPI_SPEC)
    validator = OpenAPIValidator(specification)

    client = TargetAPIClient(
        base_url=CRAPI_BASE_URL,
        target_service="crapi",
    )

    await client.login(
        email=email,
        password=password,
        user_id="crapi-unsupported-method-test-user",
    )

    response, event = await client.request(
        "DELETE",
        "/workshop/api/shop/products",
    )

    print(
        "HTTP status:",
        response.status_code,
    )

    print(
        "APIEvent:",
        event.model_dump(),
    )

    result = validator.validate(event)

    print(
        "Conformance result:",
        result.model_dump(),
    )

    assert result.valid is False
    assert len(result.violations) > 0

    method_violations = [
        violation
        for violation in result.violations
        if (
            violation.violation_type.value == "unknown_endpoint"
            and violation.location == "method"
        )
    ]

    assert len(method_violations) == 1

    violation = method_violations[0]

    assert violation.location == "method"
    assert violation.severity == "high"