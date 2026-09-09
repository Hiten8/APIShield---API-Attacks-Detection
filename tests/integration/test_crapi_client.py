import os
import pytest
from dotenv import load_dotenv
from pathlib import Path

from apishield.conformance.openapi_loader import OpenAPILoader
from apishield.conformance.validator import OpenAPIValidator
from apishield.traffic.client import TargetAPIClient

load_dotenv()

CRAPI_BASE_URL = "http://localhost:8888"

CRAPI_SPEC = Path(
    "targets/crAPI-main/openapi-spec/crapi-openapi-spec.json"
)

@pytest.mark.anyio
async def test_crapi_login_and_authenticated_request():
    email = os.environ.get("CRAPI_TEST_EMAIL")
    password = os.environ.get("CRAPI_TEST_PASSWORD")

    if not email or not password:
        pytest.skip(
            "CRAPI_TEST_EMAIL and CRAPI_TEST_PASSWORD are not configured."
        )

    client = TargetAPIClient(
        base_url=CRAPI_BASE_URL,
        target_service="crapi",
    )

    login_result = await client.login(
        email=email,
        password=password,
        user_id="crapi-test-user",
    )

    assert login_result["message"] == "Login successful"

    response, event = await client.request(
        "GET",
        "/workshop/api/shop/products",
    )

    print(event.model_dump())

    assert response.status_code == 200
    
    loader = OpenAPILoader()
    specification = loader.load(CRAPI_SPEC)
    validator = OpenAPIValidator(specification)

    result = validator.validate(event)

    assert result.valid is True
    assert result.endpoint == "/workshop/api/shop/products"
    assert result.method == "GET"
    assert result.violations == []

    assert event.method == "GET"
    assert event.path == "/workshop/api/shop/products"
    assert event.target_service == "crapi"

    # The authentication token must never appear in the event.
    assert "Authorization" not in event.request_headers

@pytest.mark.anyio
async def test_crapi_allows_unauthenticated_request():
    """
    Verify that TargetAPIClient can send an unauthenticated request
    to a real crAPI endpoint.

    The login endpoint does not require a JWT.
    """

    client = TargetAPIClient(
        base_url=CRAPI_BASE_URL,
        target_service="crapi",
    )

    response, event = await client.request(
        "POST",
        "/identity/api/auth/login",
        json={
            "email": os.environ["CRAPI_TEST_EMAIL"],
            "password": "intentionally-wrong-password",
        },
    )

    print("HTTP status:", response.status_code)
    print("APIEvent:", event.model_dump())

    assert response.status_code in (400, 401)
    assert event.user_id is None
    assert event.path == "/identity/api/auth/login"