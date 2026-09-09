import httpx
import pytest

from apishield.traffic.client import TargetAPIClient


class FakeAsyncClient:
    """
    Minimal async context-manager replacement for httpx.AsyncClient.
    Captures requests without making a real network connection.
    """

    def __init__(self, *args, **kwargs):
        self.captured_request = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        return False

    async def request(
        self,
        method,
        url,
        *,
        params=None,
        json=None,
        headers=None,
    ):
        self.captured_request = {
            "method": method,
            "url": url,
            "params": params,
            "json": json,
            "headers": headers or {},
        }

        return httpx.Response(
            status_code=200,
            json={"message": "OK"},
        )


@pytest.mark.anyio
async def test_client_allows_unauthenticated_request(monkeypatch):
    """
    The client must allow requests when no JWT is available.
    This is required for endpoints such as:
        POST /identity/api/auth/login
    """

    fake_client = FakeAsyncClient()

    monkeypatch.setattr(
        "apishield.traffic.client.httpx.AsyncClient",
        lambda *args, **kwargs: fake_client,
    )

    client = TargetAPIClient(
        base_url="http://testserver",
        target_service="crapi",
    )

    response, event = await client.request(
        "POST",
        "/identity/api/auth/login",
        json={
            "email": "test@example.com",
            "password": "Test!123",
        },
    )

    assert response.status_code == 200

    assert fake_client.captured_request is not None

    assert (
        fake_client.captured_request["headers"].get("Authorization")
        is None
    )

    assert fake_client.captured_request["method"] == "POST"

    assert (
        fake_client.captured_request["url"]
        == "/identity/api/auth/login"
    )

    assert event.method == "POST"
    assert event.path == "/identity/api/auth/login"

    assert event.request_body == {
        "email": "test@example.com",
        "password": "Test!123",
    }


@pytest.mark.anyio
async def test_client_adds_bearer_token_when_authenticated(monkeypatch):
    """
    When a JWT exists, the client must continue sending it
    as a Bearer Authorization header.
    """

    fake_client = FakeAsyncClient()

    monkeypatch.setattr(
        "apishield.traffic.client.httpx.AsyncClient",
        lambda *args, **kwargs: fake_client,
    )

    client = TargetAPIClient(
        base_url="http://testserver",
        target_service="crapi",
    )

    # Simulate an authenticated client.
    client._token = "test-jwt-token"

    response, event = await client.request(
        "GET",
        "/workshop/api/shop/products",
    )

    assert response.status_code == 200

    assert fake_client.captured_request is not None

    assert (
        fake_client.captured_request["headers"].get("Authorization")
        == "Bearer test-jwt-token"
    )

    assert fake_client.captured_request["method"] == "GET"

    assert (
        fake_client.captured_request["url"]
        == "/workshop/api/shop/products"
    )

    assert event.method == "GET"
    assert event.path == "/workshop/api/shop/products"