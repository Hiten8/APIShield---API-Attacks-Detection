from datetime import datetime, timezone
from typing import Any
import httpx
import uuid

from apishield.ingestion.models import APIEvent


class TargetAPIClient:
    """
    HTTP client for interacting with a target API such as crAPI.

    Authentication tokens are kept in memory and are never
    included in APIEvent objects.
    """

    def __init__(
        self,
        base_url: str,
        target_service: str,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.target_service = target_service

        self._token: str | None = None
        self._user_id: str | None = None
        self._role: str | None = None

    async def login(
        self,
        email: str,
        password: str,
        user_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Authenticate against the target API.

        The JWT is retained only in memory.
        """

        payload = {
            "email": email,
            "password": password,
        }

        async with httpx.AsyncClient(
            base_url=self.base_url,
        ) as client:
            response = await client.post(
                "/identity/api/auth/login",
                json=payload,
            )

        response.raise_for_status()

        data = response.json()

        token = data.get("token")

        if not token:
            raise RuntimeError(
                "Login succeeded but no authentication token was returned."
            )

        self._token = token
        self._user_id = user_id
        self._role = data.get("role")

        return {
            "type": data.get("type"),
            "message": data.get("message"),
            "role": self._role,
        }

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
    ) -> tuple[httpx.Response, APIEvent]:

        # if not self._token:
        #     raise RuntimeError(
        #         "Client is not authenticated. Call login() first."
        #     )

        headers: dict[str, str] = {}

        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        async with httpx.AsyncClient(
            base_url=self.base_url,
        ) as client:
            response = await client.request(
                method=method,
                url=path,
                params=params,
                json=json,
                headers=headers,
            )

        event = APIEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            user_id=self._user_id,
            method=method.upper(),
            path=path,
            endpoint=path,
            query_parameters=params or {},
            request_body=json,
            response_status=response.status_code,
            target_service=self.target_service,
        )

        return response, event