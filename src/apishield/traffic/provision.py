"""
Provision crAPI vehicles for users by claiming VIN/PIN from MailHog.

Flow:
  login → list vehicles → if empty:
    resend_email → read MailHog → add_vehicle
"""

from __future__ import annotations

import asyncio
import quopri
import re
from typing import Any

import httpx


DEFAULT_BASE_URL = "http://localhost:8888"
DEFAULT_MAILHOG_URL = "http://localhost:8025"


def decode_mail_body(body: str) -> str:
    """Decode quoted-printable MailHog HTML bodies."""

    cleaned = body.replace("=\r\n", "").replace("=\n", "")
    try:
        return quopri.decodestring(
            cleaned.encode("utf-8", errors="ignore")
        ).decode("utf-8", errors="ignore")
    except Exception:
        return cleaned


def parse_vin_pin(body: str) -> tuple[str | None, str | None]:
    decoded = decode_mail_body(body)

    vin_match = re.search(r">([A-HJ-NPR-Z0-9]{17})<", decoded)
    pin_match = re.search(
        r"Pincode:.*?>([0-9]{4,6})<",
        decoded,
        flags=re.IGNORECASE | re.DOTALL,
    )

    vin = vin_match.group(1).upper() if vin_match else None
    pin = pin_match.group(1) if pin_match else None
    return vin, pin


class VehicleProvisioner:
    def __init__(
        self,
        *,
        base_url: str = DEFAULT_BASE_URL,
        mailhog_url: str = DEFAULT_MAILHOG_URL,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.mailhog_url = mailhog_url.rstrip("/")
        self.timeout = timeout

    async def ensure_vehicle(
        self,
        email: str,
        password: str,
        *,
        max_mail_attempts: int = 5,
    ) -> dict[str, Any]:
        """
        Ensure the user has at least one claimed vehicle.

        Returns a status dict describing what happened.
        """

        async with httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout,
        ) as client:
            token = await self._login(client, email, password)
            headers = {"Authorization": f"Bearer {token}"}

            vehicles = await self._list_vehicles(client, headers)
            if vehicles:
                return {
                    "email": email,
                    "status": "already_claimed",
                    "vehicle_count": len(vehicles),
                }

            resend = await client.post(
                "/identity/api/v2/vehicle/resend_email",
                headers=headers,
            )
            if resend.status_code != 200:
                return {
                    "email": email,
                    "status": "resend_failed",
                    "detail": resend.text,
                }

            vin, pin = await self._wait_for_vin_pin(
                email,
                max_attempts=max_mail_attempts,
            )
            if not vin or not pin:
                return {
                    "email": email,
                    "status": "mail_credentials_not_found",
                }

            add = await client.post(
                "/identity/api/v2/vehicle/add_vehicle",
                headers=headers,
                json={
                    "vin": vin,
                    "pincode": pin,
                },
            )
            if add.status_code != 200:
                return {
                    "email": email,
                    "status": "add_vehicle_failed",
                    "vin": vin,
                    "detail": add.text,
                }

            vehicles = await self._list_vehicles(client, headers)
            return {
                "email": email,
                "status": "claimed",
                "vin": vin,
                "vehicle_count": len(vehicles),
            }

    async def _login(
        self,
        client: httpx.AsyncClient,
        email: str,
        password: str,
    ) -> str:
        response = await client.post(
            "/identity/api/auth/login",
            json={
                "email": email,
                "password": password,
            },
        )
        response.raise_for_status()
        payload = response.json()
        token = payload.get("token")
        if not token:
            raise RuntimeError(f"Login for {email} returned no token.")
        return token

    async def _list_vehicles(
        self,
        client: httpx.AsyncClient,
        headers: dict[str, str],
    ) -> list[dict[str, Any]]:
        response = await client.get(
            "/identity/api/v2/vehicle/vehicles",
            headers=headers,
        )
        response.raise_for_status()
        payload = response.json()
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        return []

    async def _wait_for_vin_pin(
        self,
        email: str,
        *,
        max_attempts: int,
    ) -> tuple[str | None, str | None]:
        for attempt in range(max_attempts):
            vin, pin = await self._latest_vin_pin_from_mailhog(email)
            if vin and pin:
                return vin, pin
            await asyncio.sleep(1.0 + attempt * 0.5)
        return None, None

    async def _latest_vin_pin_from_mailhog(
        self,
        email: str,
    ) -> tuple[str | None, str | None]:
        async with httpx.AsyncClient(
            base_url=self.mailhog_url,
            timeout=self.timeout,
        ) as mail_client:
            response = await mail_client.get(
                "/api/v2/search",
                params={
                    "kind": "to",
                    "query": email,
                },
            )
            response.raise_for_status()
            payload = response.json()

        for item in payload.get("items") or []:
            content = item.get("Content") or {}
            body = content.get("Body") or ""
            vin, pin = parse_vin_pin(body)
            if vin and pin:
                return vin, pin

        return None, None
