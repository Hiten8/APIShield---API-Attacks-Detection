"""
Normal-user traffic workflows against a live crAPI instance.

Each workflow:
  - hits http://localhost:8888 by default
  - appends every APIEvent to data/raw/workflow.jsonl by default
  - inserts quantified random human delays between steps
  - may quit early after login (default p=0.10)
"""

from __future__ import annotations

import asyncio
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx

from apishield.ingestion.models import APIEvent
from apishield.traffic.client import TargetAPIClient
from apishield.traffic.dataset import JSONLDatasetWriter


DEFAULT_BASE_URL = "http://localhost:8888"
DEFAULT_OUTPUT_PATH = Path("data/raw/workflow.jsonl")

# Quantified delay bands (seconds). Never below 1s when delay_scale=1.0.
DELAY_BANDS: dict[str, tuple[float, float]] = {
    "MISCLICK": (1.0, 3.0),
    "NAV": (3.0, 8.0),
    "SCAN": (15.0, 45.0),
    "READ": (60.0, 180.0),
    "THINK": (20.0, 90.0),
}

EARLY_QUIT_PROBABILITY = 0.10


class NormalUserWorkflows:
    """Runs designed normal-user sessions and persists APIEvents to JSONL."""

    def __init__(
        self,
        *,
        base_url: str = DEFAULT_BASE_URL,
        output_path: str | Path = DEFAULT_OUTPUT_PATH,
        delay_scale: float = 1.0,
        early_quit_probability: float = EARLY_QUIT_PROBABILITY,
    ) -> None:
        if delay_scale <= 0:
            raise ValueError("delay_scale must be > 0")

        self.base_url = base_url.rstrip("/")
        self.output_path = Path(output_path)
        self.delay_scale = delay_scale
        self.early_quit_probability = early_quit_probability
        self.writer = JSONLDatasetWriter(self.output_path)

    async def run_shop_browse_workflow(
        self,
        email: str,
        password: str,
        user_id: str | None = None,
    ) -> list[APIEvent]:
        """
        Workflow 1 — shop browse → optional own order → own orders list.

        login → products → optional refreshes → optional order
        → orders/all → optional own order detail → rare products misclick
        """

        resolved_user_id = user_id or email
        client = TargetAPIClient(
            base_url=self.base_url,
            target_service="crapi",
        )
        session_id = str(uuid4())
        events: list[APIEvent] = []

        login_event = await self._login(
            client,
            email=email,
            password=password,
            user_id=resolved_user_id,
            session_id=session_id,
        )
        events.append(login_event)

        if login_event.response_status != 200:
            return events

        if self._should_quit_early():
            return events

        await self._pause("NAV")
        products_response, products_event = await self._request(
            client,
            "GET",
            "/workshop/api/shop/products",
            session_id=session_id,
        )
        events.append(products_event)

        product_ids = self._extract_product_ids(products_response)

        for _ in range(random.randint(0, 2)):
            await self._pause("SCAN")
            refresh_response, refresh_event = await self._request(
                client,
                "GET",
                "/workshop/api/shop/products",
                session_id=session_id,
            )
            events.append(refresh_event)
            product_ids = (
                self._extract_product_ids(refresh_response) or product_ids
            )

        created_order_id: int | None = None

        if product_ids and random.random() < 0.40:
            await self._pause("THINK")
            product_id = random.choice(product_ids)
            order_response, order_event = await self._request(
                client,
                "POST",
                "/workshop/api/shop/orders",
                session_id=session_id,
                json={
                    "product_id": product_id,
                    "quantity": 1,
                },
            )
            events.append(order_event)

            if order_response.status_code == 200:
                created_order_id = self._extract_created_order_id(order_response)

            if created_order_id is not None:
                await self._pause("NAV")
                _, detail_event = await self._request(
                    client,
                    "GET",
                    f"/workshop/api/shop/orders/{created_order_id}",
                    session_id=session_id,
                )
                events.append(detail_event)

        await self._pause("NAV")
        orders_response, orders_event = await self._request(
            client,
            "GET",
            "/workshop/api/shop/orders/all",
            session_id=session_id,
            params={
                "limit": 30,
                "offset": 0,
            },
        )
        events.append(orders_event)

        own_order_ids = self._extract_order_ids_from_list(orders_response)
        if created_order_id is not None and created_order_id not in own_order_ids:
            own_order_ids.append(created_order_id)

        if own_order_ids and random.random() < 0.55:
            await self._pause("SCAN")
            order_id = random.choice(own_order_ids)
            _, own_detail_event = await self._request(
                client,
                "GET",
                f"/workshop/api/shop/orders/{order_id}",
                session_id=session_id,
            )
            events.append(own_detail_event)

        if random.random() < 0.15:
            await self._pause("MISCLICK")
            _, misclick_event = await self._request(
                client,
                "GET",
                "/workshop/api/shop/products",
                session_id=session_id,
            )
            events.append(misclick_event)

        return events

    async def run_vehicle_tracking_workflow(
        self,
        email: str,
        password: str,
        user_id: str | None = None,
    ) -> list[APIEvent]:
        """
        Workflow 2 — dashboard → vehicles → location tracking.

        login → dashboard → vehicles → location for one owned vehicle
        → optional refresh / resend_email / dashboard misclick
        """

        resolved_user_id = user_id or email
        client = TargetAPIClient(
            base_url=self.base_url,
            target_service="crapi",
        )
        session_id = str(uuid4())
        events: list[APIEvent] = []

        login_event = await self._login(
            client,
            email=email,
            password=password,
            user_id=resolved_user_id,
            session_id=session_id,
        )
        events.append(login_event)

        if login_event.response_status != 200:
            return events

        if self._should_quit_early():
            return events

        await self._pause("NAV")
        _, dashboard_event = await self._request(
            client,
            "GET",
            "/identity/api/v2/user/dashboard",
            session_id=session_id,
        )
        events.append(dashboard_event)

        await self._pause("READ")
        vehicles_response, vehicles_event = await self._request(
            client,
            "GET",
            "/identity/api/v2/vehicle/vehicles",
            session_id=session_id,
        )
        events.append(vehicles_event)

        vehicle_ids = self._extract_vehicle_ids(vehicles_response)

        if not vehicle_ids:
            if random.random() < 0.30:
                await self._pause("MISCLICK")
                _, bounce_event = await self._request(
                    client,
                    "GET",
                    "/identity/api/v2/user/dashboard",
                    session_id=session_id,
                )
                events.append(bounce_event)
            return events

        vehicle_id = random.choice(vehicle_ids)

        await self._pause("NAV")
        _, location_event = await self._request(
            client,
            "GET",
            f"/identity/api/v2/vehicle/{vehicle_id}/location",
            session_id=session_id,
        )
        events.append(location_event)

        roll = random.random()

        if roll < 0.50:
            await self._pause("READ")
            _, refresh_event = await self._request(
                client,
                "GET",
                f"/identity/api/v2/vehicle/{vehicle_id}/location",
                session_id=session_id,
            )
            events.append(refresh_event)
        elif roll < 0.65:
            await self._pause("THINK")
            _, resend_event = await self._request(
                client,
                "POST",
                "/identity/api/v2/vehicle/resend_email",
                session_id=session_id,
            )
            events.append(resend_event)
        elif roll < 0.85:
            await self._pause("MISCLICK")
            _, misclick_event = await self._request(
                client,
                "GET",
                "/identity/api/v2/user/dashboard",
                session_id=session_id,
            )
            events.append(misclick_event)

        return events

    async def _login(
        self,
        client: TargetAPIClient,
        *,
        email: str,
        password: str,
        user_id: str,
        session_id: str,
    ) -> APIEvent:
        client._user_id = user_id

        response, event = await self._request(
            client,
            "POST",
            "/identity/api/auth/login",
            session_id=session_id,
            json={
                "email": email,
                "password": password,
            },
        )

        if response.status_code == 200:
            payload = self._safe_json(response)
            token = payload.get("token") if isinstance(payload, dict) else None

            if not token:
                raise RuntimeError(
                    "Login succeeded but no authentication token was returned."
                )

            client.apply_session(
                token,
                user_id=user_id,
                role=payload.get("role") if isinstance(payload, dict) else None,
            )

        return event

    async def _request(
        self,
        client: TargetAPIClient,
        method: str,
        path: str,
        *,
        session_id: str,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
    ) -> tuple[httpx.Response, APIEvent]:
        response, event = await client.request(
            method,
            path,
            params=params,
            json=json,
        )

        event = event.model_copy(
            update={
                "session_id": session_id,
                "timestamp": datetime.now(timezone.utc),
                "request_body": self._redact_request_body(json),
            }
        )
        self.writer.write(event)
        return response, event

    @staticmethod
    def _redact_request_body(body: dict[str, Any] | None) -> dict[str, Any] | None:
        if not isinstance(body, dict):
            return body

        redacted = dict(body)
        for key in ("password", "token", "otp", "secret"):
            if key in redacted and redacted[key] is not None:
                redacted[key] = "[REDACTED]"
        return redacted

    async def _pause(self, band: str) -> None:
        low, high = DELAY_BANDS[band]
        delay = random.uniform(low, high) * self.delay_scale
        delay = max(delay, 0.05 if self.delay_scale < 1.0 else 1.0)
        await asyncio.sleep(delay)

    def _should_quit_early(self) -> bool:
        return random.random() < self.early_quit_probability

    @staticmethod
    def _safe_json(response: httpx.Response) -> Any:
        try:
            return response.json()
        except ValueError:
            return None

    def _extract_product_ids(self, response: httpx.Response) -> list[int]:
        payload = self._safe_json(response)

        if not isinstance(payload, dict):
            return []

        products = payload.get("products", [])
        if not isinstance(products, list):
            return []

        ids: list[int] = []
        for product in products:
            if not isinstance(product, dict) or product.get("id") is None:
                continue
            try:
                ids.append(int(product["id"]))
            except (TypeError, ValueError):
                continue
        return ids

    def _extract_created_order_id(self, response: httpx.Response) -> int | None:
        payload = self._safe_json(response)
        if not isinstance(payload, dict):
            return None

        order_id = payload.get("id")
        try:
            return int(order_id) if order_id is not None else None
        except (TypeError, ValueError):
            return None

    def _extract_order_ids_from_list(self, response: httpx.Response) -> list[int]:
        payload = self._safe_json(response)
        if payload is None:
            return []

        if isinstance(payload, dict):
            orders = (
                payload.get("orders")
                or payload.get("order")
                or payload.get("data")
                or []
            )
        elif isinstance(payload, list):
            orders = payload
        else:
            return []

        if isinstance(orders, dict):
            orders = [orders]
        if not isinstance(orders, list):
            return []

        ids: list[int] = []
        for order in orders:
            if not isinstance(order, dict) or order.get("id") is None:
                continue
            try:
                ids.append(int(order["id"]))
            except (TypeError, ValueError):
                continue
        return ids

    def _extract_vehicle_ids(self, response: httpx.Response) -> list[str]:
        payload = self._safe_json(response)

        if isinstance(payload, list):
            vehicles = payload
        elif isinstance(payload, dict):
            vehicles = (
                payload.get("vehicles")
                or payload.get("vehicle")
                or payload.get("data")
                or []
            )
        else:
            return []

        if isinstance(vehicles, dict):
            vehicles = [vehicles]
        if not isinstance(vehicles, list):
            return []

        ids: list[str] = []
        for vehicle in vehicles:
            if not isinstance(vehicle, dict):
                continue
            # Location path expects a UUID.
            vehicle_id = vehicle.get("uuid") or vehicle.get("id")
            if vehicle_id is not None:
                ids.append(str(vehicle_id))
        return ids


async def run_shop_browse_workflow(
    email: str,
    password: str,
    *,
    user_id: str | None = None,
    base_url: str = DEFAULT_BASE_URL,
    output_path: str | Path = DEFAULT_OUTPUT_PATH,
    delay_scale: float = 1.0,
) -> list[APIEvent]:
    """Invokable entrypoint for the shop / own-orders normal workflow."""

    runner = NormalUserWorkflows(
        base_url=base_url,
        output_path=output_path,
        delay_scale=delay_scale,
    )
    return await runner.run_shop_browse_workflow(
        email=email,
        password=password,
        user_id=user_id,
    )


async def run_vehicle_tracking_workflow(
    email: str,
    password: str,
    *,
    user_id: str | None = None,
    base_url: str = DEFAULT_BASE_URL,
    output_path: str | Path = DEFAULT_OUTPUT_PATH,
    delay_scale: float = 1.0,
) -> list[APIEvent]:
    """Invokable entrypoint for the dashboard / vehicles / tracking workflow."""

    runner = NormalUserWorkflows(
        base_url=base_url,
        output_path=output_path,
        delay_scale=delay_scale,
    )
    return await runner.run_vehicle_tracking_workflow(
        email=email,
        password=password,
        user_id=user_id,
    )
