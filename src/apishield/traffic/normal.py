from typing import Any
from apishield.ingestion.models import APIEvent
from .client import TargetAPIClient


class NormalTrafficGenerator:
    """
    Generates deterministic legitimate traffic against a target API.

    This first implementation intentionally uses a small workflow.
    """

    def __init__(
        self,
        client: TargetAPIClient,
    ) -> None:
        self.client = client

    async def login(
        self,
        email: str,
        password: str,
        user_id: str,
    ) -> dict[str, Any]:
        return await self.client.login(
            email=email,
            password=password,
            user_id=user_id,
        )

    async def get_products(
        self,
    ) -> tuple[Any, APIEvent]:
        return await self.client.request(
            "GET",
            "/workshop/api/shop/products",
        )

    async def run_workflow(
        self,
        email: str,
        password: str,
        user_id: str,
    ) -> list[APIEvent]:

        await self.login(
            email=email,
            password=password,
            user_id=user_id,
        )

        events: list[APIEvent] = []

        response, event = await self.get_products()

        events.append(event)

        return events