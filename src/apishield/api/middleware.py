import time
from typing import Any
from fastapi import Request
from apishield.ingestion.interceptor import RequestInterceptor
from apishield.ingestion.normalizer import RequestNormalizer
from apishield.ingestion.event_store import InMemoryEventStore

SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
}


def sanitize_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        key: "[REDACTED]" if key.lower() in SENSITIVE_HEADERS else value
        for key, value in headers.items()
    }

class APIShieldMiddleware:
    """
    ASGI middleware responsible for observing incoming HTTP traffic
    and converting it into APIShield APIEvent objects.
    """

    def __init__(self, app: Any):
        self.app = app
        self.interceptor = RequestInterceptor()
        self.normalizer = RequestNormalizer()
        self.event_store = InMemoryEventStore()

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)
        start_time = time.perf_counter()
        response_status: int | None = None

        async def send_wrapper(message: dict) -> None:
            nonlocal response_status
            if message["type"] == "http.response.start":
                response_status = message["status"]

            await send(message)

        await self.app(scope, receive, send_wrapper)

        endpoint = self.normalizer.normalize_path(request.url.path)

        event = self.interceptor.create_event(
            method=request.method,
            path=request.url.path,
            endpoint=endpoint,
            query_parameters=dict(request.query_params),
            request_headers=sanitize_headers(dict(request.headers)),
            response_status=response_status,
            source_ip=request.client.host if request.client else None,
            target_service="APIShield",
        )

        self.event_store.add(event)

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        print(
            f"[APIShield] "
            f"{event.method} "
            f"{event.path} "
            f"-> "
            f"{event.response_status} "
            f"({elapsed_ms:.2f} ms)"
        )