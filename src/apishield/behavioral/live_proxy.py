"""Reverse proxy: forward each request to crAPI and score it live with the GNN."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

import httpx

from apishield.behavioral.infer import RollingSessionScorer, StreamUpdate
from apishield.behavioral.live_session import extract_session_id
from apishield.ingestion.interceptor import RequestInterceptor
from apishield.ingestion.normalizer import RequestNormalizer

HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
}

SKIP_SCORE_PREFIXES = ("/apishield/",)


class LiveGnnProxy:
    def __init__(
        self,
        scorer: RollingSessionScorer,
        *,
        target_base_url: str,
        timeout_s: float = 30.0,
    ) -> None:
        self.scorer = scorer
        self.target_base_url = target_base_url.rstrip("/")
        self.timeout_s = timeout_s
        self.interceptor = RequestInterceptor()
        self.normalizer = RequestNormalizer()
        self._event_index: dict[str, int] = defaultdict(int)
        self._flagged: set[str] = set()
        self._latest: dict[str, dict[str, Any]] = {}

    def _forward_headers(self, request: Any) -> dict[str, str]:
        headers: dict[str, str] = {}
        for key, value in request.headers.items():
            if key.lower() in HOP_BY_HOP:
                continue
            headers[key] = value
        return headers

    async def proxy(self, request: Any) -> tuple[int, dict[str, str], bytes]:
        path = request.url.path
        body = await request.body()
        url = f"{self.target_base_url}{path}"
        if request.url.query:
            url = f"{url}?{request.url.query}"

        async with httpx.AsyncClient(timeout=self.timeout_s, follow_redirects=False) as client:
            upstream = await client.request(
                request.method,
                url,
                headers=self._forward_headers(request),
                content=body,
            )

        excluded = {
            "content-encoding",
            "content-length",
            "transfer-encoding",
            "connection",
        }
        response_headers = {
            key: value
            for key, value in upstream.headers.items()
            if key.lower() not in excluded
        }
        if not any(path.startswith(prefix) for prefix in SKIP_SCORE_PREFIXES):
            self._score_request(request, upstream.status_code)
        return upstream.status_code, response_headers, bytes(upstream.content)

    def _score_request(self, request: Any, status_code: int) -> StreamUpdate | None:
        source_ip = request.client.host if request.client else None
        session_id = extract_session_id(request.headers, source_ip=source_ip)
        self._event_index[session_id] += 1
        index = self._event_index[session_id]
        path = request.url.path
        event = self.interceptor.create_event(
            method=request.method,
            path=path,
            endpoint=self.normalizer.normalize_path(path),
            user_id=session_id,
            session_id=session_id,
            query_parameters=dict(request.query_params),
            response_status=status_code,
            source_ip=source_ip,
            target_service="crapi",
        )
        update = self.scorer.apply_event(
            event.model_dump(mode="json"),
            event_index=index,
            previously_flagged=session_id in self._flagged,
        )
        snapshot = self.scorer.snapshot(session_id)
        self._latest[session_id] = {
            "session_id": session_id,
            "event_count": index,
            "max_attack_score": snapshot.session_score,
            "flagged": snapshot.flagged,
            "window_count": snapshot.window_count,
            "window_scores": snapshot.window_scores,
            "last_path": path,
            "last_status": status_code,
        }
        if update is None:
            print(
                f"[live] session={session_id} event={index} "
                f"{request.method} {path} -> {status_code} (waiting for min_events)",
                flush=True,
            )
            return None
        if update.flagged:
            self._flagged.add(session_id)
        tag = "FLAG*" if update.first_flag else ("FLAG" if update.flagged else "ok")
        print(
            f"[live {tag}] session={session_id} event={index} "
            f"{request.method} {path} -> {status_code} "
            f"window={update.window_score:.3f} session_max={update.session_score:.3f}",
            flush=True,
        )
        return update

    def status_payload(self) -> dict[str, Any]:
        return {
            "tau": self.scorer.threshold,
            "window_size": self.scorer.window_size,
            "stride": self.scorer.stride,
            "min_events": self.scorer.min_events,
            "target": self.target_base_url,
            "sessions": list(self._latest.values()),
        }


class LiveGnnASGI:
    """
    Raw ASGI app (not FastAPI). FastAPI catch-all routes treated ``request``
    as a query parameter and returned 422 for every proxied call.
    """

    def __init__(self, proxy: LiveGnnProxy) -> None:
        self.proxy = proxy

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            if scope["type"] == "lifespan":
                while True:
                    message = await receive()
                    if message["type"] == "lifespan.startup":
                        await send({"type": "lifespan.startup.complete"})
                    elif message["type"] == "lifespan.shutdown":
                        await send({"type": "lifespan.shutdown.complete"})
                        return
            return

        from starlette.requests import Request
        from starlette.responses import JSONResponse, Response

        request = Request(scope, receive)
        path = request.url.path

        if path == "/apishield/health":
            response: Any = JSONResponse(
                {"status": "ok", "service": "apishield-live-gnn"}
            )
        elif path == "/apishield/sessions":
            response = JSONResponse(self.proxy.status_payload())
        else:
            status, headers, content = await self.proxy.proxy(request)
            response = Response(
                content=content,
                status_code=status,
                headers=headers,
            )
        await response(scope, receive, send)


def create_live_app(
    scorer: RollingSessionScorer,
    *,
    target_base_url: str,
) -> LiveGnnASGI:
    proxy = LiveGnnProxy(scorer, target_base_url=target_base_url)
    return LiveGnnASGI(proxy)
