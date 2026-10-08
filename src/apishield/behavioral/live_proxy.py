"""Reverse proxy: forward each request to crAPI, then OpenAPI-check + GNN-score it."""

from __future__ import annotations

import json
from collections import defaultdict, deque
from typing import Any

import httpx

from apishield.api.middleware import sanitize_headers
from apishield.behavioral.infer import RollingSessionScorer, StreamUpdate
from apishield.behavioral.live_session import extract_session_id
from apishield.conformance.models import ConformanceResult
from apishield.conformance.validator import OpenAPIValidator
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

SHIELD_EXPOSE_HEADERS = (
    "X-APIShield-Conformance, X-APIShield-Violation-Count, "
    "X-APIShield-GNN-Window, X-APIShield-GNN-Session-Max, "
    "X-APIShield-Flagged, X-APIShield-Session"
)

MAX_CALL_LOG = 200


class LiveGnnProxy:
    def __init__(
        self,
        scorer: RollingSessionScorer,
        *,
        target_base_url: str,
        validator: OpenAPIValidator | None = None,
        timeout_s: float = 30.0,
        max_call_log: int = MAX_CALL_LOG,
    ) -> None:
        self.scorer = scorer
        self.validator = validator
        self.target_base_url = target_base_url.rstrip("/")
        self.timeout_s = timeout_s
        self.interceptor = RequestInterceptor()
        self.normalizer = RequestNormalizer()
        self._event_index: dict[str, int] = defaultdict(int)
        self._flagged: set[str] = set()
        self._latest: dict[str, dict[str, Any]] = {}
        self._calls: deque[dict[str, Any]] = deque(maxlen=max_call_log)

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
            record = self._observe_request(request, upstream.status_code, body)
            response_headers.update(self._shield_headers(record))
            _merge_expose_headers(response_headers)
        return upstream.status_code, response_headers, bytes(upstream.content)

    def _score_request(
        self,
        request: Any,
        status_code: int,
        body: bytes = b"",
    ) -> dict[str, Any]:
        """Back-compat alias used by unit tests."""
        return self._observe_request(request, status_code, body)

    def _observe_request(
        self,
        request: Any,
        status_code: int,
        body: bytes = b"",
    ) -> dict[str, Any]:
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
            request_headers=sanitize_headers(dict(request.headers)),
            request_body=_parse_request_body(body, request.headers),
            response_status=status_code,
            source_ip=source_ip,
            target_service="crapi",
        )
        conformance = self._conformance_payload(event)
        update = self.scorer.apply_event(
            event.model_dump(mode="json"),
            event_index=index,
            previously_flagged=session_id in self._flagged,
        )
        snapshot = self.scorer.snapshot(session_id)
        waiting = update is None
        window_score = None if waiting else update.window_score
        if update is not None and update.flagged:
            self._flagged.add(session_id)

        gnn = {
            "tau": self.scorer.threshold,
            "window_score": window_score,
            "session_max": snapshot.session_score,
            "flagged": snapshot.flagged,
            "window_count": snapshot.window_count,
            "waiting": waiting,
        }
        record = {
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "session_id": session_id,
            "event_index": index,
            "method": event.method,
            "path": path,
            "status": status_code,
            "conformance": conformance,
            "gnn": gnn,
        }
        self._calls.append(record)
        self._latest[session_id] = {
            "session_id": session_id,
            "event_count": index,
            "max_attack_score": snapshot.session_score,
            "flagged": snapshot.flagged,
            "window_count": snapshot.window_count,
            "window_scores": snapshot.window_scores,
            "last_path": path,
            "last_status": status_code,
            "last_call": {
                "conformance": conformance,
                "gnn": gnn,
            },
        }
        self._print_observation(record, update)
        return record

    def _conformance_payload(self, event: Any) -> dict[str, Any]:
        if self.validator is None:
            return {
                "valid": None,
                "skipped": True,
                "endpoint": event.path,
                "method": event.method,
                "violations": [],
            }
        result: ConformanceResult = self.validator.validate(event)
        payload = result.model_dump(mode="json")
        payload["skipped"] = False
        return payload

    def _print_observation(
        self,
        record: dict[str, Any],
        update: StreamUpdate | None,
    ) -> None:
        conf = record["conformance"]
        if conf.get("skipped"):
            conf_tag = "conf=skipped"
        elif conf.get("valid"):
            conf_tag = "conf=ok"
        else:
            types = [
                str(item.get("violation_type") or "")
                for item in (conf.get("violations") or [])
            ]
            shown = ",".join(types[:2]) if types else "invalid"
            extra = f"+{len(types) - 2}" if len(types) > 2 else ""
            conf_tag = f"conf=INVALID({shown}{extra})"

        if update is None:
            print(
                f"[live] session={record['session_id']} "
                f"event={record['event_index']} "
                f"{record['method']} {record['path']} -> {record['status']} "
                f"{conf_tag} (waiting for min_events)",
                flush=True,
            )
            return
        tag = "FLAG*" if update.first_flag else ("FLAG" if update.flagged else "ok")
        print(
            f"[live {tag}] session={record['session_id']} "
            f"event={record['event_index']} "
            f"{record['method']} {record['path']} -> {record['status']} "
            f"{conf_tag} "
            f"window={update.window_score:.3f} "
            f"session_max={update.session_score:.3f}",
            flush=True,
        )

    def _shield_headers(self, record: dict[str, Any]) -> dict[str, str]:
        conf = record["conformance"]
        gnn = record["gnn"]
        if conf.get("skipped"):
            conf_value = "skipped"
        else:
            conf_value = "valid" if conf.get("valid") else "invalid"
        window = gnn.get("window_score")
        return {
            "X-APIShield-Conformance": conf_value,
            "X-APIShield-Violation-Count": str(
                len(conf.get("violations") or [])
            ),
            "X-APIShield-GNN-Window": "" if window is None else f"{window:.6f}",
            "X-APIShield-GNN-Session-Max": f"{float(gnn.get('session_max') or 0.0):.6f}",
            "X-APIShield-Flagged": "true" if gnn.get("flagged") else "false",
            "X-APIShield-Session": str(record["session_id"]),
        }

    def status_payload(self) -> dict[str, Any]:
        return {
            "tau": self.scorer.threshold,
            "window_size": self.scorer.window_size,
            "stride": self.scorer.stride,
            "min_events": self.scorer.min_events,
            "target": self.target_base_url,
            "conformance_enabled": self.validator is not None,
            "sessions": list(self._latest.values()),
        }

    def calls_payload(self, *, limit: int = 50) -> dict[str, Any]:
        cap = max(1, min(int(limit), MAX_CALL_LOG))
        calls = list(self._calls)[-cap:]
        return {
            "count": len(calls),
            "retained": len(self._calls),
            "calls": calls,
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
                {
                    "status": "ok",
                    "service": "apishield-live",
                    "conformance": self.proxy.validator is not None,
                    "gnn": True,
                }
            )
        elif path == "/apishield/sessions":
            response = JSONResponse(self.proxy.status_payload())
        elif path == "/apishield/calls":
            limit = _query_int(request, "limit", 50)
            response = JSONResponse(self.proxy.calls_payload(limit=limit))
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
    specification: dict[str, Any] | None = None,
) -> LiveGnnASGI:
    validator = OpenAPIValidator(specification) if specification else None
    proxy = LiveGnnProxy(
        scorer,
        target_base_url=target_base_url,
        validator=validator,
    )
    return LiveGnnASGI(proxy)


def _parse_request_body(body: bytes, headers: Any) -> Any | None:
    if not body:
        return None
    content_type = ""
    if headers is not None:
        getter = getattr(headers, "get", None)
        if callable(getter):
            content_type = str(getter("content-type") or getter("Content-Type") or "")
        elif isinstance(headers, dict):
            content_type = str(
                headers.get("content-type") or headers.get("Content-Type") or ""
            )
    looks_json = "json" in content_type.lower() or body[:1] in (b"{", b"[")
    if not looks_json:
        return None
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return body.decode("utf-8", errors="replace")


def _merge_expose_headers(headers: dict[str, str]) -> None:
    existing_key = None
    existing_value = ""
    for key, value in headers.items():
        if key.lower() == "access-control-expose-headers":
            existing_key = key
            existing_value = value
            break
    merged = SHIELD_EXPOSE_HEADERS
    if existing_value:
        merged = f"{existing_value}, {SHIELD_EXPOSE_HEADERS}"
    headers[existing_key or "Access-Control-Expose-Headers"] = merged


def _query_int(request: Any, name: str, default: int) -> int:
    raw = request.query_params.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default
