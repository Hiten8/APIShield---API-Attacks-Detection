from datetime import datetime, timezone
from typing import Any
from uuid import uuid4
from .models import APIEvent

class RequestInterceptor:
    """
    Converts observed HTTP request/response information
    into normalized APIEvent objects.
    """

    def create_event(
        self,
        *,
        method: str,
        path: str,
        endpoint: str | None = None,
        user_id: str | None = None,
        session_id: str | None = None,
        query_parameters: dict[str, Any] | None = None,
        request_headers: dict[str, str] | None = None,
        request_body: Any | None = None,
        response_status: int | None = None,
        response_size: int | None = None,
        source_ip: str | None = None,
        target_service: str | None = None,
    ) -> APIEvent:
        """
        Create a normalized APIEvent from request/response information.
        """

        return APIEvent(
            event_id=str(uuid4()),
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            session_id=session_id,
            method=method.upper(),
            path=path,
            endpoint=endpoint,
            query_parameters=query_parameters or {},
            request_headers=request_headers or {},
            request_body=request_body,
            response_status=response_status,
            response_size=response_size,
            source_ip=source_ip,
            target_service=target_service,
        )