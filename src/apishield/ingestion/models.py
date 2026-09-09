from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field

class APIEvent(BaseModel):
    """
    Normalized representation of a single API request/response event.
    This object is the common input to the APIShield detection pipeline.
    """

    event_id: str
    timestamp: datetime

    user_id: str | None = None
    session_id: str | None = None

    method: str
    path: str
    endpoint: str | None = None

    query_parameters: dict[str, Any] = Field(default_factory=dict)
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body: Any | None = None

    response_status: int | None = None
    response_size: int | None = None

    source_ip: str | None = None
    target_service: str | None = None