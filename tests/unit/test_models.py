from datetime import datetime, timezone
from apishield.ingestion.models import APIEvent

def test_api_event_creation():
    event = APIEvent(
        event_id="event_001",
        timestamp=datetime.now(timezone.utc),
        user_id="user_001",
        session_id="session_001",
        method="GET",
        path="/api/users/123",
        endpoint="/api/users/{id}",
        query_parameters={},
        request_headers={
            "content-type": "application/json"
        },
        response_status=200,
        response_size=512,
    )

    assert event.event_id == "event_001"
    assert event.user_id == "user_001"
    assert event.method == "GET"
    assert event.path == "/api/users/123"
    assert event.endpoint == "/api/users/{id}"
    assert event.response_status == 200