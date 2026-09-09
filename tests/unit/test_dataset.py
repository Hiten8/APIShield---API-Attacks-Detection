import json
from datetime import datetime, timezone

from apishield.ingestion.models import APIEvent
from apishield.traffic.dataset import JSONLDatasetWriter


def test_dataset_writer_writes_api_event(tmp_path):
    output = tmp_path / "events.jsonl"

    event = APIEvent(
        event_id="test-event-001",
        timestamp=datetime.now(timezone.utc),
        user_id="test-user",
        session_id=None,
        method="GET",
        path="/test",
        endpoint="/test",
        query_parameters={},
        request_headers={},
        request_body=None,
        response_status=200,
        response_size=None,
        source_ip=None,
        target_service="test",
    )

    writer = JSONLDatasetWriter(output)
    writer.write(event)

    lines = output.read_text(
        encoding="utf-8"
    ).splitlines()

    assert len(lines) == 1

    record = json.loads(lines[0])

    assert record["event_id"] == "test-event-001"
    assert record["method"] == "GET"
    assert record["path"] == "/test"