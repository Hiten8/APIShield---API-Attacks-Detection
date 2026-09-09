from apishield.ingestion.interceptor import RequestInterceptor

def test_interceptor_creates_api_event():
    interceptor = RequestInterceptor()

    event = interceptor.create_event(
        method="get",
        path="/api/users/123",
        endpoint="/api/users/{id}",
        user_id="user_001",
        session_id="session_001",
        query_parameters={
            "include": "profile"
        },
        request_headers={
            "content-type": "application/json"
        },
        response_status=200,
        response_size=512,
        source_ip="192.168.1.10",
        target_service="crapi",
    )

    assert event.method == "GET"
    assert event.path == "/api/users/123"
    assert event.endpoint == "/api/users/{id}"

    assert event.user_id == "user_001"
    assert event.session_id == "session_001"

    assert event.query_parameters["include"] == "profile"

    assert event.response_status == 200
    assert event.response_size == 512

    assert event.source_ip == "192.168.1.10"
    assert event.target_service == "crapi"

    assert event.event_id is not None
    assert event.timestamp is not None