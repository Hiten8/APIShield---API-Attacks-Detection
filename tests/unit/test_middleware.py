from fastapi.testclient import TestClient
from apishield.main import app

client = TestClient(app)

def test_health_request_passes_through_api_shield():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_user_request_passes_through_api_shield():
    response = client.get("/api/users/123")

    assert response.status_code == 200
    assert response.json()["user_id"] == 123