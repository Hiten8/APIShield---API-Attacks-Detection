from fastapi import FastAPI
from apishield.api.middleware import APIShieldMiddleware

app = FastAPI(
    title="APIShield",
    description=(
        "API security framework combining OpenAPI conformance "
        "and GNN behavioural anomaly detection"
    ),
    version="0.1.0",
)

app.add_middleware(APIShieldMiddleware)

@app.get("/health")
def health_check() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "APIShield",
        "version": "0.1.0",
    }

@app.get("/api/users/{user_id}")
def get_user(user_id: int) -> dict:
    return {
        "user_id": user_id,
        "username": f"user_{user_id}",
    }