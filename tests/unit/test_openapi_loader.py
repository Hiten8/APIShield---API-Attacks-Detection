from pathlib import Path
from apishield.conformance.openapi_loader import OpenAPILoader

FIXTURE = Path("tests/fixtures/openapi/simple_api.yaml")

def test_openapi_specification_can_be_loaded():
    loader = OpenAPILoader()

    specification = loader.load(FIXTURE)

    assert specification["openapi"] == "3.0.3"
    assert "/api/users/{id}" in specification["paths"]