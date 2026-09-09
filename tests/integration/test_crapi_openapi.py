from pathlib import Path
from apishield.conformance.openapi_loader import OpenAPILoader

CRAPI_SPEC = Path(
    "targets/crAPI-main/openapi-spec/crapi-openapi-spec.json"
)

def test_crapi_openapi_spec_can_be_loaded():
    loader = OpenAPILoader()

    specification = loader.load(CRAPI_SPEC)

    assert isinstance(specification, dict)
    assert "openapi" in specification
    assert "paths" in specification

    assert len(specification["paths"]) > 0