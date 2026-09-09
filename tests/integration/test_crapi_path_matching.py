import json
from pathlib import Path

from apishield.conformance.path_matcher import OpenAPIPathMatcher


CRAPI_SPEC = Path(
    "targets/crAPI-main/openapi-spec/crapi-openapi-spec.json"
)


def load_crapi_spec() -> dict:
    with CRAPI_SPEC.open(
        "r",
        encoding="utf-8",
    ) as file:
        return json.load(file)


def test_crapi_static_path_matches():
    specification = load_crapi_spec()

    matcher = OpenAPIPathMatcher()

    result = matcher.find_match(
        "/identity/api/v2/user/dashboard",
        specification["paths"],
    )

    assert result is not None

    template, parameters = result

    assert template == "/identity/api/v2/user/dashboard"
    assert parameters == {}

def test_crapi_parameterized_path_matches():
    specification = load_crapi_spec()

    matcher = OpenAPIPathMatcher()

    result = matcher.find_match(
        "/identity/api/v2/user/videos/123",
        specification["paths"],
    )

    assert result is not None

    template, parameters = result

    assert template == "/identity/api/v2/user/videos/{video_id}"
    assert parameters == {
        "video_id": "123",
    }