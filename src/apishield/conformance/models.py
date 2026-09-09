from enum import Enum
from pydantic import BaseModel, Field

class ViolationType(str, Enum):
    UNDOCUMENTED_PARAMETER = "undocumented_parameter"
    INVALID_PARAMETER = "invalid_parameter"
    INVALID_PARAMETER_TYPE = "invalid_parameter_type"
    MISSING_REQUIRED_PARAMETER = "missing_required_parameter"
    INVALID_REQUEST_BODY = "invalid_request_body"
    UNKNOWN_ENDPOINT = "unknown_endpoint"

class ConformanceViolation(BaseModel):
    violation_type: ViolationType
    message: str

    parameter: str | None = None
    location: str | None = None

    expected_type: str | None = None
    actual_value: str | None = None

    severity: str = "medium"

class ConformanceResult(BaseModel):
    valid: bool

    endpoint: str
    method: str

    violations: list[ConformanceViolation] = Field(
        default_factory=list
    )