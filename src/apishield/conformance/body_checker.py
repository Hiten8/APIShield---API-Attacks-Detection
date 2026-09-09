from typing import Any
from jsonschema import Draft202012Validator
from apishield.ingestion.models import APIEvent
from .models import (
    ConformanceViolation,
    ViolationType,
)

class RequestBodyChecker:
    """
    Validates an APIEvent request body against the JSON Schema
    declared by an OpenAPI operation.
    """

    def check(
        self,
        event: APIEvent,
        operation: dict[str, Any],
    ) -> list[ConformanceViolation]:

        request_body_definition = operation.get("requestBody")

        if request_body_definition is None:
            return []

        if event.request_body is None:
            if request_body_definition.get("required", False):
                return [
                    ConformanceViolation(
                        violation_type=(
                            ViolationType.MISSING_REQUIRED_PARAMETER
                        ),
                        message="Required request body is missing.",
                        location="body",
                        severity="high",
                    )
                ]

            return []

        content = request_body_definition.get("content", {})

        json_content = content.get("application/json")

        if json_content is None:
            return []

        schema = json_content.get("schema")

        if schema is None:
            return []

        validator = Draft202012Validator(schema)
        violations: list[ConformanceViolation] = []

        for error in validator.iter_errors(event.request_body):
            parameter = None

            if error.validator == "additionalProperties":
                additional_properties = error.message

                parameter = self._extract_additional_property(
                    additional_properties
                )

            violations.append(
                ConformanceViolation(
                    violation_type=(
                        ViolationType.INVALID_REQUEST_BODY
                    ),
                    message=error.message,
                    parameter=parameter,
                    location="body",
                    severity="high",
                )
            )

        return violations

    @staticmethod
    def _extract_additional_property(
        message: str,
    ) -> str | None:
        """
        Extract the field name from a JSON Schema
        additionalProperties error message.

        Example:
            Additional properties are not allowed ('is_admin' was unexpected)
        """

        marker = "('"

        if marker not in message:
            return None

        start = message.find(marker) + len(marker)
        end = message.find("'", start)

        if end == -1:
            return None

        return message[start:end]