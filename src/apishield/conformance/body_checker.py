
from typing import Any

from jsonschema import Draft202012Validator, RefResolver

from apishield.ingestion.models import APIEvent
from .models import ConformanceViolation, ViolationType


class RequestBodyChecker:
    """
    Validates an APIEvent request body against the JSON Schema
    declared by an OpenAPI operation.

    The full OpenAPI specification is supplied so local references
    such as #/components/schemas/ProductQuantity can be resolved.
    """

    def check(
        self,
        event: APIEvent,
        operation: dict[str, Any],
        specification: dict[str, Any],
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

        # Resolve local OpenAPI references against the entire spec.
        resolver = RefResolver.from_schema(specification)

        validator = Draft202012Validator(
            schema,
            resolver=resolver,
        )

        violations: list[ConformanceViolation] = []

        for error in validator.iter_errors(event.request_body):
            parameter = None

            if error.validator == "additionalProperties":
                parameter = self._extract_additional_property(
                    error.message
                )

            violations.append(
                ConformanceViolation(
                    violation_type=ViolationType.INVALID_REQUEST_BODY,
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
        Extract a field name from an additionalProperties error.
        """

        marker = "('"

        if marker not in message:
            return None

        start = message.find(marker) + len(marker)
        end = message.find("'", start)

        if end == -1:
            return None

        return message[start:end]