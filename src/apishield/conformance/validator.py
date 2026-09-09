from typing import Any
from apishield.ingestion.models import APIEvent
from .models import (
    ConformanceResult,
    ConformanceViolation,
    ViolationType,
)
from .parameter_checker import ParameterChecker
from .path_matcher import OpenAPIPathMatcher
from .body_checker import RequestBodyChecker

class OpenAPIValidator:
    """
    Validates APIEvent objects against an OpenAPI specification.
    """

    def __init__(self, specification: dict[str, Any]):
        self.specification = specification

        self.parameter_checker = ParameterChecker()
        self.path_matcher = OpenAPIPathMatcher()
        self.body_checker = RequestBodyChecker()

    def validate(self, event: APIEvent) -> ConformanceResult:
        match = self.path_matcher.find_match(
            event.path,
            self.specification.get("paths", {}),
        )

        if match is None:
            return ConformanceResult(
                valid=False,
                endpoint=event.path,
                method=event.method,
                violations=[
                    ConformanceViolation(
                        violation_type=ViolationType.UNKNOWN_ENDPOINT,
                        message=(
                            f"Endpoint '{event.path}' "
                            "is not defined in the OpenAPI specification."
                        ),
                        location="path",
                        severity="high",
                    )
                ],
            )

        endpoint_template, path_parameters = match

        operation = self._find_operation(
            endpoint_template,
            event.method,
        )

        if operation is None:
            return ConformanceResult(
                valid=False,
                endpoint=endpoint_template,
                method=event.method,
                violations=[
                    ConformanceViolation(
                        violation_type=ViolationType.UNKNOWN_ENDPOINT,
                        message=(
                            f"HTTP method '{event.method}' "
                            f"is not defined for '{endpoint_template}'."
                        ),
                        location="method",
                        severity="high",
                    )
                ],
            )

        violations = self.parameter_checker.check(
            event=event,
            operation=operation,
            path_parameters=path_parameters,
        )

        violations.extend(
            self.body_checker.check(
                event=event,
                operation=operation,
            )
        )

        return ConformanceResult(
            valid=len(violations) == 0,
            endpoint=endpoint_template,
            method=event.method,
            violations=violations,
        )

    def _find_operation(
        self,
        endpoint: str,
        method: str,
    ) -> dict[str, Any] | None:

        path_definition = self.specification.get(
            "paths",
            {},
        ).get(endpoint)

        if path_definition is None:
            return None

        return path_definition.get(method.lower())