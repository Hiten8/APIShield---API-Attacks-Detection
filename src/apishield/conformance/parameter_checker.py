from typing import Any
from apishield.ingestion.models import APIEvent
from .models import (
    ConformanceViolation,
    ViolationType,
)

class ParameterChecker:
    """
    Checks request parameters against the parameters
    declared by an OpenAPI operation.
    """

    def check(
        self,
        event: APIEvent,
        operation: dict[str, Any],
        path_parameters: dict[str, str],
    ) -> list[ConformanceViolation]:

        violations: list[ConformanceViolation] = []

        declared_parameters = operation.get(
            "parameters",
            [],
        )

        parameter_definitions = {
            (
                parameter["name"],
                parameter["in"],
            ): parameter
            for parameter in declared_parameters
        }

        # Query parameters
        for name, value in event.query_parameters.items():

            definition = parameter_definitions.get(
                (name, "query")
            )

            if definition is None:
                violations.append(
                    ConformanceViolation(
                        violation_type=(
                            ViolationType.UNDOCUMENTED_PARAMETER
                        ),
                        message=(
                            f"Query parameter '{name}' "
                            "is not declared in the OpenAPI specification."
                        ),
                        parameter=name,
                        location="query",
                    )
                )
                continue

            violations.extend(
                self._validate_parameter_type(
                    name=name,
                    value=value,
                    definition=definition,
                    location="query",
                )
            )

        # Path parameters
        for name, value in path_parameters.items():

            definition = parameter_definitions.get(
                (name, "path")
            )

            if definition is None:
                violations.append(
                    ConformanceViolation(
                        violation_type=(
                            ViolationType.INVALID_PARAMETER
                        ),
                        message=(
                            f"Path parameter '{name}' "
                            "is not declared in the OpenAPI specification."
                        ),
                        parameter=name,
                        location="path",
                    )
                )
                continue

            violations.extend(
                self._validate_parameter_type(
                    name=name,
                    value=value,
                    definition=definition,
                    location="path",
                )
            )

        # Required parameters
        for (name, location), definition in parameter_definitions.items():

            if not definition.get("required", False):
                continue

            if location == "query":
                present = name in event.query_parameters

            elif location == "path":
                present = name in path_parameters

            else:
                present = True

            if not present:
                violations.append(
                    ConformanceViolation(
                        violation_type=(
                            ViolationType.MISSING_REQUIRED_PARAMETER
                        ),
                        message=(
                            f"Required {location} parameter "
                            f"'{name}' is missing."
                        ),
                        parameter=name,
                        location=location,
                        severity="high",
                    )
                )

        return violations

    @staticmethod
    def _validate_parameter_type(
        name: str,
        value: Any,
        definition: dict[str, Any],
        location: str,
    ) -> list[ConformanceViolation]:

        schema = definition.get("schema", {})
        expected_type = schema.get("type")

        if expected_type is None:
            return []

        valid = True

        if expected_type == "integer":
            try:
                int(value)
            except (ValueError, TypeError):
                valid = False

        elif expected_type == "number":
            try:
                float(value)
            except (ValueError, TypeError):
                valid = False

        elif expected_type == "boolean":
            valid = str(value).lower() in {
                "true",
                "false",
            }

        elif expected_type == "string":
            valid = isinstance(value, str)

        if valid:
            return []

        return [
            ConformanceViolation(
                violation_type=(
                    ViolationType.INVALID_PARAMETER_TYPE
                ),
                message=(
                    f"Parameter '{name}' has an invalid type."
                ),
                parameter=name,
                location=location,
                expected_type=expected_type,
                actual_value=str(value),
                severity="medium",
            )
        ]