import re
from typing import Any

class OpenAPIPathMatcher:
    """
    Matches concrete HTTP paths against OpenAPI path templates.
    """

    def find_match(
    self,
    request_path: str,
    paths: dict[str, Any],
    ) -> tuple[str, dict[str, str]] | None:

        request_segments = request_path.strip("/").split("/")

        matches: list[
            tuple[str, dict[str, str], int]
        ] = []

        for template in paths:
            template_segments = template.strip("/").split("/")

            if len(request_segments) != len(template_segments):
                continue

            parameters: dict[str, str] = {}
            matched = True
            static_segments = 0

            for request_segment, template_segment in zip(
                request_segments,
                template_segments,
            ):
                if (
                    template_segment.startswith("{")
                    and template_segment.endswith("}")
                ):
                    parameter_name = template_segment[1:-1]
                    parameters[parameter_name] = request_segment

                elif request_segment != template_segment:
                    matched = False
                    break

                else:
                    static_segments += 1

            if matched:
                matches.append(
                    (
                        template,
                        parameters,
                        static_segments,
                    )
                )

        if not matches:
            return None

        # Prefer the most specific match.
        # A path with more static segments takes precedence
        # over a path with more template parameters.
        matches.sort(
            key=lambda match: match[2],
            reverse=True,
        )

        template, parameters, _ = matches[0]

        return template, parameters