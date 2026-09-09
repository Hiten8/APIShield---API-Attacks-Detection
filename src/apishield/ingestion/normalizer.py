import re

class RequestNormalizer:
    """
    Normalizes request paths into endpoint templates suitable
    for APIShield analysis.
    """

    UUID_PATTERN = re.compile(
        r"^[0-9a-fA-F]{8}-"
        r"[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{12}$"
    )

    NUMERIC_ID_PATTERN = re.compile(r"^\d+$")

    def normalize_path(self, path: str) -> str:
        """
        Replace obvious object identifiers with {id}.
        """

        segments = path.strip("/").split("/")
        normalized_segments = []

        for segment in segments:
            if self.NUMERIC_ID_PATTERN.match(segment):
                normalized_segments.append("{id}")
            elif self.UUID_PATTERN.match(segment):
                normalized_segments.append("{id}")
            else:
                normalized_segments.append(segment)

        return "/" + "/".join(normalized_segments)