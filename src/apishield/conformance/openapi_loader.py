from pathlib import Path
from typing import Any
import yaml

class OpenAPILoader:
    """
    Loads an OpenAPI specification from YAML or JSON.
    """

    def load(self, path: str | Path) -> dict[str, Any]:
        specification_path = Path(path)

        if not specification_path.exists():
            raise FileNotFoundError(
                f"OpenAPI specification not found: {specification_path}"
            )

        with specification_path.open("r", encoding="utf-8") as file:
            specification = yaml.safe_load(file)

        if not isinstance(specification, dict):
            raise ValueError("OpenAPI specification must be a mapping/object.")

        return specification