import json
from pathlib import Path

from apishield.ingestion.models import APIEvent


class JSONLDatasetWriter:
    """Append API events to a JSON Lines dataset."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

    def write(self, event: APIEvent) -> None:
        record = event.model_dump(mode="json")

        with self.path.open(
            "a",
            encoding="utf-8",
        ) as file:
            file.write(
                json.dumps(record)
                + "\n"
            )

    def write_many(
        self,
        events: list[APIEvent],
    ) -> None:
        with self.path.open(
            "a",
            encoding="utf-8",
        ) as file:
            for event in events:
                record = event.model_dump(mode="json")

                file.write(
                    json.dumps(record)
                    + "\n"
                )