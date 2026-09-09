from collections.abc import Iterable
from .models import APIEvent

class InMemoryEventStore:
    """
    Temporary in-memory event store.

    This is intentionally simple for the first implementation stage.
    A persistent database can replace this later.
    """

    def __init__(self) -> None:
        self._events: list[APIEvent] = []

    def add(self, event: APIEvent) -> None:
        self._events.append(event)

    def get_all(self) -> list[APIEvent]:
        return list(self._events)

    def count(self) -> int:
        return len(self._events)

    def clear(self) -> None:
        self._events.clear()