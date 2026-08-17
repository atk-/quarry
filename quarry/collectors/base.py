from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Callable

from quarry.models.event import Event


class Collector(ABC):
    """Base class for all event collectors."""

    def __init__(self, emit: Callable[[Event], None]) -> None:
        self._emit = emit
        self._running = False

    @abstractmethod
    def start(self) -> None:
        """Begin collection. May start background threads."""

    @abstractmethod
    def stop(self) -> None:
        """Stop collection and release resources."""

    def emit(self, event: Event) -> None:
        self._emit(event)
