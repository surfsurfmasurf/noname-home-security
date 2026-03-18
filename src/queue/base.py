"""Message queue abstraction layer.

Defines the interface that all queue implementations must follow.
Swap local → Redis → Kafka by changing config, not code.
"""

from abc import ABC, abstractmethod
from typing import Any


class MessageQueue(ABC):
    """Abstract base class for message queues."""

    @abstractmethod
    def put(self, data: dict) -> None:
        """Put a message onto the queue."""

    @abstractmethod
    def get(self, timeout: float | None = None) -> dict | None:
        """Get a message from the queue. Returns None on timeout."""

    @abstractmethod
    def empty(self) -> bool:
        """Check if the queue is empty."""

    @abstractmethod
    def size(self) -> int:
        """Return approximate queue size."""
