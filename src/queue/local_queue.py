"""Local in-process message queue using Python's threading.Queue."""

import queue
from .base import MessageQueue


class LocalQueue(MessageQueue):
    """Thread-safe local message queue for single-server deployment."""

    def __init__(self, maxsize: int = 0):
        self._queue: queue.Queue = queue.Queue(maxsize=maxsize)

    def put(self, data: dict) -> None:
        self._queue.put(data)

    def get(self, timeout: float | None = None) -> dict | None:
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def empty(self) -> bool:
        return self._queue.empty()

    def size(self) -> int:
        return self._queue.qsize()
