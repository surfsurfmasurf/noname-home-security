from .base import MessageQueue
from .local_queue import LocalQueue


def create_queue(config: dict) -> MessageQueue:
    """Factory: create a queue based on config['queue']['type']."""
    queue_type = config.get("queue", {}).get("type", "local")
    if queue_type == "local":
        return LocalQueue()
    elif queue_type == "redis":
        raise NotImplementedError("Redis queue — Phase 4")
    elif queue_type == "kafka":
        raise NotImplementedError("Kafka queue — Phase 5")
    else:
        raise ValueError(f"Unknown queue type: {queue_type}")
