"""Traffic Generator Agent — produces synthetic normal + attack traffic."""

import random
import uuid
from datetime import datetime, timezone

from ..queue import MessageQueue
from .profiles import DEFAULT_PROFILES, DeviceProfile
from .attack_patterns import DEFAULT_ATTACKS, AttackPattern


class TrafficGenerator:
    """Generates labeled synthetic API traffic."""

    def __init__(self, queue: MessageQueue, config: dict,
                 profiles: list[DeviceProfile] | None = None,
                 attacks: list[tuple[AttackPattern, float]] | None = None):
        self.queue = queue
        self.normal_ratio = config.get("generator", {}).get("normal_ratio", 0.8)
        self.seed = config.get("generator", {}).get("seed", 42)
        self.profiles = profiles or DEFAULT_PROFILES
        self.attacks = attacks or DEFAULT_ATTACKS

        random.seed(self.seed)
        self._attack_patterns, self._attack_weights = zip(*self.attacks)

    def generate_normal(self, hour: int | None = None) -> dict:
        """Generate a single normal traffic event."""
        if hour is None:
            hour = datetime.now(timezone.utc).hour

        active_profiles = [p for p in self.profiles if p.is_active(hour)]
        if not active_profiles:
            active_profiles = self.profiles  # fallback

        profile = random.choice(active_profiles)
        endpoint = profile.get_endpoint()

        return {
            "request_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": profile.src_ip,
            "dst_ip": "192.168.0.1",
            "dst_port": 443,
            "method": endpoint["method"],
            "path": endpoint["path"],
            "query_params": "",
            "headers": {
                "User-Agent": profile.get_user_agent(),
                "Content-Type": "application/json",
                "Content-Length": str(profile.get_payload_size()),
            },
            "payload_size": profile.get_payload_size(),
            "response_code": endpoint["response_code"],
            "response_size": profile.get_response_size(),
            "response_time_ms": profile.get_response_time(),
            "label": "normal",
        }

    def generate_attack(self, hour: int | None = None) -> dict:
        """Generate a single attack traffic event."""
        if hour is None:
            hour = datetime.now(timezone.utc).hour

        pattern = random.choices(
            self._attack_patterns, weights=self._attack_weights, k=1
        )[0]
        event = pattern.generate(hour)
        event["request_id"] = str(uuid.uuid4())
        event["timestamp"] = datetime.now(timezone.utc).isoformat()
        return event

    def generate_batch(self, count: int, hour: int | None = None) -> list[dict]:
        """Generate a batch of mixed traffic events."""
        events = []
        for _ in range(count):
            if random.random() < self.normal_ratio:
                events.append(self.generate_normal(hour))
            else:
                events.append(self.generate_attack(hour))
        random.shuffle(events)
        return events

    def run(self, count: int, hour: int | None = None) -> int:
        """Generate events and put them on the queue. Returns count generated."""
        events = self.generate_batch(count, hour)
        for event in events:
            self.queue.put(event)
        return len(events)
