"""Tests for Traffic Generator."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.queue import LocalQueue
from src.generator import TrafficGenerator
from src.generator.profiles import DEFAULT_PROFILES
from src.generator.attack_patterns import DEFAULT_ATTACKS


def test_generate_normal():
    q = LocalQueue()
    gen = TrafficGenerator(q, {"generator": {"normal_ratio": 1.0, "seed": 42}})
    event = gen.generate_normal(hour=14)

    assert "request_id" in event
    assert "timestamp" in event
    assert "src_ip" in event
    assert event["label"] == "normal"
    assert event["method"] in ("GET", "POST", "PUT", "DELETE", "PATCH")
    assert 100 <= event["response_code"] <= 599


def test_generate_attack():
    q = LocalQueue()
    gen = TrafficGenerator(q, {"generator": {"normal_ratio": 0.0, "seed": 42}})
    event = gen.generate_attack(hour=3)

    assert event["label"] != "normal"
    assert event["label"] in ("sqli", "xss", "brute_force", "port_scan", "c2", "path_traversal")


def test_generate_batch_ratio():
    q = LocalQueue()
    gen = TrafficGenerator(q, {"generator": {"normal_ratio": 0.8, "seed": 42}})
    batch = gen.generate_batch(1000, hour=12)

    normal = sum(1 for e in batch if e["label"] == "normal")
    attack = sum(1 for e in batch if e["label"] != "normal")

    # Should be roughly 80/20 (allow ±5%)
    assert 750 <= normal <= 850, f"Expected ~800 normal, got {normal}"
    assert 150 <= attack <= 250, f"Expected ~200 attack, got {attack}"


def test_run_puts_on_queue():
    q = LocalQueue()
    gen = TrafficGenerator(q, {"generator": {"normal_ratio": 0.8, "seed": 42}})
    count = gen.run(50)

    assert count == 50
    assert q.size() == 50


def test_profiles_active_hours():
    for profile in DEFAULT_PROFILES:
        # IoT devices should be active 24h
        if profile.device_type == "iot":
            for hour in range(24):
                assert profile.is_active(hour), f"{profile.name} should be active at {hour}"


def test_attack_patterns_generate():
    for pattern, weight in DEFAULT_ATTACKS:
        event = pattern.generate(hour=3)
        assert "src_ip" in event
        assert "label" in event
        assert event["label"] == pattern.label
