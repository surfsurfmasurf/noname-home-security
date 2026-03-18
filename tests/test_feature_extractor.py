"""Tests for Feature Extractor."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.collector.feature_extractor import FeatureExtractor, FEATURE_NAMES


def _make_event(**overrides):
    base = {
        "request_id": "test-123",
        "timestamp": "2026-03-18T14:30:00Z",
        "src_ip": "192.168.0.10",
        "dst_ip": "192.168.0.1",
        "dst_port": 443,
        "method": "GET",
        "path": "/api/v1/products",
        "query_params": "",
        "headers": {
            "User-Agent": "Mozilla/5.0",
            "Content-Type": "application/json",
        },
        "payload_size": 0,
        "response_code": 200,
        "response_size": 1024,
        "response_time_ms": 45,
        "label": "normal",
    }
    base.update(overrides)
    return base


def test_extract_basic():
    extractor = FeatureExtractor(window_seconds=300)
    event = _make_event()
    result = extractor.extract(event)

    assert "features" in result
    assert "feature_vector" in result
    assert len(result["feature_vector"]) == 15
    assert result["label"] == "normal"
    assert result["src_ip"] == "192.168.0.10"


def test_feature_names_match():
    extractor = FeatureExtractor()
    result = extractor.extract(_make_event())

    for name in FEATURE_NAMES:
        assert name in result["features"], f"Missing feature: {name}"


def test_special_chars_detection():
    extractor = FeatureExtractor()

    # Normal query
    normal = extractor.extract(_make_event(query_params="q=shoes&page=1"))
    assert normal["features"]["has_special_chars"] == 0

    # SQLi query
    sqli = extractor.extract(_make_event(query_params="q=' OR 1=1--"))
    assert sqli["features"]["has_special_chars"] == 1


def test_path_depth():
    extractor = FeatureExtractor()

    shallow = extractor.extract(_make_event(path="/api"))
    assert shallow["features"]["path_depth"] == 1

    deep = extractor.extract(_make_event(path="/api/v1/users/123/orders"))
    assert deep["features"]["path_depth"] == 5


def test_ip_aggregation():
    extractor = FeatureExtractor(window_seconds=300)

    # Send multiple requests from same IP
    for i in range(10):
        result = extractor.extract(_make_event(
            src_ip="192.168.0.50",
            path=f"/api/v1/endpoint{i % 3}",
            response_code=200 if i < 7 else 401,
        ))

    # Last result should have aggregated stats
    assert result["features"]["req_count_5min"] == 10
    assert result["features"]["unique_paths_5min"] == 3
    assert result["features"]["error_rate_5min"] > 0


def test_raw_summary():
    extractor = FeatureExtractor()
    result = extractor.extract(_make_event(
        method="POST",
        path="/api/v1/auth/login",
        query_params="user=admin",
        src_ip="10.0.0.1",
    ))
    assert "POST" in result["raw_summary"]
    assert "/api/v1/auth/login" in result["raw_summary"]
    assert "10.0.0.1" in result["raw_summary"]
