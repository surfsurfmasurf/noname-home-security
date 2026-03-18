"""Feature extraction from raw traffic events.

Extracts 15 numerical features per request for ML models:
  - Time features: hour_of_day, is_weekend, req_interval_sec
  - Request features: method_encoded, path_depth, query_length,
    has_special_chars, payload_size
  - Response features: response_code, response_size, response_time_ms
  - IP aggregate features (5-min window): req_count_5min, unique_paths_5min,
    error_rate_5min, unique_ua_count
"""

import re
import time
from collections import defaultdict
from datetime import datetime

# Characters commonly found in injection payloads
SPECIAL_CHARS_PATTERN = re.compile(r"['\";|<>\\`$(){}]")

METHOD_ENCODING = {"GET": 0, "POST": 1, "PUT": 2, "DELETE": 3, "PATCH": 4, "HEAD": 5}

FEATURE_NAMES = [
    "hour_of_day", "is_weekend", "req_interval_sec",
    "method_encoded", "path_depth", "query_length",
    "has_special_chars", "payload_size",
    "response_code", "response_size", "response_time_ms",
    "req_count_5min", "unique_paths_5min", "error_rate_5min",
    "unique_ua_count",
]


class FeatureExtractor:
    """Extracts numerical features from raw traffic events."""

    def __init__(self, window_seconds: int = 300):
        self.window_seconds = window_seconds
        # Per-IP sliding window state
        self._ip_history: dict[str, list[dict]] = defaultdict(list)
        self._last_request_time: dict[str, float] = {}

    def _prune_window(self, ip: str, now: float) -> None:
        """Remove entries older than the window."""
        cutoff = now - self.window_seconds
        self._ip_history[ip] = [
            e for e in self._ip_history[ip] if e["time"] >= cutoff
        ]

    def _get_ip_aggregates(self, ip: str, now: float) -> dict:
        """Compute aggregate features over the sliding window for an IP."""
        self._prune_window(ip, now)
        history = self._ip_history[ip]

        if not history:
            return {
                "req_count_5min": 0,
                "unique_paths_5min": 0,
                "error_rate_5min": 0.0,
                "unique_ua_count": 0,
            }

        error_count = sum(1 for e in history if e.get("code", 200) >= 400)
        unique_paths = len(set(e.get("path", "") for e in history))
        unique_uas = len(set(e.get("ua", "") for e in history))

        return {
            "req_count_5min": len(history),
            "unique_paths_5min": unique_paths,
            "error_rate_5min": error_count / len(history) if history else 0.0,
            "unique_ua_count": unique_uas,
        }

    def extract(self, event: dict) -> dict:
        """Extract features from a single raw traffic event.

        Returns a dict with 'features' (dict of 15 floats),
        'feature_vector' (list of 15 floats), and metadata.
        """
        now = time.time()
        ip = event.get("src_ip", "unknown")
        timestamp = event.get("timestamp", "")
        headers = event.get("headers", {})
        ua = headers.get("User-Agent", "")

        # Parse timestamp for time features
        try:
            dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            hour = dt.hour
            is_weekend = 1 if dt.weekday() >= 5 else 0
        except (ValueError, AttributeError):
            hour = 0
            is_weekend = 0

        # Request interval
        last_time = self._last_request_time.get(ip, now)
        req_interval = now - last_time
        self._last_request_time[ip] = now

        # Request features
        method = event.get("method", "GET")
        path = event.get("path", "/")
        query = event.get("query_params", "")

        method_encoded = METHOD_ENCODING.get(method, 0)
        path_depth = len([p for p in path.split("/") if p])
        query_length = len(query)
        has_special = 1 if SPECIAL_CHARS_PATTERN.search(query + path) else 0
        payload_size = event.get("payload_size", 0)

        # Response features
        response_code = event.get("response_code", 200)
        response_size = event.get("response_size", 0)
        response_time = event.get("response_time_ms", 0)

        # Update IP history before computing aggregates
        self._ip_history[ip].append({
            "time": now,
            "path": path,
            "code": response_code,
            "ua": ua,
        })

        # IP aggregates
        aggregates = self._get_ip_aggregates(ip, now)

        features = {
            "hour_of_day": hour,
            "is_weekend": is_weekend,
            "req_interval_sec": min(req_interval, 3600),  # cap at 1 hour
            "method_encoded": method_encoded,
            "path_depth": path_depth,
            "query_length": query_length,
            "has_special_chars": has_special,
            "payload_size": payload_size,
            "response_code": response_code,
            "response_size": response_size,
            "response_time_ms": response_time,
            **aggregates,
        }

        feature_vector = [float(features[name]) for name in FEATURE_NAMES]

        # Build summary string
        raw_summary = f"{method} {path}"
        if query:
            raw_summary += f"?{query[:100]}"
        raw_summary += f" from {ip}"

        return {
            "request_id": event.get("request_id", ""),
            "timestamp": timestamp,
            "src_ip": ip,
            "features": features,
            "feature_vector": feature_vector,
            "raw_summary": raw_summary,
            "label": event.get("label", "unknown"),
        }
