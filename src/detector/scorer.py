"""Ensemble anomaly scorer — combines IF, Autoencoder, and signature rules."""

import re
import logging

logger = logging.getLogger(__name__)

# Signature patterns for known attacks
SIGNATURE_RULES = [
    {
        "name": "sqli",
        "patterns": [
            re.compile(r"('|\b)(OR|AND)\b.*=", re.IGNORECASE),
            re.compile(r"UNION\s+(ALL\s+)?SELECT", re.IGNORECASE),
            re.compile(r"DROP\s+TABLE", re.IGNORECASE),
            re.compile(r";\s*--"),
            re.compile(r"'\s*OR\s*'", re.IGNORECASE),
        ],
    },
    {
        "name": "xss",
        "patterns": [
            re.compile(r"<script", re.IGNORECASE),
            re.compile(r"javascript:", re.IGNORECASE),
            re.compile(r"onerror\s*=", re.IGNORECASE),
            re.compile(r"onload\s*=", re.IGNORECASE),
            re.compile(r"<svg\s+onload", re.IGNORECASE),
        ],
    },
    {
        "name": "path_traversal",
        "patterns": [
            re.compile(r"\.\./"),
            re.compile(r"\.\.\\"),
            re.compile(r"%2e%2e", re.IGNORECASE),
            re.compile(r"/etc/(passwd|shadow)"),
        ],
    },
    {
        "name": "cmd_injection",
        "patterns": [
            re.compile(r";\s*(cat|ls|wget|curl|whoami|id)\b"),
            re.compile(r"\|\s*(cat|ls|wget|curl)\b"),
            re.compile(r"&&\s*(wget|curl)\b"),
            re.compile(r"\$\("),
        ],
    },
]


def check_signatures(raw_summary: str) -> list[str]:
    """Check raw_summary against signature rules. Returns list of matched attack names."""
    matches = []
    for rule in SIGNATURE_RULES:
        for pattern in rule["patterns"]:
            if pattern.search(raw_summary):
                matches.append(rule["name"])
                break
    return matches


class EnsembleScorer:
    """Combines multiple model scores into a final anomaly score (0-100)."""

    def __init__(self, weights: dict | None = None):
        self.weights = weights or {
            "isolation_forest": 0.4,
            "autoencoder": 0.4,
            "signature": 0.2,
        }

    def score(self, if_score: float, ae_score: float,
              signature_matches: list[str]) -> dict:
        """Compute ensemble anomaly score.

        Args:
            if_score: Isolation Forest score (0-1)
            ae_score: Autoencoder score (0-1)
            signature_matches: list of matched signature names

        Returns:
            dict with anomaly_score (0-100) and model_scores breakdown
        """
        # Signature score: 1.0 if any match, 0.0 if none
        sig_score = 1.0 if signature_matches else 0.0

        w = self.weights
        combined = (
            w["isolation_forest"] * if_score
            + w["autoencoder"] * ae_score
            + w["signature"] * sig_score
        )

        # Scale to 0-100
        anomaly_score = min(100, max(0, combined * 100))

        return {
            "anomaly_score": round(anomaly_score, 1),
            "model_scores": {
                "isolation_forest": round(if_score, 4),
                "autoencoder": round(ae_score, 4),
                "signature": signature_matches,
            },
        }
