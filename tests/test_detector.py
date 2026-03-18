"""Tests for ML Detector components."""

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.detector.isolation_forest import IsolationForestModel
from src.detector.autoencoder import AutoencoderModel
from src.detector.scorer import EnsembleScorer, check_signatures


def _make_training_data(n_normal=500, n_anomaly=50):
    """Create synthetic training data."""
    rng = np.random.RandomState(42)
    # Normal: clustered around center
    normal = rng.randn(n_normal, 15) * 0.5 + 2.0
    # Anomaly: spread out
    anomaly = rng.randn(n_anomaly, 15) * 3.0 + 8.0
    X = np.vstack([normal, anomaly])
    return X, normal, anomaly


def test_isolation_forest_train_predict():
    X, normal, anomaly = _make_training_data()
    model = IsolationForestModel(n_estimators=50, contamination=0.1)
    model.train(X)

    assert model.is_trained

    # Normal should score lower than anomaly
    normal_scores = model.predict(normal)
    anomaly_scores = model.predict(anomaly)

    assert np.mean(normal_scores) < np.mean(anomaly_scores)


def test_isolation_forest_predict_one():
    X, normal, _ = _make_training_data()
    model = IsolationForestModel()
    model.train(X)

    score = model.predict_one(normal[0].tolist())
    assert 0 <= score <= 1


def test_isolation_forest_save_load(tmp_path):
    X, _, _ = _make_training_data()
    model = IsolationForestModel()
    model.train(X)

    path = str(tmp_path / "if_model.pkl")
    model.save(path)

    loaded = IsolationForestModel()
    loaded.load(path)
    assert loaded.is_trained

    # Should produce same scores
    original = model.predict_one([2.0] * 15)
    reloaded = loaded.predict_one([2.0] * 15)
    assert abs(original - reloaded) < 1e-6


def test_autoencoder_train_predict():
    X, normal, anomaly = _make_training_data()
    model = AutoencoderModel(input_dim=15, hidden_dim=8, latent_dim=4, epochs=20)
    model.train(X)

    assert model.is_trained

    normal_scores = model.predict(normal)
    anomaly_scores = model.predict(anomaly)

    # Anomalies should generally score higher
    assert np.mean(anomaly_scores) > np.mean(normal_scores)


def test_autoencoder_save_load(tmp_path):
    X, _, _ = _make_training_data()
    model = AutoencoderModel(input_dim=15, epochs=10)
    model.train(X)

    path = str(tmp_path / "ae_model.pt")
    model.save(path)

    loaded = AutoencoderModel(input_dim=15)
    loaded.load(path)
    assert loaded.is_trained


def test_ensemble_scorer():
    scorer = EnsembleScorer()
    result = scorer.score(if_score=0.8, ae_score=0.7, signature_matches=["sqli"])

    assert "anomaly_score" in result
    assert 0 <= result["anomaly_score"] <= 100
    # With high scores + signature match, should be high
    assert result["anomaly_score"] > 50


def test_ensemble_scorer_low():
    scorer = EnsembleScorer()
    result = scorer.score(if_score=0.1, ae_score=0.1, signature_matches=[])

    assert result["anomaly_score"] < 20


def test_check_signatures():
    assert "sqli" in check_signatures("GET /api?q=' OR 1=1--")
    assert "xss" in check_signatures("POST /api body=<script>alert(1)</script>")
    assert "path_traversal" in check_signatures("GET /files/../../etc/passwd")
    assert len(check_signatures("GET /api/v1/products")) == 0
