"""Integration test — runs the full pipeline end-to-end without LLM/ES."""

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.queue import LocalQueue
from src.generator import TrafficGenerator
from src.collector import Collector
from src.detector import Detector


def test_full_pipeline():
    """End-to-end: generate → collect → train → detect."""
    config = {
        "generator": {"normal_ratio": 0.8, "seed": 42},
        "collector": {"window_seconds": 300},
        "detector": {
            "models_dir": "src/models",
            "threshold": {"alert": 50, "block": 80},
            "ensemble_weights": {
                "isolation_forest": 0.4,
                "autoencoder": 0.4,
                "signature": 0.2,
            },
            "isolation_forest": {"n_estimators": 50, "contamination": 0.1},
            "autoencoder": {
                "hidden_dim": 8, "latent_dim": 4,
                "epochs": 10, "learning_rate": 0.001, "batch_size": 64,
            },
        },
    }

    # Step 1: Generate
    raw_q = LocalQueue()
    gen = TrafficGenerator(raw_q, config)
    gen.run(500)
    assert raw_q.size() == 500

    # Step 2: Collect features
    feat_q = LocalQueue()
    collector = Collector(raw_q, feat_q, config)
    collector.run(max_events=500)

    # Drain features for training
    features = []
    all_events = []
    while not feat_q.empty():
        event = feat_q.get(timeout=0.1)
        if event:
            features.append(event["feature_vector"])
            all_events.append(event)

    assert len(features) == 500
    assert len(features[0]) == 15  # 15 features

    # Step 3: Train
    alerts_q = LocalQueue()
    detector = Detector(LocalQueue(), alerts_q, None, config)
    detector.train(features)

    # Step 4: Score all events
    normal_scores = []
    attack_scores = []

    for event in all_events:
        result = detector.score_one(event)
        if event["label"] == "normal":
            normal_scores.append(result["anomaly_score"])
        else:
            attack_scores.append(result["anomaly_score"])

    # Attacks should score higher than normal on average
    assert np.mean(attack_scores) > np.mean(normal_scores), (
        f"Attack mean {np.mean(attack_scores):.1f} should be > "
        f"normal mean {np.mean(normal_scores):.1f}"
    )
