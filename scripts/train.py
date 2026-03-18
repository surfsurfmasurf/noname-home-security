"""Training script — generates synthetic data and trains ML models.

Usage:
    python -m scripts.train [--samples 10000] [--config config/settings.yaml]
"""

import argparse
import logging
import sys
from pathlib import Path

import yaml

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.queue import LocalQueue
from src.generator import TrafficGenerator
from src.collector import Collector, FeatureExtractor
from src.detector import Detector

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("train")


def load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def main():
    parser = argparse.ArgumentParser(description="Train anomaly detection models")
    parser.add_argument("--samples", type=int, default=10000,
                        help="Number of training samples to generate")
    parser.add_argument("--config", type=str, default="config/settings.yaml")
    args = parser.parse_args()

    config = load_config(args.config)
    n_samples = args.samples

    # --- Step 1: Generate synthetic traffic ---
    logger.info(f"=== Step 1: Generating {n_samples} synthetic traffic events ===")

    raw_queue = LocalQueue()
    generator = TrafficGenerator(raw_queue, config)
    generated = generator.run(n_samples)
    logger.info(f"Generated {generated} events")

    # --- Step 2: Extract features ---
    logger.info("=== Step 2: Extracting features ===")

    features_queue = LocalQueue()
    collector = Collector(raw_queue, features_queue, config)
    collected = collector.run(max_events=generated)
    logger.info(f"Extracted features from {collected} events")

    # --- Step 3: Collect feature vectors and labels ---
    logger.info("=== Step 3: Collecting feature vectors ===")

    feature_vectors = []
    labels = []
    all_events = []

    while not features_queue.empty():
        event = features_queue.get(timeout=0.1)
        if event:
            feature_vectors.append(event["feature_vector"])
            labels.append(event["label"])
            all_events.append(event)

    logger.info(f"Collected {len(feature_vectors)} feature vectors")

    # Show label distribution
    from collections import Counter
    label_counts = Counter(labels)
    logger.info(f"Label distribution: {dict(label_counts)}")

    # --- Step 4: Train models (on normal data only for baseline) ---
    logger.info("=== Step 4: Training ML models ===")

    # For unsupervised learning, train on ALL data (including attacks)
    # The models learn what's "dense" (normal) vs "isolated" (anomaly)
    alerts_queue = LocalQueue()
    detector = Detector(
        input_queue=LocalQueue(),
        output_queue=alerts_queue,
        es_queue=None,
        config=config,
    )
    detector.train(feature_vectors)

    # --- Step 5: Save models ---
    logger.info("=== Step 5: Saving models ===")
    detector.save_models()

    # --- Step 6: Evaluate on training data ---
    logger.info("=== Step 6: Evaluating model performance ===")

    normal_scores = []
    attack_scores = []

    for event in all_events:
        result = detector.score_one(event)
        score = result["anomaly_score"]
        if event["label"] == "normal":
            normal_scores.append(score)
        else:
            attack_scores.append(score)

    import numpy as np
    if normal_scores:
        logger.info(
            f"Normal traffic scores: "
            f"mean={np.mean(normal_scores):.1f}, "
            f"median={np.median(normal_scores):.1f}, "
            f"max={np.max(normal_scores):.1f}"
        )
    if attack_scores:
        logger.info(
            f"Attack traffic scores: "
            f"mean={np.mean(attack_scores):.1f}, "
            f"median={np.median(attack_scores):.1f}, "
            f"min={np.min(attack_scores):.1f}"
        )

    # Detection accuracy at threshold
    threshold = config.get("detector", {}).get("threshold", {}).get("alert", 50)
    if normal_scores and attack_scores:
        fp = sum(1 for s in normal_scores if s >= threshold)
        tp = sum(1 for s in attack_scores if s >= threshold)
        fpr = fp / len(normal_scores)
        tpr = tp / len(attack_scores)
        logger.info(f"At threshold {threshold}:")
        logger.info(f"  True Positive Rate:  {tpr:.2%} ({tp}/{len(attack_scores)})")
        logger.info(f"  False Positive Rate: {fpr:.2%} ({fp}/{len(normal_scores)})")

    logger.info("=== Training complete! ===")
    logger.info(f"Models saved to: {config.get('detector', {}).get('models_dir', 'src/models')}")


if __name__ == "__main__":
    main()
