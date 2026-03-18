"""ML Detector Agent — scores traffic features and raises alerts."""

import logging
from pathlib import Path

import numpy as np

from ..queue import MessageQueue
from .isolation_forest import IsolationForestModel
from .autoencoder import AutoencoderModel
from .scorer import EnsembleScorer, check_signatures

logger = logging.getLogger(__name__)


class Detector:
    """Reads feature vectors, scores with ML models, sends alerts."""

    def __init__(self, input_queue: MessageQueue, output_queue: MessageQueue,
                 es_queue: MessageQueue | None, config: dict):
        det_cfg = config.get("detector", {})
        self.input_queue = input_queue
        self.output_queue = output_queue  # alerts queue
        self.es_queue = es_queue          # all results → ES

        self.alert_threshold = det_cfg.get("threshold", {}).get("alert", 50)
        self.block_threshold = det_cfg.get("threshold", {}).get("block", 80)

        # Initialize models
        if_cfg = det_cfg.get("isolation_forest", {})
        ae_cfg = det_cfg.get("autoencoder", {})
        weights = det_cfg.get("ensemble_weights", {})

        self.if_model = IsolationForestModel(
            n_estimators=if_cfg.get("n_estimators", 100),
            contamination=if_cfg.get("contamination", 0.1),
        )
        self.ae_model = AutoencoderModel(
            input_dim=15,
            hidden_dim=ae_cfg.get("hidden_dim", 8),
            latent_dim=ae_cfg.get("latent_dim", 4),
            epochs=ae_cfg.get("epochs", 50),
            learning_rate=ae_cfg.get("learning_rate", 0.001),
            batch_size=ae_cfg.get("batch_size", 64),
        )
        self.scorer = EnsembleScorer(weights=weights)

        self.models_dir = Path(det_cfg.get("models_dir", "src/models"))
        self._processed = 0
        self._alerts = 0

    def train(self, feature_vectors: list[list[float]]) -> None:
        """Train both models on collected feature vectors."""
        X = np.array(feature_vectors)
        logger.info(f"Training detector models on {X.shape[0]} samples")
        self.if_model.train(X)
        self.ae_model.train(X)
        logger.info("Detector training complete")

    def save_models(self) -> None:
        """Save trained models to disk."""
        self.if_model.save(str(self.models_dir / "isolation_forest.pkl"))
        self.ae_model.save(str(self.models_dir / "autoencoder.pt"))

    def load_models(self) -> None:
        """Load trained models from disk."""
        self.if_model.load(str(self.models_dir / "isolation_forest.pkl"))
        self.ae_model.load(str(self.models_dir / "autoencoder.pt"))

    def score_one(self, feature_data: dict) -> dict:
        """Score a single feature vector and return full result."""
        fv = feature_data["feature_vector"]
        raw_summary = feature_data.get("raw_summary", "")

        # Get model scores
        if_score = self.if_model.predict_one(fv)
        ae_score = self.ae_model.predict_one(fv)
        sig_matches = check_signatures(raw_summary)

        # Ensemble
        result = self.scorer.score(if_score, ae_score, sig_matches)

        return {
            "request_id": feature_data.get("request_id", ""),
            "timestamp": feature_data.get("timestamp", ""),
            "src_ip": feature_data.get("src_ip", ""),
            "raw_summary": raw_summary,
            "features": feature_data.get("features", {}),
            "feature_vector": fv,
            "anomaly_score": result["anomaly_score"],
            "model_scores": result["model_scores"],
            "label": feature_data.get("label", "unknown"),
        }

    def process_one(self) -> dict | None:
        """Process a single event from the features queue."""
        event = self.input_queue.get(timeout=1.0)
        if event is None:
            return None

        result = self.score_one(event)
        self._processed += 1

        # Send all results to ES queue
        if self.es_queue is not None:
            self.es_queue.put(result)

        # Send alerts (above threshold) to analyst queue
        if result["anomaly_score"] >= self.alert_threshold:
            self.output_queue.put(result)
            self._alerts += 1

        if self._processed % 100 == 0:
            logger.info(f"Detector: {self._processed} processed, "
                        f"{self._alerts} alerts")

        return result

    def run(self, max_events: int | None = None) -> int:
        """Process events continuously or up to max_events."""
        count = 0
        while max_events is None or count < max_events:
            result = self.process_one()
            if result is not None:
                count += 1
            elif max_events is not None and self.input_queue.empty():
                break
        return count

    @property
    def stats(self) -> dict:
        return {
            "processed": self._processed,
            "alerts": self._alerts,
            "alert_rate": self._alerts / max(self._processed, 1),
        }
