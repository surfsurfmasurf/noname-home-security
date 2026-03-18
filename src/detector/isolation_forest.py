"""Isolation Forest anomaly detector wrapper."""

import logging
import pickle
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest as SklearnIF
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)


class IsolationForestModel:
    """Wraps sklearn IsolationForest with preprocessing and score normalization."""

    def __init__(self, n_estimators: int = 100, contamination: float = 0.1):
        self.model = SklearnIF(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=42,
            n_jobs=-1,
        )
        self.scaler = StandardScaler()
        self._is_trained = False

    def train(self, X: np.ndarray) -> None:
        """Train on feature matrix X (n_samples, n_features)."""
        logger.info(f"Training Isolation Forest on {X.shape[0]} samples, "
                     f"{X.shape[1]} features")
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self._is_trained = True
        logger.info("Isolation Forest training complete")

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Return anomaly scores normalized to 0-1 (higher = more anomalous).

        Args:
            X: shape (n_samples, n_features) or (n_features,) for single sample

        Returns:
            scores: shape (n_samples,) with values in [0, 1]
        """
        if not self._is_trained:
            raise RuntimeError("Model not trained. Call train() first.")

        if X.ndim == 1:
            X = X.reshape(1, -1)

        X_scaled = self.scaler.transform(X)
        # decision_function: negative = anomaly, positive = normal
        raw_scores = self.model.decision_function(X_scaled)
        # Normalize: map to 0-1 where 1 = most anomalous
        # Typical range is roughly [-0.5, 0.5]
        scores = 1.0 / (1.0 + np.exp(5 * raw_scores))  # sigmoid inversion
        return scores

    def predict_one(self, feature_vector: list[float]) -> float:
        """Score a single sample. Returns float in [0, 1]."""
        X = np.array(feature_vector).reshape(1, -1)
        return float(self.predict(X)[0])

    def save(self, path: str) -> None:
        """Save model and scaler to disk."""
        filepath = Path(path)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "wb") as f:
            pickle.dump({"model": self.model, "scaler": self.scaler}, f)
        logger.info(f"Isolation Forest saved to {filepath}")

    def load(self, path: str) -> None:
        """Load model and scaler from disk."""
        with open(path, "rb") as f:
            data = pickle.load(f)
        self.model = data["model"]
        self.scaler = data["scaler"]
        self._is_trained = True
        logger.info(f"Isolation Forest loaded from {path}")

    @property
    def is_trained(self) -> bool:
        return self._is_trained
