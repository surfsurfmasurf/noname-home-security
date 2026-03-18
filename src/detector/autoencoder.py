"""Autoencoder-based anomaly detector using PyTorch."""

import logging
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

logger = logging.getLogger(__name__)


class _AutoencoderNet(nn.Module):
    """Simple encoder-decoder network."""

    def __init__(self, input_dim: int, hidden_dim: int, latent_dim: int):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, latent_dim),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, input_dim),
        )

    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded


class AutoencoderModel:
    """Wraps a PyTorch Autoencoder for anomaly detection via reconstruction error."""

    def __init__(self, input_dim: int = 15, hidden_dim: int = 8,
                 latent_dim: int = 4, epochs: int = 50,
                 learning_rate: float = 0.001, batch_size: int = 64):
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.latent_dim = latent_dim
        self.epochs = epochs
        self.lr = learning_rate
        self.batch_size = batch_size

        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = _AutoencoderNet(input_dim, hidden_dim, latent_dim).to(self.device)
        self.criterion = nn.MSELoss(reduction="none")

        self._is_trained = False
        self._mean: np.ndarray | None = None
        self._std: np.ndarray | None = None
        self._threshold_95: float = 0.0  # 95th percentile of training errors

    def _normalize(self, X: np.ndarray) -> np.ndarray:
        if self._mean is None:
            return X
        std = np.where(self._std == 0, 1, self._std)
        return (X - self._mean) / std

    def train(self, X: np.ndarray) -> None:
        """Train autoencoder on normal traffic features."""
        logger.info(f"Training Autoencoder on {X.shape[0]} samples")

        # Compute normalization stats
        self._mean = X.mean(axis=0)
        self._std = X.std(axis=0)
        X_norm = self._normalize(X)

        tensor = torch.FloatTensor(X_norm).to(self.device)
        dataset = TensorDataset(tensor, tensor)
        loader = DataLoader(dataset, batch_size=self.batch_size, shuffle=True)

        optimizer = torch.optim.Adam(self.model.parameters(), lr=self.lr)

        self.model.train()
        for epoch in range(self.epochs):
            total_loss = 0.0
            for batch_x, _ in loader:
                output = self.model(batch_x)
                loss = self.criterion(output, batch_x).mean()
                optimizer.zero_grad()
                loss.backward()
                optimizer.step()
                total_loss += loss.item()

            if (epoch + 1) % 10 == 0:
                avg_loss = total_loss / len(loader)
                logger.info(f"  Epoch {epoch+1}/{self.epochs}, Loss: {avg_loss:.6f}")

        # Compute threshold from training data reconstruction errors
        self.model.eval()
        with torch.no_grad():
            output = self.model(tensor)
            errors = self.criterion(output, tensor).mean(dim=1).cpu().numpy()
        self._threshold_95 = float(np.percentile(errors, 95))
        self._is_trained = True
        logger.info(f"Autoencoder training complete. 95th percentile error: "
                     f"{self._threshold_95:.6f}")

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Return anomaly scores normalized to 0-1 (higher = more anomalous).

        Uses reconstruction error relative to training threshold.
        """
        if not self._is_trained:
            raise RuntimeError("Model not trained. Call train() first.")

        if X.ndim == 1:
            X = X.reshape(1, -1)

        X_norm = self._normalize(X)
        tensor = torch.FloatTensor(X_norm).to(self.device)

        self.model.eval()
        with torch.no_grad():
            output = self.model(tensor)
            errors = self.criterion(output, tensor).mean(dim=1).cpu().numpy()

        # Normalize: error / threshold → clip to [0, 1]
        # error at threshold_95 → score ~0.5
        # error at 2x threshold → score ~0.73 (sigmoid)
        scores = 1.0 / (1.0 + np.exp(-2 * (errors / max(self._threshold_95, 1e-6) - 1)))
        return scores

    def predict_one(self, feature_vector: list[float]) -> float:
        """Score a single sample."""
        X = np.array(feature_vector).reshape(1, -1)
        return float(self.predict(X)[0])

    def save(self, path: str) -> None:
        """Save model state and normalization params."""
        filepath = Path(path)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        torch.save({
            "model_state": self.model.state_dict(),
            "mean": self._mean,
            "std": self._std,
            "threshold_95": self._threshold_95,
            "config": {
                "input_dim": self.input_dim,
                "hidden_dim": self.hidden_dim,
                "latent_dim": self.latent_dim,
            },
        }, filepath)
        logger.info(f"Autoencoder saved to {filepath}")

    def load(self, path: str) -> None:
        """Load model state and normalization params."""
        checkpoint = torch.load(path, map_location=self.device, weights_only=False)
        cfg = checkpoint["config"]
        self.model = _AutoencoderNet(
            cfg["input_dim"], cfg["hidden_dim"], cfg["latent_dim"]
        ).to(self.device)
        self.model.load_state_dict(checkpoint["model_state"])
        self._mean = checkpoint["mean"]
        self._std = checkpoint["std"]
        self._threshold_95 = checkpoint["threshold_95"]
        self._is_trained = True
        logger.info(f"Autoencoder loaded from {path}")

    @property
    def is_trained(self) -> bool:
        return self._is_trained
