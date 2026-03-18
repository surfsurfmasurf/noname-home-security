"""Benchmark — compare our ensemble model against top Kaggle/HuggingFace approaches.

Models:
  1. Ours: Isolation Forest + Autoencoder + Signature (ensemble)
  2. Kaggle #1: Random Forest (NSL-KDD top performer)
  3. Kaggle #2: XGBoost (UNSW-NB15 top performer)
  4. HuggingFace #1: Deep Neural Network / MLP (common top approach)
  5. HuggingFace #2: One-Class SVM (anomaly detection baseline)

Usage:
    python -m scripts.benchmark [--samples 10000]
"""

import argparse
import logging
import sys
import time
from collections import Counter
from pathlib import Path

import numpy as np
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.queue import LocalQueue
from src.generator import TrafficGenerator
from src.collector import Collector

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("benchmark")


def load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def generate_data(config: dict, n_samples: int):
    """Generate synthetic data and extract features."""
    raw_queue = LocalQueue()
    features_queue = LocalQueue()

    generator = TrafficGenerator(raw_queue, config)
    generator.run(n_samples)

    collector = Collector(raw_queue, features_queue, config)
    collector.run(max_events=n_samples)

    X, y, labels = [], [], []
    while not features_queue.empty():
        event = features_queue.get(timeout=0.1)
        if event:
            X.append(event["feature_vector"])
            label = event["label"]
            labels.append(label)
            y.append(0 if label == "normal" else 1)

    return np.array(X), np.array(y), labels


def evaluate(y_true, y_pred, y_scores, model_name: str) -> dict:
    """Calculate metrics for a model."""
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score,
        f1_score, roc_auc_score, confusion_matrix,
    )

    tp = int(np.sum((y_pred == 1) & (y_true == 1)))
    fp = int(np.sum((y_pred == 1) & (y_true == 0)))
    tn = int(np.sum((y_pred == 0) & (y_true == 0)))
    fn = int(np.sum((y_pred == 0) & (y_true == 1)))

    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)

    try:
        auc = roc_auc_score(y_true, y_scores)
    except ValueError:
        auc = 0.0

    return {
        "model": model_name,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "auc": auc,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
    }


# ──────────────────────────────────────────────
# Model 1: Our Ensemble (IF + AE + Signature)
# ──────────────────────────────────────────────
def run_our_ensemble(X_train, y_train, X_test, y_test, config):
    from src.detector import Detector

    alerts_queue = LocalQueue()
    detector = Detector(LocalQueue(), alerts_queue, None, config)
    detector.train(X_train.tolist())

    threshold = config.get("detector", {}).get("threshold", {}).get("alert", 50)
    scores = []
    for fv in X_test:
        result = detector.scorer.score(
            detector.if_model.predict_one(fv.tolist()),
            detector.ae_model.predict_one(fv.tolist()),
            [],
        )
        scores.append(result["anomaly_score"])

    scores = np.array(scores)
    preds = (scores >= threshold).astype(int)
    return preds, scores / 100.0


# ──────────────────────────────────────────────
# Model 2: Random Forest (Kaggle NSL-KDD #1)
# ──────────────────────────────────────────────
def run_random_forest(X_train, y_train, X_test, y_test):
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler

    scaler = StandardScaler()
    X_tr = scaler.fit_transform(X_train)
    X_te = scaler.transform(X_test)

    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_split=5,
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X_tr, y_train)

    preds = rf.predict(X_te)
    probs = rf.predict_proba(X_te)[:, 1]
    return preds, probs


# ──────────────────────────────────────────────
# Model 3: XGBoost (Kaggle UNSW-NB15 #1)
# ──────────────────────────────────────────────
def run_xgboost(X_train, y_train, X_test, y_test):
    from xgboost import XGBClassifier
    from sklearn.preprocessing import StandardScaler

    scaler = StandardScaler()
    X_tr = scaler.fit_transform(X_train)
    X_te = scaler.transform(X_test)

    xgb = XGBClassifier(
        n_estimators=200,
        max_depth=8,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        eval_metric="logloss",
        use_label_encoder=False,
    )
    xgb.fit(X_tr, y_train)

    preds = xgb.predict(X_te)
    probs = xgb.predict_proba(X_te)[:, 1]
    return preds, probs


# ──────────────────────────────────────────────
# Model 4: Deep Neural Network / MLP (HF #1)
# ──────────────────────────────────────────────
def run_dnn(X_train, y_train, X_test, y_test):
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader, TensorDataset
    from sklearn.preprocessing import StandardScaler

    scaler = StandardScaler()
    X_tr = scaler.fit_transform(X_train).astype(np.float32)
    X_te = scaler.transform(X_test).astype(np.float32)

    input_dim = X_tr.shape[1]

    class MLP(nn.Module):
        def __init__(self):
            super().__init__()
            self.net = nn.Sequential(
                nn.Linear(input_dim, 128),
                nn.ReLU(),
                nn.BatchNorm1d(128),
                nn.Dropout(0.3),
                nn.Linear(128, 64),
                nn.ReLU(),
                nn.BatchNorm1d(64),
                nn.Dropout(0.2),
                nn.Linear(64, 32),
                nn.ReLU(),
                nn.Linear(32, 1),
                nn.Sigmoid(),
            )

        def forward(self, x):
            return self.net(x)

    # Handle class imbalance with weighted loss
    n_pos = y_train.sum()
    n_neg = len(y_train) - n_pos
    pos_weight = torch.tensor([n_neg / max(n_pos, 1)], dtype=torch.float32)

    model = MLP()
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001, weight_decay=1e-4)

    # Remove final sigmoid for BCEWithLogitsLoss — rebuild without it
    model.net = nn.Sequential(
        nn.Linear(input_dim, 128),
        nn.ReLU(),
        nn.BatchNorm1d(128),
        nn.Dropout(0.3),
        nn.Linear(128, 64),
        nn.ReLU(),
        nn.BatchNorm1d(64),
        nn.Dropout(0.2),
        nn.Linear(64, 32),
        nn.ReLU(),
        nn.Linear(32, 1),
    )
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001, weight_decay=1e-4)

    dataset = TensorDataset(
        torch.FloatTensor(X_tr),
        torch.FloatTensor(y_train.astype(np.float32)),
    )
    loader = DataLoader(dataset, batch_size=128, shuffle=True)

    model.train()
    for epoch in range(30):
        for xb, yb in loader:
            optimizer.zero_grad()
            out = model(xb).squeeze()
            loss = criterion(out, yb)
            loss.backward()
            optimizer.step()

    model.eval()
    with torch.no_grad():
        logits = model(torch.FloatTensor(X_te)).squeeze()
        probs = torch.sigmoid(logits).numpy()

    preds = (probs >= 0.5).astype(int)
    return preds, probs


# ──────────────────────────────────────────────
# Model 5: One-Class SVM (HF anomaly detection #2)
# ──────────────────────────────────────────────
def run_ocsvm(X_train, y_train, X_test, y_test):
    from sklearn.svm import OneClassSVM
    from sklearn.preprocessing import StandardScaler

    scaler = StandardScaler()
    # Train only on normal data (unsupervised)
    X_normal = X_train[y_train == 0]
    X_tr = scaler.fit_transform(X_normal)
    X_te = scaler.transform(X_test)

    ocsvm = OneClassSVM(
        kernel="rbf",
        gamma="scale",
        nu=0.1,
    )
    ocsvm.fit(X_tr)

    raw_preds = ocsvm.predict(X_te)  # 1=normal, -1=anomaly
    preds = (raw_preds == -1).astype(int)  # convert: 1=attack
    scores = -ocsvm.decision_function(X_te)  # higher = more anomalous
    # Normalize scores to [0, 1]
    scores = (scores - scores.min()) / (scores.max() - scores.min() + 1e-8)
    return preds, scores


def print_results(results: list[dict]):
    """Pretty-print benchmark results."""
    print("\n" + "=" * 90)
    print(f"{'Model':<35} {'Accuracy':>8} {'Precision':>9} {'Recall':>8} "
          f"{'F1':>8} {'AUC':>8}")
    print("=" * 90)

    for r in sorted(results, key=lambda x: x["f1"], reverse=True):
        print(f"{r['model']:<35} {r['accuracy']:>8.2%} {r['precision']:>9.2%} "
              f"{r['recall']:>8.2%} {r['f1']:>8.4f} {r['auc']:>8.4f}")

    print("=" * 90)

    print(f"\n{'Model':<35} {'TP':>6} {'FP':>6} {'TN':>6} {'FN':>6}")
    print("-" * 65)
    for r in sorted(results, key=lambda x: x["f1"], reverse=True):
        print(f"{r['model']:<35} {r['tp']:>6} {r['fp']:>6} {r['tn']:>6} {r['fn']:>6}")

    print()
    best = max(results, key=lambda x: x["f1"])
    print(f"Best F1 Score: {best['model']} ({best['f1']:.4f})")


def main():
    parser = argparse.ArgumentParser(description="Benchmark anomaly detection models")
    parser.add_argument("--samples", type=int, default=10000,
                        help="Total samples to generate")
    parser.add_argument("--test-ratio", type=float, default=0.3,
                        help="Test set ratio")
    parser.add_argument("--config", type=str, default="config/settings.yaml")
    parser.add_argument("--no-xgboost", action="store_true",
                        help="Skip XGBoost (if not installed)")
    args = parser.parse_args()

    config = load_config(args.config)

    # --- Generate data ---
    logger.info(f"Generating {args.samples} synthetic samples...")
    X, y, labels = generate_data(config, args.samples)
    logger.info(f"Dataset: {len(X)} samples, {sum(y)} attacks, "
                f"{len(y) - sum(y)} normal")
    logger.info(f"Labels: {dict(Counter(labels))}")

    # --- Train/test split ---
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_ratio, random_state=42, stratify=y,
    )
    logger.info(f"Train: {len(X_train)}, Test: {len(X_test)}")

    results = []

    # --- Model 1: Our Ensemble ---
    logger.info("\n=== Model 1: Our Ensemble (IF + AE + Signature) ===")
    t0 = time.time()
    preds, scores = run_our_ensemble(X_train, y_train, X_test, y_test, config)
    elapsed = time.time() - t0
    r = evaluate(y_test, preds, scores, "1. Ours (IF+AE+Sig)")
    r["time"] = elapsed
    results.append(r)
    logger.info(f"  F1={r['f1']:.4f}, AUC={r['auc']:.4f} ({elapsed:.1f}s)")

    # --- Model 2: Random Forest ---
    logger.info("\n=== Model 2: Random Forest (Kaggle NSL-KDD) ===")
    t0 = time.time()
    preds, scores = run_random_forest(X_train, y_train, X_test, y_test)
    elapsed = time.time() - t0
    r = evaluate(y_test, preds, scores, "2. Random Forest (Kaggle)")
    r["time"] = elapsed
    results.append(r)
    logger.info(f"  F1={r['f1']:.4f}, AUC={r['auc']:.4f} ({elapsed:.1f}s)")

    # --- Model 3: XGBoost ---
    if not args.no_xgboost:
        try:
            logger.info("\n=== Model 3: XGBoost (Kaggle UNSW-NB15) ===")
            t0 = time.time()
            preds, scores = run_xgboost(X_train, y_train, X_test, y_test)
            elapsed = time.time() - t0
            r = evaluate(y_test, preds, scores, "3. XGBoost (Kaggle)")
            r["time"] = elapsed
            results.append(r)
            logger.info(f"  F1={r['f1']:.4f}, AUC={r['auc']:.4f} ({elapsed:.1f}s)")
        except ImportError:
            logger.warning("XGBoost not installed. Run: pip install xgboost")
            logger.warning("Skipping XGBoost benchmark.")

    # --- Model 4: DNN ---
    logger.info("\n=== Model 4: Deep Neural Network (HuggingFace) ===")
    t0 = time.time()
    preds, scores = run_dnn(X_train, y_train, X_test, y_test)
    elapsed = time.time() - t0
    r = evaluate(y_test, preds, scores, "4. DNN/MLP (HuggingFace)")
    r["time"] = elapsed
    results.append(r)
    logger.info(f"  F1={r['f1']:.4f}, AUC={r['auc']:.4f} ({elapsed:.1f}s)")

    # --- Model 5: One-Class SVM ---
    logger.info("\n=== Model 5: One-Class SVM (HuggingFace) ===")
    t0 = time.time()
    preds, scores = run_ocsvm(X_train, y_train, X_test, y_test)
    elapsed = time.time() - t0
    r = evaluate(y_test, preds, scores, "5. One-Class SVM (HuggingFace)")
    r["time"] = elapsed
    results.append(r)
    logger.info(f"  F1={r['f1']:.4f}, AUC={r['auc']:.4f} ({elapsed:.1f}s)")

    # --- Final Results ---
    print_results(results)

    # Timing summary
    print(f"\n{'Model':<35} {'Time':>8}")
    print("-" * 45)
    for r in results:
        print(f"{r['model']:<35} {r['time']:>7.1f}s")


if __name__ == "__main__":
    main()
