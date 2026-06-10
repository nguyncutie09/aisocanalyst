#!/usr/bin/env python3
"""
Model Training Script.
Trains all UEBA models (anomaly, classifier) using synthetic or provided data.

Usage:
    python scripts/train.py                          # Use synthetic data
    python scripts/train.py --from-file data.parquet # Use custom data
    python scripts/train.py --epochs 100 --lr 0.001  # Custom params
"""

import os
import sys
import time
import argparse
import numpy as np
import pandas as pd

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import settings
from app.models.anomaly import AnomalyDetector
from app.models.classifier import AttackClassifier
from app.pipeline.ingestion import SyntheticLogGenerator, LogIngestor
from app.pipeline.normalizer import LogNormalizer


def train_synthetic(epochs: int = 50, lr: float = 0.001, batch_size: int = 256):
    """Generate synthetic data and train all models."""
    print("=" * 60)
    print("  UEBA - Model Training (Synthetic Data)")
    print("=" * 60)

    # Generate data
    print("\n[1/5] Generating synthetic security logs...")
    generator = SyntheticLogGenerator()
    df = generator.generate_attack_scenarios(n_normal=5000, n_attack=500, seed=42)
    print(f"  Generated {len(df)} events ({df['is_anomaly'].sum()} attacks)")

    _train(df, epochs, lr, batch_size)


def train_from_file(filepath: str, epochs: int = 50, lr: float = 0.001,
                    batch_size: int = 256, label_col: str = "attack_type",
                    tactic_col: str = "tactic"):
    """Train from a labeled data file."""
    print("=" * 60)
    print(f"  UEBA - Model Training (From File: {filepath})")
    print("=" * 60)

    if not os.path.exists(filepath):
        print(f"✗ File not found: {filepath}")
        sys.exit(1)

    print(f"\n[1/5] Loading data from {filepath}...")
    ingestor = LogIngestor()
    df = ingestor.ingest_file(filepath)
    print(f"  Loaded {len(df)} events")

    if label_col not in df.columns:
        print(f"✗ Label column '{label_col}' not found")
        sys.exit(1)

    _train(df, epochs, lr, batch_size, label_col, tactic_col)


def _train(df: pd.DataFrame, epochs: int, lr: float, batch_size: int,
           label_col: str = "attack_type", tactic_col: str = "tactic"):
    """Internal training pipeline."""
    # Prepare features
    print("\n[2/5] Extracting features...")
    normalizer = LogNormalizer()
    feature_df = normalizer.extract_features(df, fit=True)
    print(f"  Features: {feature_df.shape[1]} dimensions")
    print(f"  Samples: {feature_df.shape[0]}")

    # Ensure output dir
    os.makedirs(settings.MODEL_DIR, exist_ok=True)

    # Save normalizer
    normalizer.save_encoders(os.path.join(settings.MODEL_DIR, "label_encoders.pkl"))

    X = feature_df.values.astype(np.float32)
    y_attack = df[label_col].values
    y_tactic = df.get(tactic_col, ["TA0000_Benign"] * len(df)).values

    start_time = time.time()

    # Train Anomaly Detector
    print("\n[3/5] Training Anomaly Detector ensemble...")
    detector = AnomalyDetector()
    normal_mask = df[label_col] == "normal"
    X_normal = X[normal_mask]
    detector.fit(
        X_normal,
        fit_iso_forest=True,
        fit_deep_if=True,
        fit_autoencoder=True,
        epochs=epochs,
        batch_size=batch_size,
        lr=lr,
        verbose=True,
    )
    detector.save(settings.MODEL_DIR)

    # Evaluate anomaly detector
    print("\n  Evaluating anomaly detector...")
    scores_dict = detector.predict(X)
    ensemble_scores = detector.predict_ensemble(X)
    y_true = (~normal_mask).astype(int)
    from sklearn.metrics import roc_auc_score, average_precision_score
    try:
        auc = roc_auc_score(y_true, ensemble_scores)
        ap = average_precision_score(y_true, ensemble_scores)
        print(f"  ✓ Anomaly AUC: {auc:.4f} | AP: {ap:.4f}")
    except Exception as e:
        print(f"  ⚠ AUC/AP computation: {e}")

    # Train Classifier
    print("\n[4/5] Training Attack Classifier (XGBoost)...")
    classifier = AttackClassifier()
    classifier.fit(
        X, y_attack, y_tactic,
        feature_names=list(feature_df.columns),
        verbose=True,
    )
    classifier.save(settings.MODEL_DIR)

    # Evaluate
    pred_result = classifier.predict(X)
    acc = np.mean(np.array(pred_result["attack_type"]) == y_attack)
    print(f"\n  ✓ Classification accuracy: {acc:.4f} ({acc*100:.1f}%)")

    elapsed = time.time() - start_time
    print(f"\n[5/5] ✓ Training complete in {elapsed:.1f}s")
    print(f"  Models saved to: {settings.MODEL_DIR}")
    print(f"  - isolation_forest.pkl")
    print(f"  - deep_isolation_forest.pt")
    print(f"  - autoencoder.pt")
    print(f"  - xgb_attack.json")
    print(f"  - xgb_tactic.json")
    print(f"  - scaler.pkl")
    print(f"  - label_encoders.pkl")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train UEBA ML models")
    parser.add_argument("--from-file", type=str, default=None,
                        help="Path to labeled data file (JSON/CSV/Parquet)")
    parser.add_argument("--epochs", type=int, default=50,
                        help="Training epochs (default: 50)")
    parser.add_argument("--lr", type=float, default=0.001,
                        help="Learning rate (default: 0.001)")
    parser.add_argument("--batch-size", type=int, default=256,
                        help="Batch size (default: 256)")
    parser.add_argument("--label-col", type=str, default="attack_type",
                        help="Label column name (default: attack_type)")
    parser.add_argument("--tactic-col", type=str, default="tactic",
                        help="Tactic column name (default: tactic)")

    args = parser.parse_args()

    if args.from_file:
        train_from_file(args.from_file, args.epochs, args.lr,
                         args.batch_size, args.label_col, args.tactic_col)
    else:
        train_synthetic(args.epochs, args.lr, args.batch_size)
