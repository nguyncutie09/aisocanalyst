#!/usr/bin/env python3
"""
UEBA Demo Script - End-to-end pipeline test.
Demonstrates full system: data generation → training → analysis → alerting.

Usage:
    python scripts/demo.py                    # Quick demo (500 events, 10 epochs)
    python scripts/demo.py --full             # Full demo (5000 events, 50 epochs)
    python scripts/demo.py --api              # Test against running API
"""

import os
import sys
import time
import json
import argparse
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import settings
from app.pipeline.ingestion import SyntheticLogGenerator
from app.pipeline.normalizer import LogNormalizer
from app.models.anomaly import AnomalyDetector
from app.models.classifier import AttackClassifier
from app.models.risk_scorer import RiskScorer


def run_demo(n_normal: int = 2000, n_attack: int = 200, epochs: int = 10):
    """Run end-to-end UEBA demo."""
    print("=" * 70)
    print("  UEBA - End-to-End Demo")
    print("  User & Entity Behavior Analytics System v2.0")
    print("=" * 70)

    os.makedirs(settings.MODEL_DIR, exist_ok=True)

    # ─── Step 1: Generate Data ───
    print("\n[1/6] Generating synthetic security logs...")
    generator = SyntheticLogGenerator()
    df = generator.generate_attack_scenarios(
        n_normal=n_normal, n_attack=n_attack, seed=42
    )
    normal_count = (~df["is_anomaly"]).sum()
    attack_count = df["is_anomaly"].sum()
    print(f"  ✓ {len(df)} events generated"
          f" ({normal_count} normal, {attack_count} attacks)")

    # ─── Step 2: Feature Extraction ───
    print("\n[2/6] Extracting features...")
    normalizer = LogNormalizer()
    feature_df = normalizer.extract_features(df, fit=True)
    X = feature_df.values.astype(np.float32)
    print(f"  ✓ {X.shape[1]} features extracted from {X.shape[0]} samples")
    print(f"  Features: {list(feature_df.columns)}")

    # ─── Step 3: Train Anomaly Detector ───
    print("\n[3/6] Training Anomaly Detector ensemble...")
    start = time.time()
    detector = AnomalyDetector()
    normal_mask = df["attack_type"] == "normal"
    detector.fit(
        X[normal_mask],
        fit_iso_forest=True,
        fit_deep_if=True,
        fit_autoencoder=True,
        epochs=epochs,
        batch_size=256,
        lr=0.001,
        verbose=True,
    )
    print(f"  ✓ Anomaly Detector trained in {time.time()-start:.1f}s")

    # ─── Step 4: Train Classifier ───
    print("\n[4/6] Training Attack Classifier (XGBoost)...")
    start = time.time()
    classifier = AttackClassifier()
    classifier.fit(
        X, df["attack_type"].values, df["tactic"].values,
        feature_names=list(feature_df.columns),
        verbose=True,
    )
    print(f"  ✓ Classifier trained in {time.time()-start:.1f}s")

    # ─── Step 5: Evaluate ───
    print("\n[5/6] Evaluating system performance...")
    risk_scorer = RiskScorer()

    # Anomaly detection
    scores_dict = detector.predict(X)
    ensemble_scores = detector.predict_ensemble(X)
    y_true = df["is_anomaly"].astype(int).values

    from sklearn.metrics import (roc_auc_score, average_precision_score,
                                  confusion_matrix, classification_report)
    auc = roc_auc_score(y_true, ensemble_scores)
    ap = average_precision_score(y_true, ensemble_scores)
    print(f"  • Anomaly Detection:")
    print(f"    - ROC-AUC:  {auc:.4f}")
    print(f"    - Avg Prec: {ap:.4f}")

    # Classification
    pred_result = classifier.predict(X)
    pred_attacks = np.array(pred_result["attack_type"])
    true_attacks = df["attack_type"].values
    acc = np.mean(pred_attacks == true_attacks)
    print(f"  • Attack Classification:")
    print(f"    - Accuracy: {acc:.4f} ({acc*100:.1f}%)")
    print(f"    - Classes:  {classifier.label_encoder.classes_}")

    # ─── Step 6: Risk Scoring Demo ───
    print("\n[6/6] Risk scoring demonstration...")
    print(f"\n  {'Event':<20} {'Attack Type':<20} {'Risk Score':<10} {'Level':<10}")
    print(f"  {'-'*20} {'-'*20} {'-'*10} {'-'*10}")

    # Score a few example events
    example_indices = []
    for atype in ["brute_force", "lateral_movement", "data_exfiltration",
                   "normal", "reconnaissance", "privilege_escalation"]:
        idx = df[df["attack_type"] == atype].index[:2].tolist()
        example_indices.extend(idx)

    for idx in example_indices[:12]:
        row = df.loc[idx]
        features = X[idx:idx+1]

        # Get scores
        anom_scores = detector.predict(features)
        anom_prob = float(np.mean(list(anom_scores.values())))

        try:
            cls = classifier.predict(features)
            attack_type = cls["attack_type"][0]
            confidence = cls["attack_confidence"][0]
            tactic = cls["tactic"][0]
        except Exception:
            attack_type = "normal"
            confidence = 0.5
            tactic = "TA0000_Benign"

        risk = risk_scorer.compute(
            anomaly_prob=anom_prob,
            attack_type=attack_type,
            tactic=tactic,
            confidence=confidence,
            user_role=row.get("user_role", "user"),
            asset_type=row.get("asset_type", "unknown"),
            hour_of_day=int(row.get("hour_of_day", 12)),
            is_weekend=bool(row.get("is_weekend", False)),
            failed_logins_1h=int(row.get("failed_attempts_last_1h", 0)),
        )

        print(f"  {row.get('event_type', '?'):<20} {attack_type:<20} "
              f"{risk.score:<10.1f} {risk.level:<10}")

    print(f"\n{'='*70}")
    print(f"  Demo Complete! System ready for deployment.")
    print(f"  Start server: uvicorn app.main:app --host 0.0.0.0 --port 8000")
    print(f"  API Docs:    http://localhost:8000/docs")
    print(f"  Dashboard:   http://localhost:8000/dashboard")
    print(f"{'='*70}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="UEBA Demo Script")
    parser.add_argument("--full", action="store_true",
                        help="Full demo with more data and epochs")
    parser.add_argument("--epochs", type=int, default=None,
                        help="Training epochs (default: 10 quick, 50 full)")
    parser.add_argument("--events", type=int, default=None,
                        help="Number of events (default: 2200 quick, 5500 full)")

    args = parser.parse_args()

    if args.full:
        n_events = args.events or 5000
        n_attacks = int(n_events * 0.1)
        n_epochs = args.epochs or 50
    else:
        n_events = args.events or 2200
        n_attacks = int(n_events * 0.09)
        n_epochs = args.epochs or 10

    run_demo(n_normal=n_events - n_attacks, n_attack=n_attacks,
              epochs=n_epochs)
