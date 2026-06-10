#!/usr/bin/env python3
"""
Tests for the UEBA pipeline.
Tests data generation, normalization, model training, and risk scoring.
"""

import os
import sys
import unittest
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.pipeline.ingestion import SyntheticLogGenerator, LogIngestor
from app.pipeline.normalizer import LogNormalizer
from app.models.anomaly import AnomalyDetector
from app.models.classifier import AttackClassifier
from app.models.risk_scorer import RiskScorer


class TestLogGeneration(unittest.TestCase):
    """Test synthetic log generation."""

    def setUp(self):
        self.generator = SyntheticLogGenerator()

    def test_normal_generation(self):
        df = self.generator.generate_normal(n_events=100)
        self.assertEqual(len(df), 100)
        self.assertIn("event_type", df.columns)
        self.assertIn("user_name", df.columns)
        self.assertIn("timestamp", df.columns)

    def test_attack_generation(self):
        df = self.generator.generate_attack_scenarios(n_normal=200, n_attack=50)
        self.assertGreater(len(df), 200)
        self.assertIn("is_anomaly", df.columns)
        self.assertIn("attack_type", df.columns)
        self.assertIn("tactic", df.columns)
        # At least some attacks
        self.assertGreater(df["is_anomaly"].sum(), 0)


class TestNormalizer(unittest.TestCase):
    """Test feature extraction and normalization."""

    def setUp(self):
        self.normalizer = LogNormalizer()
        self.generator = SyntheticLogGenerator()
        self.df = self.generator.generate_attack_scenarios(n_normal=100, n_attack=20)

    def test_feature_extraction(self):
        features = self.normalizer.extract_features(self.df, fit=True)
        self.assertGreater(features.shape[1], 5)
        self.assertEqual(features.shape[0], len(self.df))
        # All columns should be numeric
        for col in features.columns:
            self.assertTrue(np.issubdtype(features[col].dtype, np.number),
                            f"Column {col} is not numeric")

    def test_normalization(self):
        norm = self.normalizer.normalize(self.df)
        self.assertIn("@timestamp", norm.columns)
        self.assertIn("user.name", norm.columns)
        self.assertIn("event.action", norm.columns)


class TestAnomalyDetector(unittest.TestCase):
    """Test anomaly detection models."""

    def setUp(self):
        self.generator = SyntheticLogGenerator()
        self.normalizer = LogNormalizer()
        self.df = self.generator.generate_attack_scenarios(n_normal=200, n_attack=30)
        self.features = self.normalizer.extract_features(self.df, fit=True)
        self.X = self.features.values.astype(np.float32)
        self.detector = AnomalyDetector()

    def test_training_and_prediction(self):
        normal_mask = self.df["attack_type"] == "normal"
        self.detector.fit(
            self.X[normal_mask],
            fit_iso_forest=True,
            fit_deep_if=False,
            fit_autoencoder=False,
            epochs=5,
            batch_size=64,
            verbose=False,
        )
        scores = self.detector.predict(self.X)
        self.assertIn("isolation_forest", scores)
        self.assertEqual(len(scores["isolation_forest"]), len(self.X))

    def test_ensemble(self):
        normal_mask = self.df["attack_type"] == "normal"
        self.detector.fit(
            self.X[normal_mask],
            fit_iso_forest=True,
            fit_deep_if=False,
            fit_autoencoder=False,
            epochs=5,
            batch_size=64,
            verbose=False,
        )
        ensemble = self.detector.predict_ensemble(self.X)
        self.assertEqual(len(ensemble), len(self.X))
        self.assertTrue(np.all(ensemble >= 0))
        self.assertTrue(np.all(ensemble <= 1))


class TestClassifier(unittest.TestCase):
    """Test attack classification."""

    def setUp(self):
        self.generator = SyntheticLogGenerator()
        self.normalizer = LogNormalizer()
        self.df = self.generator.generate_attack_scenarios(n_normal=300, n_attack=50)
        self.features = self.normalizer.extract_features(self.df, fit=True)
        self.X = self.features.values.astype(np.float32)

    def test_classification(self):
        classifier = AttackClassifier()
        classifier.fit(
            self.X, self.df["attack_type"].values, self.df["tactic"].values,
            verbose=False,
        )
        result = classifier.predict(self.X)
        self.assertIn("attack_type", result)
        self.assertIn("attack_confidence", result)
        self.assertIn("tactic", result)
        self.assertEqual(len(result["attack_type"]), len(self.X))
        self.assertGreater(result["attack_confidence"][0], 0)


class TestRiskScorer(unittest.TestCase):
    """Test risk scoring engine."""

    def setUp(self):
        self.scorer = RiskScorer()

    def test_normal_event(self):
        risk = self.scorer.compute(
            anomaly_prob=0.05,
            attack_type="normal",
            tactic="TA0000_Benign",
            confidence=0.9,
            user_role="user",
            hour_of_day=14,
        )
        self.assertLess(risk.score, 20)
        self.assertEqual(risk.level, "info")

    def test_critical_event(self):
        risk = self.scorer.compute(
            anomaly_prob=0.95,
            attack_type="credential_dumping",
            tactic="TA0006_Credential_Access",
            confidence=0.95,
            user_role="admin",
            hour_of_day=3,
            is_weekend=True,
            failed_logins_1h=50,
        )
        self.assertGreaterEqual(risk.score, 85)
        self.assertEqual(risk.level, "critical")
        self.assertGreater(len(risk.risk_factors), 0)
        self.assertGreater(len(risk.recommendations), 0)

    def test_high_event(self):
        risk = self.scorer.compute(
            anomaly_prob=0.7,
            attack_type="brute_force",
            tactic="TA0006_Credential_Access",
            confidence=0.8,
            user_role="admin",
            hour_of_day=22,
            failed_logins_1h=15,
        )
        self.assertGreaterEqual(risk.score, 40)
        self.assertIn(risk.level, ["high", "medium", "critical"])

    def test_aggregate(self):
        results = [
            self.scorer.compute(0.05, "normal", "TA0000_Benign", 0.9),
            self.scorer.compute(0.95, "brute_force", "TA0006", 0.95),
            self.scorer.compute(0.5, "reconnaissance", "TA0007", 0.7),
        ]
        agg = RiskScorer.aggregate_scores(results)
        self.assertIn("avg", agg)
        self.assertIn("max", agg)
        self.assertIn("critical", agg)
        self.assertIn("high", agg)


if __name__ == "__main__":
    unittest.main(verbosity=2)
