"""
SOCal SIEM - ML-based Anomaly Detection Engine
Ensemble of Isolation Forest + optional AutoEncoder
On-device training, no data leaves the machine
"""

import logging
import numpy as np
from collections import deque
from typing import List, Optional, Tuple

logger = logging.getLogger('socal.detection.ml')

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn not available - ML detection disabled")
    IsolationForest = None
    StandardScaler = None


class MLDetectionEngine:
    """
    Ensemble ML detection engine.
    Primary: Isolation Forest for real-time anomaly scoring
    Optional: AutoEncoder (if PyTorch available) for deep pattern detection
    """

    def __init__(self, contamination: float = 0.05, buffer_size: int = 10000):
        self.contamination = contamination
        self.buffer_size = buffer_size
        self.training_buffer = deque(maxlen=buffer_size)
        self.feature_names: Optional[List[str]] = None
        self.is_trained = False
        self.sample_count = 0

        # Models
        if SKLEARN_AVAILABLE:
            self.scaler = StandardScaler()
            self.iso_forest = IsolationForest(
                contamination=contamination,
                random_state=42,
                n_estimators=200,
                max_samples='auto',
                n_jobs=-1,
            )
        else:
            self.scaler = None
            self.iso_forest = None

        # AutoEncoder (lazy import torch)
        self.autoencoder = None

    def add_sample(self, features: np.ndarray, feature_names: List[str]):
        """Add a feature vector to the training buffer"""
        self.training_buffer.append(features)
        self.feature_names = feature_names
        self.sample_count += 1

    def train(self, force: bool = False) -> bool:
        """
        Train models. Auto-trains when buffer >= 1000 samples.
        Returns True if training occurred.
        """
        if not SKLEARN_AVAILABLE:
            return False

        if len(self.training_buffer) < max(100, self.buffer_size * 0.1) and not force:
            return False

        if self.is_trained and not force:
            return False

        try:
            X = np.array(list(self.training_buffer))
            X = np.nan_to_num(X, nan=0.0, posinf=1.0, neginf=-1.0)

            if X.shape[0] < 10 or X.shape[1] < 1:
                logger.warning("Not enough samples for training")
                return False

            X_scaled = self.scaler.fit_transform(X)
            self.iso_forest.fit(X_scaled)
            self.is_trained = True
            logger.info(f"ML model trained on {X.shape[0]} samples, {X.shape[1]} features")
            return True

        except Exception as e:
            logger.error(f"ML training failed: {e}")
            return False

    def predict(self, features: np.ndarray) -> dict:
        """
        Predict anomaly for a feature vector.
        Returns dict with anomaly score and explanations.
        """
        result = {
            'is_anomaly': False,
            'anomaly_score': 0.0,
            'raw_score': 0.0,
            'confidence': 0.0,
            'contributing_features': [],
        }

        if not self.is_trained or not SKLEARN_AVAILABLE:
            return result

        try:
            features = np.nan_to_num(features, nan=0.0, posinf=1.0, negfin=-1.0)
            X_scaled = self.scaler.transform([features])

            # Isolation Forest scores (lower = more anomalous)
            raw_score = self.iso_forest.decision_function(X_scaled)[0]
            prediction = self.iso_forest.predict(X_scaled)[0]

            # Convert to anomaly score 0-1 (higher = more anomalous)
            # Typical raw scores: ~0.5 for normal, ~-0.5 for anomalies
            anomaly_score = max(0.0, min(1.0, (0.5 - raw_score) / 0.5))
            confidence = max(0.0, min(1.0, abs(raw_score) * 2.0))

            result = {
                'is_anomaly': bool(prediction == -1),
                'anomaly_score': float(anomaly_score),
                'raw_score': float(raw_score),
                'confidence': float(confidence),
                'contributing_features': self._explain_anomaly(features),
            }

        except Exception as e:
            logger.error(f"ML prediction error: {e}")

        return result

    def _explain_anomaly(self, features: np.ndarray) -> List[dict]:
        """Identify top contributing features to anomaly score"""
        if self.feature_names is None or len(self.training_buffer) < 10:
            return []

        try:
            X = np.array(list(self.training_buffer))
            means = X.mean(axis=0)
            stds = X.std(axis=0) + 1e-8
            z_scores = np.abs((features - means) / stds)

            # Top 3 most anomalous features
            top_indices = np.argsort(z_scores)[-3:][::-1]
            explanations = []
            for idx in top_indices:
                if z_scores[idx] > 1.5 and idx < len(self.feature_names):
                    explanations.append({
                        'feature': self.feature_names[idx],
                        'value': float(features[idx]),
                        'mean': float(means[idx]),
                        'std_dev': float(stds[idx]),
                        'z_score': float(z_scores[idx]),
                    })
            return explanations

        except Exception as e:
            logger.debug(f"Explain anomaly error: {e}")
            return []

    def get_model_info(self) -> dict:
        """Get model state info for dashboard"""
        return {
            'is_trained': self.is_trained,
            'samples_trained': len(self.training_buffer),
            'contamination': self.contamination,
            'features': self.feature_names or [],
        }
