"""
Attack Classification Model using XGBoost.
Classifies detected anomalies into specific attack categories
mapped to MITRE ATT&CK techniques.

Uses XGBoost with:
  - Multi-output classification for attack + tactic prediction
  - Calibrated probabilities for confidence scoring
  - Feature importance for explainability
"""

import os
import json
import warnings
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from typing import Optional, List, Dict, Tuple
import joblib

warnings.filterwarnings("ignore")

# ─── MITRE ATT&CK Attack Taxonomy ───
ATTACK_CLASSES = [
    "brute_force",          # T1110
    "credential_dumping",   # T1003
    "phishing",             # T1566
    "reconnaissance",       # T1595
    "lateral_movement",     # T1021
    "data_exfiltration",    # T1048
    "privilege_escalation", # T1068
    "persistence",          # T1098
    "defense_evasion",      # T1562
    "command_and_control",  # T1071
    "normal",               # Benign
]

TACTIC_CLASSES = [
    "TA0001_Initial_Access",
    "TA0002_Execution",
    "TA0003_Persistence",
    "TA0004_Privilege_Escalation",
    "TA0005_Defense_Evasion",
    "TA0006_Credential_Access",
    "TA0007_Discovery",
    "TA0008_Lateral_Movement",
    "TA0009_Collection",
    "TA0010_Exfiltration",
    "TA0011_Command_and_Control",
    "TA0040_Impact",
    "TA0000_Benign",
]


class AttackClassifier:
    """
    XGBoost-based multi-class classifier for attack type and tactic prediction.
    Also provides calibrated confidence scores and feature importance.
    """

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.model: Optional[xgb.XGBClassifier] = None
        self.tactic_model: Optional[xgb.XGBClassifier] = None
        self.label_encoder = LabelEncoder()
        self.tactic_encoder = LabelEncoder()
        self.scaler = StandardScaler()
        self.feature_names: List[str] = []
        self.is_fitted = False

    def _build_model(self, objective: str = "multi:softprob") -> xgb.XGBClassifier:
        return xgb.XGBClassifier(
            n_estimators=self.config.get("n_estimators", 300),
            max_depth=self.config.get("max_depth", 8),
            learning_rate=self.config.get("learning_rate", 0.05),
            subsample=self.config.get("subsample", 0.8),
            colsample_bytree=self.config.get("colsample_bytree", 0.8),
            min_child_weight=self.config.get("min_child_weight", 3),
            gamma=self.config.get("gamma", 0.1),
            reg_lambda=self.config.get("reg_lambda", 2.0),
            reg_alpha=self.config.get("reg_alpha", 0.5),
            objective=objective,
            eval_metric="mlogloss",
            use_label_encoder=False,
            verbosity=0,
            random_state=42,
            n_jobs=-1,
            early_stopping_rounds=self.config.get("early_stopping_rounds", 20),
        )

    def fit(self, X: np.ndarray, y_attack: np.ndarray, y_tactic: np.ndarray,
            feature_names: Optional[List[str]] = None,
            val_split: float = 0.2, verbose: bool = True):
        """
        Train both attack-type and tactic classifiers.

        Args:
            X: Feature matrix [n_samples, n_features]
            y_attack: Attack class labels (strings)
            y_tactic: Tactic class labels (strings)
            feature_names: Column names for explainability
        """
        self.feature_names = feature_names or [f"f{i}" for i in range(X.shape[1])]

        # Encode labels
        y_attack_enc = self.label_encoder.fit_transform(y_attack)
        y_tactic_enc = self.tactic_encoder.fit_transform(y_tactic)

        # Scale
        X_scaled = self.scaler.fit_transform(X)

        # Split
        X_train, X_val, y_train_att, y_val_att, y_train_tac, y_val_tac = \
            train_test_split(X_scaled, y_attack_enc, y_tactic_enc,
                             test_size=val_split, random_state=42,
                             stratify=y_attack_enc)

        # ─── Attack Type Classifier ───
        if verbose:
            print(f"[Classifier] Training XGBoost attack classifier "
                  f"({len(np.unique(y_attack_enc))} classes)...")
        self.model = self._build_model()
        self.model.fit(
            X_train, y_train_att,
            eval_set=[(X_val, y_val_att)],
            verbose=False,
        )
        if verbose:
            val_pred = self.model.predict(X_val)
            val_acc = np.mean(val_pred == y_val_att)
            print(f"  ✓ Attack classifier | Validation accuracy: {val_acc:.4f}")

        # ─── Tactic Classifier ───
        if verbose:
            print(f"[Classifier] Training XGBoost tactic classifier "
                  f"({len(np.unique(y_tactic_enc))} classes)...")
        self.tactic_model = self._build_model()
        self.tactic_model.fit(
            X_train, y_train_tac,
            eval_set=[(X_val, y_val_tac)],
            verbose=False,
        )
        if verbose:
            val_pred_t = self.tactic_model.predict(X_val)
            val_acc_t = np.mean(val_pred_t == y_val_tac)
            print(f"  ✓ Tactic classifier | Validation accuracy: {val_acc_t:.4f}")

        self.is_fitted = True
        return self

    def predict(self, X: np.ndarray) -> Dict:
        """
        Predict attack type, tactic, and confidences for samples.

        Returns:
            dict with keys: attack_type, attack_confidence, tactic, tactic_confidence
        """
        if not self.is_fitted:
            raise RuntimeError("Model not fitted. Call fit() first.")

        X_scaled = self.scaler.transform(X)

        # Attack predictions
        att_proba = self.model.predict_proba(X_scaled)
        att_idx = np.argmax(att_proba, axis=1)
        att_conf = np.max(att_proba, axis=1)
        attack_types = self.label_encoder.inverse_transform(att_idx)

        # Tactic predictions
        tac_proba = self.tactic_model.predict_proba(X_scaled)
        tac_idx = np.argmax(tac_proba, axis=1)
        tac_conf = np.max(tac_proba, axis=1)
        tactic_types = self.tactic_encoder.inverse_transform(tac_idx)

        return {
            "attack_type": attack_types.tolist(),
            "attack_confidence": att_conf.tolist(),
            "tactic": tactic_types.tolist(),
            "tactic_confidence": tac_conf.tolist(),
        }

    def predict_proba_attack(self, X: np.ndarray) -> np.ndarray:
        """Return full probability matrix for attack classes."""
        X_scaled = self.scaler.transform(X)
        return self.model.predict_proba(X_scaled)

    def feature_importance(self, top_n: int = 20) -> Dict[str, float]:
        """Return feature importance scores."""
        if self.model is None:
            return {}
        importance = self.model.feature_importances_
        if self.feature_names:
            idx = np.argsort(importance)[::-1][:top_n]
            return {self.feature_names[i]: float(importance[i]) for i in idx}
        return {f"f{i}": float(v) for i, v in enumerate(importance)}

    def save(self, model_dir: str):
        """Save models to disk."""
        os.makedirs(model_dir, exist_ok=True)
        if self.model:
            self.model.save_model(os.path.join(model_dir, "xgb_attack.json"))
        if self.tactic_model:
            self.tactic_model.save_model(os.path.join(model_dir, "xgb_tactic.json"))
        joblib.dump(self.label_encoder, os.path.join(model_dir, "label_encoder.pkl"))
        joblib.dump(self.tactic_encoder, os.path.join(model_dir, "tactic_encoder.pkl"))
        joblib.dump(self.scaler, os.path.join(model_dir, "classifier_scaler.pkl"))
        joblib.dump(self.feature_names, os.path.join(model_dir, "feature_names.pkl"))
        print(f"✓ Classifier saved to {model_dir}")

    def load(self, model_dir: str):
        """Load models from disk."""
        att_path = os.path.join(model_dir, "xgb_attack.json")
        if os.path.exists(att_path):
            self.model = xgb.XGBClassifier()
            self.model.load_model(att_path)

        tac_path = os.path.join(model_dir, "xgb_tactic.json")
        if os.path.exists(tac_path):
            self.tactic_model = xgb.XGBClassifier()
            self.tactic_model.load_model(tac_path)

        le_path = os.path.join(model_dir, "label_encoder.pkl")
        if os.path.exists(le_path):
            self.label_encoder = joblib.load(le_path)
        te_path = os.path.join(model_dir, "tactic_encoder.pkl")
        if os.path.exists(te_path):
            self.tactic_encoder = joblib.load(te_path)
        sc_path = os.path.join(model_dir, "classifier_scaler.pkl")
        if os.path.exists(sc_path):
            self.scaler = joblib.load(sc_path)
        fn_path = os.path.join(model_dir, "feature_names.pkl")
        if os.path.exists(fn_path):
            self.feature_names = joblib.load(fn_path)

        self.is_fitted = self.model is not None
        print(f"✓ Classifier loaded from {model_dir}")
        return self
