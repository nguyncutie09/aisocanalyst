"""
Data Normalization Pipeline.
Converts raw security logs to standardized format (ECS-compatible).
Handles feature engineering for ML models.
"""

import pandas as pd
import numpy as np
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from sklearn.preprocessing import LabelEncoder
import joblib
import os
import json


class LogNormalizer:
    """
    Normalizes raw security logs into ML-ready feature vectors.

    Implements:
    - ECS (Elastic Common Schema) field mapping
    - Categorical encoding
    - Numerical feature engineering
    - Temporal feature extraction
    - Rolling window statistics
    """

    # Target schema mapping
    ECS_FIELD_MAP = {
        "timestamp": "@timestamp",
        "event_type": "event.action",
        "event_code": "event.code",
        "user_name": "user.name",
        "source_ip": "source.ip",
        "dest_ip": "destination.ip",
        "auth_type": "authentication.type",
        "device_type": "observer.type",
        "user_role": "user.roles",
        "asset_type": "observer.product",
        "geo_city": "source.geo.city_name",
        "geo_country": "source.geo.country_iso_code",
        "hour_of_day": "event.hour_of_day",
        "day_of_week": "event.day_of_week",
        "session_duration_sec": "event.duration",
        "bytes_transferred": "network.bytes",
        "failed_attempts_last_1h": "event.failed_attempts_1h",
        "unique_dest_ips_last_1h": "event.unique_dest_ips_1h",
        "login_frequency_last_1h": "event.login_freq_1h",
        "is_anomaly": "event.is_anomaly",
        "attack_type": "threat.technique.name",
        "tactic": "threat.tactic.id",
    }

    def __init__(self):
        self.label_encoders: Dict[str, LabelEncoder] = {}
        self.fitted = False

    def normalize(self, df: pd.DataFrame,
                  fit: bool = False) -> pd.DataFrame:
        """
        Normalize raw DataFrame to ECS-compatible schema.

        Args:
            df: Raw input DataFrame
            fit: If True, fit label encoders

        Returns:
            Normalized DataFrame
        """
        if df.empty:
            return df

        norm_df = pd.DataFrame()

        # Map known fields
        for src_col, target_col in self.ECS_FIELD_MAP.items():
            if src_col in df.columns:
                norm_df[target_col] = df[src_col]

        # Ensure timestamp parsing
        ts_cols = [c for c in df.columns if 'time' in c.lower() and c in df.columns]
        if ts_cols and "@timestamp" not in norm_df:
            norm_df["@timestamp"] = pd.to_datetime(df[ts_cols[0]],
                                                     errors="coerce")

        if "@timestamp" in norm_df.columns:
            norm_df["@timestamp"] = pd.to_datetime(norm_df["@timestamp"],
                                                     errors="coerce")

        # Add metadata
        norm_df["event.kind"] = "event"
        norm_df["event.category"] = norm_df.get("event.action", "unknown")
        norm_df["event.severity"] = 0
        norm_df["tags"] = "ueba"

        return norm_df

    def extract_features(self, df: pd.DataFrame,
                         fit: bool = False,
                         feature_cols: Optional[List[str]] = None,
                         cat_cols: Optional[List[str]] = None,
                         num_cols: Optional[List[str]] = None) -> pd.DataFrame:
        """
        Extract ML-ready feature matrix from raw DataFrame.

        Args:
            df: Raw DataFrame
            fit: Fit label encoders if True
            feature_cols: All feature columns to use
            cat_cols: Categorical columns
            num_cols: Numerical columns

        Returns:
            Feature DataFrame (all numerical)
        """
        if feature_cols is None:
            feature_cols = [
                "event_code", "hour_of_day", "day_of_week",
                "session_duration_sec", "bytes_transferred",
                "failed_attempts_last_1h", "unique_dest_ips_last_1h",
                "login_frequency_last_1h", "is_weekend",
            ]
        if cat_cols is None:
            cat_cols = ["user_name", "source_ip", "dest_ip",
                         "auth_type", "device_type",
                         "user_role", "asset_type",
                         "geo_city", "geo_country"]
        if num_cols is None:
            num_cols = [c for c in feature_cols if c not in cat_cols and c != "is_weekend"]

        # Select available columns
        available_cols = [c for c in feature_cols if c in df.columns]
        cat_avail = [c for c in cat_cols if c in df.columns]
        num_avail = [c for c in num_cols if c in df.columns]

        result = pd.DataFrame(index=df.index)

        # Numerical features - fill NaN
        for col in num_avail:
            result[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

        # Weekend flag
        if "is_weekend" in df.columns:
            result["is_weekend"] = df["is_weekend"].astype(int)
        elif "day_of_week" in df.columns:
            result["is_weekend"] = (df["day_of_week"] >= 5).astype(int)
        else:
            result["is_weekend"] = 0

        # Categorical encoding
        for col in cat_avail:
            if fit:
                self.label_encoders[col] = LabelEncoder()
                df[col] = df[col].astype(str).fillna("unknown")
                encoded = self.label_encoders[col].fit_transform(df[col])
                result[f"{col}_enc"] = encoded
            elif col in self.label_encoders:
                df[col] = df[col].astype(str).fillna("unknown")
                # Handle unseen categories
                known = set(self.label_encoders[col].classes_)
                df[col] = df[col].apply(
                    lambda x: x if x in known else "unknown")
                if "unknown" not in self.label_encoders[col].classes_:
                    self.label_encoders[col].classes_ = (
                        list(self.label_encoders[col].classes_) + ["unknown"])
                encoded = self.label_encoders[col].transform(df[col])
                result[f"{col}_enc"] = encoded

        if fit:
            self.fitted = True

        return result

    def compute_rolling_features(self, df: pd.DataFrame,
                                  time_col: str = "timestamp",
                                  user_col: str = "user_name",
                                  windows_minutes: List[int] = None) -> pd.DataFrame:
        """
        Compute rolling window statistics per user/entity.

        Features:
        - login_frequency_last_{w}h
        - failed_attempts_last_{w}h
        - unique_dest_ips_last_{w}h
        - bytes_transferred_last_{w}h
        """
        if windows_minutes is None:
            windows_minutes = [60, 1440]  # 1h, 24h

        df = df.copy()
        if time_col not in df.columns:
            return df
        if user_col not in df.columns:
            return df

        df[time_col] = pd.to_datetime(df[time_col], errors="coerce")
        df = df.sort_values([user_col, time_col])

        # Rolling features per user
        for window in windows_minutes:
            label = f"{window // 60}h" if window >= 60 else f"{window}min"
            delta = pd.Timedelta(minutes=window)

            def count_in_window(group, col, condition=None):
                if condition:
                    return group.rolling(delta, on=time_col)[col].apply(
                        lambda x: condition(x).sum())
                return group.rolling(delta, on=time_col)[col].count()

            # Count events in window
            if "event_code" in df.columns:
                df[f"event_count_last_{label}"] = (
                    df.groupby(user_col)
                    .apply(lambda g: count_in_window(g, "event_code"))
                    .reset_index(level=0, drop=True)
                )

        return df

    def save_encoders(self, path: str):
        """Save fitted label encoders."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump(self.label_encoders, path)

    def load_encoders(self, path: str):
        """Load label encoders."""
        self.label_encoders = joblib.load(path)
        self.fitted = True
