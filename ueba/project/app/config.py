"""System configuration using pydantic-settings."""

from pydantic_settings import BaseSettings
from typing import List, Optional
import os


class Settings(BaseSettings):
    # ─── App ───
    APP_NAME: str = "UEBA - User & Entity Behavior Analytics"
    APP_VERSION: str = "2.0.0"
    DEBUG: bool = False

    # ─── Paths ───
    BASE_DIR: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    DATA_DIR: str = os.path.join(BASE_DIR, "data")
    MODEL_DIR: str = os.path.join(DATA_DIR, "models")
    RAW_LOG_DIR: str = os.path.join(DATA_DIR, "raw")
    PROCESSED_DIR: str = os.path.join(DATA_DIR, "processed")

    # ─── Server ───
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # ─── ML Model paths ───
    ISOLATION_FOREST_PATH: str = os.path.join(MODEL_DIR, "isolation_forest.pkl")
    AUTOENCODER_PATH: str = os.path.join(MODEL_DIR, "autoencoder.pt")
    TRANSFORMER_PATH: str = os.path.join(MODEL_DIR, "transformer_seq.pt")
    XGBOOST_PATH: str = os.path.join(MODEL_DIR, "xgb_classifier.json")
    SCALER_PATH: str = os.path.join(MODEL_DIR, "scaler.pkl")
    FEATURES_PATH: str = os.path.join(MODEL_DIR, "feature_columns.pkl")

    # ─── Anomaly thresholds ───
    ANOMALY_THRESHOLD: float = 0.7       # Isolation Forest anomaly probability
    RISK_CRITICAL_THRESHOLD: float = 85.0
    RISK_HIGH_THRESHOLD: float = 65.0
    RISK_MEDIUM_THRESHOLD: float = 40.0
    RISK_LOW_THRESHOLD: float = 20.0

    # ─── Timeseries ───
    SEQUENCE_LENGTH: int = 10            # steps for Transformer/LSTM
    BASELINE_DAYS: int = 14              # days to learn normal behavior

    # ─── Alerting ───
    ALERT_ENABLED: bool = True
    ALERT_COOLDOWN_SECONDS: int = 300    # don't re-alert same entity

    # ─── Feature engineering ───
    CATEGORICAL_FEATURES: List[str] = [
        "event_code", "source_ip", "dest_ip", "user_name",
        "auth_type", "device_type", "geo_city", "geo_country"
    ]
    NUMERICAL_FEATURES: List[str] = [
        "hour_of_day", "day_of_week", "session_duration_sec",
        "bytes_transferred", "failed_attempts_last_1h",
        "unique_dest_ips_last_1h", "login_frequency_last_1h"
    ]

    # ─── MITRE ATT&CK ───
    MITRE_TACTICS_MAPPING: dict = {
        "TA0001": "Initial Access",
        "TA0002": "Execution",
        "TA0003": "Persistence",
        "TA0004": "Privilege Escalation",
        "TA0005": "Defense Evasion",
        "TA0006": "Credential Access",
        "TA0007": "Discovery",
        "TA0008": "Lateral Movement",
        "TA0009": "Collection",
        "TA0011": "Command and Control",
        "TA0010": "Exfiltration",
        "TA0040": "Impact",
    }

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
