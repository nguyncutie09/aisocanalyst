"""
Data Ingestion Pipeline.
Reads raw security logs from various sources (file, HTTP, syslog),
parses them, and feeds into the normalization pipeline.

Supports:
  - JSON/CSV/Parquet file ingestion
  - Live HTTP endpoint ingestion
  - Directory watching for new log files
  - Kafka integration (optional)
"""

import os
import json
import csv
import glob
import time
import uuid
from typing import List, Dict, Optional, Generator, Any
from datetime import datetime
from pathlib import Path
import pandas as pd
import numpy as np


class LogIngestor:
    """
    Flexible log ingestor supporting multiple source types and formats.
    """

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}

    def ingest_file(self, filepath: str, format: str = "auto") -> pd.DataFrame:
        """
        Read logs from a single file.

        Args:
            filepath: Path to log file
            format: 'json', 'jsonl', 'csv', 'parquet', or 'auto'

        Returns:
            DataFrame with parsed logs
        """
        if format == "auto":
            ext = Path(filepath).suffix.lower()
            format = {"json": "json", "jsonl": "jsonl",
                       "csv": "csv", "parquet": "parquet",
                       "log": "jsonl"}.get(ext, "jsonl")

        if format == "csv":
            df = pd.read_csv(filepath)
        elif format == "parquet":
            df = pd.read_parquet(filepath)
        elif format in ("json", "jsonl"):
            lines = []
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        lines.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
            if not lines:
                # Try as single JSON array
                with open(filepath, "r") as f:
                    try:
                        data = json.load(f)
                        if isinstance(data, list):
                            lines = data
                    except json.JSONDecodeError:
                        pass
            df = pd.DataFrame(lines) if lines else pd.DataFrame()
        else:
            raise ValueError(f"Unsupported format: {format}")

        # Add ingestion metadata
        if not df.empty:
            df["_ingest_ts"] = datetime.utcnow().isoformat()
            df["_source_file"] = os.path.basename(filepath)
            df["_event_id"] = [str(uuid.uuid4()) for _ in range(len(df))]

        return df

    def ingest_directory(self, dirpath: str, pattern: str = "*.*",
                         recursive: bool = True) -> pd.DataFrame:
        """
        Ingest all log files from a directory.

        Args:
            dirpath: Directory path
            pattern: Glob pattern for file matching
            recursive: Search subdirectories

        Returns:
            Combined DataFrame with all logs
        """
        path = Path(dirpath) / ("**/" if recursive else "") / pattern
        files = glob.glob(str(path), recursive=recursive)
        frames = []
        for fpath in sorted(files):
            if os.path.isfile(fpath):
                try:
                    df = self.ingest_file(fpath)
                    if not df.empty:
                        frames.append(df)
                except Exception as e:
                    print(f"  ⚠ Skip {fpath}: {e}")
        if not frames:
            return pd.DataFrame()
        return pd.concat(frames, ignore_index=True)

    def ingest_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add ingestion metadata to an existing DataFrame."""
        if df.empty:
            return df
        df["_ingest_ts"] = datetime.utcnow().isoformat()
        df["_event_id"] = [str(uuid.uuid4()) for _ in range(len(df))]
        return df

    def stream_jsonl(self, filepath: str,
                     batch_size: int = 100) -> Generator[List[Dict], None, None]:
        """
        Stream JSONL file in batches for memory-efficient processing.
        Yields lists of parsed JSON objects.
        """
        batch = []
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    record["_event_id"] = str(uuid.uuid4())
                    record["_ingest_ts"] = datetime.utcnow().isoformat()
                    batch.append(record)
                    if len(batch) >= batch_size:
                        yield batch
                        batch = []
                except json.JSONDecodeError:
                    continue
        if batch:
            yield batch


# ─── Synthetic log generator for testing ───

class SyntheticLogGenerator:
    """Generate realistic security logs for testing and demo."""

    SAMPLE_USERS = [
        "alice@corp.com", "bob@corp.com", "charlie@corp.com",
        "david@corp.com", "eve@corp.com", "admin@corp.com",
        "svc_backup", "svc_monitor", "root",
    ]

    SAMPLE_IPS = [
        "10.0.0.1", "10.0.0.2", "10.0.1.10", "10.0.1.20",
        "192.168.1.100", "192.168.1.101", "172.16.0.50",
        "203.0.113.5", "198.51.100.20",
    ]

    SAMPLE_EVENTS = [
        "windows_security_4624",   # Logon success
        "windows_security_4625",   # Logon failure
        "windows_security_4648",   # Explicit credential logon
        "windows_security_4672",   # Admin logon
        "vpn_connect",             # VPN connection
        "vpn_disconnect",          # VPN disconnection
        "firewall_allow",          # Firewall allow
        "firewall_deny",           # Firewall deny
        "ssh_login",               # SSH login
        "ssh_failed",              # SSH failed login
        "process_create",          # Process creation
        "file_access",             # File access
        "dns_query",               # DNS query
        "web_request",             # Web request
    ]

    EVENT_FEATURES = {
        "windows_security_4624": {"event_code": 4624, "auth_type": "kerberos",
                                   "device_type": "windows_workstation"},
        "windows_security_4625": {"event_code": 4625, "auth_type": "kerberos",
                                   "device_type": "windows_workstation"},
        "vpn_connect": {"event_code": 2001, "auth_type": "vpn_cert",
                        "device_type": "vpn_gateway"},
        "firewall_deny": {"event_code": 5154, "auth_type": "none",
                          "device_type": "firewall"},
        "ssh_login": {"event_code": 6001, "auth_type": "ssh_key",
                      "device_type": "linux_server"},
        "ssh_failed": {"event_code": 6002, "auth_type": "password",
                       "device_type": "linux_server"},
        "process_create": {"event_code": 4688, "auth_type": "none",
                           "device_type": "endpoint"},
    }

    @staticmethod
    def _random_choice(items, rng: np.random.Generator):
        return items[rng.integers(len(items))]

    @staticmethod
    def _random_ip(rng: np.random.Generator) -> str:
        return f"{rng.integers(1, 255)}.{rng.integers(0, 255)}.{rng.integers(0, 255)}.{rng.integers(1, 255)}"

    def generate_normal(self, n_events: int = 1000,
                        seed: int = 42) -> pd.DataFrame:
        """Generate normal (benign) user behavior."""
        rng = np.random.default_rng(seed)
        records = []
        base_time = datetime(2026, 6, 1, 8, 0, 0)

        event_probs = {
            "windows_security_4624": 0.20,
            "windows_security_4625": 0.02,
            "vpn_connect": 0.05,
            "firewall_allow": 0.25,
            "ssh_login": 0.08,
            "ssh_failed": 0.01,
            "process_create": 0.15,
            "file_access": 0.12,
            "dns_query": 0.10,
            "web_request": 0.02,
        }

        events_list = list(event_probs.keys())
        probs = list(event_probs.values())

        for i in range(n_events):
            event = rng.choice(events_list, p=probs)
            user = self._random_choice(self.SAMPLE_USERS, rng)
            features = self.EVENT_FEATURES.get(event, {})

            # Business hours distribution
            hour = int(rng.normal(14, 3)) % 24  # peak around 14:00
            if hour < 7:
                hour = rng.integers(8, 18)

            timestamp = base_time + pd.Timedelta(
                minutes=i * rng.exponential(3))
            is_weekend = timestamp.weekday() >= 5

            record = {
                "_event_id": str(uuid.uuid4()),
                "timestamp": timestamp.isoformat(),
                "event_type": event,
                "event_code": features.get("event_code", 0),
                "user_name": user,
                "source_ip": self._random_choice(self.SAMPLE_IPS, rng),
                "dest_ip": self._random_choice(self.SAMPLE_IPS, rng),
                "auth_type": features.get("auth_type", "unknown"),
                "device_type": features.get("device_type", "unknown"),
                "hour_of_day": hour,
                "day_of_week": timestamp.weekday(),
                "is_weekend": is_weekend,
                "session_duration_sec": max(1, int(rng.exponential(1800))),
                "bytes_transferred": int(rng.lognormal(8, 1.5)),
                "failed_attempts_last_1h": 0,
                "unique_dest_ips_last_1h": int(rng.poisson(3)),
                "login_frequency_last_1h": int(rng.poisson(2)),
                "user_role": rng.choice(["user", "admin", "developer",
                                          "analyst"], p=[0.6, 0.1, 0.2, 0.1]),
                "asset_type": "workstation",
                "geo_city": "Singapore",
                "geo_country": "SG",
                "is_anomaly": False,
                "attack_type": "normal",
                "tactic": "TA0000_Benign",
            }
            records.append(record)

        return pd.DataFrame(records)

    def generate_attack_scenarios(self, n_normal: int = 2000,
                                   n_attack: int = 200,
                                   seed: int = 42) -> pd.DataFrame:
        """
        Generate mixed normal + attack data with labeled samples.
        Includes various attack scenarios mapped to MITRE ATT&CK.
        """
        rng = np.random.default_rng(seed)
        normal_df = self.generate_normal(n_normal, seed)

        attack_records = []
        base_time = datetime(2026, 6, 1, 0, 0, 0)

        attack_scenarios = [
            # (name, event_type, technique, tactic, modifier)
            ("brute_force", "windows_security_4625",
             "brute_force", "TA0006_Credential_Access",
             {"hour_of_day": 3, "failed_attempts_last_1h": 50,
              "source_ip": "45.33.32.156", "unique_dest_ips_last_1h": 1,
              "user_name": "admin@corp.com"}),
            ("brute_force", "ssh_failed",
             "brute_force", "TA0006_Credential_Access",
             {"hour_of_day": 2, "failed_attempts_last_1h": 100,
              "source_ip": "185.220.101.45", "unique_dest_ips_last_1h": 1,
              "user_name": "root"}),
            ("lateral_movement", "windows_security_4648",
             "lateral_movement", "TA0008_Lateral_Movement",
             {"hour_of_day": 22, "unique_dest_ips_last_1h": 12,
              "source_ip": "10.0.1.10", "user_name": "eve@corp.com"}),
            ("credential_dumping", "process_create",
             "credential_dumping", "TA0006_Credential_Access",
             {"hour_of_day": 1, "session_duration_sec": 5,
              "bytes_transferred": 50000,
              "auth_type": "none", "user_name": "eve@corp.com"}),
            ("data_exfiltration", "web_request",
             "data_exfiltration", "TA0010_Exfiltration",
             {"hour_of_day": 23, "bytes_transferred": 10_000_000,
              "dest_ip": "198.51.100.20",
              "unique_dest_ips_last_1h": 3,
              "user_name": "charlie@corp.com"}),
            ("privilege_escalation", "windows_security_4672",
             "privilege_escalation", "TA0004_Privilege_Escalation",
             {"hour_of_day": 4, "auth_type": "kerberos",
              "user_name": "david@corp.com",
              "failed_attempts_last_1h": 5}),
            ("reconnaissance", "dns_query",
             "reconnaissance", "TA0007_Discovery",
             {"hour_of_day": 3, "unique_dest_ips_last_1h": 25,
              "bytes_transferred": 200,
              "user_name": "svc_monitor"}),
            ("command_and_control", "dns_query",
             "command_and_control", "TA0011_Command_and_Control",
             {"hour_of_day": 2, "dest_ip": "185.220.101.45",
              "bytes_transferred": 500,
              "unique_dest_ips_last_1h": 15,
              "user_name": "svc_backup"}),
        ]

        for i, (name, event, attack_type, tactic, modifier) in enumerate(
                attack_scenarios):
            n_copies = rng.poisson(8) + 2
            features = self.EVENT_FEATURES.get(event, {})
            for j in range(n_copies):
                ts = base_time + pd.Timedelta(hours=i * 3 + j * 0.01)
                record = {
                    "_event_id": str(uuid.uuid4()),
                    "timestamp": ts.isoformat(),
                    "event_type": event,
                    "event_code": features.get("event_code", 0),
                    "user_name": modifier.get("user_name", "unknown"),
                    "source_ip": modifier.get("source_ip",
                                              self._random_ip(rng)),
                    "dest_ip": modifier.get("dest_ip",
                                            self._random_ip(rng)),
                    "auth_type": features.get("auth_type", "unknown"),
                    "device_type": features.get("device_type", "unknown"),
                    "hour_of_day": modifier.get("hour_of_day",
                                                 rng.integers(0, 24)),
                    "day_of_week": ts.weekday(),
                    "is_weekend": ts.weekday() >= 5,
                    "session_duration_sec": modifier.get(
                        "session_duration_sec",
                        int(rng.exponential(1800))),
                    "bytes_transferred": modifier.get(
                        "bytes_transferred",
                        int(rng.lognormal(8, 1.5))),
                    "failed_attempts_last_1h": modifier.get(
                        "failed_attempts_last_1h", 0),
                    "unique_dest_ips_last_1h": modifier.get(
                        "unique_dest_ips_last_1h", 3),
                    "login_frequency_last_1h": modifier.get(
                        "login_frequency_last_1h", 0),
                    "user_role": "user",
                    "asset_type": "server",
                    "geo_city": "Moscow" if "185." in str(modifier.get(
                        "source_ip", "")) else "Unknown",
                    "geo_country": "RU" if "185." in str(modifier.get(
                        "source_ip", "")) else "XX",
                    "is_anomaly": True,
                    "attack_type": attack_type,
                    "tactic": tactic,
                }
                attack_records.append(record)

        attack_df = pd.DataFrame(attack_records)
        combined = pd.concat([normal_df, attack_df], ignore_index=True)

        # Shuffle
        combined = combined.sample(frac=1, random_state=seed).reset_index(
            drop=True)
        return combined
