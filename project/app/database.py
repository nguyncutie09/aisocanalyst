"""
In-memory data store for the UEBA system.
Stores alerts, events, risk assessments with time-based retention.
Supports fast lookups for the dashboard.
"""

import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from collections import defaultdict, deque
from threading import Lock


class AlertStore:
    """
    Thread-safe in-memory store for alerts and risk events.
    Old entries are automatically pruned based on retention policy.
    """

    def __init__(self, max_alerts: int = 10000, retention_hours: int = 72):
        self.max_alerts = max_alerts
        self.retention_hours = retention_hours
        self._alerts: Dict[str, dict] = {}
        self._risk_events: deque = deque(maxlen=50000)
        self._events_by_user: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=1000))
        self._lock = Lock()
        self._total_processed = 0

    def add_alert(self, alert: dict) -> str:
        """Add an alert and return its ID."""
        alert_id = str(uuid.uuid4())
        alert["id"] = alert_id
        alert["created_at"] = datetime.utcnow().isoformat()
        alert["acknowledged"] = alert.get("acknowledged", False)

        with self._lock:
            self._alerts[alert_id] = alert
            self._risk_events.append(alert)
            user = alert.get("user_name", "unknown")
            self._events_by_user[user].append(alert)
            self._total_processed += 1
            self._prune()
        return alert_id

    def add_batch_alerts(self, alerts: List[dict]) -> List[str]:
        """Add multiple alerts."""
        return [self.add_alert(a) for a in alerts]

    def get_alerts(self, limit: int = 100, offset: int = 0,
                   min_risk: Optional[float] = None,
                   level: Optional[str] = None,
                   attack_type: Optional[str] = None) -> List[dict]:
        """Get alerts with optional filters."""
        with self._lock:
            items = list(self._alerts.values())

        # Filter
        if min_risk is not None:
            items = [a for a in items if a.get("risk_score", 0) >= min_risk]
        if level:
            items = [a for a in items if a.get("risk_level") == level]
        if attack_type:
            items = [a for a in items if a.get("attack_type") == attack_type]

        # Sort by timestamp descending
        items.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return items[offset:offset + limit]

    def get_alert_by_id(self, alert_id: str) -> Optional[dict]:
        with self._lock:
            return self._alerts.get(alert_id)

    def acknowledge_alert(self, alert_id: str) -> bool:
        with self._lock:
            if alert_id in self._alerts:
                self._alerts[alert_id]["acknowledged"] = True
                return True
            return False

    def get_stats(self) -> dict:
        """Return summary statistics."""
        with self._lock:
            alerts = list(self._alerts.values())

        now = datetime.utcnow()
        last_hour = now - timedelta(hours=1)
        last_24h = now - timedelta(hours=24)

        critical = sum(1 for a in alerts
                       if a.get("risk_level") == "critical")
        high = sum(1 for a in alerts
                   if a.get("risk_level") == "high")
        medium = sum(1 for a in alerts
                     if a.get("risk_level") == "medium")
        low = sum(1 for a in alerts
                  if a.get("risk_level") == "low")

        return {
            "total_alerts": len(alerts),
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "total_processed": self._total_processed,
            "unique_users": len(self._events_by_user),
        }

    def get_risk_history(self, hours: int = 24) -> List[dict]:
        """Get risk score time series for dashboard charts."""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        with self._lock:
            events = list(self._risk_events)

        # Aggregate by hour
        hourly: Dict[str, List[float]] = defaultdict(list)
        for ev in events:
            ts_str = ev.get("created_at", "")
            try:
                ts = datetime.fromisoformat(ts_str)
                if ts < cutoff:
                    continue
                bucket = ts.strftime("%Y-%m-%d %H:00")
                hourly[bucket].append(ev.get("risk_score", 0))
            except (ValueError, TypeError):
                continue

        result = []
        for bucket in sorted(hourly.keys()):
            scores = hourly[bucket]
            result.append({
                "time": bucket,
                "avg": round(sum(scores) / len(scores), 1),
                "max": round(max(scores), 1),
                "count": len(scores),
            })
        return result

    def get_top_attack_types(self, top_n: int = 10) -> List[dict]:
        """Get most common attack types."""
        with self._lock:
            counts: Dict[str, int] = defaultdict(int)
            for a in self._alerts.values():
                atype = a.get("attack_type", "normal")
                counts[atype] += 1
        sorted_types = sorted(counts.items(),
                              key=lambda x: x[1], reverse=True)[:top_n]
        return [{"attack_type": k, "count": v} for k, v in sorted_types]

    def get_user_risk_summary(self, top_n: int = 20) -> List[dict]:
        """Get highest-risk users."""
        with self._lock:
            user_risk: Dict[str, List[float]] = defaultdict(list)
            for a in self._alerts.values():
                user = a.get("user_name", "unknown")
                user_risk[user].append(a.get("risk_score", 0))

        summaries = []
        for user, scores in user_risk.items():
            summaries.append({
                "user": user,
                "avg_risk": round(sum(scores) / len(scores), 1),
                "max_risk": round(max(scores), 1),
                "alert_count": len(scores),
                "last_alert": max(scores) if scores else 0,
            })
        summaries.sort(key=lambda x: x["max_risk"], reverse=True)
        return summaries[:top_n]

    def get_mitre_coverage(self) -> Dict[str, float]:
        """Get MITRE tactic coverage based on alerts."""
        with self._lock:
            counts: Dict[str, int] = defaultdict(int)
            for a in self._alerts.values():
                tactic = a.get("tactic", "TA0000_Benign")
                counts[tactic] += 1
        total = sum(counts.values()) or 1
        return {k: round(v / total * 100, 1) for k, v in counts.items()}

    def _prune(self):
        """Remove old alerts beyond retention period."""
        if len(self._alerts) <= self.max_alerts:
            return
        cutoff = datetime.utcnow() - timedelta(hours=self.retention_hours)
        to_delete = []
        for aid, alert in self._alerts.items():
            try:
                ts = datetime.fromisoformat(alert.get("created_at", ""))
                if ts < cutoff:
                    to_delete.append(aid)
            except (ValueError, TypeError):
                continue
        for aid in to_delete:
            del self._alerts[aid]


# Global store
store = AlertStore()
