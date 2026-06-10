"""
Risk Scoring Engine (UEBA Core).

Computes risk scores using:
  - Anomaly probability × MITRE impact severity
  - Context (asset criticality, user role, time)
  - Historical deviation from baseline
  - NIST SP 800-61 incident response severity guide

Score = (Anomaly_Probability × Impact_Weight) + Context_Bonus
"""

import numpy as np
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict

# ─── MITRE ATT&CK Severity Weights ───
# Severity based on NIST SP 800-30 + industry threat intelligence
MITRE_SEVERITY: Dict[str, float] = {
    # Impact tactics - highest severity
    "TA0040_Impact": 95.0,
    "TA0010_Exfiltration": 90.0,
    "TA0006_Credential_Access": 85.0,
    "TA0004_Privilege_Escalation": 80.0,
    # Movement / Persistence
    "TA0008_Lateral_Movement": 75.0,
    "TA0003_Persistence": 70.0,
    "TA0011_Command_and_Control": 70.0,
    # Execution / Access
    "TA0002_Execution": 60.0,
    "TA0001_Initial_Access": 55.0,
    # Recon / Defense Evasion
    "TA0007_Discovery": 45.0,
    "TA0005_Defense_Evasion": 50.0,
    "TA0009_Collection": 50.0,
    # Benign
    "TA0000_Benign": 0.0,
}

ATTACK_SEVERITY: Dict[str, float] = {
    "brute_force": 65.0,
    "credential_dumping": 90.0,
    "phishing": 55.0,
    "reconnaissance": 40.0,
    "lateral_movement": 80.0,
    "data_exfiltration": 95.0,
    "privilege_escalation": 85.0,
    "persistence": 70.0,
    "defense_evasion": 60.0,
    "command_and_control": 75.0,
    "normal": 0.0,
}

# ─── Role-based criticality ───
ROLE_CRITICALITY: Dict[str, float] = {
    "admin": 30.0,
    "domain_admin": 40.0,
    "db_admin": 35.0,
    "developer": 20.0,
    "analyst": 15.0,
    "user": 10.0,
    "service_account": 25.0,
    "guest": 5.0,
    "unknown": 15.0,
}

ASSET_CRITICALITY: Dict[str, float] = {
    "domain_controller": 40.0,
    "database_server": 35.0,
    "application_server": 25.0,
    "web_server": 20.0,
    "workstation": 10.0,
    "laptop": 10.0,
    "server": 25.0,
    "network_device": 20.0,
    "unknown": 10.0,
}

HOUR_RISK_WEIGHTS = {
    # Off-hours (higher risk): 0-6
    **{h: 15.0 for h in range(0, 6)},
    # Early morning: 6-8
    **{h: 5.0 for h in range(6, 8)},
    # Business hours (low risk): 8-18
    **{h: 0.0 for h in range(8, 18)},
    # Evening: 18-22
    **{h: 5.0 for h in range(18, 22)},
    # Night: 22-24
    **{h: 10.0 for h in range(22, 24)},
}


@dataclass
class RiskResult:
    """Risk assessment result for a single event/session."""
    score: float                       # Final risk score [0-100]
    level: str                         # critical / high / medium / low / info
    anomaly_probability: float         # [0-1]
    attack_type: str                   # MITRE technique ID or label
    tactic: str                        # MITRE tactic
    context_bonus: float               # Context-based addition
    impact_weight: float               # MITRE severity weight
    confidence: float                  # Model confidence
    risk_factors: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict:
        return asdict(self)


class RiskScorer:
    """
    Computes unified risk scores combining:
      - Anomaly detection probability
      - MITRE ATT&CK tactic/technique severity
      - Context (user role, asset criticality, time)
      - Historical deviation
    """

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}

    def compute(self,
                anomaly_prob: float,
                attack_type: str = "normal",
                tactic: str = "TA0000_Benign",
                confidence: float = 0.5,
                user_role: str = "user",
                asset_type: str = "unknown",
                hour_of_day: int = 12,
                is_weekend: bool = False,
                failed_logins_1h: int = 0,
                geo_change: bool = False,
                device_change: bool = False,
                **kwargs) -> RiskResult:
        """
        Full risk score computation.

        Args:
            anomaly_prob: Score from anomaly detector [0-1]
            attack_type: Classified attack type
            tactic: MITRE tactic ID
            confidence: Model confidence [0-1]
            user_role: User's role
            asset_type: Target asset type
            hour_of_day: 0-23
            is_weekend: bool
            failed_logins_1h: Count of failed logins in last hour
            geo_change: Whether geo-location changed
            device_change: Whether device changed

        Returns:
            RiskResult with final score and factors
        """
        risk_factors = []
        recommendations = []

        # 1. Base = Anomaly probability × Impact
        tactic_weight = MITRE_SEVERITY.get(tactic, 50.0)
        attack_weight = ATTACK_SEVERITY.get(attack_type, 50.0)
        impact_weight = max(tactic_weight, attack_weight)

        base_score = anomaly_prob * impact_weight

        # 2. Context bonus
        context_bonus = 0.0

        # Role criticality
        role_bonus = ROLE_CRITICALITY.get(user_role.lower(), 10.0)
        if role_bonus > 20:
            context_bonus += role_bonus * anomaly_prob
            risk_factors.append(f"High-privilege role: {user_role}")

        # Asset criticality
        asset_bonus = ASSET_CRITICALITY.get(asset_type.lower(), 10.0)
        if asset_bonus > 15:
            context_bonus += asset_bonus * anomaly_prob
            risk_factors.append(f"Critical asset: {asset_type}")

        # Time-based
        time_bonus = HOUR_RISK_WEIGHTS.get(hour_of_day, 0.0)
        if is_weekend:
            time_bonus += 10.0
        if time_bonus > 0:
            context_bonus += time_bonus * anomaly_prob
            risk_factors.append(f"Off-hours access ({hour_of_day}:00, {'weekend' if is_weekend else 'weekday'})")

        # Failed logins
        if failed_logins_1h > 3:
            fb = min(failed_logins_1h * 5.0, 30.0)
            context_bonus += fb
            risk_factors.append(f"Multiple failed logins ({failed_logins_1h} in 1h)")

        # Geo/device changes
        if geo_change:
            context_bonus += 15.0 * anomaly_prob
            risk_factors.append("Geolocation change detected")
        if device_change:
            context_bonus += 10.0 * anomaly_prob
            risk_factors.append("New device detected")

        # 3. Final score with sigmoid normalization to [0, 100]
        raw_score = base_score + context_bonus
        confidence_weight = 0.5 + 0.5 * confidence
        final_score = min(raw_score * confidence_weight, 100.0)

        # 4. Risk level
        thresholds = self.config.get("thresholds", {})
        critical = thresholds.get("critical", 85.0)
        high = thresholds.get("high", 65.0)
        medium = thresholds.get("medium", 40.0)
        low = thresholds.get("low", 20.0)

        if final_score >= critical:
            level = "critical"
            recommendations.append("Immediate SOC escalation required")
            recommendations.append("Isolate affected user/asset")
        elif final_score >= high:
            level = "high"
            recommendations.append("Alert SOC team immediately")
            recommendations.append("Review user activity logs")
        elif final_score >= medium:
            level = "medium"
            recommendations.append("Flag for SOC review within 24h")
            recommendations.append("Monitor user activity")
        elif final_score >= low:
            level = "low"
            recommendations.append("Log for periodic review")
        else:
            level = "info"

        return RiskResult(
            score=round(final_score, 2),
            level=level,
            anomaly_probability=round(anomaly_prob, 4),
            attack_type=attack_type,
            tactic=tactic,
            context_bonus=round(context_bonus, 2),
            impact_weight=round(impact_weight, 2),
            confidence=round(confidence, 4),
            risk_factors=risk_factors,
            recommendations=recommendations,
        )

    @staticmethod
    def aggregate_scores(results: List[RiskResult],
                         window_minutes: int = 60) -> Dict:
        """Aggregate risk scores over a time window for dashboards."""
        if not results:
            return {"avg": 0, "max": 0, "count": 0, "critical": 0,
                    "high": 0, "medium": 0, "low": 0, "info": 0}

        scores = [r.score for r in results]
        levels = [r.level for r in results]

        return {
            "avg": round(np.mean(scores), 2) if len(scores) > 1 else scores[0],
            "max": round(max(scores), 2),
            "min": round(min(scores), 2),
            "count": len(results),
            "critical": levels.count("critical"),
            "high": levels.count("high"),
            "medium": levels.count("medium"),
            "low": levels.count("low"),
            "info": levels.count("info"),
        }
