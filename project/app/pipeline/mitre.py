"""
MITRE ATT&CK Framework Integration.
Maps detected behaviors to the MITRE ATT&CK framework.
Provides tactic, technique IDs, and severity metadata.
"""

from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
import json
import os


# ─── MITRE ATT&CK Technique Definitions ───

@dataclass
class MitreTechnique:
    """A single MITRE ATT&CK technique entry."""
    technique_id: str          # e.g. T1078
    name: str                   # e.g. Valid Accounts
    tactic: str                 # e.g. TA0001_Initial_Access
    tactic_name: str            # e.g. Initial Access
    severity: float             # 0-100
    description: str
    detections: List[str] = field(default_factory=list)


MITRE_DATABASE: Dict[str, MitreTechnique] = {
    # ── Initial Access (TA0001) ──
    "T1078": MitreTechnique("T1078", "Valid Accounts", "TA0001_Initial_Access",
                             "Initial Access", 55.0,
                             "Adversary uses legitimate credentials to access system",
                             ["Unusual login time", "Login from new geo",
                              "Multiple failed logins followed by success"]),
    "T1566": MitreTechnique("T1566", "Phishing", "TA0001_Initial_Access",
                             "Initial Access", 55.0,
                             "Adversary sends malicious link/attachment",
                             ["Suspicious email attachment", "URL in email"]),
    "T1190": MitreTechnique("T1190", "Exploit Public-Facing Application",
                             "TA0001_Initial_Access", "Initial Access", 65.0,
                             "Exploits vulnerability in public-facing app",
                             ["Web exploit attempt", "Abnormal HTTP requests"]),

    # ── Execution (TA0002) ──
    "T1059": MitreTechnique("T1059", "Command and Scripting Interpreter",
                             "TA0002_Execution", "Execution", 60.0,
                             "Abuses command interpreters for execution",
                             ["PowerShell execution", "WMI execution",
                              "Shell command anomalies"]),
    "T1204": MitreTechnique("T1204", "User Execution", "TA0002_Execution",
                             "Execution", 50.0,
                             "User executes malicious file",
                             ["Suspicious file execution", "Office macro execution"]),

    # ── Persistence (TA0003) ──
    "T1098": MitreTechnique("T1098", "Account Manipulation",
                             "TA0003_Persistence", "Persistence", 70.0,
                             "Adversary modifies account for persistence",
                             ["New account creation", "Account permission change",
                              "Suspicious group membership change"]),
    "T1547": MitreTechnique("T1547", "Boot or Logon Autostart Execution",
                             "TA0003_Persistence", "Persistence", 65.0,
                             "Uses startup folders/registry for persistence",
                             ["Registry autorun modification",
                              "Startup folder changes"]),

    # ── Privilege Escalation (TA0004) ──
    "T1068": MitreTechnique("T1068", "Exploitation for Privilege Escalation",
                             "TA0004_Privilege_Escalation",
                             "Privilege Escalation", 80.0,
                             "Exploits vulnerability to gain higher privileges",
                             ["Privilege escalation exploit detection",
                              "Abnormal process privileges"]),
    "T1078_003": MitreTechnique("T1078.003", "Local Accounts",
                                 "TA0004_Privilege_Escalation",
                                 "Privilege Escalation", 70.0,
                                 "Uses local accounts for privilege escalation",
                                 ["Local admin login", "Suspicious local account usage"]),

    # ── Defense Evasion (TA0005) ──
    "T1562": MitreTechnique("T1562", "Impair Defenses", "TA0005_Defense_Evasion",
                             "Defense Evasion", 60.0,
                             "Disables or impairs security tools",
                             ["Security service stopped", "Firewall rule deleted",
                              "AV disabled"]),
    "T1070": MitreTechnique("T1070", "Indicator Removal",
                             "TA0005_Defense_Evasion", "Defense Evasion", 55.0,
                             "Clears logs or artifacts",
                             ["Event log cleared", "Timestomping detection"]),

    # ── Credential Access (TA0006) ──
    "T1110": MitreTechnique("T1110", "Brute Force", "TA0006_Credential_Access",
                             "Credential Access", 75.0,
                             "Attempts to guess or brute force credentials",
                             ["Multiple failed logins", "Password spraying",
                              "Credential stuffing"]),
    "T1003": MitreTechnique("T1003", "OS Credential Dumping",
                             "TA0006_Credential_Access", "Credential Access", 90.0,
                             "Dumps credentials from OS",
                             ["LSASS process access", "SAM registry access",
                              "Mimikatz detection"]),

    # ── Discovery (TA0007) ──
    "T1046": MitreTechnique("T1046", "Network Service Discovery",
                             "TA0007_Discovery", "Discovery", 45.0,
                             "Scans network for services",
                             ["Port scan", "Network sweeps", "Service enumeration"]),
    "T1082": MitreTechnique("T1082", "System Information Discovery",
                             "TA0007_Discovery", "Discovery", 40.0,
                             "Gathers system information",
                             ["Systeminfo execution", "Hostname query"]),

    # ── Lateral Movement (TA0008) ──
    "T1021": MitreTechnique("T1021", "Remote Services",
                             "TA0008_Lateral_Movement", "Lateral Movement", 75.0,
                             "Uses remote services to move laterally",
                             ["RDP connection", "SSH to new host",
                              "SMB/PsExec execution"]),
    "T1550": MitreTechnique("T1550", "Use Alternate Authentication Material",
                             "TA0008_Lateral_Movement", "Lateral Movement", 70.0,
                             "Uses stolen credentials for lateral movement",
                             ["Pass-the-hash detection", "Pass-the-ticket"]),

    # ── Collection (TA0009) ──
    "T1114": MitreTechnique("T1114", "Email Collection", "TA0009_Collection",
                             "Collection", 50.0,
                             "Collects email data",
                             ["Abnormal email access pattern",
                              "Mailbox export"]),

    # ── Exfiltration (TA0010) ──
    "T1048": MitreTechnique("T1048", "Exfiltration Over C2 Channel",
                             "TA0010_Exfiltration", "Exfiltration", 95.0,
                             "Exfiltrates data over C2 channel",
                             ["Large outbound data transfer",
                              "Unusual DNS traffic",
                              "Data upload to unusual destination"]),
    "T1567": MitreTechnique("T1567", "Exfiltration Over Web Service",
                             "TA0010_Exfiltration", "Exfiltration", 90.0,
                             "Exfiltrates data via web services",
                             ["Large data upload", "Unusual API calls"]),

    # ── Command and Control (TA0011) ──
    "T1071": MitreTechnique("T1071", "Application Layer Protocol",
                             "TA0011_Command_and_Control",
                             "Command and Control", 70.0,
                             "Uses app-layer protocols for C2",
                             ["Beaconing traffic", "DNS tunneling",
                              "Unusual HTTP headers"]),
    "T1572": MitreTechnique("T1572", "Protocol Tunneling",
                             "TA0011_Command_and_Control",
                             "Command and Control", 75.0,
                             "Tunnels C2 through existing protocols",
                             ["SSH tunnel", "ICMP tunneling"]),

    # ── Impact (TA0040) ──
    "T1486": MitreTechnique("T1486", "Data Encrypted for Impact",
                             "TA0040_Impact", "Impact", 95.0,
                             "Encrypts data for ransom/destruction",
                             ["Mass file encryption", "Ransomware notes",
                              "Abnormal file extension changes"]),
    "T1499": MitreTechnique("T1499", "Endpoint Denial of Service",
                             "TA0040_Impact", "Impact", 80.0,
                             "DoS attack on endpoints",
                             ["Resource exhaustion", "Abnormal process count"]),
}


# ─── MITRE MATRIX LAYER FOR NAVIGATOR ───

def build_mitre_navigator_layer(techniques: Dict[str, float],
                                 layer_name: str = "UEBA Detections") -> dict:
    """
    Build a MITRE ATT&CK Navigator layer from detection scores.
    Can be imported into https://mitre-attack.github.io/attack-navigator/

    Args:
        techniques: dict of {technique_id: score (0-100)}
        layer_name: Name for the layer

    Returns:
        Navigator-compatible JSON dict
    """
    scores = []
    for tid, score in techniques.items():
        if tid in MITRE_DATABASE:
            tech = MITRE_DATABASE[tid]
            color = _score_to_color(score)
            scores.append({
                "techniqueID": tid,
                "score": int(score),
                "color": color,
                "comment": f"UEBA score: {score:.1f} - {tech.name}",
                "enabled": score > 10,
            })

    layer = {
        "name": layer_name,
        "version": "4.5",
        "domain": "enterprise-attack",
        "description": "UEBA System - Automated detection scores mapped to MITRE ATT&CK",
        "techniques": scores,
        "gradient": {
            "colors": ["#ffd5d5", "#ff4444"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "Critical (80-100)", "color": "#ff0000"},
            {"label": "High (60-80)", "color": "#ff6600"},
            {"label": "Medium (30-60)", "color": "#ffaa00"},
            {"label": "Low (0-30)", "color": "#ffd5d5"},
        ],
        "showAggregateScores": True,
    }
    return layer


def _score_to_color(score: float) -> str:
    if score >= 80:
        return "#ff0000"
    elif score >= 60:
        return "#ff6600"
    elif score >= 30:
        return "#ffaa00"
    return "#ffd5d5"


# ─── Inference functions ───

def map_event_to_technique(event_type: str, features: dict) -> List[str]:
    """
    Map an event type + features to MITRE technique IDs.
    Returns a list of candidate technique IDs.
    """
    candidates = []

    event_map = {
        "windows_security_4625": ["T1110"],       # Failed login -> Brute Force
        "windows_security_4624": ["T1078"],        # Successful login -> Valid Accounts
        "windows_security_4672": ["T1068"],        # Admin logon -> Priv Esc
        "windows_security_4648": ["T1021"],        # Explicit credential -> Lateral Movement
        "vpn_connect": ["T1078"],                   # VPN -> Valid Accounts
        "firewall_deny": ["T1562"],                  # Firewall deny -> Impair Defenses
        "firewall_allow": ["T1562"],                 # Firewall allow
        "ssh_login": ["T1021"],                      # SSH -> Remote Services
        "ssh_failed": ["T1110"],                     # SSH failed -> Brute Force
        "process_create": ["T1059"],                 # Process create -> Execution
        "dns_query": ["T1071"],                      # DNS query -> C2
        "web_request": ["T1071", "T1567"],           # Web request -> C2/Exfil
    }

    candidates = event_map.get(event_type, ["T1078"])

    # Refine based on features
    if features:
        hour = features.get("hour_of_day", 12)
        if hour < 6 or hour > 22:
            # Off-hours activity more suspicious
            pass

        failed = features.get("failed_attempts_last_1h", 0)
        if failed > 10 and "T1110" not in candidates:
            candidates.append("T1110")

        bytes_tx = features.get("bytes_transferred", 0)
        if bytes_tx > 5_000_000:  # >5MB
            if "T1048" not in candidates:
                candidates.append("T1048")

    return candidates


def get_tactic_for_technique(technique_id: str) -> str:
    """Return tactic ID for a technique ID."""
    tech = MITRE_DATABASE.get(technique_id)
    return tech.tactic if tech else "TA0000_Benign"


def get_technique_info(technique_id: str) -> Optional[dict]:
    """Get full technique info as dict."""
    tech = MITRE_DATABASE.get(technique_id)
    if not tech:
        return None
    return {
        "id": tech.technique_id,
        "name": tech.name,
        "tactic": tech.tactic,
        "tactic_name": tech.tactic_name,
        "severity": tech.severity,
        "description": tech.description,
        "detections": tech.detections,
    }


def export_navigator_layer(techniques: Dict[str, float],
                           output_path: str,
                           layer_name: str = "UEBA Detections"):
    """Export MITRE ATT&CK Navigator layer JSON."""
    layer = build_mitre_navigator_layer(techniques, layer_name)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(layer, f, indent=2)
    print(f"✓ Navigator layer exported to {output_path}")
    return layer
