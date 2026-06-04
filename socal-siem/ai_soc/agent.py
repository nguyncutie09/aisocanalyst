"""
SOCal SIEM - AI SOC Analyst Agent
Local LLM-powered investigation agent using Ollama.
Automatically triages alerts, queries context, maps to MITRE ATT&CK,
and produces structured incident reports.
"""

import asyncio
import json
import logging
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger('socal.aisoc')

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False


class SOCAgent:
    """
    AI SOC Analyst Agent with tool-based investigation pipeline.

    Tools:
    - query_logs(): search logs in database
    - get_host_context(): host information
    - enrich_ip(): IP reputation from local DB
    - mitre_lookup(): MITRE ATT&CK lookup
    - extract_iocs(): IOC extraction from text
    """

    def __init__(
        self,
        ollama_url: str = "http://localhost:11434",
        model: str = "qwen2.5:7b",
        db_path: str = "storage/soc_knowledge.db",
        auto_investigate: bool = True,
    ):
        self.ollama_url = ollama_url.rstrip('/')
        self.model = model
        self.auto_investigate = auto_investigate
        self.conversation_history: List[dict] = []

        # Local knowledge DB
        self.db_path = db_path
        self._ensure_db()

        # System prompt
        self.system_prompt = (
            "You are an AI SOC (Security Operations Center) Analyst. "
            "Your role is to investigate security alerts and produce structured reports.\n\n"
            "FOLLOW THIS PROCESS FOR EVERY INVESTIGATION:\n"
            "1. Understand the alert - what rule triggered, what's the severity\n"
            "2. Query context - check recent logs, host info, IP reputation\n"
            "3. Correlate - connect this alert with other events\n"
            "4. Map to MITRE ATT&CK - identify tactics and techniques\n"
            "5. Assess severity and confidence\n"
            "6. Extract IOCs (IPs, domains, hashes)\n"
            "7. Recommend containment and remediation actions\n\n"
            "You run LOCALLY. All data stays on this machine. "
            "Be concise but thorough. Always use the provided context data."
        )

    def _ensure_db(self):
        """Ensure local SQLite database exists"""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS investigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT,
                rule_name TEXT,
                severity TEXT,
                hostname TEXT,
                report TEXT,
                iocs TEXT,
                confidence TEXT,
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS mitre_cache (
                id TEXT PRIMARY KEY,
                name TEXT,
                description TEXT,
                tactic TEXT,
                technique TEXT
            );
            CREATE TABLE IF NOT EXISTS ip_reputation (
                ip TEXT PRIMARY KEY,
                source TEXT,
                score REAL,
                tags TEXT,
                last_seen TEXT
            );
        """)
        conn.commit()
        conn.close()

    async def investigate_alert(self, alert: dict) -> dict:
        """
        Full investigation pipeline for a single alert.
        Returns structured investigation report.
        """
        logger.info(f"AI SOC investigating: {alert.get('rule_name', 'unknown')}")

        # Step 1: Gather context using tools
        context = await self._gather_context(alert)

        # Step 2: Build investigation prompt
        prompt = self._build_prompt(alert, context)

        # Step 3: Call LLM
        report_text = await self._call_llm(prompt)

        # Step 4: Parse + structure
        report = {
            'alert_id': alert.get('rule_id'),
            'rule_name': alert.get('rule_name'),
            'severity': alert.get('severity'),
            'hostname': alert.get('hostname'),
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'report_text': report_text,
            'iocs': self.extract_iocs(report_text + '\n' + str(alert.get('raw', ''))),
            'confidence': self._extract_confidence(report_text),
        }

        # Step 5: Save to DB
        self._save_investigation(alert, report)

        return report

    async def _gather_context(self, alert: dict) -> dict:
        """Use all available tools to gather context"""
        context = {
            'alert': alert,
            'recent_logs': [],
            'host_info': {},
            'ip_info': {},
            'mitre_info': {},
        }

        # Extract IP from alert for enrichment
        raw = alert.get('raw', '')
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', raw)

        if ips:
            context['ip_info'] = await self.enrich_ip(ips[0])

        # MITRE lookup
        mitre_tech = alert.get('mitre_technique')
        if mitre_tech:
            context['mitre_info'] = await self.mitre_lookup(mitre_tech)

        # Host context
        hostname = alert.get('hostname', 'unknown')
        context['host_info'] = await self.get_host_context(hostname)

        return context

    def _build_prompt(self, alert: dict, context: dict) -> str:
        """Build structured prompt for LLM"""
        return f"""## SECURITY ALERT

**Rule:** {alert.get('rule_name', 'N/A')}
**Severity:** {alert.get('severity', 'N/A')}
**Source:** {alert.get('source', 'N/A')}
**Hostname:** {alert.get('hostname', 'N/A')}
**Timestamp:** {alert.get('timestamp', alert.get('event_timestamp', 'N/A'))}
**Tags:** {', '.join(alert.get('tags', []))}

**Raw Log:**
```
{alert.get('raw', 'N/A')[:2000]}
```

## INVESTIGATION CONTEXT

### IP Intelligence:
{json.dumps(context.get('ip_info', {}), indent=2)}

### MITRE ATT&CK Context:
{json.dumps(context.get('mitre_info', {}), indent=2)}

### Host Information:
{json.dumps(context.get('host_info', {}), indent=2)}

## INSTRUCTIONS

Produce a structured investigation report with the following sections:

1. **Executive Summary** — What happened in 1-2 sentences
2. **Detailed Analysis** — Step-by-step investigation of the alert
3. **MITRE ATT&CK Mapping** — Tactic, technique, procedure IDs
4. **Indicators of Compromise** — IPs, domains, hashes found
5. **Severity Assessment** — Using CVSS-like scoring (Critical/High/Medium/Low)
6. **Recommended Actions** — Containment, eradication, recovery steps
7. **Confidence Level** — High/Medium/Low with reasoning"""

    async def _call_llm(self, prompt: str) -> str:
        """Call Ollama local LLM"""
        if not HTTPX_AVAILABLE:
            return self._fallback_report(prompt)

        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                response = await client.post(
                    f"{self.ollama_url}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "system": self.system_prompt,
                        "stream": False,
                        "options": {
                            "temperature": 0.1,
                            "num_predict": 2048,
                            "top_k": 40,
                            "top_p": 0.9,
                        }
                    }
                )
                if response.status_code == 200:
                    return response.json().get('response', self._fallback_report(prompt))
                else:
                    logger.warning(f"Ollama API error: {response.status_code}")
                    return self._fallback_report(prompt)

        except httpx.ConnectError:
            logger.warning("Cannot connect to Ollama - using fallback report")
            return self._fallback_report(prompt)
        except Exception as e:
            logger.error(f"LLM call failed: {e}")
            return self._fallback_report(prompt)

    def _fallback_report(self, prompt: str) -> str:
        """Generate a structured report without LLM when Ollama is unavailable"""
        return """## INVESTIGATION REPORT (Automated - No LLM Available)

### Executive Summary
Alert triggered by rule-based detection. Manual investigation recommended.

### Detailed Analysis
- Alert matched correlation rule conditions
- Check raw log and context for details
- Verify with additional log sources

### Indicators of Compromise
- Review raw log for IPs, domains, and hashes
- Cross-reference with threat intelligence feeds

### Recommended Actions
1. Review the raw log alert details
2. Check recent events on affected host
3. Verify if this is a false positive or genuine threat
4. If genuine: isolate host, collect forensic data, investigate root cause
"""

    def extract_iocs(self, text: str) -> List[dict]:
        """Extract Indicators of Compromise from text"""
        iocs = []

        # IP addresses
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        for ip in set(ip_pattern.findall(text)):
            if not ip.startswith(('10.', '172.16.', '192.168.', '127.')):
                iocs.append({'type': 'ip', 'value': ip})
            else:
                iocs.append({'type': 'ip_private', 'value': ip})

        # Domains
        domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
        for domain in set(domain_pattern.findall(text)):
            # Filter out common false positives
            if not domain.endswith(('.local', '.lan', '.internal')):
                blacklist = {'localhost', 'example.com', 'test.com'}
                if domain not in blacklist and '.' in domain:
                    iocs.append({'type': 'domain', 'value': domain.lower()})

        # Hashes (MD5/SHA1/SHA256)
        hash_pattern = re.compile(r'\b[a-fA-F0-9]{32,64}\b')
        for h in set(hash_pattern.findall(text)):
            htype = 'sha256' if len(h) == 64 else 'sha1' if len(h) == 40 else 'md5'
            iocs.append({'type': htype, 'value': h})

        # URLs
        url_pattern = re.compile(r'https?://[^\s"\']+')
        for url in set(url_pattern.findall(text)):
            iocs.append({'type': 'url', 'value': url})

        return iocs

    def _extract_confidence(self, text: str) -> str:
        """Extract confidence level from LLM report"""
        text_lower = text.lower()
        if 'high confidence' in text_lower or 'confidence.*high' in text_lower:
            return 'high'
        elif 'medium confidence' in text_lower or 'confidence.*medium' in text_lower:
            return 'medium'
        elif 'low confidence' in text_lower or 'confidence.*low' in text_lower:
            return 'low'
        return 'medium'

    def _save_investigation(self, alert: dict, report: dict):
        """Save investigation to local database"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute(
                """INSERT INTO investigations
                   (alert_id, rule_name, severity, hostname, report, iocs, confidence, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    alert.get('rule_id', ''),
                    alert.get('rule_name', ''),
                    alert.get('severity', ''),
                    alert.get('hostname', ''),
                    json.dumps(report.get('report_text', '')),
                    json.dumps(report.get('iocs', [])),
                    report.get('confidence', 'medium'),
                    datetime.utcnow().isoformat(),
                )
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to save investigation: {e}")

    # =============== TOOL METHODS ===============

    async def query_logs(self, query_filter: dict, limit: int = 100) -> List[dict]:
        """Query recent logs from database"""
        # This connects to the main TimescaleDB - placeholder for async
        return [{'note': 'Database query - check TimescaleDB connection'}]

    async def get_host_context(self, hostname: str) -> dict:
        """Get host information from inventory"""
        return {
            'hostname': hostname,
            'os': 'Linux (Ubuntu 22.04)',
            'criticality': 'high',
            'services': ['ssh', 'http', 'database'],
            'last_seen': datetime.utcnow().isoformat() + 'Z',
        }

    async def enrich_ip(self, ip: str) -> dict:
        """Local IP reputation check"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute("SELECT * FROM ip_reputation WHERE ip = ?", (ip,))
        row = cursor.fetchone()
        conn.close()

        if row:
            return {
                'ip': row[0],
                'source': row[1],
                'score': row[2],
                'tags': json.loads(row[3]) if row[3] else [],
            }
        return {
            'ip': ip,
            'source': 'local_db',
            'score': 0.0,
            'tags': [],
            'note': 'No reputation data available'
        }

    async def mitre_lookup(self, technique_id: str) -> dict:
        """Look up MITRE ATT&CK technique"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute("SELECT * FROM mitre_cache WHERE id = ?", (technique_id,))
        row = cursor.fetchone()
        conn.close()

        if row:
            return {
                'id': row[0],
                'name': row[1],
                'description': row[2],
                'tactic': row[3],
                'technique': row[4],
            }

        # Return basic info even without DB
        return {
            'id': technique_id,
            'name': technique_id,
            'description': 'Lookup from MITRE ATT&CK framework',
            'note': 'Full details available when mitre_cache is populated'
        }
