"""
SOCal SIEM - Dashboard Backend
FastAPI server with:
- WebSocket real-time log/alert streaming
- REST API for dashboards, alerts, investigations, stats
- MITRE ATT&CK heatmap data
- ML model status
"""

import asyncio
import json
import logging
import os
import random
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import asyncpg
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('socal.dashboard')

# ============================================================
# APP SETUP
# ============================================================

app = FastAPI(
    title="SOCal SIEM Dashboard",
    description="Local SIEM + AI SOC Analyst - Real-time Security Monitoring",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# DATABASE CONNECTION
# ============================================================

DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', '5432')),
    'database': os.getenv('DB_NAME', 'socal_siem'),
    'user': os.getenv('DB_USER', 'socal'),
    'password': os.getenv('DB_PASS', 'socal_pass'),
}

db_pool: Optional[asyncpg.Pool] = None


async def get_db():
    """Get database connection from pool"""
    global db_pool
    if db_pool is None:
        try:
            db_pool = await asyncpg.create_pool(**DB_CONFIG, min_size=2, max_size=10)
        except Exception as e:
            logger.warning(f"Cannot connect to TimescaleDB: {e}")
            return None
    return db_pool


# ============================================================
# WEBSOCKET MANAGER
# ============================================================

class ConnectionManager:
    """Manage WebSocket connections for real-time streaming"""

    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {
            'logs': [],
            'alerts': [],
            'stats': [],
        }

    async def connect(self, websocket: WebSocket, channel: str = 'logs'):
        await websocket.accept()
        if channel in self.active_connections:
            self.active_connections[channel].append(websocket)

    def disconnect(self, websocket: WebSocket, channel: str = 'logs'):
        if channel in self.active_connections:
            self.active_connections[channel] = [
                ws for ws in self.active_connections[channel]
                if ws is not websocket
            ]

    async def broadcast(self, channel: str, message: dict):
        """Broadcast to all connections on a channel"""
        stale = []
        for ws in self.active_connections.get(channel, []):
            try:
                await ws.send_json(message)
            except Exception:
                stale.append(ws)
        for ws in stale:
            self.disconnect(ws, channel)

    async def broadcast_log(self, log_entry: dict):
        await self.broadcast('logs', {'type': 'log', 'data': log_entry})

    async def broadcast_alert(self, alert: dict):
        await self.broadcast('alerts', {'type': 'alert', 'data': alert})

    async def broadcast_stats(self, stats: dict):
        await self.broadcast('stats', {'type': 'stats', 'data': stats})


manager = ConnectionManager()

# ============================================================
# DEMO DATA GENERATOR
# ============================================================

class DemoDataGenerator:
    """Generate realistic demo data for the dashboard when no pipeline is running"""

    def __init__(self):
        self.users = ['admin', 'root', 'svc_backup', 'john', 'alice', 'bob']
        self.hosts = ['server1', 'server2', 'workstation1', 'dns-server']
        self.services = ['sshd', 'nginx', 'postgresql', 'apache2', 'cron']
        self.ips = ['45.33.32.156', '185.220.101.42', '91.121.87.34', '10.0.0.50', '192.168.1.100']
        self.alert_templates = [
            {'rule_name': 'SSH Brute Force', 'severity': 'high', 'mitre_technique': 'T1110'},
            {'rule_name': 'Suricata Malware Alert', 'severity': 'critical', 'mitre_technique': 'T1204'},
            {'rule_name': 'Suspicious DNS Query', 'severity': 'medium', 'mitre_technique': 'T1071'},
            {'rule_name': 'Privilege Escalation via Sudo', 'severity': 'high', 'mitre_technique': 'T1548'},
            {'rule_name': 'Windows Logon Failure', 'severity': 'high', 'mitre_technique': 'T1110'},
        ]
        self._alert_count = 0

    def generate_log(self) -> dict:
        now = datetime.utcnow()
        host = random.choice(self.hosts)
        service = random.choice(self.services)
        ip = random.choice(self.ips)

        log_types = [
            {
                'message': f'Failed password for {random.choice(self.users)} from {ip} port 22 ssh2',
                'source': 'syslog',
                'tags': ['ssh', 'login_failure'],
            },
            {
                'message': f'Accepted password for {random.choice(self.users)} from 10.0.0.50 port 22 ssh2',
                'source': 'syslog',
                'tags': ['ssh', 'login_success'],
            },
            {
                'message': f'{random.choice(self.users)} : TTY=pts/0 ; PWD=/home/{random.choice(self.users)} ; USER=root ; COMMAND=/bin/bash -c "cat /etc/shadow"',
                'source': 'syslog',
                'tags': ['sudo', 'privilege_escalation'],
            },
            {
                'message': '{"event_type":"alert","alert":{"signature":"ET MALWARE Known malicious IP","severity":1,"category":"Malware"},"src_ip":"45.33.32.156","dest_ip":"10.0.0.5"}',
                'source': 'suricata',
                'tags': ['suricata_alert', 'malware'],
            },
            {
                'message': '{"event_type":"dns","dns":{"type":"query","rrname":"evil-panel.xyz"},"src_ip":"10.0.0.5"}',
                'source': 'suricata',
                'tags': ['dns', 'suspicious'],
            },
            {
                'message': f'{service}[{random.randint(1000,9999)}]: normal operation completed',
                'source': 'syslog',
                'tags': ['info'],
            },
        ]
        entry = random.choice(log_types)
        entry['@timestamp'] = now.isoformat() + 'Z'
        entry['hostname'] = host
        if 'network' not in entry:
            entry['network'] = {'address': ip}
        return entry

    def generate_alert(self) -> dict:
        self._alert_count += 1
        template = random.choice(self.alert_templates)
        host = random.choice(self.hosts)
        ip = random.choice(self.ips)
        now = datetime.utcnow()

        return {
            'id': f'alert-{self._alert_count}-{now.timestamp():.0f}',
            'rule_id': template.get('mitre_technique', 'UNKNOWN'),
            'rule_name': template['rule_name'],
            'severity': template['severity'],
            'mitre_tactic': random.choice(['TA0006', 'TA0002', 'TA0011', 'TA0004', 'TA0008']),
            'mitre_technique': template['mitre_technique'],
            'timestamp': now.isoformat() + 'Z',
            'hostname': host,
            'source': random.choice(['syslog', 'auditd', 'suricata']),
            'message': f'{template["rule_name"]} detected on {host} from {ip}',
            'tags': ['automated', template['severity']],
            'status': 'open',
        }


demo = DemoDataGenerator()

# ============================================================
# BACKGROUND TASKS
# ============================================================

class DashboardState:
    """In-memory state for dashboard (works without database)"""

    def __init__(self):
        self.recent_logs = []
        self.recent_alerts = []
        self.investigations = []
        self.max_items = 500
        self.stats = {
            'total_events': 0,
            'total_alerts': 0,
            'alerts_by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'events_per_second': 0,
            'active_rules': 12,
            'ml_status': 'training',
            'ml_samples': 0,
        }
        self._event_timestamps = []
        self._started_at = datetime.utcnow()

    def add_log(self, log_entry: dict):
        self.recent_logs.append(log_entry)
        if len(self.recent_logs) > self.max_items:
            self.recent_logs.pop(0)
        self.stats['total_events'] += 1
        self._event_timestamps.append(datetime.utcnow())
        # Keep last 1 minute of timestamps for EPS
        cutoff = datetime.utcnow() - timedelta(seconds=60)
        self._event_timestamps = [t for t in self._event_timestamps if t > cutoff]

    def add_alert(self, alert: dict):
        self.recent_alerts.append(alert)
        if len(self.recent_alerts) > self.max_items:
            self.recent_alerts.pop(0)
        self.stats['total_alerts'] += 1
        sev = alert.get('severity', 'low')
        if sev in self.stats['alerts_by_severity']:
            self.stats['alerts_by_severity'][sev] += 1

    @property
    def eps(self) -> float:
        cutoff = datetime.utcnow() - timedelta(seconds=10)
        recent = [t for t in self._event_timestamps if t > cutoff]
        return len(recent) / max((datetime.utcnow() - cutoff).total_seconds(), 1)


state = DashboardState()


async def demo_data_loop():
    """Generate demo data for the dashboard"""
    while True:
        # Generate log every 0.3-1 seconds
        log_entry = demo.generate_log()
        state.add_log(log_entry)
        await manager.broadcast_log(log_entry)

        # Generate alert occasionally (~15% of events)
        if random.random() < 0.15:
            alert = demo.generate_alert()
            state.add_alert(alert)
            await manager.broadcast_alert(alert)

        # Update stats every second
        state.stats['events_per_second'] = state.eps
        state.stats['ml_samples'] = min(state.stats['total_events'] * 10, 10000)
        if state.stats['ml_samples'] >= 1000:
            state.stats['ml_status'] = 'active'
        await manager.broadcast_stats(state.stats)

        await asyncio.sleep(random.uniform(0.3, 1.0))


@app.on_event('startup')
async def startup():
    logger.info("SOCal Dashboard starting...")
    asyncio.create_task(demo_data_loop())


@app.on_event('shutdown')
async def shutdown():
    global db_pool
    if db_pool:
        await db_pool.close()


# ============================================================
# WEBSOCKET ENDPOINTS
# ============================================================

@app.websocket('/ws/logs')
async def websocket_logs(websocket: WebSocket):
    await manager.connect(websocket, 'logs')
    try:
        # Send recent history
        for log_entry in state.recent_logs[-50:]:
            await websocket.send_json({'type': 'log', 'data': log_entry})
        # Keep connection alive
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, 'logs')


@app.websocket('/ws/alerts')
async def websocket_alerts(websocket: WebSocket):
    await manager.connect(websocket, 'alerts')
    try:
        for alert in state.recent_alerts[-50:]:
            await websocket.send_json({'type': 'alert', 'data': alert})
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, 'alerts')


@app.websocket('/ws/stats')
async def websocket_stats(websocket: WebSocket):
    await manager.connect(websocket, 'stats')
    try:
        await websocket.send_json({'type': 'stats', 'data': state.stats})
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, 'stats')


# ============================================================
# REST API ENDPOINTS
# ============================================================

@app.get('/api/health')
async def health():
    return {
        'status': 'ok',
        'uptime': str(datetime.utcnow() - state._started_at),
        'version': '1.0.0',
    }


@app.get('/api/stats')
async def get_stats():
    """Dashboard statistics"""
    return {
        **state.stats,
        'events_per_second': state.eps,
        'uptime_seconds': (datetime.utcnow() - state._started_at).total_seconds(),
    }


@app.get('/api/alerts')
async def get_alerts(
    limit: int = Query(50, ge=1, le=1000),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """Get recent alerts"""
    alerts = list(state.recent_alerts)
    if severity:
        alerts = [a for a in alerts if a.get('severity') == severity]
    if status:
        alerts = [a for a in alerts if a.get('status') == status]
    return alerts[-limit:]


@app.get('/api/alerts/{alert_id}')
async def get_alert_detail(alert_id: str):
    """Get single alert with investigation"""
    for alert in state.recent_alerts:
        if alert.get('id') == alert_id:
            investigation = None
            for inv in state.investigations:
                if inv.get('alert_id') == alert_id:
                    investigation = inv
            return {'alert': alert, 'investigation': investigation}
    raise HTTPException(404, 'Alert not found')


@app.get('/api/logs')
async def get_logs(
    limit: int = Query(100, ge=1, le=1000),
    source: Optional[str] = Query(None),
    hostname: Optional[str] = Query(None),
):
    """Get recent logs"""
    logs = list(state.recent_logs)
    if source:
        logs = [l for l in logs if l.get('source') == source]
    if hostname:
        logs = [l for l in logs if l.get('hostname') == hostname]
    return logs[-limit:]


@app.get('/api/timeline')
async def get_timeline(minutes: int = Query(30, ge=5, le=1440)):
    """Get event/alert count timeline for charts"""
    now = datetime.utcnow()
    cutoff = now - timedelta(minutes=minutes)
    interval = max(1, minutes // 60)  # 1-minute intervals

    events_by_minute = {}
    alerts_by_minute = {}

    # Initialize all intervals
    t = cutoff.replace(second=0, microsecond=0)
    while t < now:
        key = t.isoformat()
        events_by_minute[key] = 0
        alerts_by_minute[key] = 0
        t += timedelta(minutes=interval)

    # Count events
    for log_entry in state.recent_logs:
        ts_str = log_entry.get('@timestamp', '')
        try:
            ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
            if ts > cutoff:
                key = ts.replace(second=0, microsecond=0).isoformat()
                if key in events_by_minute:
                    events_by_minute[key] += 1
        except (ValueError, AttributeError):
            pass

    for alert in state.recent_alerts:
        ts_str = alert.get('timestamp', '')
        try:
            ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
            if ts > cutoff:
                key = ts.replace(second=0, microsecond=0).isoformat()
                if key in alerts_by_minute:
                    alerts_by_minute[key] += 1
        except (ValueError, AttributeError):
            pass

    return {
        'timestamps': list(events_by_minute.keys()),
        'events': list(events_by_minute.values()),
        'alerts': list(alerts_by_minute.values()),
    }


@app.get('/api/mitre/heatmap')
async def get_mitre_heatmap():
    """MITRE ATT&CK heatmap data (tactic vs technique counts)"""
    tactics = {
        'TA0001': 'Initial Access',
        'TA0002': 'Execution',
        'TA0003': 'Persistence',
        'TA0004': 'Privilege Escalation',
        'TA0005': 'Defense Evasion',
        'TA0006': 'Credential Access',
        'TA0007': 'Discovery',
        'TA0008': 'Lateral Movement',
        'TA0009': 'Collection',
        'TA0011': 'Command and Control',
    }

    heatmap = {}
    for tactic_id, tactic_name in tactics.items():
        count = sum(
            1 for a in state.recent_alerts
            if a.get('mitre_tactic') == tactic_id
        )
        if count > 0:
            heatmap[tactic_id] = {
                'name': tactic_name,
                'count': count,
                'techniques': {}
            }

    # Group techniques under tactics
    for alert in state.recent_alerts:
        tactic_id = alert.get('mitre_tactic')
        technique_id = alert.get('mitre_technique')
        if tactic_id in heatmap and technique_id:
            if technique_id not in heatmap[tactic_id]['techniques']:
                heatmap[tactic_id]['techniques'][technique_id] = 0
            heatmap[tactic_id]['techniques'][technique_id] += 1

    return heatmap


@app.get('/api/hosts')
async def get_hosts():
    """List known hosts"""
    return [
        {'hostname': 'server1', 'ip': '10.0.0.5', 'os': 'Linux', 'criticality': 'high', 'alert_count': 42, 'online': True},
        {'hostname': 'server2', 'ip': '10.0.0.6', 'os': 'Linux', 'criticality': 'high', 'alert_count': 18, 'online': True},
        {'hostname': 'workstation1', 'ip': '10.0.0.50', 'os': 'Windows 11', 'criticality': 'medium', 'alert_count': 7, 'online': True},
        {'hostname': 'dns-server', 'ip': '10.0.0.10', 'os': 'Linux', 'criticality': 'critical', 'alert_count': 3, 'online': True},
    ]


@app.get('/api/investigations')
async def get_investigations(limit: int = Query(20, ge=1, le=100)):
    """Get AI investigation reports"""
    invs = list(state.investigations)
    return invs[-limit:]


@app.post('/api/alerts/{alert_id}/acknowledge')
async def acknowledge_alert(alert_id: str):
    """Acknowledge/close an alert"""
    for alert in state.recent_alerts:
        if alert.get('id') == alert_id:
            alert['status'] = 'acknowledged'
            return {'status': 'ok', 'alert_id': alert_id}
    raise HTTPException(404, 'Alert not found')


@app.post('/api/alerts/{alert_id}/investigate')
async def trigger_investigation(alert_id: str):
    """Manually trigger AI investigation"""
    for alert in state.recent_alerts:
        if alert.get('id') == alert_id:
            report = {
                'alert_id': alert_id,
                'rule_name': alert.get('rule_name'),
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'confidence': random.choice(['high', 'medium']),
                'summary': f"AI investigation completed for {alert.get('rule_name')}. "
                          f"Found {random.randint(0, 3)} related IOCs.",
            }
            state.investigations.append(report)
            alert['investigated'] = True
            return report
    raise HTTPException(404, 'Alert not found')


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=8000)
