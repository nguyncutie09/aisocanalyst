# SOCal SIEM — Local SIEM + AI SOC Analyst

Hệ thống **SIEM (Security Information and Event Management)** tự build, chạy local, tích hợp **AI SOC Analyst** với LLM local (Ollama). Toàn bộ dữ liệu ở trên máy bạn — không gửi đi đâu.

## 🏗️ Kiến Trúc Tổng Thể

```
Log Sources ──► Collector ──► Redis Streams ──► Parser (Drain3) ──► Detection Engine ──► AI SOC Analyst ──► Dashboard
                     │                                                        │
                     └── Syslog/UDP, Auditd, Suricata EVE, Windows Event       ├── Rule-based (YAML + MITRE)
                                                                               └── ML Anomaly (Isolation Forest)
```

## 🚀 Quick Start

### Yêu cầu
- **Docker** & **Docker Compose** (v2)
- 4GB+ RAM (8GB recommended)
- Optional: NVIDIA GPU cho AI SOC Agent

### Cài đặt và chạy (1 lệnh duy nhất)

```bash
# Linux / macOS
python install.py

# Windows (PowerShell)
python install.py
```

Sau khi chạy, mở **http://localhost:8080** để xem dashboard.

### Hoặc chạy thủ công

```bash
docker compose up -d --build
```

## 📊 Dashboard

Truy cập **http://localhost:8080**

| Page | Mô tả |
|------|-------|
| **Dashboard** | Tổng quan: stats, timeline chart, live log stream, alerts, MITRE heatmap |
| **Alerts** | Chi tiết alerts, filter theo severity, acknowledge, AI investigation |
| **Live Logs** | Real-time log stream từ các sources, filter theo source type |
| **MITRE ATT&CK** | Heatmap coverage theo tactic, mapping chi tiết |
| **Hosts** | Danh sách monitored hosts, criticality, alert count |

### API Endpoints

| Endpoint | Mô tả |
|----------|-------|
| `GET /api/stats` | Dashboard statistics |
| `GET /api/alerts` | Alert list (query params: limit, severity, status) |
| `GET /api/logs` | Recent logs (query params: limit, source, hostname) |
| `GET /api/timeline` | Event/alert count theo time |
| `GET /api/mitre/heatmap` | MITRE ATT&CK heatmap data |
| `GET /api/hosts` | Host inventory |
| `GET /api/investigations` | AI investigation reports |
| `WS /ws/logs` | Real-time log stream (WebSocket) |
| `WS /ws/alerts` | Real-time alert stream (WebSocket) |
| `WS /ws/stats` | Real-time stats stream (WebSocket) |

## 🧩 Components

### 1. Log Collector (`collector/`)
- **AuditdCollector**: Tail /var/log/audit/audit.log
- **SyslogCollector**: UDP syslog receiver (port 514)
- **FileCollector**: Generic file tail
- **WindowsEventCollector**: Windows Event Log via wevtutil
- **MockLogGenerator**: Fake logs for demo/testing

### 2. Parser (`parser/`)
- Regex-based field extraction (auditd, syslog RFC3164, Suricata EVE, Windows Event)
- Drain3 template mining
- ECS-like normalization

### 3. Detection (`detection/`)
- **Rule Engine**: YAML rules, stateful correlation (threshold, sequence), MITRE mapping
- **ML Engine**: Isolation Forest anomaly detection, feature importance explainability

### 4. Features (`features/`)
- Temporal (hour sin/cos, day_of_week, weekend)
- Event rate, source diversity, error ratio
- Template diversity, event type encoding
- Severity normalization, time-since-similar

### 5. AI SOC Agent (`ai_soc/`)
- Ollama local LLM integration
- Tool-based investigation: query_logs, enrich_ip, mitre_lookup, extract_iocs
- Structured report generation
- Fallback mode when LLM unavailable

### 6. Storage (`storage/`)
- TimescaleDB hypertable for hot logs
- PostgreSQL for alerts, investigations, MITRE cache
- SQLite fallback for dev

### 7. Dashboard (`dashboard/`)
- **Backend**: FastAPI + WebSocket real-time streaming
- **Frontend**: React 18 + Recharts + responsive dark theme SOC UI

## ⚙️ Custom Rules

Add/edit rules in `rules/custom_rules.yaml`:

```yaml
rules:
  - id: "MY_CUSTOM_RULE"
    name: "Custom Detection"
    severity: "high"
    enabled: true
    mitre:
      tactic: "TA0006"
      technique: "T1110"
    conditions:
      match:
        "message": "my pattern"
    correlation:
      type: "threshold"
      window_seconds: 300
      count: 5
```

## 🔧 Commands

```bash
# Start
python install.py

# Stop
python install.py --stop

# View logs
python install.py --logs

# Restart
python install.py --restart

# Update
python install.py --update

# Status
python install.py --status
```

## 🐳 Docker Services

| Service | Port | Mô tả |
|---------|------|-------|
| `pipeline` | - | Core SIEM pipeline |
| `dashboard-backend` | 8000 | FastAPI + WebSocket API |
| `dashboard-frontend` | 3000 | React SPA |
| `nginx` | 8080 | Reverse proxy |
| `redis` | 6379 | Message queue |
| `timescaledb` | 5432 | Time-series database |
| `ollama` | 11434 | Local LLM |

## 📁 Project Structure

```
socal-siem/
├── install.py              # Single-command installer
├── docker-compose.yml      # Service definitions
├── Dockerfile              # Pipeline container
├── .env.example            # Configuration template
├── main.py                 # Pipeline orchestrator
├── requirements.txt        # Python dependencies
├── collector/
│   ├── __init__.py
│   └── agent.py           # Log collectors
├── parser/
│   ├── __init__.py
│   └── drain_parser.py    # Log parsing & normalization
├── detection/
│   ├── __init__.py
│   ├── rules_engine.py    # Stateful correlation rules
│   └── ml_engine.py       # ML anomaly detection
├── features/
│   ├── __init__.py
│   └── extractor.py       # Feature extraction pipeline
├── ai_soc/
│   ├── __init__.py
│   └── agent.py           # AI SOC Analyst agent
├── storage/
│   ├── schema.sql         # Database schema
│   └── seed.sql           # MITRE & inventory seed data
├── rules/
│   └── custom_rules.yaml  # Detection rules
├── dashboard/
│   ├── backend/
│   │   ├── main.py        # FastAPI server
│   │   ├── Dockerfile
│   │   └── requirements.txt
│   └── frontend/
│       ├── public/
│       ├── src/
│       │   ├── App.js
│       │   ├── App.css
│       │   ├── pages/     # Dashboard, Alerts, Logs, MITRE, Hosts
│       │   └── components/ # StatCard, AlertList, TimelineChart, etc.
│       ├── package.json
│       ├── Dockerfile
│       └── nginx.conf
└── scripts/
    ├── deploy.sh           # Linux deployment
    └── deploy.ps1          # Windows deployment
```

## 🎯 Use Cases

1. **Security Monitoring**: Real-time log collection, parsing, and alerting
2. **Threat Detection**: Rule-based (MITRE ATT&CK) + ML anomaly detection
3. **Incident Investigation**: AI-powered SOC analyst generates structured reports
4. **Compliance**: Log storage, audit trail, MITRE mapping
5. **Demo/Lab**: Built-in mock log generator for testing

## 📝 License

MIT — Free to use, modify, and distribute.
