# UEBA System - Hướng Dẫn Cài Đặt & Kiểm Thử

## Hệ Thống Phát Hiện Tấn Công & Đánh Giá Truy Cập (UEBA)
**Phiên bản**: 2.0  
**Model hiện đại**: Deep Isolation Forest, Transformer, XGBoost, VAE Autoencoder  
**Framework**: MITRE ATT&CK, NIST SP 800-61

---

## Kiến Trúc Hệ Thống

```
┌─────────────┐    ┌──────────────┐    ┌─────────────────┐    ┌──────────────┐
│  Log Data   │───▶│  Pipeline    │───▶│  ML Models      │───▶│  Risk Engine │
│  (JSONL/CSV)│    │  Normalize   │    │  Anomaly + Class│    │  + MITRE Map │
└─────────────┘    └──────────────┘    └─────────────────┘    └──────┬───────┘
                                                                     │
┌─────────────┐    ┌──────────────┐    ┌─────────────────┐          │
│  Dashboard  │◀───│  FastAPI     │◀───│  Alert Store    │◀─────────┘
│  Chart.js   │    │  REST API    │    │  In-Memory      │
└─────────────┘    └──────────────┘    └─────────────────┘
```

---

## 1. Cài Đặt Nhanh (Ubuntu CLI)

### Yêu Cầu
- Python 3.10+
- pip
- Git (optional)

### Cài Đặt

```bash
# Bước 1: Clone project
cd /home/user
git clone <repo-url> ueba-system
# hoặc copy thư mục project từ Windows sang Ubuntu

cd ueba-system

# Bước 2: Cài dependencies
pip install -r requirements.txt

# Bước 3: Train models
python scripts/train.py

# Bước 4: Khởi động server
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Hoặc dùng startup script
```bash
chmod +x scripts/start.sh
./scripts/start.sh --train   # Train + Start
```

---

## 2. Kiểm Thử API (Ubuntu CLI)

Server chạy tại `http://localhost:8000`. Dùng curl để test:

### 2.1 Kiểm tra health
```bash
curl http://localhost:8000/api/v1/health
# {"status":"healthy","version":"2.0.0","models_ready":true,...}
```

### 2.2 Phân tích 1 event đơn lẻ
```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2026-06-09T03:15:00",
    "event_type": "windows_security_4625",
    "event_code": 4625,
    "user_name": "admin@corp.com",
    "source_ip": "45.33.32.156",
    "dest_ip": "10.0.0.1",
    "auth_type": "kerberos",
    "device_type": "windows_workstation",
    "hour_of_day": 3,
    "day_of_week": 2,
    "failed_attempts_last_1h": 50,
    "unique_dest_ips_last_1h": 1,
    "user_role": "admin",
    "asset_type": "domain_controller"
  }'
```

Kết quả mẫu (Brute Force attack detected at 3AM):
```json
{
  "risk": {
    "score": 87.3,
    "level": "critical",
    "attack_type": "brute_force",
    "tactic": "TA0006_Credential_Access",
    "risk_factors": [
      "Multiple failed logins (50 in 1h)",
      "Off-hours access (3:00, weekday)",
      "High-privilege role: admin"
    ],
    "recommendations": [
      "Immediate SOC escalation required",
      "Isolate affected user/asset"
    ]
  },
  "mitre_technique_ids": ["T1110"]
}
```

### 2.3 Batch analysis
```bash
curl -X POST http://localhost:8000/api/v1/analyze/batch \
  -H "Content-Type: application/json" \
  -d '{
    "events": [
      {"timestamp":"2026-06-09T08:00:00","event_type":"windows_security_4624","user_name":"alice@corp.com","hour_of_day":8,"failed_attempts_last_1h":0},
      {"timestamp":"2026-06-09T03:00:00","event_type":"windows_security_4625","user_name":"admin@corp.com","hour_of_day":3,"failed_attempts_last_1h":50}
    ]
  }'
```

### 2.4 Lấy alerts
```bash
# Tất cả alerts
curl http://localhost:8000/api/v1/alerts

# Chỉ critical
curl "http://localhost:8000/api/v1/alerts?level=critical"

# High risk score
curl "http://localhost:8000/api/v1/alerts?min_risk=65"
```

### 2.5 Dashboard data (JSON)
```bash
curl http://localhost:8000/api/v1/dashboard/summary
curl http://localhost:8000/api/v1/dashboard/risk-timeline?hours=24
curl http://localhost:8000/api/v1/dashboard/top-entities
curl http://localhost:8000/api/v1/dashboard/mitre-coverage
```

### 2.6 MITRE ATT&CK
```bash
# Danh sách techniques
curl http://localhost:8000/api/v1/mitre/techniques

# Chi tiết 1 technique
curl http://localhost:8000/api/v1/mitre/techniques/T1110

# Export MITRE Navigator layer
curl http://localhost:8000/api/v1/mitre/navigator-layer > ueba_mitre_layer.json
```

### 2.7 Kiểm tra model status
```bash
curl http://localhost:8000/api/v1/status
# {"isolation_forest":true,"deep_isolation_forest":true,"autoencoder_vae":true,...}
```

### 2.8 Train models via API
```bash
curl -X POST http://localhost:8000/api/v1/train \
  -H "Content-Type: application/json" \
  -d '{"epochs": 30, "learning_rate": 0.001, "batch_size": 256, "force_retrain": true}'
```

---

## 3. Mô Phỏng Dữ Liệu (Ubuntu CLI)

### 3.1 Generate synthetic logs
```bash
# Generate 2200 events (2000 normal + 200 attack)
python scripts/simulate_logs.py --n-normal 2000 --n-attack 200

# Generate nhiều hơn
python scripts/simulate_logs.py --n-normal 10000 --n-attack 1000
```

### 3.2 Stream logs trực tiếp vào API (real-time simulation)
```bash
# Stream 500 events với delay 0.05s mỗi event
python scripts/simulate_logs.py \
  --stream http://localhost:8000/api/v1/analyze \
  --n-normal 500 --n-attack 50 \
  --delay 0.05
```

### 3.3 Run demo pipeline
```bash
# Quick demo (không cần server)
python scripts/demo.py

# Full demo
python scripts/demo.py --full
```

---

## 4. Dashboard (Truy Cập Từ Windows)

Dashboard chạy trên browser, **tương thích mọi hệ điều hành** (Windows, Mac, Linux).

### 4.1 Truy cập
Sau khi server chạy trên Ubuntu, mở browser trên Windows:

```
http://<UBUNTU_IP>:8000/dashboard
```

Nếu test local:
```
http://localhost:8000/dashboard
http://127.0.0.1:8000/dashboard
```

### 4.2 Các trang dashboard

| Trang | URL | Chức năng |
|-------|-----|-----------|
| Tổng quan | `/dashboard` | KPI, biểu đồ risk timeline, attack distribution, top entities |
| Alerts | `/alerts` | Danh sách alert, filter theo level/type, pagination, acknowledge |
| Analytics | `/analytics` | Risk distribution histogram, severity pie, entity ranking |
| MITRE | `/mitre` | Coverage heatmap, technique details, export Navigator layer |
| Settings | `/settings` | Train models, view system status, risk thresholds |
| API Docs | `/docs` | Swagger UI documentation |
| ReDoc | `/redoc` | Alternative API docs |

### 4.3 Tính năng dashboard
- **Auto-refresh**: Dữ liệu cập nhật mỗi 10 giây
- **Filter alerts**: Theo risk level (critical/high/medium/low) và attack type
- **Acknowledge alerts**: Xác nhận đã xử lý
- **Export MITRE Navigator**: Tải về JSON để import vào MITRE ATT&CK Navigator
- **Train models**: Click button để train lại model từ dashboard

---

## 5. Docker Deployment

### 5.1 Build & run
```bash
# Build và chạy
docker-compose up -d

# Xem logs
docker-compose logs -f

# Dừng
docker-compose down
```

### 5.2 Kiểm tra container
```bash
docker ps
curl http://localhost:8000/api/v1/health
```

### 5.3 Mở rộng (Scaling)
```yaml
# docker-compose.yml - thêm nhiều instances
docker-compose up -d --scale ueba=3
```

---

## 6. Các Model AI Đã Implement

| Model | Loại | Mục Đích |
|-------|------|----------|
| **Deep Isolation Forest** | Unsupervised (Neural) | Phát hiện bất thường qua random projection + representation learning |
| **Isolation Forest** | Unsupervised (Ensemble) | Baseline anomaly detection |
| **VAE Autoencoder** | Unsupervised (Deep) | Reconstruction-based anomaly detection |
| **Transformer Encoder** | Self-Supervised | Sequence anomaly detection cho log time-series |
| **XGBoost** | Supervised | Phân loại attack type và MITRE tactic |

### Feature Engineering
- **Temporal**: hour_of_day, day_of_week, is_weekend
- **Behavioral**: session_duration, bytes_transferred, login_frequency
- **Security**: failed_attempts_last_1h, unique_dest_ips_last_1h
- **Contextual**: user_role, asset_type, geo_city/country
- **Categorical encoding**: user_name, source_ip, auth_type, device_type

### Risk Scoring Formula
```
Score = (Anomaly_Probability × MITRE_Impact_Weight) + Context_Bonus
```
Trong đó Context Bonus tính từ: role criticality, asset criticality, time (off-hours), failed logins, geo/device changes.

---

## 7. Kiểm Thử Toàn Diện

### 7.1 Chạy unit tests
```bash
python -m pytest tests/test_pipeline.py -v
```
hoặc
```bash
python tests/test_pipeline.py -v
```

### 7.2 Test kịch bản tấn công

| Kịch Bản | Event Pattern | Expected Result |
|-----------|--------------|-----------------|
| Brute Force | 50 failed logins từ IP lạ lúc 3AM | Critical alert, T1110 |
| Data Exfiltration | 10MB transfer ra IP lạ lúc 23h | Critical alert, T1048 |
| Lateral Movement | User login vào 12+ máy trong 1h | High alert, T1021 |
| Reconnaissance | 25+ DNS queries đến nhiều IP lạ | Medium alert, T1046 |
| Normal Activity | User login 9AM-5PM, local IP | Info/Low risk |

### 7.3 Test script mẫu
```bash
# Gửi 1 event normal
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"timestamp":"2026-06-09T14:30:00","event_type":"windows_security_4624","user_name":"alice@corp.com","source_ip":"10.0.0.1","hour_of_day":14,"failed_attempts_last_1h":0,"user_role":"user"}'

# Gửi 1 event attack (brute force)
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"timestamp":"2026-06-09T03:15:00","event_type":"windows_security_4625","user_name":"admin@corp.com","source_ip":"45.33.32.156","hour_of_day":3,"failed_attempts_last_1h":50,"user_role":"admin"}'
```

---

## 8. Cấu Trúc Thư Mục

```
ueba-system/
├── app/
│   ├── main.py              # FastAPI entry point
│   ├── config.py             # Configuration
│   ├── database.py           # In-memory alert store
│   ├── models/
│   │   ├── anomaly.py        # Deep Isolation Forest + VAE + IF
│   │   ├── sequence_model.py # Transformer for sequences
│   │   ├── classifier.py     # XGBoost classifier
│   │   └── risk_scorer.py    # Risk scoring engine
│   ├── pipeline/
│   │   ├── ingestion.py      # Log ingestion + synthetic generator
│   │   ├── normalizer.py     # ECS normalization + feature extraction
│   │   └── mitre.py          # MITRE ATT&CK mapping
│   ├── api/
│   │   ├── routes.py         # REST API endpoints
│   │   └── schemas.py        # Pydantic schemas
│   └── dashboard/
│       ├── templates/        # HTML templates (Jinja2 + Chart.js)
│       └── static/           # Static assets
├── scripts/
│   ├── train.py              # Model training script
│   ├── simulate_logs.py      # Log generation & streaming
│   └── demo.py               # End-to-end demo
├── tests/
│   └── test_pipeline.py      # Unit tests
├── data/                     # Data storage
├── Dockerfile                # Docker image
├── docker-compose.yml        # Docker orchestration
└── requirements.txt          # Python dependencies
```

---

## 9. Xử Lý Sự Cố

### Server không khởi động
```bash
# Kiểm tra port
sudo lsof -i :8000
# Kill process đang chiếm
sudo kill -9 <PID>

# Kiểm tra dependencies
pip install -r requirements.txt --upgrade
```

### Model training thất bại
```bash
# Kiểm tra data directory
ls -la data/
mkdir -p data/raw data/processed data/models

# Run với verbose
python scripts/train.py --epochs 10  # Test với epochs nhỏ trước
```

### Dashboard không hiển thị
- Kiểm tra browser console (F12) cho JavaScript errors
- Đảm bảo server đang chạy: `curl http://localhost:8000/api/v1/health`
- Thử hard refresh: `Ctrl+F5`
- Thử browser khác (Chrome, Edge, Firefox)

### Kết nối từ Windows tới Ubuntu server
```bash
# Trên Ubuntu, kiểm tra IP
ip addr show | grep inet
# Output: inet 192.168.1.100/24 ...
# Trên Windows, truy cập: http://192.168.1.100:8000/dashboard
```

---

## 10. API Cheat Sheet

```bash
# ── Analysis ──
POST /api/v1/analyze              # Phân tích 1 event
POST /api/v1/analyze/batch        # Phân tích batch events

# ── Alerts ──
GET  /api/v1/alerts                # Lấy alerts (có filter)
GET  /api/v1/alerts/:id            # Chi tiết 1 alert
POST /api/v1/alerts/:id/acknowledge # Xác nhận alert

# ── Dashboard ──
GET  /api/v1/dashboard/summary     # Dashboard data
GET  /api/v1/dashboard/risk-timeline # Risk timeline
GET  /api/v1/dashboard/top-entities # Top risk entities
GET  /api/v1/dashboard/mitre-coverage # MITRE coverage

# ── MITRE ──
GET  /api/v1/mitre/techniques      # All techniques
GET  /api/v1/mitre/techniques/:id  # Technique detail
GET  /api/v1/mitre/navigator-layer # Navigator JSON

# ── System ──
GET  /api/v1/health                # Health check
GET  /api/v1/status                # Model status
POST /api/v1/train                # Train models
POST /api/v1/train/from-data      # Train từ file
```

---

## 11. Mở Rộng & Tùy Chỉnh

### Thêm nguồn log mới
1. Tạo class mới trong `app/pipeline/ingestion.py`
2. Implement `ingest_<source>()` method
3. Map fields theo ECS schema trong `normalizer.py`

### Thêm MITRE technique mới
1. Thêm vào `MITRE_DATABASE` trong `app/pipeline/mitre.py`
2. Cập nhật `map_event_to_technique()` mapping

### Tune model
```python
from app.models.anomaly import AnomalyDetector
detector = AnomalyDetector({
    "contamination": 0.03,      # Giảm false positives
    "n_estimators": 500,        # Tăng độ chính xác
    "deep_hidden_dims": [256, 128, 64],  # Deep hơn
    "vae_latent_dim": 32,       # Tăng latent dimension
})
```

### Tune risk thresholds
```python
from app.config import settings
settings.RISK_CRITICAL_THRESHOLD = 90  # Chỉ cảnh báo critical ở 90+
settings.ANOMALY_THRESHOLD = 0.8       # Giảm false positives
```

---

> **UEBA System v2.0** - Built with Deep Learning, MITRE ATT&CK, and NIST framework compliance.
