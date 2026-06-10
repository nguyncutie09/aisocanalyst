"""End-to-end test for UEBA system."""
import sys, os
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

import requests

BASE = 'http://localhost:8000/api/v1'

def test_health():
    r = requests.get(f'{BASE}/health', timeout=5)
    assert r.status_code == 200, f"Health check failed: {r.status_code}"
    d = r.json()
    print(f"[OK] Health: models_ready={d['models_ready']}")
    return d

def test_train():
    print("[1] Training models via API...")
    r = requests.post(f'{BASE}/train', json={
        'epochs': 20, 'batch_size': 256, 'learning_rate': 0.001, 'force_retrain': True
    }, timeout=300)
    assert r.status_code == 200
    d = r.json()
    assert d['status'] == 'success'
    print(f"    Status: {d['status']}")
    print(f"    Models: {d['models_trained']}")
    print(f"    Time: {d['training_time_seconds']}s")
    print(f"    Accuracy: {d['metrics']['accuracy']:.4f}")
    return d

def test_brute_force():
    print("\n[2] Testing brute force attack (3AM, 50 failed logins, admin)...")
    event = {
        'timestamp': '2026-06-09T03:15:00', 'event_type': 'windows_security_4625',
        'event_code': 4625, 'user_name': 'admin@corp.com',
        'source_ip': '45.33.32.156', 'dest_ip': '10.0.0.1',
        'auth_type': 'kerberos', 'device_type': 'windows_workstation',
        'hour_of_day': 3, 'day_of_week': 2, 'is_weekend': False,
        'session_duration_sec': 0, 'bytes_transferred': 0,
        'failed_attempts_last_1h': 50, 'unique_dest_ips_last_1h': 1,
        'login_frequency_last_1h': 0, 'user_role': 'admin',
        'asset_type': 'domain_controller', 'geo_city': 'Moscow', 'geo_country': 'RU'
    }
    r = requests.post(f'{BASE}/analyze', json=event, timeout=10)
    assert r.status_code == 200
    d = r.json()
    risk = d['risk']
    print(f"    Risk Score: {risk['score']:.1f}")
    print(f"    Level: {risk['level']}")
    print(f"    Attack Type: {risk['attack_type']}")
    print(f"    Tactic: {risk['tactic']}")
    print(f"    Confidence: {risk['confidence']:.3f}")
    print(f"    Anomaly Scores: {d['anomaly_scores']}")
    print(f"    MITRE: {d['mitre_technique_ids']}")
    if d['anomaly_scores']['ensemble'] != 0.5:
        print(f"    [OK] Real anomaly inference active")
    else:
        print(f"    [WARN] ensemble=0.5 fallback")
    return d

def test_normal():
    print("\n[3] Testing normal activity (business hours)...")
    event = {
        'timestamp': '2026-06-09T14:30:00', 'event_type': 'windows_security_4624',
        'event_code': 4624, 'user_name': 'alice@corp.com',
        'source_ip': '10.0.0.1', 'dest_ip': '10.0.0.2',
        'auth_type': 'kerberos', 'device_type': 'windows_workstation',
        'hour_of_day': 14, 'day_of_week': 2, 'is_weekend': False,
        'session_duration_sec': 3600, 'bytes_transferred': 1024,
        'failed_attempts_last_1h': 0, 'unique_dest_ips_last_1h': 2,
        'login_frequency_last_1h': 1, 'user_role': 'user',
        'asset_type': 'workstation', 'geo_city': 'Singapore', 'geo_country': 'SG'
    }
    r = requests.post(f'{BASE}/analyze', json=event, timeout=10)
    assert r.status_code == 200
    d = r.json()
    risk = d['risk']
    print(f"    Risk Score: {risk['score']:.1f}")
    print(f"    Level: {risk['level']}")
    print(f"    Attack Type: {risk['attack_type']}")
    return d

def test_exfiltration():
    print("\n[4] Testing data exfiltration (50MB outbound, 10PM)...")
    event = {
        'timestamp': '2026-06-09T22:00:00', 'event_type': 'web_request',
        'event_code': 200, 'user_name': 'bob@corp.com',
        'source_ip': '10.0.0.5', 'dest_ip': '203.0.113.50',
        'auth_type': 'oauth', 'device_type': 'server',
        'hour_of_day': 22, 'day_of_week': 1, 'is_weekend': False,
        'session_duration_sec': 500, 'bytes_transferred': 50000000,
        'failed_attempts_last_1h': 0, 'unique_dest_ips_last_1h': 1,
        'login_frequency_last_1h': 1, 'user_role': 'user',
        'asset_type': 'server', 'geo_city': 'Unknown', 'geo_country': 'XX'
    }
    r = requests.post(f'{BASE}/analyze', json=event, timeout=10)
    assert r.status_code == 200
    d = r.json()
    risk = d['risk']
    print(f"    Risk Score: {risk['score']:.1f}")
    print(f"    Level: {risk['level']}")
    print(f"    Attack Type: {risk['attack_type']}")
    print(f"    Anomaly: {d['anomaly_scores']}")
    return d

def test_alerts():
    print("\n[5] Checking alerts endpoint...")
    r = requests.get(f'{BASE}/alerts?limit=10', timeout=5)
    assert r.status_code == 200
    alerts = r.json()
    print(f"    Total alerts: {len(alerts)}")
    for a in alerts[:3]:
        print(f"    [{a['risk_level']}] {a['attack_type']} | score={a['risk_score']:.1f}")
    return alerts

def test_mitre():
    print("\n[6] Checking MITRE techniques...")
    r = requests.get(f'{BASE}/mitre/techniques', timeout=5)
    assert r.status_code == 200
    techniques = r.json()
    print(f"    Total techniques: {len(techniques)}")
    if 'T1110' in techniques:
        print(f"    T1110: {techniques['T1110']['name']} (score: {techniques['T1110']['severity']})")
    return techniques

def test_dashboard():
    print("\n[7] Checking dashboard summary...")
    r = requests.get(f'{BASE}/dashboard/summary', timeout=5)
    assert r.status_code == 200
    d = r.json()
    print(f"    Events: {d['total_events_analyzed']} | Alerts: {d['active_alerts']}")
    print(f"    Critical: {d['critical_alerts']} | High: {d['high_alerts']} | Medium: {d['medium_alerts']}")
    return d

def test_dashboard_html():
    print("\n[8] Checking dashboard HTML pages...")
    for page in ['/dashboard', '/alerts', '/analytics', '/mitre']:
        r = requests.get(f'http://localhost:8000{page}', timeout=5)
        assert r.status_code == 200, f"{page} returned {r.status_code}"
        print(f"    [OK] {page} ({len(r.text)} bytes)")
    print("    All dashboard pages loading")

if __name__ == '__main__':
    print("=== UEBA End-to-End Test ===\n")
    test_health()
    test_train()
    d1 = test_brute_force()
    test_normal()
    test_exfiltration()
    test_alerts()
    test_mitre()
    test_dashboard()
    test_dashboard_html()
    print("\n=== ALL TESTS PASSED ===")
