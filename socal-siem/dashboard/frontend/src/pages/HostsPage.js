import React, { useState, useEffect } from 'react';

const API_BASE = process.env.REACT_APP_API_URL || `http://${window.location.hostname}:8000`;

const CRIT_COLORS = {
    critical: 'var(--severity-critical)',
    high: 'var(--severity-high)',
    medium: 'var(--severity-medium)',
    low: 'var(--severity-low)',
};

export default function HostsPage() {
    const [hosts, setHosts] = useState([]);

    useEffect(() => {
        fetch(`${API_BASE}/api/hosts`).then(r => r.json())
            .then(setHosts).catch(() => {});
    }, []);

    return (
        <div>
            <h1 className="page-title">Hosts & Assets</h1>
            <p style={{ color: 'var(--text-muted)', marginBottom: 24 }}>
                Monitored hosts and their security status
            </p>

            <div className="host-grid">
                {hosts.map(host => (
                    <div key={host.hostname} className="host-card">
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <div className="host-name">{host.hostname}</div>
                            <span style={{
                                width: 8, height: 8, borderRadius: '50%',
                                background: host.online ? 'var(--accent-green)' : 'var(--text-muted)',
                                boxShadow: host.online ? '0 0 8px rgba(34,197,94,0.4)' : 'none',
                            }} />
                        </div>
                        <div className="host-detail">{host.ip} · {host.os}</div>
                        <div className="host-detail">
                            Criticality: <span style={{ color: CRIT_COLORS[host.criticality], fontWeight: 600 }}>
                                {host.criticality}
                            </span>
                        </div>
                        <div className="host-alerts" style={{ color: host.alert_count > 0 ? 'var(--severity-red)' : 'var(--text-muted)' }}>
                            {host.alert_count} alerts
                        </div>
                    </div>
                ))}
            </div>

            {hosts.length === 0 && (
                <div className="panel">
                    <div className="panel-body" style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 40 }}>
                        No hosts discovered yet
                    </div>
                </div>
            )}
        </div>
    );
}
