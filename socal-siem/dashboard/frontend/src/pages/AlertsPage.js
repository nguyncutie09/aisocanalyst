import React, { useState, useEffect, useCallback } from 'react';
import AlertList from '../components/AlertList';
import useWebSocket from '../components/useWebSocket';

const API_BASE = process.env.REACT_APP_API_URL || `http://${window.location.hostname}:8000`;

export default function AlertsPage() {
    const [alerts, setAlerts] = useState([]);
    const [filter, setFilter] = useState('all');
    const [selectedAlert, setSelectedAlert] = useState(null);
    const [investigation, setInvestigation] = useState(null);

    // Fetch initial alerts
    useEffect(() => {
        fetch(`${API_BASE}/api/alerts?limit=200`).then(r => r.json())
            .then(setAlerts).catch(() => {});
    }, []);

    // Live updates
    const handleAlert = useCallback((msg) => {
        if (msg.type === 'alert') {
            setAlerts(prev => {
                const next = [...prev, msg.data];
                if (next.length > 200) return next.slice(-200);
                return next;
            });
        }
    }, []);

    useWebSocket('alerts', handleAlert);

    const filteredAlerts = filter === 'all'
        ? alerts
        : alerts.filter(a => a.severity === filter);

    const handleInvestigate = async (alert) => {
        setSelectedAlert(alert);
        try {
            const res = await fetch(`${API_BASE}/api/alerts/${alert.id}/investigate`, { method: 'POST' });
            if (res.ok) {
                setInvestigation(await res.json());
            }
        } catch {}
    };

    const handleAcknowledge = async (alertId) => {
        try {
            await fetch(`${API_BASE}/api/alerts/${alertId}/acknowledge`, { method: 'POST' });
            setAlerts(prev => prev.map(a =>
                a.id === alertId ? { ...a, status: 'acknowledged' } : a
            ));
        } catch {}
    };

    return (
        <div>
            <h1 className="page-title">Alerts</h1>

            <div className="filter-bar">
                <select value={filter} onChange={e => setFilter(e.target.value)}>
                    <option value="all">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                </select>
                <span style={{ color: 'var(--text-muted)', fontSize: 13, alignSelf: 'center' }}>
                    {filteredAlerts.length} alerts
                </span>
            </div>

            <div className="grid-2">
                <div className="panel">
                    <div className="panel-header">Alert List</div>
                    <AlertList alerts={filteredAlerts} onInvestigate={handleInvestigate} maxHeight={600} />
                </div>

                <div>
                    {selectedAlert ? (
                        <div className="panel">
                            <div className="panel-header">
                                <span>Alert Detail: {selectedAlert.rule_name}</span>
                                <button
                                    className="btn btn-primary"
                                    onClick={() => handleAcknowledge(selectedAlert.id)}
                                >
                                    Acknowledge
                                </button>
                            </div>
                            <div className="panel-body">
                                <table className="data-table">
                                    <tbody>
                                        <tr><td style={{ fontWeight: 600 }}>Rule</td><td>{selectedAlert.rule_name}</td></tr>
                                        <tr><td style={{ fontWeight: 600 }}>Severity</td><td><span className={`severity-badge ${selectedAlert.severity}`}>{selectedAlert.severity}</span></td></tr>
                                        <tr><td style={{ fontWeight: 600 }}>Host</td><td>{selectedAlert.hostname}</td></tr>
                                        <tr><td style={{ fontWeight: 600 }}>Source</td><td>{selectedAlert.source}</td></tr>
                                        <tr><td style={{ fontWeight: 600 }}>Status</td><td><span className={`status-tag ${selectedAlert.status}`}>{selectedAlert.status}</span></td></tr>
                                        <tr><td style={{ fontWeight: 600 }}>Time</td><td>{selectedAlert.timestamp}</td></tr>
                                        <tr><td style={{ fontWeight: 600 }}>MITRE Technique</td><td>{selectedAlert.mitre_technique || 'N/A'}</td></tr>
                                        <tr><td style={{ fontWeight: 600 }}>Message</td><td style={{ wordBreak: 'break-word' }}>{selectedAlert.message}</td></tr>
                                    </tbody>
                                </table>

                                {investigation && (
                                    <div style={{ marginTop: 16 }}>
                                        <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 8, color: 'var(--accent-cyan)' }}>
                                            AI Investigation Report
                                        </h3>
                                        <div style={{ background: '#0d1117', padding: 16, borderRadius: 8, fontSize: 13, lineHeight: 1.6, color: 'var(--text-secondary)' }}>
                                            <p><strong>Confidence:</strong> {investigation.confidence}</p>
                                            <p>{investigation.summary}</p>
                                        </div>
                                    </div>
                                )}
                            </div>
                        </div>
                    ) : (
                        <div className="panel">
                            <div className="panel-body" style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 40 }}>
                                Select an alert to view details
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
