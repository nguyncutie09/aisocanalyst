import React from 'react';

function formatTime(ts) {
    if (!ts) return '';
    try {
        const d = new Date(ts);
        return d.toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch { return ts; }
}

function SeverityBadge({ severity }) {
    return (
        <span className={`severity-badge ${severity}`}>
            {severity || 'unknown'}
        </span>
    );
}

export default function AlertList({ alerts, onInvestigate, maxHeight }) {
    if (!alerts || alerts.length === 0) {
        return <div className="panel-body" style={{ color: 'var(--text-muted)', textAlign: 'center', padding: 32 }}>No alerts yet</div>;
    }

    return (
        <div style={{ maxHeight: maxHeight || 400, overflowY: 'auto' }}>
            {alerts.slice(-50).reverse().map((alert, i) => (
                <div key={alert.id || i} className="alert-item" onClick={() => onInvestigate && onInvestigate(alert)}>
                    <SeverityBadge severity={alert.severity} />
                    <div className="alert-info">
                        <div className="alert-name">{alert.rule_name}</div>
                        <div className="alert-meta">
                            <span>{alert.hostname}</span>
                            <span>{alert.source}</span>
                            {alert.tags && alert.tags.slice(0, 3).map(t => (
                                <span key={t} className="status-tag">{t}</span>
                            ))}
                        </div>
                    </div>
                    <div className="alert-time">{formatTime(alert.timestamp)}</div>
                </div>
            ))}
        </div>
    );
}
