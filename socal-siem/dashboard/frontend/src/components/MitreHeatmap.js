import React, { useState, useEffect } from 'react';

const API_BASE = process.env.REACT_APP_API_URL || `http://${window.location.hostname}:8000`;

const SEVERITY_COLORS = {
    0: '#1a2332',
    1: '#1a3a1a',
    2: '#2a4a1a',
    3: '#3a5a1a',
    4: '#4a4a0a',
    5: '#5a3a0a',
    6: '#6a2a0a',
    7: '#7a1a0a',
    8: '#8a0a0a',
    9: '#9a0000',
    10: '#aa0000',
};

function getColor(count) {
    if (count === 0) return SEVERITY_COLORS[0];
    if (count >= 10) return SEVERITY_COLORS[10];
    return SEVERITY_COLORS[count];
}

export default function MitreHeatmap() {
    const [heatmap, setHeatmap] = useState({});

    useEffect(() => {
        const fetchHeatmap = async () => {
            try {
                const res = await fetch(`${API_BASE}/api/mitre/heatmap`);
                if (res.ok) {
                    setHeatmap(await res.json());
                }
            } catch {}
        };

        fetchHeatmap();
        const interval = setInterval(fetchHeatmap, 15000);
        return () => clearInterval(interval);
    }, []);

    const entries = Object.entries(heatmap);

    if (entries.length === 0) {
        return <div className="panel-body" style={{ color: 'var(--text-muted)', textAlign: 'center', padding: 32 }}>
            No MITRE data yet. Waiting for alerts...
        </div>;
    }

    return (
        <div className="mitre-grid">
            {entries.map(([tacticId, tactic]) => (
                <div
                    key={tacticId}
                    className="mitre-cell"
                    style={{ background: getColor(tactic.count) }}
                    title={`${tactic.name}: ${tactic.count} alerts`}
                >
                    <span className="mitre-count">{tactic.count}</span>
                    <span className="mitre-label">{tactic.name}</span>
                    {tactic.techniques && Object.entries(tactic.techniques).length > 0 && (
                        <div style={{ marginTop: 6, fontSize: 10, color: 'var(--text-muted)' }}>
                            {Object.entries(tactic.techniques).slice(0, 3).map(([techId, techCount]) => (
                                <div key={techId}>{techId}: {techCount}</div>
                            ))}
                        </div>
                    )}
                </div>
            ))}
        </div>
    );
}
