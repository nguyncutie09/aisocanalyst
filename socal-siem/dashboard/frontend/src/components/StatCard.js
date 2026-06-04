import React from 'react';

export default function StatCard({ label, value, sub, variant = 'info' }) {
    return (
        <div className={`stat-card ${variant}`}>
            <div className="stat-label">{label}</div>
            <div className="stat-value">{value ?? '—'}</div>
            {sub && <div className="stat-sub">{sub}</div>}
        </div>
    );
}
