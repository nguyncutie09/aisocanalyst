import React, { useState, useEffect, useCallback } from 'react';
import StatCard from '../components/StatCard';
import AlertList from '../components/AlertList';
import LiveLogStream from '../components/LiveLogStream';
import TimelineChart from '../components/TimelineChart';
import MitreHeatmap from '../components/MitreHeatmap';
import useWebSocket from '../components/useWebSocket';

const API_BASE = process.env.REACT_APP_API_URL || `http://${window.location.hostname}:8000`;

export default function Dashboard() {
    const [stats, setStats] = useState({
        total_events: 0,
        total_alerts: 0,
        events_per_second: 0,
        alerts_by_severity: { critical: 0, high: 0, medium: 0, low: 0 },
        ml_status: 'training',
        ml_samples: 0,
        active_rules: 12,
    });
    const [alerts, setAlerts] = useState([]);

    // WebSocket for stats
    const handleStats = useCallback((msg) => {
        if (msg.type === 'stats') setStats(msg.data);
    }, []);

    useWebSocket('stats', handleStats);

    // WebSocket for alerts
    const handleAlert = useCallback((msg) => {
        if (msg.type === 'alert') {
            setAlerts(prev => {
                const next = [...prev, msg.data];
                if (next.length > 100) return next.slice(-100);
                return next;
            });
        }
    }, []);

    useWebSocket('alerts', handleAlert);

    // Fetch initial stats
    useEffect(() => {
        const fetchStats = async () => {
            try {
                const res = await fetch(`${API_BASE}/api/stats`);
                if (res.ok) setStats(await res.json());
            } catch {}
        };
        fetchStats();

        const fetchAlerts = async () => {
            try {
                const res = await fetch(`${API_BASE}/api/alerts?limit=50`);
                if (res.ok) setAlerts(await res.json());
            } catch {}
        };
        fetchAlerts();
    }, []);

    const handleInvestigate = (alert) => {
        fetch(`${API_BASE}/api/alerts/${alert.id}/investigate`, { method: 'POST' }).catch(() => {});
    };

    const { critical = 0, high = 0, medium = 0, low = 0 } = stats.alerts_by_severity || {};

    return (
        <div>
            <div className="dashboard-header">
                <h1>Security Dashboard</h1>
                <p>Real-time monitoring and threat detection</p>
            </div>

            {/* Stats Cards */}
            <div className="stats-grid">
                <StatCard label="Events" value={stats.total_events?.toLocaleString()} sub={`${stats.events_per_second?.toFixed(1) || 0} eps`} variant="info" />
                <StatCard label="Total Alerts" value={stats.total_alerts} variant="critical" />
                <StatCard label="Critical" value={critical} variant="critical" />
                <StatCard label="High" value={high} variant="high" />
                <StatCard label="Medium" value={medium} variant="medium" />
                <StatCard
                    label="ML Engine"
                    value={stats.ml_status === 'active' ? 'Active' : 'Training'}
                    sub={`${stats.ml_samples} samples`}
                    variant={stats.ml_status === 'active' ? 'info' : 'medium'}
                />
            </div>

            {/* Timeline + Alerts */}
            <div className="grid-2">
                <div className="panel">
                    <div className="panel-header">
                        <span>Event Timeline</span>
                        <span className="badge">Live</span>
                    </div>
                    <div className="panel-body">
                        <TimelineChart minutes={30} />
                    </div>
                </div>

                <div className="panel">
                    <div className="panel-header">
                        <span>Recent Alerts</span>
                        <span className="badge">{alerts.length}</span>
                    </div>
                    <AlertList alerts={alerts} onInvestigate={handleInvestigate} maxHeight={300} />
                </div>
            </div>

            {/* Live Log Stream */}
            <div className="panel">
                <div className="panel-header">
                    <span>Live Log Stream</span>
                </div>
                <div className="panel-body">
                    <LiveLogStream maxEntries={50} />
                </div>
            </div>

            {/* MITRE Heatmap */}
            <div className="panel">
                <div className="panel-header">
                    <span>MITRE ATT&CK Coverage</span>
                </div>
                <div className="panel-body">
                    <MitreHeatmap />
                </div>
            </div>
        </div>
    );
}
