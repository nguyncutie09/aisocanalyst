import React, { useState, useEffect } from 'react';
import {
    AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Legend
} from 'recharts';

const API_BASE = process.env.REACT_APP_API_URL || `http://${window.location.hostname}:8000`;

export default function TimelineChart({ minutes = 30 }) {
    const [data, setData] = useState([]);

    useEffect(() => {
        const fetchTimeline = async () => {
            try {
                const res = await fetch(`${API_BASE}/api/timeline?minutes=${minutes}`);
                if (res.ok) {
                    const json = await res.json();
                    const chartData = json.timestamps.map((ts, i) => ({
                        time: new Date(ts).toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
                        events: json.events[i] || 0,
                        alerts: json.alerts[i] || 0,
                    }));
                    setData(chartData);
                }
            } catch {}
        };

        fetchTimeline();
        const interval = setInterval(fetchTimeline, 10000);
        return () => clearInterval(interval);
    }, [minutes]);

    if (data.length === 0) {
        return <div className="loading"><div className="spinner" /> Loading timeline...</div>;
    }

    return (
        <div className="chart-container">
            <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={data}>
                    <defs>
                        <linearGradient id="colorEvents" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                            <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                        </linearGradient>
                        <linearGradient id="colorAlerts" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                            <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                        </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis dataKey="time" stroke="#64748b" fontSize={11} />
                    <YAxis stroke="#64748b" fontSize={11} />
                    <Tooltip
                        contentStyle={{
                            background: '#1a2332',
                            border: '1px solid #1e293b',
                            borderRadius: 8,
                            color: '#e2e8f0',
                            fontSize: 12,
                        }}
                    />
                    <Legend />
                    <Area
                        type="monotone"
                        dataKey="events"
                        stroke="#3b82f6"
                        fillOpacity={1}
                        fill="url(#colorEvents)"
                        name="Events"
                    />
                    <Area
                        type="monotone"
                        dataKey="alerts"
                        stroke="#ef4444"
                        fillOpacity={1}
                        fill="url(#colorAlerts)"
                        name="Alerts"
                    />
                </AreaChart>
            </ResponsiveContainer>
        </div>
    );
}
