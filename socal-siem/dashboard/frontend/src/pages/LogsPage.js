import React, { useState } from 'react';
import LiveLogStream from '../components/LiveLogStream';

export default function LogsPage() {
    const [filterSource, setFilterSource] = useState('all');

    return (
        <div>
            <h1 className="page-title">Live Logs</h1>

            <div className="filter-bar">
                <select
                    value={filterSource}
                    onChange={e => setFilterSource(e.target.value)}
                >
                    <option value="all">All Sources</option>
                    <option value="syslog">Syslog</option>
                    <option value="auditd">Auditd</option>
                    <option value="suricata">Suricata</option>
                    <option value="windows_event">Windows Event</option>
                </select>
            </div>

            <div className="panel">
                <div className="panel-header">
                    <span>Log Stream</span>
                </div>
                <div className="panel-body">
                    <LiveLogStream
                        maxEntries={200}
                        filterSource={filterSource === 'all' ? null : filterSource}
                    />
                </div>
            </div>
        </div>
    );
}
