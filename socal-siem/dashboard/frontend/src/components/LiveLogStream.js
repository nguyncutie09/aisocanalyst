import React, { useState, useRef, useEffect } from 'react';
import useWebSocket from './useWebSocket';

function formatTime(ts) {
    if (!ts) return '';
    try {
        const d = new Date(ts);
        return d.toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch { return ''; }
}

export default function LiveLogStream({ maxEntries = 100, filterSource }) {
    const [logs, setLogs] = useState([]);
    const streamRef = useRef(null);
    const autoScrollRef = useRef(true);

    const handleLog = (msg) => {
        if (msg.type === 'log') {
            const entry = msg.data;
            if (filterSource && entry.source !== filterSource) return;

            setLogs(prev => {
                const next = [...prev, entry];
                if (next.length > maxEntries) return next.slice(-maxEntries);
                return next;
            });
        }
    };

    const { connected } = useWebSocket('logs', handleLog);

    // Auto-scroll
    useEffect(() => {
        if (autoScrollRef.current && streamRef.current) {
            streamRef.current.scrollTop = streamRef.current.scrollHeight;
        }
    }, [logs]);

    const handleScroll = () => {
        if (!streamRef.current) return;
        const { scrollTop, scrollHeight, clientHeight } = streamRef.current;
        autoScrollRef.current = scrollHeight - scrollTop - clientHeight < 50;
    };

    const getLogClass = (entry) => {
        const tags = entry.tags || [];
        const msg = (entry.message || '').toLowerCase();
        if (tags.includes('suricata_alert') || msg.includes('malware') || msg.includes('attack')) return 'critical-log';
        if (tags.includes('login_failure') || tags.includes('privilege') || msg.includes('fail') || msg.includes('denied')) return 'alert-log';
        return '';
    };

    return (
        <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>
                    {connected ? '🟢 Live' : '🔴 Disconnected'}
                </span>
                <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>
                    {logs.length} events
                </span>
            </div>
            <div className="log-stream" ref={streamRef} onScroll={handleScroll}>
                {logs.length === 0 ? (
                    <div style={{ color: 'var(--text-muted)', textAlign: 'center', padding: 40 }}>
                        Waiting for events...
                    </div>
                ) : (
                    logs.map((entry, i) => (
                        <div key={i} className={`log-line ${getLogClass(entry)}`}>
                            <span className="log-time">{formatTime(entry['@timestamp'])}</span>
                            <span className="log-source">{entry.source || '?'}</span>
                            <span className="log-msg">
                                {entry.hostname && `[${entry.hostname}] `}
                                {(entry.message || entry.raw || '').substring(0, 200)}
                            </span>
                        </div>
                    ))
                )}
            </div>
        </div>
    );
}
