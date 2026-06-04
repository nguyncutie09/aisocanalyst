import { useEffect, useRef, useState, useCallback } from 'react';

const WS_BASE = process.env.REACT_APP_WS_URL || `ws://${window.location.hostname}:8000`;

export function useWebSocket(channel, onMessage) {
    const wsRef = useRef(null);
    const [connected, setConnected] = useState(false);
    const reconnectTimeoutRef = useRef(null);

    const connect = useCallback(() => {
        if (wsRef.current?.readyState === WebSocket.OPEN) return;

        const ws = new WebSocket(`${WS_BASE}/ws/${channel}`);
        wsRef.current = ws;

        ws.onopen = () => {
            setConnected(true);
            console.log(`WS connected: ${channel}`);
        };

        ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                if (onMessage) onMessage(data);
            } catch (e) {
                console.warn('WS parse error:', e);
            }
        };

        ws.onclose = () => {
            setConnected(false);
            wsRef.current = null;
            // Auto-reconnect after 3 seconds
            reconnectTimeoutRef.current = setTimeout(connect, 3000);
        };

        ws.onerror = () => {
            ws.close();
        };
    }, [channel, onMessage]);

    useEffect(() => {
        connect();
        return () => {
            if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
            if (wsRef.current) wsRef.current.close();
        };
    }, [connect]);

    return { connected };
}

export default useWebSocket;
