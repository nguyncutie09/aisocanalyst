/**
 * UEBA Dashboard - Main JavaScript
 * Shared utilities for dashboard pages.
 */

const API_BASE = '/api/v1';

/**
 * Fetch JSON from the UEBA API.
 * @param {string} url - API endpoint path
 * @param {Object} options - Fetch options
 * @returns {Promise<Object|null>}
 */
async function apiFetch(url, options = {}) {
    try {
        const res = await fetch(url.startsWith('/') ? url : `${API_BASE}${url}`, options);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return await res.json();
    } catch (err) {
        console.error(`API Error [${url}]:`, err);
        return null;
    }
}

/**
 * Get CSS class for risk level badge.
 * @param {string} level - risk level
 * @returns {string} CSS class name
 */
function riskBadgeClass(level) {
    const map = {
        'critical': 'badge-critical',
        'high': 'badge-high',
        'medium': 'badge-medium',
        'low': 'badge-low',
        'info': 'badge-info',
    };
    return map[level] || 'badge-info';
}

/**
 * Format ISO timestamp to locale string.
 * @param {string} ts - ISO timestamp
 * @returns {string}
 */
function fmtTime(ts) {
    if (!ts) return '-';
    try {
        return new Date(ts).toLocaleString();
    } catch {
        return ts;
    }
}

/**
 * Format large numbers with K/M suffix.
 * @param {number} n
 * @returns {string}
 */
function fmtNum(n) {
    if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
    if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
    return n.toString();
}

/**
 * Update system status indicator.
 * @param {boolean} healthy
 */
function updateSystemStatus(healthy) {
    const dot = document.querySelector('.status-dot');
    const text = document.getElementById('systemStatus');
    if (dot) {
        dot.style.background = healthy ? 'var(--risk-low)' : 'var(--risk-critical)';
    }
    if (text) {
        text.textContent = healthy ? 'System Ready' : 'Disconnected';
    }
}

// Periodic health check
setInterval(async () => {
    const health = await apiFetch('/api/v1/health');
    updateSystemStatus(health && health.status === 'healthy');
}, 30000);

// Initial health check
(async () => {
    const health = await apiFetch('/api/v1/health');
    updateSystemStatus(health && health.status === 'healthy');
})();
