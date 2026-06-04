import React from 'react';
import { BrowserRouter as Router, Routes, Route, Link, useLocation } from 'react-router-dom';
import Dashboard from './pages/Dashboard';
import AlertsPage from './pages/AlertsPage';
import LogsPage from './pages/LogsPage';
import MitrePage from './pages/MitrePage';
import HostsPage from './pages/HostsPage';
import './App.css';

function NavLink({ to, icon, label }) {
    const location = useLocation();
    const isActive = location.pathname === to;
    return (
        <Link to={to} className={`nav-link ${isActive ? 'active' : ''}`}>
            <span className="nav-icon">{icon}</span>
            <span className="nav-label">{label}</span>
        </Link>
    );
}

function AppLayout() {
    return (
        <div className="app-layout">
            <aside className="sidebar">
                <div className="sidebar-header">
                    <h1 className="logo">SOCal SIEM</h1>
                    <span className="logo-sub">Security Dashboard</span>
                </div>
                <nav className="sidebar-nav">
                    <NavLink to="/" icon="📊" label="Dashboard" />
                    <NavLink to="/alerts" icon="🔔" label="Alerts" />
                    <NavLink to="/logs" icon="📋" label="Live Logs" />
                    <NavLink to="/mitre" icon="🎯" label="MITRE ATT&CK" />
                    <NavLink to="/hosts" icon="🖥️" label="Hosts" />
                </nav>
                <div className="sidebar-footer">
                    <span className="status-dot online"></span>
                    System Online
                </div>
            </aside>
            <main className="main-content">
                <Routes>
                    <Route path="/" element={<Dashboard />} />
                    <Route path="/alerts" element={<AlertsPage />} />
                    <Route path="/logs" element={<LogsPage />} />
                    <Route path="/mitre" element={<MitrePage />} />
                    <Route path="/hosts" element={<HostsPage />} />
                </Routes>
            </main>
        </div>
    );
}

export default function App() {
    return (
        <Router>
            <AppLayout />
        </Router>
    );
}
