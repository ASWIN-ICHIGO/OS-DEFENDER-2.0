import { Outlet } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { useState, useEffect } from 'react';
import type { AgentStatus } from '../lib/types';
import { getAgentStatus } from '../lib/ipc';

export function Layout() {
  const [collapsed, setCollapsed] = useState(false);
  const [status, setStatus] = useState<AgentStatus | null>(null);

  useEffect(() => {
    const poll = async () => {
      try {
        const s = await getAgentStatus();
        setStatus(s);
      } catch {
        setStatus(null);
      }
    };
    poll();
    const id = setInterval(poll, 5000);
    return () => clearInterval(id);
  }, []);

  return (
    <div className="app-layout">
      <Sidebar collapsed={collapsed} onToggle={() => setCollapsed(!collapsed)} />
      <div className={`main-content ${collapsed ? 'sidebar-collapsed' : ''}`}>
        <header className="top-bar">
          <div className="status-indicator">
            <span className={`dot ${status?.running ? 'active' : 'inactive'}`} />
            <span className="status-text">
              {status?.running ? 'Agent Active' : 'Agent Offline'}
            </span>
          </div>
          {status && (
            <div className="status-stats">
              <span className="stat">
                <span className="stat-value">{status.events_processed.toLocaleString()}</span>
                <span className="stat-label">Events</span>
              </span>
              <span className="stat">
                <span className="stat-value">{status.alerts_generated.toLocaleString()}</span>
                <span className="stat-label">Alerts</span>
              </span>
              <span className="stat">
                <span className="stat-value">{status.policy_mode}</span>
                <span className="stat-label">Mode</span>
              </span>
              <span className="stat">
                <span className="stat-value">v{status.version}</span>
                <span className="stat-label">Version</span>
              </span>
            </div>
          )}
        </header>
        <main className="page-content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
