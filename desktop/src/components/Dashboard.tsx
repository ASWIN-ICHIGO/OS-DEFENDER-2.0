import { useState, useEffect } from 'react';
import type { AgentStatus, NormalizedEvent, AiEngineStatus } from '../lib/types';
import { getAgentStatus, getEvents, getAlerts, getAiStatus } from '../lib/ipc';

export function Dashboard() {
  const [status, setStatus] = useState<AgentStatus | null>(null);
  const [recentEvents, setRecentEvents] = useState<NormalizedEvent[]>([]);
  const [recentAlerts, setRecentAlerts] = useState<NormalizedEvent[]>([]);
  const [aiStatus, setAiStatus] = useState<AiEngineStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const load = async () => {
      try {
        const [s, ev, al, ai] = await Promise.all([
          getAgentStatus(),
          getEvents(10),
          getAlerts(5),
          getAiStatus(),
        ]);
        setStatus(s);
        setRecentEvents(ev);
        setRecentAlerts(al);
        setAiStatus(ai);
        setError(null);
      } catch (e) {
        setError(String(e));
      }
    };
    load();
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  }, []);

  if (error) {
    return (
      <div className="page">
        <h1 className="page-title">Dashboard</h1>
        <div className="card error-card">
          <p>Agent connection failed: {error}</p>
          <p className="hint">Make sure the OS Defender agent is running.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      <h1 className="page-title">Dashboard</h1>

      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-card-value">{status?.events_processed.toLocaleString() ?? '—'}</div>
          <div className="stat-card-label">Events Processed</div>
        </div>
        <div className="stat-card accent">
          <div className="stat-card-value">{status?.alerts_generated.toLocaleString() ?? '—'}</div>
          <div className="stat-card-label">Alerts Generated</div>
        </div>
        <div className="stat-card success">
          <div className="stat-card-value">{status?.actions_taken.toLocaleString() ?? '—'}</div>
          <div className="stat-card-label">Actions Taken</div>
        </div>
        <div className="stat-card">
          <div className="stat-card-value">{formatUptime(status?.uptime_secs ?? 0)}</div>
          <div className="stat-card-label">Uptime</div>
        </div>
      </div>

      <div className="dashboard-grid">
        <div className="card">
          <h2 className="card-title">Active Collectors</h2>
          <div className="collector-list">
            {status?.collectors_active.map((c) => (
              <span key={c} className="badge badge-success">{c}</span>
            )) ?? <span className="text-muted">None</span>}
          </div>
        </div>

        <div className="card">
          <h2 className="card-title">AI Engine</h2>
          {aiStatus ? (
            <div className="ai-summary">
              <div className="ai-row">
                <span>Model</span>
                <span className={`badge ${aiStatus.model_loaded ? 'badge-success' : 'badge-muted'}`}>
                  {aiStatus.model_loaded ? 'Loaded' : 'Not loaded'}
                </span>
              </div>
              <div className="ai-row">
                <span>Baseline</span>
                <span className={`badge ${aiStatus.baseline_learned ? 'badge-success' : 'badge-warning'}`}>
                  {aiStatus.baseline_learned ? 'Learned' : 'Learning'}
                </span>
              </div>
              <div className="ai-row">
                <span>Anomalies</span>
                <span className="text-accent">{aiStatus.anomalies_detected}</span>
              </div>
              <div className="ai-row">
                <span>Drift</span>
                <span className={aiStatus.drift_detected ? 'text-danger' : 'text-success'}>
                  {aiStatus.drift_detected ? 'Detected' : 'Stable'}
                </span>
              </div>
            </div>
          ) : (
            <span className="text-muted">Unavailable</span>
          )}
        </div>
      </div>

      <div className="card">
        <h2 className="card-title">Recent Alerts</h2>
        {recentAlerts.length === 0 ? (
          <p className="text-muted">No recent alerts</p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Type</th>
                <th>Severity</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {recentAlerts.map((a) => (
                <tr key={a.event_id}>
                  <td className="mono">{new Date(a.timestamp).toLocaleTimeString()}</td>
                  <td>{a.event_type}</td>
                  <td><span className={`badge badge-${severityColor(a.severity)}`}>{a.severity}</span></td>
                  <td className="truncate">{eventSummary(a)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="card">
        <h2 className="card-title">Recent Events</h2>
        {recentEvents.length === 0 ? (
          <p className="text-muted">No events yet</p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Type</th>
                <th>Severity</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {recentEvents.map((e) => (
                <tr key={e.event_id}>
                  <td className="mono">{new Date(e.timestamp).toLocaleTimeString()}</td>
                  <td>{e.event_type}</td>
                  <td><span className={`badge badge-${severityColor(e.severity)}`}>{e.severity}</span></td>
                  <td className="truncate">{eventSummary(e)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function formatUptime(secs: number): string {
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m`;
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  return `${h}h ${m}m`;
}

function severityColor(severity: string): string {
  switch (severity.toLowerCase()) {
    case 'critical': return 'danger';
    case 'high': return 'danger';
    case 'medium': return 'warning';
    case 'low': return 'info';
    default: return 'muted';
  }
}

function eventSummary(e: NormalizedEvent): string {
  if (e.process_context) return `${e.process_context.name} (PID ${e.process_context.pid})`;
  if (e.file_context) return `${e.file_context.action} ${e.file_context.path}`;
  if (e.network_context) return `${e.network_context.protocol} ${e.network_context.remote_addr ?? ''}:${e.network_context.remote_port ?? ''}`;
  if (e.auth_context) return `${e.auth_context.action} ${e.auth_context.username}`;
  return e.event_type;
}
