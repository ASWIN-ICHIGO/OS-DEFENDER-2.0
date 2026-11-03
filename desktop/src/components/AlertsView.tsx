import { useState, useEffect } from 'react';
import type { NormalizedEvent } from '../lib/types';
import { getAlerts } from '../lib/ipc';

export function AlertsView() {
  const [alerts, setAlerts] = useState<NormalizedEvent[]>([]);
  const [limit, setLimit] = useState(50);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      try {
        setAlerts(await getAlerts(limit));
      } catch { /* handled by layout */ }
      setLoading(false);
    };
    load();
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  }, [limit]);

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Alerts</h1>
        <div className="page-actions">
          <select value={limit} onChange={(e) => setLimit(Number(e.target.value))} className="select-input">
            <option value={25}>Last 25</option>
            <option value={50}>Last 50</option>
            <option value={100}>Last 100</option>
          </select>
        </div>
      </div>

      {loading && alerts.length === 0 ? (
        <div className="card"><p className="text-muted">Loading alerts...</p></div>
      ) : alerts.length === 0 ? (
        <div className="card"><p className="text-muted">No alerts recorded</p></div>
      ) : (
        <div className="card">
          <table className="data-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Type</th>
                <th>Severity</th>
                <th>Event ID</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((a) => (
                <tr key={a.event_id} className={`severity-row-${a.severity.toLowerCase()}`}>
                  <td className="mono">{new Date(a.timestamp).toLocaleString()}</td>
                  <td>{a.event_type}</td>
                  <td><span className={`badge badge-${sevColor(a.severity)}`}>{a.severity}</span></td>
                  <td className="mono truncate">{a.event_id.slice(0, 8)}</td>
                  <td className="truncate">{summarize(a)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function sevColor(s: string): string {
  switch (s.toLowerCase()) {
    case 'critical': case 'high': return 'danger';
    case 'medium': return 'warning';
    case 'low': return 'info';
    default: return 'muted';
  }
}

function summarize(e: NormalizedEvent): string {
  if (e.process_context) return `${e.process_context.name} (PID ${e.process_context.pid})`;
  if (e.file_context) return `${e.file_context.action} ${e.file_context.path}`;
  if (e.network_context) return `${e.network_context.protocol} → ${e.network_context.remote_addr ?? '?'}`;
  if (e.auth_context) return `${e.auth_context.action} ${e.auth_context.username}`;
  return e.event_type;
}
