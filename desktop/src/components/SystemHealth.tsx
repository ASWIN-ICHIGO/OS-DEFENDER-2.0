import { useState, useEffect } from 'react';
import type { VisibilityAssessment } from '../lib/types';
import { getHealth } from '../lib/ipc';

export function SystemHealth() {
  const [health, setHealth] = useState<VisibilityAssessment | null>(null);

  useEffect(() => {
    const load = async () => {
      try { setHealth(await getHealth()); } catch {}
    };
    load();
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  }, []);

  return (
    <div className="page">
      <h1 className="page-title">System Health</h1>

      {!health ? (
        <div className="card"><p className="text-muted">Loading health data...</p></div>
      ) : (
        <>
          <div className="stats-grid">
            <div className={`stat-card ${health.overall_healthy ? 'success' : 'danger'}`}>
              <div className="stat-card-value">{health.overall_healthy ? 'Healthy' : 'Degraded'}</div>
              <div className="stat-card-label">Overall Status</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-value">{health.sensors.filter(s => s.is_healthy).length}</div>
              <div className="stat-card-label">Healthy Sensors</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-value">{health.sensors.length}</div>
              <div className="stat-card-label">Total Sensors</div>
            </div>
          </div>

          {health.blind_spots.length > 0 && (
            <div className="card border-warning">
              <h2 className="card-title">Blind Spots</h2>
              <p className="text-muted">Areas where monitoring coverage is degraded or absent.</p>
              <div className="tag-list">
                {health.blind_spots.map((bs, i) => (
                  <span key={i} className="badge badge-warning">{bs}</span>
                ))}
              </div>
            </div>
          )}

          <div className="card">
            <h2 className="card-title">Sensor Status</h2>
            <table className="data-table">
              <thead>
                <tr><th>Sensor</th><th>State</th><th>Events</th><th>Dropped</th><th>Lag</th><th>Last Heartbeat</th></tr>
              </thead>
              <tbody>
                {health.sensors.map((s, i) => (
                  <tr key={i}>
                    <td>{s.name}</td>
                    <td><span className={`badge badge-${s.is_healthy ? 'success' : 'danger'}`}>{s.is_healthy ? 'Healthy' : 'Unhealthy'}</span></td>
                    <td>{s.events_collected.toLocaleString()}</td>
                    <td className={s.events_dropped > 0 ? 'text-danger' : ''}>{s.events_dropped}</td>
                    <td>{s.lag_ms != null ? `${s.lag_ms}ms` : '—'}</td>
                    <td className="mono">{s.last_heartbeat ? new Date(s.last_heartbeat).toLocaleTimeString() : 'Never'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="card">
            <p className="text-muted">{health.caveat}</p>
          </div>
        </>
      )}
    </div>
  );
}
