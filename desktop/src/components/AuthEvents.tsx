import { useState, useEffect } from 'react';
import type { NormalizedEvent } from '../lib/types';
import { getEvents } from '../lib/ipc';

export function AuthEvents() {
  const [events, setEvents] = useState<NormalizedEvent[]>([]);

  useEffect(() => {
    const load = async () => {
      try {
        const all = await getEvents(200);
        setEvents(all.filter((e) => e.event_type === 'authentication'));
      } catch {}
    };
    load();
    const id = setInterval(load, 3000);
    return () => clearInterval(id);
  }, []);

  return (
    <div className="page">
      <h1 className="page-title">Authentication Events</h1>
      <div className="card">
        <table className="data-table">
          <thead>
            <tr><th>Time</th><th>Action</th><th>User</th><th>Source</th><th>Method</th><th>Service</th><th>Severity</th></tr>
          </thead>
          <tbody>
            {events.length === 0 ? (
              <tr><td colSpan={7} className="text-muted text-center">No auth events</td></tr>
            ) : events.map((e) => {
              const a = e.auth_context!;
              return (
                <tr key={e.event_id}>
                  <td className="mono">{new Date(e.timestamp).toLocaleTimeString()}</td>
                  <td><span className={`badge badge-${authColor(a.action)}`}>{a.action}</span></td>
                  <td>{a.username}</td>
                  <td className="mono">{a.source_addr ?? '—'}</td>
                  <td>{a.method ?? '—'}</td>
                  <td>{a.service ?? '—'}</td>
                  <td><span className={`badge badge-${sevColor(e.severity)}`}>{e.severity}</span></td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function authColor(action: string): string {
  switch (action.toLowerCase()) {
    case 'login': return 'success';
    case 'logout': return 'muted';
    case 'failed': return 'danger';
    case 'escalation': return 'warning';
    default: return 'info';
  }
}

function sevColor(s: string): string {
  switch (s.toLowerCase()) {
    case 'critical': case 'high': return 'danger';
    case 'medium': return 'warning';
    default: return 'muted';
  }
}
