import { useState, useEffect } from 'react';
import type { NormalizedEvent } from '../lib/types';
import { getEvents } from '../lib/ipc';

export function NetworkMonitor() {
  const [events, setEvents] = useState<NormalizedEvent[]>([]);
  const [filter, setFilter] = useState('');

  useEffect(() => {
    const load = async () => {
      try {
        const all = await getEvents(200);
        setEvents(all.filter((e) => e.event_type === 'network'));
      } catch {}
    };
    load();
    const id = setInterval(load, 3000);
    return () => clearInterval(id);
  }, []);

  const filtered = events.filter((e) => {
    if (!filter) return true;
    const lf = filter.toLowerCase();
    const n = e.network_context;
    return (
      n?.remote_addr?.toLowerCase().includes(lf) ||
      n?.local_addr.toLowerCase().includes(lf) ||
      n?.protocol.toLowerCase().includes(lf) ||
      n?.process_name?.toLowerCase().includes(lf)
    );
  });

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Network Monitor</h1>
        <input className="search-input" placeholder="Filter connections..." value={filter} onChange={(e) => setFilter(e.target.value)} />
      </div>
      <div className="card">
        <table className="data-table">
          <thead>
            <tr><th>Time</th><th>Proto</th><th>Direction</th><th>Local</th><th>Remote</th><th>State</th><th>Process</th><th>Severity</th></tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr><td colSpan={8} className="text-muted text-center">No network events</td></tr>
            ) : filtered.map((e) => {
              const n = e.network_context!;
              return (
                <tr key={e.event_id}>
                  <td className="mono">{new Date(e.timestamp).toLocaleTimeString()}</td>
                  <td>{n.protocol.toUpperCase()}</td>
                  <td><span className={`badge badge-${n.direction === 'inbound' ? 'info' : 'accent'}`}>{n.direction}</span></td>
                  <td className="mono">{n.local_addr}:{n.local_port}</td>
                  <td className="mono">{n.remote_addr ?? '—'}:{n.remote_port ?? '—'}</td>
                  <td>{n.state ?? '—'}</td>
                  <td>{n.process_name ?? '—'}</td>
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

function sevColor(s: string): string {
  switch (s.toLowerCase()) {
    case 'critical': case 'high': return 'danger';
    case 'medium': return 'warning';
    default: return 'muted';
  }
}
