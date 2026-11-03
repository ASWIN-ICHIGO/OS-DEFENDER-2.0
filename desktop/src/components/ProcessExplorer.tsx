import { useState, useEffect } from 'react';
import type { NormalizedEvent } from '../lib/types';
import { getEvents } from '../lib/ipc';

export function ProcessExplorer() {
  const [events, setEvents] = useState<NormalizedEvent[]>([]);
  const [filter, setFilter] = useState('');

  useEffect(() => {
    const load = async () => {
      try {
        const all = await getEvents(200);
        setEvents(all.filter((e) => e.event_type === 'process'));
      } catch { /* handled by layout */ }
    };
    load();
    const id = setInterval(load, 3000);
    return () => clearInterval(id);
  }, []);

  const filtered = events.filter((e) => {
    if (!filter) return true;
    const lf = filter.toLowerCase();
    const p = e.process_context;
    if (!p) return false;
    return (
      p.name.toLowerCase().includes(lf) ||
      p.exe?.toLowerCase().includes(lf) ||
      p.cmdline?.toLowerCase().includes(lf) ||
      String(p.pid).includes(lf) ||
      p.username?.toLowerCase().includes(lf)
    );
  });

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Process Explorer</h1>
        <input
          className="search-input"
          placeholder="Filter processes..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
      </div>

      <div className="card">
        <table className="data-table">
          <thead>
            <tr>
              <th>PID</th>
              <th>PPID</th>
              <th>Name</th>
              <th>Executable</th>
              <th>User</th>
              <th>Severity</th>
              <th>Time</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr><td colSpan={7} className="text-muted text-center">No process events</td></tr>
            ) : (
              filtered.map((e) => {
                const p = e.process_context!;
                return (
                  <tr key={e.event_id}>
                    <td className="mono">{p.pid}</td>
                    <td className="mono">{p.ppid ?? '—'}</td>
                    <td>{p.name}</td>
                    <td className="mono truncate">{p.exe ?? '—'}</td>
                    <td>{p.username ?? p.uid ?? '—'}</td>
                    <td><span className={`badge badge-${sevColor(e.severity)}`}>{e.severity}</span></td>
                    <td className="mono">{new Date(e.timestamp).toLocaleTimeString()}</td>
                  </tr>
                );
              })
            )}
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
    case 'low': return 'info';
    default: return 'muted';
  }
}
