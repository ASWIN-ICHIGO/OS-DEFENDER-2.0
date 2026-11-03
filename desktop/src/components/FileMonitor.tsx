import { useState, useEffect } from 'react';
import type { NormalizedEvent } from '../lib/types';
import { getEvents } from '../lib/ipc';

export function FileMonitor() {
  const [events, setEvents] = useState<NormalizedEvent[]>([]);
  const [filter, setFilter] = useState('');

  useEffect(() => {
    const load = async () => {
      try {
        const all = await getEvents(200);
        setEvents(all.filter((e) => e.event_type === 'file'));
      } catch {}
    };
    load();
    const id = setInterval(load, 3000);
    return () => clearInterval(id);
  }, []);

  const filtered = events.filter((e) => {
    if (!filter) return true;
    const lf = filter.toLowerCase();
    const f = e.file_context;
    return f?.path.toLowerCase().includes(lf) || f?.action.toLowerCase().includes(lf);
  });

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">File Monitor</h1>
        <input className="search-input" placeholder="Filter by path..." value={filter} onChange={(e) => setFilter(e.target.value)} />
      </div>
      <div className="card">
        <table className="data-table">
          <thead>
            <tr><th>Time</th><th>Action</th><th>Path</th><th>Size</th><th>SHA-256</th><th>Severity</th></tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr><td colSpan={6} className="text-muted text-center">No file events</td></tr>
            ) : filtered.map((e) => {
              const f = e.file_context!;
              return (
                <tr key={e.event_id}>
                  <td className="mono">{new Date(e.timestamp).toLocaleTimeString()}</td>
                  <td><span className={`badge badge-${actionColor(f.action)}`}>{f.action}</span></td>
                  <td className="mono truncate">{f.path}</td>
                  <td className="mono">{f.size_bytes != null ? formatBytes(f.size_bytes) : '—'}</td>
                  <td className="mono truncate">{f.sha256?.slice(0, 12) ?? '—'}</td>
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

function actionColor(a: string): string {
  switch (a.toLowerCase()) {
    case 'create': return 'success';
    case 'delete': return 'danger';
    case 'modify': return 'warning';
    case 'rename': return 'info';
    default: return 'muted';
  }
}

function sevColor(s: string): string {
  switch (s.toLowerCase()) {
    case 'critical': case 'high': return 'danger';
    case 'medium': return 'warning';
    default: return 'muted';
  }
}

function formatBytes(b: number): string {
  if (b < 1024) return `${b} B`;
  if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1048576).toFixed(1)} MB`;
}
