import { useState } from 'react';
import type { HuntQuery, HuntResult } from '../lib/types';
import { threatHunt } from '../lib/ipc';

export function ThreatHunting() {
  const [query, setQuery] = useState<Partial<HuntQuery>>({});
  const [result, setResult] = useState<HuntResult | null>(null);
  const [hunting, setHunting] = useState(false);

  const hunt = async () => {
    setHunting(true);
    try {
      const q: HuntQuery = {
        event_type: query.event_type || null,
        severity_min: query.severity_min || null,
        process_name: query.process_name || null,
        file_path_contains: query.file_path_contains || null,
        remote_addr: query.remote_addr || null,
        username: query.username || null,
        payload_contains: query.payload_contains || null,
        limit: query.limit || 50,
      };
      setResult(await threatHunt(q));
    } catch {}
    setHunting(false);
  };

  return (
    <div className="page">
      <h1 className="page-title">Threat Hunting</h1>

      <div className="card">
        <h2 className="card-title">Hunt Query</h2>
        <div className="hunt-form">
          <div className="form-row">
            <label>Event Type</label>
            <select className="select-input" value={query.event_type ?? ''} onChange={(e) => setQuery({ ...query, event_type: e.target.value || null })}>
              <option value="">Any</option>
              <option value="process">Process</option>
              <option value="file">File</option>
              <option value="network">Network</option>
              <option value="authentication">Authentication</option>
              <option value="persistence">Persistence</option>
            </select>
          </div>
          <div className="form-row">
            <label>Min Severity</label>
            <select className="select-input" value={query.severity_min ?? ''} onChange={(e) => setQuery({ ...query, severity_min: e.target.value || null })}>
              <option value="">Any</option>
              <option value="info">Info</option>
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </div>
          <div className="form-row">
            <label>Process Name</label>
            <input className="text-input" placeholder="e.g. bash, python3" value={query.process_name ?? ''} onChange={(e) => setQuery({ ...query, process_name: e.target.value || null })} />
          </div>
          <div className="form-row">
            <label>File Path</label>
            <input className="text-input" placeholder="e.g. /etc/shadow" value={query.file_path_contains ?? ''} onChange={(e) => setQuery({ ...query, file_path_contains: e.target.value || null })} />
          </div>
          <div className="form-row">
            <label>Remote Address</label>
            <input className="text-input" placeholder="e.g. 10.0.0.5" value={query.remote_addr ?? ''} onChange={(e) => setQuery({ ...query, remote_addr: e.target.value || null })} />
          </div>
          <div className="form-row">
            <label>Username</label>
            <input className="text-input" placeholder="e.g. root" value={query.username ?? ''} onChange={(e) => setQuery({ ...query, username: e.target.value || null })} />
          </div>
          <div className="form-row">
            <label>Payload Contains</label>
            <input className="text-input" placeholder="Text search in event payloads" value={query.payload_contains ?? ''} onChange={(e) => setQuery({ ...query, payload_contains: e.target.value || null })} />
          </div>
          <div className="form-row">
            <label>Limit</label>
            <input className="text-input" type="number" value={query.limit ?? 50} onChange={(e) => setQuery({ ...query, limit: Number(e.target.value) || 50 })} />
          </div>
          <button className="btn btn-accent" onClick={hunt} disabled={hunting}>
            {hunting ? 'Hunting...' : 'Execute Hunt'}
          </button>
        </div>
      </div>

      {result && (
        <div className="card">
          <h2 className="card-title">Results ({result.total_matches} matches)</h2>
          <table className="data-table">
            <thead>
              <tr><th>Time</th><th>Type</th><th>Severity</th><th>Details</th></tr>
            </thead>
            <tbody>
              {result.events.map((e) => (
                <tr key={e.event_id}>
                  <td className="mono">{new Date(e.timestamp).toLocaleString()}</td>
                  <td>{e.event_type}</td>
                  <td><span className={`badge badge-${sevColor(e.severity)}`}>{e.severity}</span></td>
                  <td className="truncate">{summarize(e)}</td>
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
    default: return 'muted';
  }
}

function summarize(e: { process_context?: { name: string; pid: number } | null; file_context?: { action: string; path: string } | null; network_context?: { remote_addr?: string | null } | null; auth_context?: { action: string; username: string } | null; event_type: string }): string {
  if (e.process_context) return `${e.process_context.name} (PID ${e.process_context.pid})`;
  if (e.file_context) return `${e.file_context.action} ${e.file_context.path}`;
  if (e.network_context) return `→ ${e.network_context.remote_addr ?? '?'}`;
  if (e.auth_context) return `${e.auth_context.action} ${e.auth_context.username}`;
  return e.event_type;
}
