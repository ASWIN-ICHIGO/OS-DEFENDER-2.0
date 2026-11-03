import { useState, useEffect } from 'react';
import type { PersistenceEntry } from '../lib/types';
import { getPersistence } from '../lib/ipc';

export function PersistenceScanner() {
  const [entries, setEntries] = useState<PersistenceEntry[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      try { setEntries(await getPersistence()); } catch {}
      setLoading(false);
    };
    load();
  }, []);

  const refresh = async () => {
    setLoading(true);
    try { setEntries(await getPersistence()); } catch {}
    setLoading(false);
  };

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Persistence Scanner</h1>
        <button className="btn btn-accent" onClick={refresh} disabled={loading}>
          {loading ? 'Scanning...' : 'Re-scan'}
        </button>
      </div>

      <div className="card">
        <table className="data-table">
          <thead>
            <tr><th>Type</th><th>Name</th><th>Path</th><th>Risk</th><th>MITRE</th><th>Detail</th></tr>
          </thead>
          <tbody>
            {entries.length === 0 ? (
              <tr><td colSpan={6} className="text-muted text-center">{loading ? 'Scanning...' : 'No persistence entries found'}</td></tr>
            ) : entries.map((e, i) => (
              <tr key={i} className={e.risk === 'high_risk' ? 'row-danger' : ''}>
                <td><span className="badge badge-accent">{e.kind}</span></td>
                <td>{e.name}</td>
                <td className="mono truncate">{e.path}</td>
                <td><span className={`badge badge-${riskColor(e.risk)}`}>{e.risk}</span></td>
                <td><span className="badge badge-accent">{e.mitre_technique}</span></td>
                <td className="text-muted truncate">{e.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function riskColor(r: string): string {
  switch (r) {
    case 'known': return 'success';
    case 'suspicious': return 'warning';
    case 'high_risk': return 'danger';
    default: return 'muted';
  }
}
