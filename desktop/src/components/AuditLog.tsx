import { useState, useEffect } from 'react';
import type { AuditEntry } from '../lib/types';
import { getAuditLog, verifyAuditChain } from '../lib/ipc';

export function AuditLog() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [chainValid, setChainValid] = useState<boolean | null>(null);
  const [chainEntries, setChainEntries] = useState(0);
  const [verifying, setVerifying] = useState(false);

  useEffect(() => {
    getAuditLog(100).then(setEntries).catch(() => {});
  }, []);

  const verify = async () => {
    setVerifying(true);
    try {
      const result = await verifyAuditChain();
      setChainValid(result.valid);
      setChainEntries(result.entries);
    } catch {
      setChainValid(false);
    }
    setVerifying(false);
  };

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Audit Log</h1>
        <button className="btn btn-accent" onClick={verify} disabled={verifying}>
          {verifying ? 'Verifying...' : 'Verify Chain'}
        </button>
      </div>

      {chainValid !== null && (
        <div className={`card ${chainValid ? 'border-success' : 'border-danger'}`}>
          <p>
            Chain integrity: <strong className={chainValid ? 'text-success' : 'text-danger'}>
              {chainValid ? 'VALID' : 'TAMPERED'}
            </strong>
            {' '}({chainEntries} entries)
          </p>
        </div>
      )}

      <div className="card">
        <table className="data-table">
          <thead>
            <tr><th>Time</th><th>Action</th><th>Target</th><th>Decision</th><th>Reason</th></tr>
          </thead>
          <tbody>
            {entries.length === 0 ? (
              <tr><td colSpan={5} className="text-muted text-center">No audit entries</td></tr>
            ) : entries.map((e) => (
              <tr key={e.entry_id}>
                <td className="mono">{new Date(e.timestamp).toLocaleString()}</td>
                <td>{e.action}</td>
                <td className="mono truncate">{e.target}</td>
                <td><span className={`badge badge-${decisionColor(e.decision)}`}>{e.decision}</span></td>
                <td className="text-muted truncate">{e.reason}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function decisionColor(d: string): string {
  switch (d.toLowerCase()) {
    case 'execute': return 'success';
    case 'dry_run': return 'info';
    case 'pending_approval': return 'warning';
    case 'denied': return 'danger';
    default: return 'muted';
  }
}
