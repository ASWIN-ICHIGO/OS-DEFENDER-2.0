import { useState, useEffect } from 'react';
import type { TamperCheckResult } from '../lib/types';
import { verifyIntegrity } from '../lib/ipc';

export function TamperProtection() {
  const [result, setResult] = useState<TamperCheckResult | null>(null);
  const [checking, setChecking] = useState(false);

  useEffect(() => {
    check();
  }, []);

  const check = async () => {
    setChecking(true);
    try { setResult(await verifyIntegrity()); } catch {}
    setChecking(false);
  };

  const isClean = result ? result.tampered.length === 0 && result.missing.length === 0 : false;

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Tamper Protection</h1>
        <button className="btn btn-accent" onClick={check} disabled={checking}>
          {checking ? 'Checking...' : 'Verify Integrity'}
        </button>
      </div>

      <div className="card">
        <h2 className="card-title">How It Works</h2>
        <div className="info-steps">
          <div className="step"><span className="step-num">1</span><span>Integrity manifest records SHA-256 hashes of protected files and directories</span></div>
          <div className="step"><span className="step-num">2</span><span>Periodic verification compares current hashes against the manifest</span></div>
          <div className="step"><span className="step-num">3</span><span>Signed configuration files use hash validation to prevent tampering</span></div>
          <div className="step"><span className="step-num">4</span><span>Any mismatch triggers an alert with details of the changed file</span></div>
        </div>
      </div>

      {result && (
        <div className={`card ${isClean ? 'border-success' : 'border-danger'}`}>
          <h2 className="card-title">Verification Result</h2>
          <div className="detail-list">
            <div className="detail-row">
              <span>Overall Status</span>
              <span className={isClean ? 'text-success' : 'text-danger'}>
                {isClean ? 'INTACT — No tampering detected' : 'TAMPERED — Integrity violations found'}
              </span>
            </div>
            <div className="detail-row"><span>Files Checked</span><span>{result.total_files}</span></div>
            <div className="detail-row"><span>Intact</span><span className="text-success">{result.intact}</span></div>
            <div className="detail-row"><span>Tampered</span><span className={result.tampered.length > 0 ? 'text-danger' : 'text-success'}>{result.tampered.length}</span></div>
            <div className="detail-row"><span>Missing</span><span className={result.missing.length > 0 ? 'text-danger' : 'text-success'}>{result.missing.length}</span></div>
          </div>
          {result.tampered.length > 0 && (
            <div className="mt-4">
              <h3 className="card-subtitle">Tampered Files</h3>
              <table className="data-table">
                <thead>
                  <tr><th>File</th><th>Expected Hash</th><th>Actual Hash</th></tr>
                </thead>
                <tbody>
                  {result.tampered.map((v, i) => (
                    <tr key={i}>
                      <td className="mono">{v.path}</td>
                      <td className="mono truncate">{v.expected_sha256.slice(0, 16)}...</td>
                      <td className="mono truncate">{v.actual_sha256.slice(0, 16)}...</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {result.missing.length > 0 && (
            <div className="mt-4">
              <h3 className="card-subtitle">Missing Files</h3>
              <div className="tag-list">
                {result.missing.map((p, i) => (
                  <span key={i} className="badge badge-danger">{p}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
