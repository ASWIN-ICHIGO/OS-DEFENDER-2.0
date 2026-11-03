import { useState, useEffect } from 'react';
import type { PolicyMode } from '../lib/types';
import { getPolicyMode, setPolicyMode } from '../lib/ipc';

export function Enforcement() {
  const [mode, setMode] = useState<PolicyMode>('dry_run');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    getPolicyMode().then(setMode).catch(() => {});
  }, []);

  const handleModeChange = async (newMode: PolicyMode) => {
    setSaving(true);
    try {
      await setPolicyMode(newMode);
      setMode(newMode);
    } catch {}
    setSaving(false);
  };

  return (
    <div className="page">
      <h1 className="page-title">Enforcement / Prevention</h1>

      <div className="card">
        <h2 className="card-title">Policy Mode</h2>
        <p className="text-muted">Controls whether response actions are simulated or enforced.</p>
        <div className="mode-selector">
          {(['dry_run', 'approve', 'execute'] as PolicyMode[]).map((m) => (
            <button
              key={m}
              className={`mode-btn ${mode === m ? 'active' : ''}`}
              onClick={() => handleModeChange(m)}
              disabled={saving}
            >
              <span className="mode-name">{modeLabel(m)}</span>
              <span className="mode-desc">{modeDesc(m)}</span>
            </button>
          ))}
        </div>
      </div>

      <div className="card">
        <h2 className="card-title">Response Actions</h2>
        <table className="data-table">
          <thead>
            <tr><th>Action</th><th>Platform</th><th>Description</th></tr>
          </thead>
          <tbody>
            <tr><td>Block IP</td><td>Linux: nftables / Windows: WFP</td><td>Block inbound+outbound traffic from a malicious IP</td></tr>
            <tr><td>Unblock IP</td><td>Linux: nftables / Windows: WFP</td><td>Rollback a previous IP block</td></tr>
            <tr><td>Freeze Process</td><td>Linux: cgroup v2 / Windows: Job Object</td><td>Suspend a suspicious process without killing it</td></tr>
            <tr><td>Thaw Process</td><td>Linux: cgroup v2 / Windows: Job Object</td><td>Resume a previously frozen process</td></tr>
            <tr><td>Quarantine File</td><td>Cross-platform</td><td>Move file to quarantine with SHA-256 integrity verification</td></tr>
            <tr><td>Restore File</td><td>Cross-platform</td><td>Restore a quarantined file after integrity check</td></tr>
            <tr><td>Kill Process</td><td>Cross-platform</td><td>Terminate a confirmed malicious process</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}

function modeLabel(m: PolicyMode): string {
  switch (m) {
    case 'dry_run': return 'Dry Run';
    case 'approve': return 'Approve';
    case 'execute': return 'Execute';
  }
}

function modeDesc(m: PolicyMode): string {
  switch (m) {
    case 'dry_run': return 'Log actions without enforcement';
    case 'approve': return 'Auto-execute critical, queue others';
    case 'execute': return 'Enforce all response actions';
  }
}
