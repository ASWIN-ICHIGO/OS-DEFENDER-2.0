import { useState, useEffect } from 'react';
import type { PolicyMode } from '../lib/types';
import { getPolicyMode, setPolicyMode, getAgentStatus } from '../lib/ipc';

export function Settings() {
  const [mode, setMode] = useState<PolicyMode>('dry_run');
  const [version, setVersion] = useState('');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    getPolicyMode().then(setMode).catch(() => {});
    getAgentStatus().then((s) => setVersion(s.version)).catch(() => {});
  }, []);

  const save = async (m: PolicyMode) => {
    setSaving(true);
    try {
      await setPolicyMode(m);
      setMode(m);
    } catch {}
    setSaving(false);
  };

  return (
    <div className="page">
      <h1 className="page-title">Settings</h1>

      <div className="card">
        <h2 className="card-title">Policy Mode</h2>
        <div className="mode-selector">
          {(['dry_run', 'approve', 'execute'] as PolicyMode[]).map((m) => (
            <button key={m} className={`mode-btn ${mode === m ? 'active' : ''}`} onClick={() => save(m)} disabled={saving}>
              {m === 'dry_run' ? 'Dry Run' : m === 'approve' ? 'Approve' : 'Execute'}
            </button>
          ))}
        </div>
      </div>

      <div className="card">
        <h2 className="card-title">Agent Configuration</h2>
        <div className="detail-list">
          <div className="detail-row"><span>Socket Path</span><span className="mono">~/.local/share/os-defender/agent.sock</span></div>
          <div className="detail-row"><span>Database</span><span className="mono">~/.local/share/os-defender/events.db</span></div>
          <div className="detail-row"><span>Quarantine Dir</span><span className="mono">~/.local/share/os-defender/quarantine/</span></div>
          <div className="detail-row"><span>AI Model</span><span className="mono">~/.local/share/os-defender/model.onnx</span></div>
          <div className="detail-row"><span>Version</span><span className="mono">{version || '—'}</span></div>
        </div>
      </div>

      <div className="card">
        <h2 className="card-title">Collector Intervals</h2>
        <div className="detail-list">
          <div className="detail-row"><span>Process Polling</span><span>2 seconds</span></div>
          <div className="detail-row"><span>File Monitoring</span><span>Real-time (inotify / FindFirstChangeNotification)</span></div>
          <div className="detail-row"><span>Network Polling</span><span>5 seconds</span></div>
          <div className="detail-row"><span>Auth Monitoring</span><span>Real-time (journalctl / Event Log)</span></div>
          <div className="detail-row"><span>Health Check</span><span>30 seconds</span></div>
        </div>
      </div>
    </div>
  );
}
