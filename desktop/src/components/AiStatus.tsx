import { useState, useEffect } from 'react';
import type { AiEngineStatus } from '../lib/types';
import { getAiStatus } from '../lib/ipc';

export function AiStatus() {
  const [status, setStatus] = useState<AiEngineStatus | null>(null);

  useEffect(() => {
    const load = async () => {
      try { setStatus(await getAiStatus()); } catch {}
    };
    load();
    const id = setInterval(load, 10000);
    return () => clearInterval(id);
  }, []);

  return (
    <div className="page">
      <h1 className="page-title">AI Engine</h1>

      {!status ? (
        <div className="card"><p className="text-muted">Loading AI status...</p></div>
      ) : (
        <>
          <div className="stats-grid">
            <div className={`stat-card ${status.available ? 'success' : ''}`}>
              <div className="stat-card-value">{status.available ? 'Online' : 'Offline'}</div>
              <div className="stat-card-label">AI Engine</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-value">{status.events_scored.toLocaleString()}</div>
              <div className="stat-card-label">Events Scored</div>
            </div>
            <div className="stat-card accent">
              <div className="stat-card-value">{status.anomalies_detected.toLocaleString()}</div>
              <div className="stat-card-label">Anomalies Found</div>
            </div>
            <div className={`stat-card ${status.drift_detected ? 'danger' : 'success'}`}>
              <div className="stat-card-value">{status.drift_detected ? 'Drift' : 'Stable'}</div>
              <div className="stat-card-label">Baseline Status</div>
            </div>
          </div>

          <div className="dashboard-grid">
            <div className="card">
              <h2 className="card-title">Model Status</h2>
              <div className="detail-list">
                <div className="detail-row"><span>Model Loaded</span><span className={status.model_loaded ? 'text-success' : 'text-muted'}>{status.model_loaded ? 'Yes' : 'No'}</span></div>
                <div className="detail-row"><span>Model Path</span><span className="mono">{status.model_path ?? 'N/A'}</span></div>
                <div className="detail-row"><span>Baseline Learned</span><span className={status.baseline_learned ? 'text-success' : 'text-warning'}>{status.baseline_learned ? 'Yes' : 'Learning...'}</span></div>
                <div className="detail-row"><span>Last Drift Check</span><span className="mono">{status.last_drift_check ?? 'Never'}</span></div>
              </div>
            </div>

            <div className="card">
              <h2 className="card-title">Components</h2>
              <div className="detail-list">
                <div className="detail-row"><span>IsolationForest (ONNX)</span><span className={`badge ${status.model_loaded ? 'badge-success' : 'badge-muted'}`}>{status.model_loaded ? 'Active' : 'Inactive'}</span></div>
                <div className="detail-row"><span>Behavioural Features</span><span className="badge badge-success">17 features</span></div>
                <div className="detail-row"><span>Z-Score Drift Detection</span><span className={`badge ${status.baseline_learned ? 'badge-success' : 'badge-warning'}`}>{status.baseline_learned ? 'Active' : 'Calibrating'}</span></div>
                <div className="detail-row"><span>Local LLM (Ollama)</span><span className={`badge ${status.ollama_available ? 'badge-success' : 'badge-muted'}`}>{status.ollama_available ? 'Available' : 'Not available'}</span></div>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
