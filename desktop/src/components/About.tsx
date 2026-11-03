export function About() {
  return (
    <div className="page">
      <h1 className="page-title">About OS Defender 2.0</h1>

      <div className="card about-card">
        <div className="about-header">
          <span className="about-logo">🛡</span>
          <div>
            <h2>OS Defender 2.0</h2>
            <p className="text-muted">Offline-first AI-powered endpoint detection, prevention and response</p>
          </div>
        </div>
      </div>

      <div className="dashboard-grid">
        <div className="card">
          <h2 className="card-title">Principles</h2>
          <div className="detail-list">
            <div className="detail-row"><span>Real-time Protection</span><span>Native OS integration for immediate response</span></div>
            <div className="detail-row"><span>Offline-first AI</span><span>IsolationForest + ONNX, no cloud required</span></div>
            <div className="detail-row"><span>Explainable Detection</span><span>Per-feature contributing factors for every alert</span></div>
            <div className="detail-row"><span>Dry-run by Default</span><span>Safe policy engine with approve/execute escalation</span></div>
            <div className="detail-row"><span>Privacy-first</span><span>All data stays local, no telemetry</span></div>
          </div>
        </div>

        <div className="card">
          <h2 className="card-title">Technology Stack</h2>
          <div className="detail-list">
            <div className="detail-row"><span>Core Engine</span><span>Rust</span></div>
            <div className="detail-row"><span>AI / ML</span><span>Python, scikit-learn, ONNX Runtime</span></div>
            <div className="detail-row"><span>Storage</span><span>SQLite (WAL mode)</span></div>
            <div className="detail-row"><span>Desktop</span><span>Tauri + React + TypeScript</span></div>
            <div className="detail-row"><span>Linux</span><span>/proc, inotify, journalctl, nftables, cgroups</span></div>
            <div className="detail-row"><span>Windows</span><span>ETW, Event Log, WFP, Job Objects</span></div>
          </div>
        </div>
      </div>

      <div className="card">
        <h2 className="card-title">MITRE ATT&CK Coverage</h2>
        <div className="tag-list">
          {['T1110', 'T1059', 'T1059.004', 'T1565.001', 'T1486', 'T1071', 'T1571',
            'T1053.003', 'T1543.002', 'T1546.004', 'T1574.006', 'T1098.004', 'T1547.001'
          ].map((t) => (
            <span key={t} className="badge badge-accent">{t}</span>
          ))}
        </div>
      </div>

      <div className="card">
        <p className="text-muted text-center">
          Version 2.0.0-alpha.1 &middot; MIT License &middot; Aswin
        </p>
      </div>
    </div>
  );
}
