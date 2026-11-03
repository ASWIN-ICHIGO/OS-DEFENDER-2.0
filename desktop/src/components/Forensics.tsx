export function Forensics() {
  return (
    <div className="page">
      <h1 className="page-title">Digital Forensics</h1>

      <div className="dashboard-grid">
        <div className="card">
          <h2 className="card-title">Timeline Builder</h2>
          <p className="text-muted">Constructs chronological timelines from events, alerts, and response actions for incident investigation.</p>
          <div className="detail-list">
            <div className="detail-row"><span>Event Sources</span><span>Process, File, Network, Auth</span></div>
            <div className="detail-row"><span>Alert Integration</span><span className="badge badge-success">Active</span></div>
            <div className="detail-row"><span>Action Tracking</span><span className="badge badge-success">Active</span></div>
            <div className="detail-row"><span>Time Range Filter</span><span className="badge badge-success">Supported</span></div>
          </div>
        </div>

        <div className="card">
          <h2 className="card-title">Evidence Collector</h2>
          <p className="text-muted">Collects and preserves digital evidence during incident response.</p>
          <div className="detail-list">
            <div className="detail-row"><span>Log Collection</span><span className="badge badge-success">Active</span></div>
            <div className="detail-row"><span>File Snapshots</span><span className="badge badge-success">Active</span></div>
            <div className="detail-row"><span>Raw Evidence</span><span className="badge badge-success">Supported</span></div>
            <div className="detail-row"><span>Chain of Custody</span><span className="badge badge-success">SHA-256</span></div>
          </div>
        </div>
      </div>

      <div className="card">
        <h2 className="card-title">Forensic Reports</h2>
        <p className="text-muted">Generate comprehensive incident reports with timeline, evidence catalog, and findings.</p>
        <div className="info-steps">
          <div className="step"><span className="step-num">1</span><span>Timeline construction from all event sources</span></div>
          <div className="step"><span className="step-num">2</span><span>Evidence collection and integrity verification</span></div>
          <div className="step"><span className="step-num">3</span><span>Alert correlation and impact assessment</span></div>
          <div className="step"><span className="step-num">4</span><span>JSON export for external analysis tools</span></div>
        </div>
      </div>
    </div>
  );
}
