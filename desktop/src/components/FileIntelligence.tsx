export function FileIntelligence() {
  return (
    <div className="page">
      <h1 className="page-title">File Intelligence</h1>

      <div className="dashboard-grid">
        <div className="card">
          <h2 className="card-title">Capabilities</h2>
          <div className="detail-list">
            <div className="detail-row"><span>SHA-256 Hashing</span><span className="badge badge-success">Active</span></div>
            <div className="detail-row"><span>Reputation Database</span><span className="badge badge-success">In-memory</span></div>
            <div className="detail-row"><span>Known-Good List</span><span className="badge badge-success">Loaded</span></div>
            <div className="detail-row"><span>Known-Bad List</span><span className="badge badge-success">Loaded</span></div>
            <div className="detail-row"><span>IOC Loading</span><span className="badge badge-success">Supported</span></div>
          </div>
        </div>

        <div className="card">
          <h2 className="card-title">Reputation Levels</h2>
          <div className="detail-list">
            <div className="detail-row"><span className="badge badge-success">Known Good</span><span>Verified safe files (OS binaries, signed packages)</span></div>
            <div className="detail-row"><span className="badge badge-muted">Unknown</span><span>Not yet classified — monitored for behavior</span></div>
            <div className="detail-row"><span className="badge badge-warning">Suspicious</span><span>Anomalous behavior detected — under review</span></div>
            <div className="detail-row"><span className="badge badge-danger">Known Bad</span><span>Confirmed malicious — matched IOC or known hash</span></div>
          </div>
        </div>
      </div>

      <div className="card">
        <h2 className="card-title">How It Works</h2>
        <div className="info-steps">
          <div className="step"><span className="step-num">1</span><span>Every file event triggers SHA-256 hash computation</span></div>
          <div className="step"><span className="step-num">2</span><span>Hash is checked against known-good and known-bad lists</span></div>
          <div className="step"><span className="step-num">3</span><span>Unknown files get tracked and scored by AI behavioral analysis</span></div>
          <div className="step"><span className="step-num">4</span><span>IOC feeds can be loaded to update known-bad hashes</span></div>
        </div>
      </div>
    </div>
  );
}
