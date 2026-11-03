export function RansomwareDefense() {
  const indicators = [
    { name: 'Canary File Monitoring', status: 'active', desc: 'Sentinel files deployed in monitored directories detect unauthorized access or deletion.' },
    { name: 'Entropy Detection', status: 'active', desc: 'Shannon entropy analysis identifies encrypted file writes above threshold (7.5 bits/byte).' },
    { name: 'Rapid Modification Tracking', status: 'active', desc: 'Aggregates file modifications within 60-second windows to detect mass encryption.' },
    { name: 'Rename Storm Detection', status: 'active', desc: 'Detects rapid file renaming patterns common in ransomware (>10 renames/60s).' },
    { name: 'Known Extension Matching', status: 'active', desc: 'Matches against 20+ known ransomware extensions (.encrypted, .locked, .crypted, etc.).' },
  ];

  const extensions = [
    '.encrypted', '.locked', '.crypted', '.crypto', '.crypt', '.enc',
    '.locky', '.cerber', '.zepto', '.thor', '.aesir', '.zzzzz',
    '.micro', '.rekt', '.fucked', '.wncry', '.wcry', '.xtbl',
    '.dharma', '.wallet', '.onion',
  ];

  return (
    <div className="page">
      <h1 className="page-title">Ransomware Defense</h1>
      <p className="page-subtitle">Rule R006 — MITRE ATT&CK T1486</p>

      <div className="rules-grid">
        {indicators.map((ind) => (
          <div key={ind.name} className="card">
            <div className="rule-header">
              <h3 className="rule-name">{ind.name}</h3>
              <span className="badge badge-success">{ind.status}</span>
            </div>
            <p className="rule-desc">{ind.desc}</p>
          </div>
        ))}
      </div>

      <div className="card">
        <h2 className="card-title">Monitored Ransomware Extensions</h2>
        <div className="tag-list">
          {extensions.map((ext) => (
            <span key={ext} className="badge badge-danger">{ext}</span>
          ))}
        </div>
      </div>
    </div>
  );
}
