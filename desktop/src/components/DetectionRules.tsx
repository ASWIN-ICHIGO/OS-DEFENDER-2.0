export function DetectionRules() {
  const rules = [
    { id: 'R001', name: 'Brute-Force Detection', mitre: 'T1110', severity: 'high', description: 'Detects repeated authentication failures from the same source exceeding threshold within time window.' },
    { id: 'R002', name: 'Suspicious Process Execution', mitre: 'T1059, T1059.004', severity: 'high', description: 'Identifies reverse shells, crypto miners, recon tools, and suspicious command patterns.' },
    { id: 'R003', name: 'Sensitive File Tampering', mitre: 'T1565.001, T1486', severity: 'critical', description: 'Monitors /etc/shadow, sudoers, authorized_keys, ld.so.preload, SSH configs for unauthorized changes.' },
    { id: 'R004', name: 'Anomalous Network Activity', mitre: 'T1071, T1571', severity: 'medium', description: 'Detects non-standard ports, connections to suspicious IPs, and unexpected outbound traffic.' },
    { id: 'R005', name: 'Persistence Mechanism Change', mitre: 'T1053.003, T1543.002, T1546.004, T1574.006, T1098.004, T1547.001', severity: 'high', description: 'Monitors systemd, cron, shell rc, init.d, XDG autostart, udev rules, and SSH key changes.' },
    { id: 'R006', name: 'Ransomware Defense', mitre: 'T1486', severity: 'critical', description: 'Canary files, high-entropy writes, rapid modifications, mass renames, and known ransomware extensions.' },
  ];

  return (
    <div className="page">
      <h1 className="page-title">Detection Rules</h1>
      <div className="rules-grid">
        {rules.map((r) => (
          <div key={r.id} className="card rule-card">
            <div className="rule-header">
              <span className="mono rule-id">{r.id}</span>
              <span className={`badge badge-${r.severity === 'critical' ? 'danger' : r.severity === 'high' ? 'danger' : 'warning'}`}>{r.severity}</span>
            </div>
            <h3 className="rule-name">{r.name}</h3>
            <p className="rule-desc">{r.description}</p>
            <div className="rule-mitre">
              {r.mitre.split(', ').map((t) => (
                <span key={t} className="badge badge-accent">{t}</span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
