import { useState, useEffect } from 'react';
import type { PostureReport } from '../lib/types';
import { getPosture } from '../lib/ipc';

export function PostureAssessment() {
  const [report, setReport] = useState<PostureReport | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      try { setReport(await getPosture()); } catch {}
      setLoading(false);
    };
    load();
  }, []);

  const refresh = async () => {
    setLoading(true);
    try { setReport(await getPosture()); } catch {}
    setLoading(false);
  };

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Security Posture</h1>
        <button className="btn btn-accent" onClick={refresh} disabled={loading}>
          {loading ? 'Assessing...' : 'Re-assess'}
        </button>
      </div>

      {report && (
        <>
          <div className="stats-grid">
            <div className="stat-card">
              <div className="stat-card-value">{report.grade}</div>
              <div className="stat-card-label">Grade</div>
            </div>
            <div className="stat-card accent">
              <div className="stat-card-value">{report.score.toFixed(0)}%</div>
              <div className="stat-card-label">Score</div>
            </div>
            <div className="stat-card success">
              <div className="stat-card-value">{report.checks.filter(c => c.status === 'pass').length}</div>
              <div className="stat-card-label">Passed</div>
            </div>
            <div className="stat-card danger">
              <div className="stat-card-value">{report.checks.filter(c => c.status === 'fail').length}</div>
              <div className="stat-card-label">Failed</div>
            </div>
          </div>

          <div className="card">
            <table className="data-table">
              <thead>
                <tr><th>ID</th><th>Check</th><th>Status</th><th>Details</th><th>Remediation</th></tr>
              </thead>
              <tbody>
                {report.checks.map((c, i) => (
                  <tr key={i}>
                    <td className="mono">{c.id}</td>
                    <td>{c.description}</td>
                    <td><span className={`badge badge-${checkColor(c.status)}`}>{c.status}</span></td>
                    <td className="text-muted">{c.detail}</td>
                    <td className="text-muted">{c.remediation}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}

function checkColor(s: string): string {
  switch (s.toLowerCase()) {
    case 'pass': return 'success';
    case 'fail': return 'danger';
    case 'skip': return 'warning';
    default: return 'muted';
  }
}
