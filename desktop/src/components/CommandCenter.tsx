import { useState } from 'react';
import { getAgentStatus, getEvents, getAlerts, getHealth, getAuditLog, getPolicyMode, getAiStatus, getPosture, getPersistence, verifyIntegrity, verifyAuditChain } from '../lib/ipc';

export function CommandCenter() {
  const [output, setOutput] = useState<string[]>([]);
  const [input, setInput] = useState('');
  const [running, setRunning] = useState(false);

  const execute = async () => {
    if (!input.trim()) return;
    const cmd = input.trim().toLowerCase();
    setInput('');
    setOutput((prev) => [...prev, `> ${cmd}`]);
    setRunning(true);

    try {
      let result: string;
      switch (cmd) {
        case 'status':
          result = JSON.stringify(await getAgentStatus(), null, 2);
          break;
        case 'events':
          result = JSON.stringify(await getEvents(20), null, 2);
          break;
        case 'alerts':
          result = JSON.stringify(await getAlerts(20), null, 2);
          break;
        case 'health':
          result = JSON.stringify(await getHealth(), null, 2);
          break;
        case 'audit':
          result = JSON.stringify(await getAuditLog(20), null, 2);
          break;
        case 'policy':
          result = JSON.stringify(await getPolicyMode(), null, 2);
          break;
        case 'ai':
          result = JSON.stringify(await getAiStatus(), null, 2);
          break;
        case 'posture':
          result = JSON.stringify(await getPosture(), null, 2);
          break;
        case 'persistence':
          result = JSON.stringify(await getPersistence(), null, 2);
          break;
        case 'integrity':
          result = JSON.stringify(await verifyIntegrity(), null, 2);
          break;
        case 'verify-chain':
          result = JSON.stringify(await verifyAuditChain(), null, 2);
          break;
        case 'help':
          result = [
            'Available commands:',
            '  status        — Agent status',
            '  events        — Recent events',
            '  alerts        — Recent alerts',
            '  health        — System health',
            '  audit         — Audit log',
            '  policy        — Policy mode',
            '  ai            — AI engine status',
            '  posture       — Security posture',
            '  persistence   — Persistence scan',
            '  integrity     — Tamper check',
            '  verify-chain  — Audit chain verification',
            '  clear         — Clear output',
            '  help          — This message',
          ].join('\n');
          break;
        case 'clear':
          setOutput([]);
          setRunning(false);
          return;
        default:
          result = `Unknown command: ${cmd}\nType 'help' for available commands.`;
      }
      setOutput((prev) => [...prev, result]);
    } catch (e) {
      setOutput((prev) => [...prev, `Error: ${e}`]);
    }
    setRunning(false);
  };

  return (
    <div className="page">
      <h1 className="page-title">Command Center</h1>
      <div className="card terminal-card">
        <div className="terminal-output">
          {output.length === 0 ? (
            <p className="text-muted">Type 'help' for available commands.</p>
          ) : (
            output.map((line, i) => (
              <pre key={i} className={line.startsWith('>') ? 'terminal-cmd' : 'terminal-result'}>{line}</pre>
            ))
          )}
        </div>
        <div className="terminal-input">
          <span className="terminal-prompt">$</span>
          <input
            className="terminal-field"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && execute()}
            placeholder="Enter command..."
            disabled={running}
            autoFocus
          />
        </div>
      </div>
    </div>
  );
}
