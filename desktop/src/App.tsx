import { Routes, Route } from 'react-router-dom';
import { Layout } from './components/Layout';
import { Dashboard } from './components/Dashboard';
import { AlertsView } from './components/AlertsView';
import { ProcessExplorer } from './components/ProcessExplorer';
import { FileMonitor } from './components/FileMonitor';
import { NetworkMonitor } from './components/NetworkMonitor';
import { AuthEvents } from './components/AuthEvents';
import { DetectionRules } from './components/DetectionRules';
import { Enforcement } from './components/Enforcement';
import { AuditLog } from './components/AuditLog';
import { AiStatus } from './components/AiStatus';
import { RansomwareDefense } from './components/RansomwareDefense';
import { PersistenceScanner } from './components/PersistenceScanner';
import { FileIntelligence } from './components/FileIntelligence';
import { ThreatHunting } from './components/ThreatHunting';
import { Forensics } from './components/Forensics';
import { PostureAssessment } from './components/PostureAssessment';
import { TamperProtection } from './components/TamperProtection';
import { SystemHealth } from './components/SystemHealth';
import { CommandCenter } from './components/CommandCenter';
import { Settings } from './components/Settings';
import { About } from './components/About';
import './styles/global.css';

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="alerts" element={<AlertsView />} />
        <Route path="processes" element={<ProcessExplorer />} />
        <Route path="files" element={<FileMonitor />} />
        <Route path="network" element={<NetworkMonitor />} />
        <Route path="auth" element={<AuthEvents />} />
        <Route path="rules" element={<DetectionRules />} />
        <Route path="enforcement" element={<Enforcement />} />
        <Route path="audit" element={<AuditLog />} />
        <Route path="ai" element={<AiStatus />} />
        <Route path="ransomware" element={<RansomwareDefense />} />
        <Route path="persistence" element={<PersistenceScanner />} />
        <Route path="file-intel" element={<FileIntelligence />} />
        <Route path="hunt" element={<ThreatHunting />} />
        <Route path="forensics" element={<Forensics />} />
        <Route path="posture" element={<PostureAssessment />} />
        <Route path="tamper" element={<TamperProtection />} />
        <Route path="health" element={<SystemHealth />} />
        <Route path="command" element={<CommandCenter />} />
        <Route path="settings" element={<Settings />} />
        <Route path="about" element={<About />} />
      </Route>
    </Routes>
  );
}
