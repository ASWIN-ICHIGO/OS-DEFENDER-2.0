export type OsType = "linux" | "windows";

export type EventType =
  | "process"
  | "file"
  | "authentication"
  | "network"
  | "sensor-health"
  | "persistence"
  | "memory";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type FileAction =
  | "create"
  | "modify"
  | "delete"
  | "rename"
  | "permission"
  | "access";

export type NetworkProtocol = "tcp" | "udp" | "icmp" | "other";

export type NetDirection = "inbound" | "outbound" | "local" | "unknown";

export type AuthAction =
  | "login"
  | "logout"
  | "failed"
  | "escalation"
  | "key_auth";

export type CollectorState = "running" | "degraded" | "stopped" | "error";

export type DetectionSource = "rule" | "anomaly" | "correlation";

export type PolicyMode = "dry_run" | "approve" | "execute";

export type PolicyDecision =
  | "execute"
  | "dry_run"
  | "pending_approval"
  | "denied";

export type ResponseActionKind =
  | "block_ip"
  | "unblock_ip"
  | "freeze_process"
  | "thaw_process"
  | "quarantine_file"
  | "restore_file"
  | "kill_process";

export type PersistenceKind =
  | "systemd_service"
  | "systemd_timer"
  | "cron"
  | "shell_rc"
  | "init_script"
  | "xdg_autostart"
  | "udev_rule"
  | "registry_run"
  | "startup_folder"
  | "scheduled_task";

export type PostureCheckStatus = "pass" | "fail" | "warning" | "skipped";

export interface ProcessContext {
  pid: number;
  ppid: number | null;
  name: string;
  exe: string | null;
  cmdline: string | null;
  uid: number | null;
  username: string | null;
  start_time: string | null;
  children_pids: number[];
}

export interface FileContext {
  path: string;
  action: FileAction;
  sha256: string | null;
  size_bytes: number | null;
  owner_uid: number | null;
  permissions: string | null;
}

export interface NetworkContext {
  protocol: NetworkProtocol;
  direction: NetDirection;
  local_addr: string;
  local_port: number;
  remote_addr: string | null;
  remote_port: number | null;
  state: string | null;
  pid: number | null;
  process_name: string | null;
  bytes_sent: number | null;
  bytes_received: number | null;
}

export interface AuthContext {
  action: AuthAction;
  username: string;
  source_addr: string | null;
  method: string | null;
  service: string | null;
  session_id: string | null;
}

export interface CollectorStatus {
  collector_name: string;
  state: CollectorState;
  events_collected: number;
  events_dropped: number;
  lag_ms: number | null;
  last_heartbeat: string | null;
  error_message: string | null;
}

export interface EvidenceRef {
  source: string;
  detail: string;
}

export interface NormalizedEvent {
  event_id: string;
  timestamp: string;
  endpoint_id: string;
  os_type: OsType;
  event_type: EventType;
  severity: Severity;
  process_context: ProcessContext | null;
  file_context: FileContext | null;
  network_context: NetworkContext | null;
  auth_context: AuthContext | null;
  collector_status: CollectorStatus | null;
  evidence_refs: EvidenceRef[];
  fingerprint: string;
}

export interface Factor {
  name: string;
  weight: number;
  description: string;
}

export interface Alert {
  alert_id: string;
  event_id: string;
  timestamp: string;
  source: DetectionSource;
  rule_id: string | null;
  severity: Severity;
  title: string;
  description: string;
  confidence: number;
  factors: Factor[];
  mitre_techniques: string[];
}

export interface ResponseAction {
  action_id: string;
  alert_id: string;
  kind: ResponseActionKind;
  target: string;
  reason: string;
  timestamp: string;
}

export interface PolicyResult {
  action: ResponseAction;
  decision: PolicyDecision;
  mode: PolicyMode;
}

export interface AuditEntry {
  entry_id: number;
  timestamp: string;
  action: string;
  target: string;
  actor: string;
  reason: string;
  decision: string;
  prev_hash: string;
  entry_hash: string;
}

export interface AgentStatus {
  running: boolean;
  uptime_secs: number;
  events_processed: number;
  alerts_generated: number;
  actions_taken: number;
  policy_mode: string;
  collectors_active: string[];
  version: string;
}

export interface AiEngineStatus {
  available: boolean;
  model_loaded: boolean;
  model_path: string | null;
  baseline_learned: boolean;
  events_scored: number;
  anomalies_detected: number;
  last_drift_check: string | null;
  drift_detected: boolean;
  ollama_available: boolean;
}

export interface HuntQuery {
  event_type: string | null;
  severity_min: string | null;
  endpoint_id?: string | null;
  process_name: string | null;
  file_path_contains?: string | null;
  remote_addr: string | null;
  username: string | null;
  time_from?: string | null;
  time_to?: string | null;
  payload_contains: string | null;
  limit: number | null;
}

export interface HuntResult {
  query: HuntQuery;
  total_matches: number;
  events: NormalizedEvent[];
  executed_at: string;
}

export interface PostureCheck {
  id: string;
  category: string;
  description: string;
  status: PostureCheckStatus;
  detail: string;
  remediation: string;
}

export interface PostureReport {
  assessed_at: string;
  endpoint_id: string;
  checks: PostureCheck[];
  score: number;
  grade: string;
}

export type PersistenceRisk = "known" | "suspicious" | "high_risk";

export interface PersistenceEntry {
  kind: PersistenceKind;
  name: string;
  path: string;
  risk: PersistenceRisk;
  detail: string;
  mitre_technique: string;
  discovered_at: string;
}

export interface TamperViolation {
  path: string;
  expected_sha256: string;
  actual_sha256: string;
  detected_at: string;
}

export interface TamperCheckResult {
  checked_at: string;
  total_files: number;
  intact: number;
  tampered: TamperViolation[];
  missing: string[];
}

export interface SensorStatus {
  name: string;
  last_heartbeat: string | null;
  events_collected: number;
  events_dropped: number;
  is_healthy: boolean;
  lag_ms: number | null;
}

export interface VisibilityAssessment {
  timestamp: string;
  sensors: SensorStatus[];
  overall_healthy: boolean;
  blind_spots: string[];
  caveat: string;
}
