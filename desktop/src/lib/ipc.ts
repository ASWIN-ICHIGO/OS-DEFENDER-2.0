import { invoke } from "@tauri-apps/api/core";
import type {
  AgentStatus,
  NormalizedEvent,
  Alert,
  VisibilityAssessment,
  AuditEntry,
  PolicyMode,
  AiEngineStatus,
  HuntQuery,
  HuntResult,
  PostureReport,
  PersistenceEntry,
  TamperCheckResult,
} from "./types";

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  return invoke<T>(cmd, args);
}

export async function getAgentStatus(): Promise<AgentStatus> {
  return call<AgentStatus>("get_agent_status");
}

export async function getEvents(limit: number = 100): Promise<NormalizedEvent[]> {
  return call<NormalizedEvent[]>("get_events", { limit });
}

export async function getAlerts(limit: number = 100): Promise<Alert[]> {
  return call<Alert[]>("get_alerts", { limit });
}

export async function getHealth(): Promise<VisibilityAssessment> {
  return call<VisibilityAssessment>("get_health");
}

export async function getAuditLog(limit: number = 100): Promise<AuditEntry[]> {
  return call<AuditEntry[]>("get_audit_log", { limit });
}

export async function getPolicyMode(): Promise<PolicyMode> {
  return call<PolicyMode>("get_policy_mode");
}

export async function setPolicyMode(mode: PolicyMode): Promise<void> {
  return call<void>("set_policy_mode", { mode });
}

export async function verifyAuditChain(): Promise<{ valid: boolean; entries: number }> {
  return call<{ valid: boolean; entries: number }>("verify_audit_chain");
}

export async function getAiStatus(): Promise<AiEngineStatus> {
  return call<AiEngineStatus>("get_ai_status");
}

export async function threatHunt(query: HuntQuery): Promise<HuntResult> {
  return call<HuntResult>("threat_hunt", { queryJson: JSON.stringify(query) });
}

export async function getPosture(): Promise<PostureReport> {
  return call<PostureReport>("get_posture");
}

export async function getPersistence(): Promise<PersistenceEntry[]> {
  return call<PersistenceEntry[]>("get_persistence");
}

export async function verifyIntegrity(): Promise<TamperCheckResult> {
  return call<TamperCheckResult>("verify_integrity");
}
