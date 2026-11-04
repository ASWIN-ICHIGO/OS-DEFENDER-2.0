#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use os_defender_core::ipc::{IpcRequest, IpcResponse, IpcStream};

async fn send_request(request: &IpcRequest) -> Result<IpcResponse, String> {
    let stream = IpcStream::connect_default()
        .await
        .map_err(|e| format!("Agent not running: {}", e))?;

    let (reader, mut writer) = tokio::io::split(stream);

    let mut payload = serde_json::to_string(request).map_err(|e| e.to_string())?;
    payload.push('\n');
    writer
        .write_all(payload.as_bytes())
        .await
        .map_err(|e| format!("Write failed: {e}"))?;
    writer.flush().await.map_err(|e| format!("Flush failed: {e}"))?;

    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();
    buf_reader
        .read_line(&mut line)
        .await
        .map_err(|e| format!("Read failed: {e}"))?;

    if line.is_empty() {
        return Err("Agent closed connection without response".into());
    }

    serde_json::from_str::<IpcResponse>(&line).map_err(|e| format!("Parse failed: {e}"))
}

fn response_to_value(resp: IpcResponse) -> Result<Value, String> {
    match resp {
        IpcResponse::Error { message } => Err(message),
        other => serde_json::to_value(other).map_err(|e| e.to_string()),
    }
}

#[tauri::command]
async fn get_agent_status() -> Result<Value, String> {
    let resp = send_request(&IpcRequest::Status).await?;
    response_to_value(resp)
}

#[tauri::command]
async fn get_events(limit: u32) -> Result<Value, String> {
    let resp = send_request(&IpcRequest::GetEvents { limit }).await?;
    response_to_value(resp)
}

#[tauri::command]
async fn get_alerts(limit: u32) -> Result<Value, String> {
    let resp = send_request(&IpcRequest::GetAlerts { limit }).await?;
    response_to_value(resp)
}

#[tauri::command]
async fn get_health() -> Result<Value, String> {
    let resp = send_request(&IpcRequest::GetHealth).await?;
    response_to_value(resp)
}

#[tauri::command]
async fn get_audit_log(limit: u32) -> Result<Value, String> {
    let resp = send_request(&IpcRequest::GetAuditLog { limit }).await?;
    response_to_value(resp)
}

#[tauri::command]
async fn get_policy_mode() -> Result<Value, String> {
    let resp = send_request(&IpcRequest::GetPolicyMode).await?;
    response_to_value(resp)
}

#[tauri::command]
async fn set_policy_mode(mode: String) -> Result<Value, String> {
    let pm: os_defender_core::response::PolicyMode =
        serde_json::from_value(Value::String(mode)).map_err(|e| e.to_string())?;
    let resp = send_request(&IpcRequest::SetPolicyMode { mode: pm }).await?;
    response_to_value(resp)
}

#[tauri::command]
async fn verify_audit_chain() -> Result<Value, String> {
    let resp = send_request(&IpcRequest::VerifyAuditChain).await?;
    response_to_value(resp)
}

#[tauri::command]
async fn get_ai_status() -> Result<Value, String> {
    let resp = send_request(&IpcRequest::GetAiStatus).await?;
    response_to_value(resp)
}

#[tauri::command]
async fn threat_hunt(query_json: String) -> Result<Value, String> {
    let query: os_defender_core::advanced::hunting::HuntQuery =
        serde_json::from_str(&query_json).map_err(|e| format!("Invalid query: {e}"))?;
    let resp = send_request(&IpcRequest::ThreatHunt {
        query: Box::new(query),
    })
    .await?;
    response_to_value(resp)
}

#[tauri::command]
async fn get_posture() -> Result<Value, String> {
    let resp = send_request(&IpcRequest::GetPosture).await?;
    response_to_value(resp)
}

#[tauri::command]
async fn get_persistence() -> Result<Value, String> {
    let resp = send_request(&IpcRequest::GetPersistence).await?;
    response_to_value(resp)
}

#[tauri::command]
async fn verify_integrity() -> Result<Value, String> {
    let resp = send_request(&IpcRequest::VerifyIntegrity).await?;
    response_to_value(resp)
}

#[tauri::command]
async fn check_update() -> Result<Value, String> {
    let resp = send_request(&IpcRequest::CheckUpdate).await?;
    response_to_value(resp)
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .invoke_handler(tauri::generate_handler![
            get_agent_status,
            get_events,
            get_alerts,
            get_health,
            get_audit_log,
            get_policy_mode,
            set_policy_mode,
            verify_audit_chain,
            get_ai_status,
            threat_hunt,
            get_posture,
            get_persistence,
            verify_integrity,
            check_update,
        ])
        .run(tauri::generate_context!())
        .expect("error while running OS Defender desktop application");
}
