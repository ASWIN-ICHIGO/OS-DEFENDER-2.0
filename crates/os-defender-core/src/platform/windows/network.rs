use crate::events::{
    EventType, EvidenceRef, NetDirection, NetworkContext, NetworkProtocol, NormalizedEvent,
    OsType, Severity,
};
use crate::platform::{CollectorError, CollectorResult, NetworkCollector};
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::pin::Pin;

use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCPTABLE_OWNER_PID,
    TCP_TABLE_OWNER_PID_ALL,
};
use windows::Win32::Networking::WinSock::{AF_INET, TCPSTATE_LISTEN};

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct ConnKey {
    local_addr: String,
    local_port: u16,
    remote_addr: String,
    remote_port: u16,
    pid: u32,
}

pub struct WindowsNetworkCollector {
    endpoint_id: String,
    known_connections: HashSet<ConnKey>,
}

impl WindowsNetworkCollector {
    pub fn new(endpoint_id: String) -> Self {
        Self {
            endpoint_id,
            known_connections: HashSet::new(),
        }
    }

    fn get_tcp_connections() -> Result<Vec<(ConnKey, u32)>, CollectorError> {
        let mut result = Vec::new();
        let mut buf_size: u32 = 0;

        unsafe {
            // First call to get required buffer size
            let _ = GetExtendedTcpTable(
                None,
                &mut buf_size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            let mut buffer = vec![0u8; buf_size as usize];
            let status = GetExtendedTcpTable(
                Some(buffer.as_mut_ptr().cast()),
                &mut buf_size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            if status != 0 {
                return Err(CollectorError::Unavailable(
                    format!("GetExtendedTcpTable error: {status}"),
                ));
            }

            let table = &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
            let rows = std::slice::from_raw_parts(
                table.table.as_ptr(),
                table.dwNumEntries as usize,
            );

            for row in rows {
                let local_addr = Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes());
                let remote_addr = Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes());
                let local_port = (row.dwLocalPort as u16).to_be();
                let remote_port = (row.dwRemotePort as u16).to_be();
                let state = row.dwState;

                let key = ConnKey {
                    local_addr: local_addr.to_string(),
                    local_port,
                    remote_addr: remote_addr.to_string(),
                    remote_port,
                    pid: row.dwOwningPid,
                };

                result.push((key, state));
            }
        }

        Ok(result)
    }
}

impl NetworkCollector for WindowsNetworkCollector {
    fn poll_connections(&mut self) -> Pin<Box<dyn std::future::Future<Output = CollectorResult> + Send + '_>> {
        Box::pin(async {
            let connections = Self::get_tcp_connections()?;
            let current_set: HashSet<ConnKey> = connections.iter().map(|(k, _)| k.clone()).collect();
            let mut events = Vec::new();

            for (conn, state) in &connections {
                if self.known_connections.contains(conn) {
                    continue;
                }

                let is_listen = *state == TCPSTATE_LISTEN.0 as u32;
                let is_loopback = conn.remote_addr == "127.0.0.1" || conn.remote_addr == "0.0.0.0";

                let direction = if is_listen || is_loopback {
                    NetDirection::Local
                } else {
                    NetDirection::Outbound
                };

                let event = NormalizedEvent::new(
                    self.endpoint_id.clone(),
                    OsType::Windows,
                    EventType::Network,
                    Severity::Info,
                )
                .with_network(NetworkContext {
                    protocol: NetworkProtocol::Tcp,
                    direction,
                    local_addr: conn.local_addr.clone(),
                    local_port: conn.local_port,
                    remote_addr: Some(conn.remote_addr.clone()),
                    remote_port: Some(conn.remote_port),
                    state: Some(format!("{state}")),
                    pid: Some(conn.pid),
                    process_name: None,
                    bytes_sent: None,
                    bytes_received: None,
                })
                .with_evidence(EvidenceRef {
                    source: "win32-tcp-table".into(),
                    detail: format!("PID {} state={state}", conn.pid),
                });

                events.push(event);
            }

            self.known_connections = current_set;
            Ok(events)
        })
    }

    fn name(&self) -> &str {
        "windows-network"
    }
}
