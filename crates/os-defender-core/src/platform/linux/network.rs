use crate::events::{
    EventType, EvidenceRef, NetDirection, NetworkContext, NetworkProtocol, NormalizedEvent,
    OsType, Severity,
};
use crate::platform::{CollectorResult, NetworkCollector};
use std::collections::HashSet;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::pin::Pin;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct ConnKey {
    protocol: &'static str,
    local_addr: String,
    local_port: u16,
    remote_addr: String,
    remote_port: u16,
    inode: u64,
}

pub struct LinuxNetworkCollector {
    endpoint_id: String,
    known_connections: HashSet<ConnKey>,
}

impl LinuxNetworkCollector {
    pub fn new(endpoint_id: String) -> Self {
        Self {
            endpoint_id,
            known_connections: HashSet::new(),
        }
    }

    fn parse_proc_net(content: &str, proto: &'static str) -> Vec<ConnKey> {
        let mut conns = Vec::new();
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }

            let (local_addr, local_port) = match Self::parse_addr_port(fields[1], proto) {
                Some(v) => v,
                None => continue,
            };
            let (remote_addr, remote_port) = match Self::parse_addr_port(fields[2], proto) {
                Some(v) => v,
                None => continue,
            };
            let inode: u64 = fields[9].parse().unwrap_or(0);

            conns.push(ConnKey {
                protocol: proto,
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                inode,
            });
        }
        conns
    }

    fn parse_addr_port(hex_str: &str, proto: &str) -> Option<(String, u16)> {
        let (addr_hex, port_hex) = hex_str.split_once(':')?;
        let port = u16::from_str_radix(port_hex, 16).ok()?;

        let addr = if proto.ends_with('6') {
            // IPv6: 32 hex chars
            if addr_hex.len() != 32 {
                return None;
            }
            let bytes: Vec<u8> = (0..32)
                .step_by(2)
                .filter_map(|i| u8::from_str_radix(&addr_hex[i..i + 2], 16).ok())
                .collect();
            if bytes.len() != 16 {
                return None;
            }
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&bytes);
            Ipv6Addr::from(arr).to_string()
        } else {
            // IPv4: 8 hex chars, little-endian
            let n = u32::from_str_radix(addr_hex, 16).ok()?;
            Ipv4Addr::from(n.swap_bytes()).to_string()
        };

        Some((addr, port))
    }

    fn scan_connections(&self) -> Vec<ConnKey> {
        let mut all = Vec::new();
        for (path, proto) in [
            ("/proc/net/tcp", "tcp"),
            ("/proc/net/tcp6", "tcp6"),
            ("/proc/net/udp", "udp"),
            ("/proc/net/udp6", "udp6"),
        ] {
            if let Ok(content) = fs::read_to_string(path) {
                all.extend(Self::parse_proc_net(&content, proto));
            }
        }
        all
    }

    fn resolve_pid_for_inode(&self, inode: u64) -> Option<(u32, String)> {
        if inode == 0 {
            return None;
        }
        let target = format!("socket:[{inode}]");
        let Ok(entries) = fs::read_dir("/proc") else {
            return None;
        };
        for entry in entries.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let fd_dir = format!("/proc/{pid}/fd");
            let Ok(fds) = fs::read_dir(&fd_dir) else {
                continue;
            };
            for fd in fds.flatten() {
                if let Ok(link) = fs::read_link(fd.path())
                    && link.to_string_lossy() == target
                {
                    let name = fs::read_to_string(format!("/proc/{pid}/comm"))
                        .unwrap_or_default()
                        .trim()
                        .to_string();
                    return Some((pid, name));
                }
            }
        }
        None
    }
}

impl NetworkCollector for LinuxNetworkCollector {
    fn poll_connections(&mut self) -> Pin<Box<dyn std::future::Future<Output = CollectorResult> + Send + '_>> {
        Box::pin(async {
            let current = self.scan_connections();
            let current_set: HashSet<ConnKey> = current.iter().cloned().collect();

            let mut events = Vec::new();
            for conn in &current {
                if self.known_connections.contains(conn) {
                    continue;
                }

                let (pid, process_name) = self
                    .resolve_pid_for_inode(conn.inode)
                    .unwrap_or((0, String::new()));

                let is_loopback =
                    conn.remote_addr == "127.0.0.1" || conn.remote_addr == "::1";
                let direction = if conn.remote_port == 0 || is_loopback {
                    NetDirection::Local
                } else {
                    NetDirection::Outbound
                };

                let protocol = if conn.protocol.starts_with("tcp") {
                    NetworkProtocol::Tcp
                } else {
                    NetworkProtocol::Udp
                };

                let event = NormalizedEvent::new(
                    self.endpoint_id.clone(),
                    OsType::Linux,
                    EventType::Network,
                    Severity::Info,
                )
                .with_network(NetworkContext {
                    protocol,
                    direction,
                    local_addr: conn.local_addr.clone(),
                    local_port: conn.local_port,
                    remote_addr: Some(conn.remote_addr.clone()),
                    remote_port: Some(conn.remote_port),
                    state: None,
                    pid: if pid > 0 { Some(pid) } else { None },
                    process_name: if process_name.is_empty() {
                        None
                    } else {
                        Some(process_name)
                    },
                    bytes_sent: None,
                    bytes_received: None,
                })
                .with_evidence(EvidenceRef {
                    source: "linux-proc-net".into(),
                    detail: format!("/proc/net/{}", conn.protocol),
                });

                events.push(event);
            }

            self.known_connections = current_set;
            Ok(events)
        })
    }

    fn name(&self) -> &str {
        "linux-network"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4_addr_port() {
        // 127.0.0.1:8080 in /proc/net/tcp format (little-endian)
        let result = LinuxNetworkCollector::parse_addr_port("0100007F:1F90", "tcp");
        let (addr, port) = result.unwrap();
        assert_eq!(addr, "127.0.0.1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn parse_proc_net_tcp_line() {
        let content = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 00000000 100 0 0 10 0";
        let conns = LinuxNetworkCollector::parse_proc_net(content, "tcp");
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].local_addr, "127.0.0.1");
        assert_eq!(conns[0].local_port, 8080);
        assert_eq!(conns[0].inode, 12345);
    }

    #[tokio::test]
    async fn scan_detects_connections() {
        let mut collector = LinuxNetworkCollector::new("test-ep".into());
        let result = collector.poll_connections().await.unwrap();
        // system always has at least some connections
        // second poll should show fewer new ones
        let result2 = collector.poll_connections().await.unwrap();
        assert!(result2.len() <= result.len());
    }
}
