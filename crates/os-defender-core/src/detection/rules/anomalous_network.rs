use std::collections::HashSet;
use std::net::IpAddr;

use crate::events::{EventType, NetDirection, NormalizedEvent, Severity};
use super::super::Alert;
use super::traits::Rule;

/// Detects suspicious outbound network connections: uncommon ports, known-bad ranges,
/// high-port listeners.
/// MITRE ATT&CK: T1071 (Application Layer Protocol), T1571 (Non-Standard Port)
pub struct AnomalousNetworkRule {
    common_outbound_ports: HashSet<u16>,
    private_ranges_v4: Vec<(u32, u32)>,
    seen_listeners: HashSet<u16>,
}

impl Default for AnomalousNetworkRule {
    fn default() -> Self {
        Self::new()
    }
}

impl AnomalousNetworkRule {
    pub fn new() -> Self {
        let common = [
            22, 53, 80, 123, 443, 465, 587, 993, 995,
            3306, 5432, 8080, 8443,
        ];
        Self {
            common_outbound_ports: common.into_iter().collect(),
            private_ranges_v4: vec![
                (Self::ip_to_u32([10, 0, 0, 0]), Self::ip_to_u32([10, 255, 255, 255])),
                (Self::ip_to_u32([172, 16, 0, 0]), Self::ip_to_u32([172, 31, 255, 255])),
                (Self::ip_to_u32([192, 168, 0, 0]), Self::ip_to_u32([192, 168, 255, 255])),
            ],
            seen_listeners: HashSet::new(),
        }
    }

    fn ip_to_u32(octets: [u8; 4]) -> u32 {
        u32::from_be_bytes(octets)
    }

    fn is_private_v4(&self, addr: &str) -> bool {
        let Ok(ip) = addr.parse::<IpAddr>() else { return false };
        match ip {
            IpAddr::V4(v4) => {
                let n = u32::from_be_bytes(v4.octets());
                self.private_ranges_v4.iter().any(|&(lo, hi)| n >= lo && n <= hi)
                    || v4.is_loopback()
            }
            IpAddr::V6(v6) => v6.is_loopback(),
        }
    }
}

impl Rule for AnomalousNetworkRule {
    fn id(&self) -> &str { "R004-anomalous-network" }
    fn name(&self) -> &str { "Anomalous Network Activity" }

    fn evaluate(&mut self, event: &NormalizedEvent) -> Option<Alert> {
        if event.event_type != EventType::Network {
            return None;
        }
        let net = event.network_context.as_ref()?;

        // Detect new high-port listeners (potential backdoor)
        if net.direction == NetDirection::Local
            && net.local_port >= 1024
            && (net.remote_port == Some(0) || net.remote_addr.as_deref() == Some("0.0.0.0"))
        {
                if self.seen_listeners.insert(net.local_port) && self.seen_listeners.len() > 10 {
                    // only alert after we have a baseline (>10 known listeners)
                    let proc_name = net.process_name.as_deref().unwrap_or("unknown");
                    return Some(
                        Alert::from_rule(
                            event.event_id,
                            self.id(),
                            Severity::Medium,
                            format!("New listener on port {} by {proc_name}", net.local_port),
                            format!(
                                "Process '{proc_name}' opened a new listening port {} — not previously seen",
                                net.local_port
                            ),
                            0.5,
                        )
                        .with_factor("port", net.local_port as f64, "listening port number")
                        .with_mitre("T1571"),
                    );
                } else {
                    self.seen_listeners.insert(net.local_port);
                }
        }

        // Detect outbound connections to uncommon ports on public IPs
        if net.direction == NetDirection::Outbound {
            let remote_addr = net.remote_addr.as_deref().unwrap_or("");
            let remote_port = net.remote_port.unwrap_or(0);

            if remote_port > 0
                && !self.common_outbound_ports.contains(&remote_port)
                && !self.is_private_v4(remote_addr)
                && !remote_addr.is_empty()
            {
                let proc_name = net.process_name.as_deref().unwrap_or("unknown");
                let severity = if remote_port == 4444 || remote_port == 1337 || remote_port == 31337 {
                    Severity::High // commonly used by reverse shells/backdoors
                } else {
                    Severity::Low
                };

                return Some(
                    Alert::from_rule(
                        event.event_id,
                        self.id(),
                        severity,
                        format!("Uncommon outbound: {proc_name} → {remote_addr}:{remote_port}"),
                        format!(
                            "Process '{proc_name}' connected to {remote_addr}:{remote_port} — \
                             port {remote_port} is not in the common services list",
                        ),
                        0.4,
                    )
                    .with_factor("remote_port", remote_port as f64, "destination port")
                    .with_mitre("T1571"),
                );
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{NetworkContext, NetworkProtocol, OsType};

    fn net_event(dir: NetDirection, remote_addr: &str, remote_port: u16, proc_name: &str) -> NormalizedEvent {
        NormalizedEvent::new("ep".into(), OsType::Linux, EventType::Network, Severity::Info)
            .with_network(NetworkContext {
                protocol: NetworkProtocol::Tcp,
                direction: dir,
                local_addr: "192.168.1.10".into(),
                local_port: 45678,
                remote_addr: Some(remote_addr.into()),
                remote_port: Some(remote_port),
                state: None,
                pid: Some(1234),
                process_name: Some(proc_name.into()),
                bytes_sent: None,
                bytes_received: None,
            })
    }

    #[test]
    fn detects_uncommon_outbound_port() {
        let mut rule = AnomalousNetworkRule::new();
        let event = net_event(NetDirection::Outbound, "8.8.4.4", 9999, "suspect");
        let alert = rule.evaluate(&event).unwrap();
        assert!(alert.title.contains("9999"));
    }

    #[test]
    fn detects_backdoor_port() {
        let mut rule = AnomalousNetworkRule::new();
        let event = net_event(NetDirection::Outbound, "1.2.3.4", 4444, "shell");
        let alert = rule.evaluate(&event).unwrap();
        assert_eq!(alert.severity, Severity::High);
    }

    #[test]
    fn ignores_common_port() {
        let mut rule = AnomalousNetworkRule::new();
        let event = net_event(NetDirection::Outbound, "1.2.3.4", 443, "curl");
        assert!(rule.evaluate(&event).is_none());
    }

    #[test]
    fn ignores_private_ip() {
        let mut rule = AnomalousNetworkRule::new();
        let event = net_event(NetDirection::Outbound, "192.168.1.1", 9999, "app");
        assert!(rule.evaluate(&event).is_none());
    }
}
