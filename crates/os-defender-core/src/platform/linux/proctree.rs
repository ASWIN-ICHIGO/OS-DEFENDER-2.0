use std::collections::HashMap;
use std::fs;

#[derive(Debug, Clone)]
pub struct ProcessNode {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub exe: String,
    pub uid: u32,
    pub children: Vec<u32>,
}

/// Maintains a live process tree from /proc.
/// Tracks parent-child relationships and provides ancestry queries.
pub struct ProcessTree {
    nodes: HashMap<u32, ProcessNode>,
}

impl ProcessTree {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
        }
    }

    /// Snapshot the entire /proc tree.
    pub fn refresh(&mut self) {
        let mut new_nodes = HashMap::new();

        let Ok(entries) = fs::read_dir("/proc") else { return };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(pid_str) = name.to_str() else { continue };
            let Ok(pid) = pid_str.parse::<u32>() else { continue };

            if let Some(node) = Self::read_node(pid) {
                new_nodes.insert(pid, node);
            }
        }

        // build children lists
        let pids: Vec<u32> = new_nodes.keys().copied().collect();
        for pid in pids {
            let ppid = new_nodes[&pid].ppid;
            if ppid != pid
                && let Some(parent) = new_nodes.get_mut(&ppid)
            {
                parent.children.push(pid);
            }
        }

        self.nodes = new_nodes;
    }

    fn read_node(pid: u32) -> Option<ProcessNode> {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let open = stat.find('(')?;
        let close = stat.rfind(')')?;
        let name = stat[open + 1..close].to_string();
        let fields: Vec<&str> = stat[close + 2..].split_whitespace().collect();
        let ppid: u32 = fields.get(1)?.parse().ok()?;

        let exe = fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();

        let uid = fs::read_to_string(format!("/proc/{pid}/status"))
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("Uid:"))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|v| v.parse().ok())
            })
            .unwrap_or(u32::MAX);

        Some(ProcessNode {
            pid,
            ppid,
            name,
            exe,
            uid,
            children: Vec::new(),
        })
    }

    /// Return the full ancestry chain from a PID up to PID 1.
    pub fn ancestry(&self, pid: u32) -> Vec<&ProcessNode> {
        let mut chain = Vec::new();
        let mut current = pid;
        let mut seen = std::collections::HashSet::new();

        while let Some(node) = self.nodes.get(&current) {
            if !seen.insert(current) {
                break; // cycle protection
            }
            chain.push(node);
            if node.ppid == 0 || node.ppid == current {
                break;
            }
            current = node.ppid;
        }
        chain
    }

    /// Get direct children of a PID.
    pub fn children(&self, pid: u32) -> Vec<&ProcessNode> {
        self.nodes
            .get(&pid)
            .map(|n| {
                n.children
                    .iter()
                    .filter_map(|c| self.nodes.get(c))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get a specific process by PID.
    pub fn get(&self, pid: u32) -> Option<&ProcessNode> {
        self.nodes.get(&pid)
    }

    /// Total tracked processes.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Find processes by executable name.
    pub fn find_by_name(&self, name: &str) -> Vec<&ProcessNode> {
        self.nodes
            .values()
            .filter(|n| n.name == name)
            .collect()
    }
}

impl Default for ProcessTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_populates_tree() {
        let mut tree = ProcessTree::new();
        tree.refresh();
        // must find at least PID 1 (init/systemd)
        assert!(tree.len() > 1);
        assert!(tree.get(1).is_some());
    }

    #[test]
    fn ancestry_traces_to_init() {
        let mut tree = ProcessTree::new();
        tree.refresh();
        let my_pid = std::process::id();
        let chain = tree.ancestry(my_pid);
        assert!(!chain.is_empty());
        // chain should end at PID 1 or 0
        let root = chain.last().unwrap();
        assert!(root.pid <= 2);
    }

    #[test]
    fn children_of_init_exist() {
        let mut tree = ProcessTree::new();
        tree.refresh();
        let kids = tree.children(1);
        assert!(!kids.is_empty());
    }

    #[test]
    fn find_by_name_works() {
        let mut tree = ProcessTree::new();
        tree.refresh();
        // there's always at least one process with a name
        let all_names: Vec<_> = tree.nodes.values().map(|n| n.name.clone()).collect();
        if let Some(name) = all_names.first() {
            let found = tree.find_by_name(name);
            assert!(!found.is_empty());
        }
    }
}
