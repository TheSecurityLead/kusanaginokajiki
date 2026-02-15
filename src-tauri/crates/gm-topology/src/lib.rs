//! # gm-topology
//!
//! Network topology graph engine.
//! Builds a directed graph from parsed packets, where:
//! - **Nodes** = unique IP addresses (network devices)
//! - **Edges** = observed connections between devices
//!
//! Uses `petgraph` for the underlying graph data structure.

use std::collections::HashMap;
use serde::Serialize;
use gm_parsers::IcsProtocol;

/// A node in the network topology graph (represents a device).
#[derive(Debug, Clone, Serialize)]
pub struct TopoNode {
    pub id: String,
    pub ip_address: String,
    pub mac_address: Option<String>,
    pub device_type: String,
    pub vendor: Option<String>,
    pub protocols: Vec<IcsProtocol>,
    pub subnet: String,
    pub packet_count: u64,
}

/// An edge in the topology graph (represents a connection).
#[derive(Debug, Clone, Serialize)]
pub struct TopoEdge {
    pub id: String,
    pub source: String,
    pub target: String,
    pub protocol: IcsProtocol,
    pub packet_count: u64,
    pub byte_count: u64,
    pub bidirectional: bool,
}

/// Serializable topology graph for the frontend.
#[derive(Debug, Clone, Serialize, Default)]
pub struct TopologyGraph {
    pub nodes: Vec<TopoNode>,
    pub edges: Vec<TopoEdge>,
}

/// Builds the topology graph from connection data.
///
/// This is a simplified builder for Phase 1-2. In later phases,
/// it will integrate with petgraph for more sophisticated analysis
/// (shortest paths, community detection, subnet clustering).
pub struct TopologyBuilder {
    /// Map IP address → node info
    nodes: HashMap<String, TopoNode>,
    /// Map (src_ip, dst_ip, protocol) → edge info
    edges: HashMap<(String, String, String), TopoEdge>,
    edge_counter: u64,
}

impl TopologyBuilder {
    pub fn new() -> Self {
        TopologyBuilder {
            nodes: HashMap::new(),
            edges: HashMap::new(),
            edge_counter: 0,
        }
    }

    /// Add a connection observation to the topology.
    pub fn add_connection(
        &mut self,
        src_ip: &str,
        dst_ip: &str,
        src_mac: Option<&str>,
        dst_mac: Option<&str>,
        protocol: IcsProtocol,
        bytes: u64,
    ) {
        // Ensure both nodes exist
        self.ensure_node(src_ip, src_mac, &protocol);
        self.ensure_node(dst_ip, dst_mac, &protocol);

        // Add or update edge
        let proto_str = format!("{:?}", protocol);
        let key = (src_ip.to_string(), dst_ip.to_string(), proto_str.clone());

        // Check for bidirectional traffic before mutably borrowing
        let reverse_key = (dst_ip.to_string(), src_ip.to_string(), proto_str.clone());
        let has_reverse = self.edges.contains_key(&reverse_key);

        let edge = self.edges.entry(key).or_insert_with(|| {
            self.edge_counter += 1;
            TopoEdge {
                id: format!("e{}", self.edge_counter),
                source: src_ip.to_string(),
                target: dst_ip.to_string(),
                protocol,
                packet_count: 0,
                byte_count: 0,
                bidirectional: false,
            }
        });

        edge.packet_count += 1;
        edge.byte_count += bytes;

        if has_reverse {
            edge.bidirectional = true;
        }
    }

    /// Build the final topology graph, consuming the builder.
    pub fn build(self) -> TopologyGraph {
        TopologyGraph {
            nodes: self.nodes.into_values().collect(),
            edges: self.edges.into_values().collect(),
        }
    }

    /// Create a snapshot of the current topology without consuming the builder.
    ///
    /// Used by live capture to periodically export the topology while
    /// continuing to accumulate data.
    pub fn snapshot(&self) -> TopologyGraph {
        TopologyGraph {
            nodes: self.nodes.values().cloned().collect(),
            edges: self.edges.values().cloned().collect(),
        }
    }

    fn ensure_node(&mut self, ip: &str, mac: Option<&str>, protocol: &IcsProtocol) {
        let node = self.nodes.entry(ip.to_string()).or_insert_with(|| {
            TopoNode {
                id: ip.to_string(),
                ip_address: ip.to_string(),
                mac_address: mac.map(String::from),
                device_type: "unknown".to_string(),
                vendor: None,
                protocols: Vec::new(),
                subnet: extract_subnet(ip),
                packet_count: 0,
            }
        });

        node.packet_count += 1;

        // Update MAC if we now have one
        if node.mac_address.is_none() {
            node.mac_address = mac.map(String::from);
        }

        // Track protocols seen on this device
        if !node.protocols.contains(protocol) {
            node.protocols.push(*protocol);
        }
    }
}

/// Extract /24 subnet from an IPv4 address.
fn extract_subnet(ip: &str) -> String {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() == 4 {
        format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2])
    } else {
        // IPv6 or malformed — just return as-is for now
        ip.to_string()
    }
}

impl Default for TopologyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_topology_builder() {
        let mut builder = TopologyBuilder::new();

        builder.add_connection(
            "192.168.1.10", "192.168.1.100",
            Some("aa:bb:cc:dd:ee:01"), Some("aa:bb:cc:dd:ee:02"),
            IcsProtocol::Modbus, 128,
        );
        builder.add_connection(
            "192.168.1.10", "192.168.1.100",
            None, None,
            IcsProtocol::Modbus, 64,
        );
        builder.add_connection(
            "192.168.1.100", "192.168.1.10",
            None, None,
            IcsProtocol::Modbus, 256,
        );

        let graph = builder.build();
        assert_eq!(graph.nodes.len(), 2);
        assert_eq!(graph.edges.len(), 2); // one per direction
    }

    #[test]
    fn test_subnet_extraction() {
        assert_eq!(extract_subnet("192.168.1.100"), "192.168.1.0/24");
        assert_eq!(extract_subnet("10.0.0.1"), "10.0.0.0/24");
    }
}
