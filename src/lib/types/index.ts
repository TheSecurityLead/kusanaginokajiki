/**
 * Kusanagi Kajiki — Core Types
 *
 * These types define the IPC contract between the Rust backend
 * and the SvelteKit frontend. Keep these in sync with the Rust
 * structs in src-tauri/src/commands/*.rs
 */

// ─── Network Interfaces ───────────────────────────────────────

export interface NetworkInterface {
	name: string;
	description: string | null;
	addresses: InterfaceAddress[];
	flags: InterfaceFlags;
}

export interface InterfaceAddress {
	addr: string;
	netmask: string | null;
	broadcast: string | null;
}

export interface InterfaceFlags {
	is_up: boolean;
	is_loopback: boolean;
	is_running: boolean;
}

// ─── Capture ──────────────────────────────────────────────────

export type CaptureStatus = 'idle' | 'capturing' | 'paused' | 'error';

export interface CaptureConfig {
	interface_name: string;
	bpf_filter: string | null;
	promiscuous: boolean;
}

export interface ImportResult {
	file_count: number;
	packet_count: number;
	connection_count: number;
	asset_count: number;
	protocols_detected: string[];
	duration_ms: number;
	per_file: FileImportResult[];
}

export interface FileImportResult {
	filename: string;
	packet_count: number;
	status: string;
}

// ─── Assets ───────────────────────────────────────────────────

export type DeviceType =
	| 'plc'
	| 'rtu'
	| 'hmi'
	| 'historian'
	| 'engineering_workstation'
	| 'scada_server'
	| 'it_device'
	| 'unknown';

export type PurdueLevel = 0 | 1 | 2 | 3 | 4 | 5;

export interface Asset {
	id: string;
	ip_address: string;
	mac_address: string | null;
	hostname: string | null;
	device_type: DeviceType;
	vendor: string | null;
	protocols: IcsProtocol[];
	first_seen: string; // ISO 8601
	last_seen: string;
	notes: string;
	purdue_level: PurdueLevel | null;
	tags: string[];
	packet_count: number;
}

// ─── Protocols ────────────────────────────────────────────────

export type IcsProtocol =
	| 'modbus'
	| 'dnp3'
	| 'ethernet_ip'
	| 'bacnet'
	| 's7comm'
	| 'opc_ua'
	| 'profinet'
	| 'iec104'
	| 'mqtt'
	| 'hart_ip'
	| 'foundation_fieldbus'
	| 'ge_srtp'
	| 'wonderware_suitelink'
	| 'http'
	| 'https'
	| 'dns'
	| 'ssh'
	| 'rdp'
	| 'snmp'
	| 'unknown';

export interface ProtocolStats {
	protocol: IcsProtocol;
	packet_count: number;
	byte_count: number;
	connection_count: number;
	unique_devices: number;
}

// ─── Connections ──────────────────────────────────────────────

export interface Connection {
	id: string;
	src_ip: string;
	src_port: number;
	src_mac: string | null;
	dst_ip: string;
	dst_port: number;
	dst_mac: string | null;
	protocol: string;
	transport: string;
	packet_count: number;
	byte_count: number;
	first_seen: string;
	last_seen: string;
	origin_files: string[];
}

// ─── Packet Summary (for connection tree) ─────────────────────

export interface PacketSummary {
	timestamp: string;
	src_ip: string;
	dst_ip: string;
	src_port: number;
	dst_port: number;
	protocol: string;
	length: number;
	origin_file: string;
}

// ─── Topology Graph ───────────────────────────────────────────

export interface TopologyGraph {
	nodes: TopologyNode[];
	edges: TopologyEdge[];
}

export interface TopologyNode {
	id: string;
	ip_address: string;
	mac_address: string | null;
	device_type: DeviceType;
	vendor: string | null;
	protocols: IcsProtocol[];
	subnet: string;
	packet_count: number;
}

export interface TopologyEdge {
	id: string;
	source: string; // node id
	target: string; // node id
	protocol: IcsProtocol;
	packet_count: number;
	byte_count: number;
	bidirectional: boolean;
}

// ─── Connection Tree ──────────────────────────────────────────

/** A node in the connection tree: represents an IP with its connections */
export interface ConnectionTreeNode {
	ip: string;
	device_type: DeviceType;
	mac_address: string | null;
	packet_count: number;
	connections: Connection[];
}

// ─── Tauri Event Payloads ─────────────────────────────────────

export interface PacketEvent {
	timestamp: string;
	src_ip: string;
	dst_ip: string;
	protocol: IcsProtocol;
	length: number;
}

export interface CaptureStatsEvent {
	packets_captured: number;
	packets_per_second: number;
	bytes_captured: number;
	active_connections: number;
	elapsed_seconds: number;
}
