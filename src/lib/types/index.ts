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
	/** Overall confidence score (1-5), highest from any signature match */
	confidence: number;
	/** Vendor-specific product identification from signatures */
	product_family: string | null;
	/** All signature matches for this asset */
	signature_matches: AssetSignatureMatch[];
}

/** A signature match result attached to an asset */
export interface AssetSignatureMatch {
	signature_name: string;
	confidence: number;
	vendor: string | null;
	product_family: string | null;
	device_type: string | null;
	role: string | null;
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
	asset_count: number;
	elapsed_seconds: number;
}

/** Result of stopping a capture */
export interface StopCaptureResult {
	packets_captured: number;
	bytes_captured: number;
	elapsed_seconds: number;
	pcap_saved: boolean;
	pcap_path: string | null;
	packets_saved: number;
}

/** Current capture status from the backend */
export interface CaptureStatusInfo {
	is_running: boolean;
	is_paused: boolean;
	packets_captured: number;
	bytes_captured: number;
	elapsed_seconds: number;
}

// ─── Topology Views (Phase 2) ────────────────────────────────

/** How to group/cluster nodes in the topology graph */
export type GroupingMode = 'subnet' | 'protocol' | 'device_role' | 'vendor' | 'none';

/** A topology sub-tab (logical, mesh, filtered view, or watch tab) */
export interface TopologyTab {
	id: string;
	type: 'logical' | 'mesh' | 'filtered' | 'watch';
	label: string;
	closeable: boolean;
}

/** Configuration for a filtered view tab */
export interface FilteredViewConfig extends TopologyTab {
	type: 'filtered';
	/** Node IDs that are hidden in this view */
	hiddenNodeIds: string[];
}

/** Configuration for a watch tab */
export interface WatchViewConfig extends TopologyTab {
	type: 'watch';
	/** The IP/node ID being watched */
	targetNodeId: string;
	/** How many hops from the target to include (1-5) */
	depth: number;
}

// ─── Signatures (Phase 3) ────────────────────────────────────

/** Information about a loaded signature */
export interface SignatureInfo {
	name: string;
	description: string;
	vendor: string | null;
	product_family: string | null;
	protocol: string | null;
	confidence: number;
	role: string | null;
	device_type: string | null;
	filter_count: number;
}

/** Summary of all loaded signatures */
export interface SignatureSummary {
	total_count: number;
	signatures: SignatureInfo[];
}

/** Result of testing a signature against loaded data */
export interface SignatureTestResult {
	match_count: number;
	matches: SignatureTestMatch[];
}

export interface SignatureTestMatch {
	packet_index: number;
	src_ip: string;
	dst_ip: string;
	src_port: number;
	dst_port: number;
	confidence: number;
}

// ─── Deep Parse (Phase 4) ────────────────────────────────────

/** Aggregated deep parse info for a single device */
export interface DeepParseInfo {
	modbus: ModbusDetail | null;
	dnp3: Dnp3Detail | null;
}

/** Modbus protocol details for a device */
export interface ModbusDetail {
	role: string;
	unit_ids: number[];
	function_codes: FunctionCodeStat[];
	register_ranges: RegisterRangeInfo[];
	device_id: ModbusDeviceIdInfo | null;
	relationships: ModbusRelationship[];
	polling_intervals: PollingInterval[];
}

/** DNP3 protocol details for a device */
export interface Dnp3Detail {
	role: string;
	addresses: number[];
	function_codes: FunctionCodeStat[];
	has_unsolicited: boolean;
	relationships: Dnp3Relationship[];
}

/** Function code usage statistics */
export interface FunctionCodeStat {
	code: number;
	name: string;
	count: number;
	is_write: boolean;
}

/** Modbus register range */
export interface RegisterRangeInfo {
	start: number;
	count: number;
	register_type: string;
	access_count: number;
}

/** Modbus device identification from FC 43/14 */
export interface ModbusDeviceIdInfo {
	vendor_name: string | null;
	product_code: string | null;
	revision: string | null;
	vendor_url: string | null;
	product_name: string | null;
	model_name: string | null;
}

/** Modbus master/slave relationship */
export interface ModbusRelationship {
	remote_ip: string;
	remote_role: string;
	unit_ids: number[];
	packet_count: number;
}

/** DNP3 master/outstation relationship */
export interface Dnp3Relationship {
	remote_ip: string;
	remote_role: string;
	packet_count: number;
}

/** Detected polling interval */
export interface PollingInterval {
	remote_ip: string;
	unit_id: number | null;
	function_code: number;
	avg_interval_ms: number;
	min_interval_ms: number;
	max_interval_ms: number;
	sample_count: number;
}
