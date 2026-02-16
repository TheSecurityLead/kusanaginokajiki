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
	/** Vendor from IEEE OUI database (MAC prefix lookup) */
	oui_vendor: string | null;
	/** ISO 3166-1 alpha-2 country code (public IPs only) */
	country: string | null;
	/** Whether this IP is a public (routable) address */
	is_public_ip: boolean;
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

// ─── Sessions (Phase 6) ─────────────────────────────────

/** Session info returned from the backend */
export interface SessionInfo {
	id: string;
	name: string;
	description: string;
	created_at: string;
	updated_at: string;
	asset_count: number;
	connection_count: number;
}

/** Partial updates for an asset's editable fields */
export interface AssetUpdate {
	device_type?: string;
	hostname?: string;
	notes?: string;
	purdue_level?: number;
	tags?: string[];
}

// ─── Physical Topology (Phase 7) ─────────────────────────

/** A physical network switch with ports and metadata */
export interface PhysicalSwitch {
	hostname: string;
	management_ip: string | null;
	model: string | null;
	ios_version: string | null;
	ports: PhysicalPort[];
	vlans: Record<number, string>;
}

/** A physical switch port with devices and config */
export interface PhysicalPort {
	name: string;
	short_name: string;
	description: string | null;
	vlans: number[];
	mode: string;
	shutdown: boolean;
	ip_address: string | null;
	subnet_mask: string | null;
	mac_addresses: string[];
	ip_addresses: string[];
	cdp_neighbor: CdpNeighbor | null;
	speed: string | null;
	duplex: string | null;
}

/** CDP/LLDP neighbor on a port */
export interface CdpNeighbor {
	device_id: string;
	remote_port: string;
	platform: string | null;
	ip_address: string | null;
	capabilities: string[];
}

/** Where a device is physically located */
export interface DeviceLocation {
	ip_address: string;
	mac_address: string | null;
	switch_hostname: string;
	port_name: string;
	vlan: number | null;
}

/** A link between two physical switches */
export interface PhysicalLink {
	src_switch: string;
	src_port: string;
	dst_switch: string;
	dst_port: string;
}

/** Full physical topology */
export interface PhysicalTopology {
	switches: PhysicalSwitch[];
	links: PhysicalLink[];
	device_locations: Record<string, DeviceLocation>;
}

// ─── External Tool Ingest (Phase 8) ─────────────────────

/** Data source for ingested results */
export type IngestSource = 'zeek' | 'suricata' | 'nmap' | 'masscan';

/** Result of importing external tool data */
export interface IngestImportResult {
	source: string;
	files_processed: number;
	asset_count: number;
	connection_count: number;
	alert_count: number;
	new_assets: number;
	updated_assets: number;
	duration_ms: number;
	errors: string[];
}

// ─── Wireshark Integration (Phase 8) ─────────────────────

/** Wireshark installation info */
export interface WiresharkInfo {
	found: boolean;
	path: string | null;
	version: string | null;
}

/** A packet frame row for the View Frames dialog */
export interface FrameRow {
	number: number;
	timestamp: string;
	src_ip: string;
	dst_ip: string;
	src_port: number;
	dst_port: number;
	protocol: string;
	length: number;
	origin_file: string;
}

// ─── Export & Reporting (Phase 9) ─────────────────────────

/** Configuration for PDF report generation */
export interface ReportConfig {
	assessor_name: string;
	client_name: string;
	assessment_date?: string;
	title?: string;
	include_executive_summary: boolean;
	include_asset_inventory: boolean;
	include_protocol_analysis: boolean;
	include_findings: boolean;
	include_recommendations: boolean;
}

/** SBOM entry (CISA BOD 23-01 format) */
export interface SbomEntry {
	ip_address: string;
	mac_address: string;
	hostname: string;
	vendor: string;
	product: string;
	firmware_version: string;
	protocols: string;
	purdue_zone: string;
	device_type: string;
	confidence: number;
	first_seen: string;
	last_seen: string;
	country: string;
	tags: string;
}

/** Export format options */
export type ExportFormat = 'csv' | 'json' | 'pdf' | 'sbom_csv' | 'sbom_json' | 'stix';

// ─── Security Analysis (Phase 10) ────────────────────────

/** Finding type classification */
export type FindingType = 'attack_technique' | 'purdue_violation' | 'anomaly';

/** Severity levels for findings */
export type FindingSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

/** A security finding from analysis */
export interface Finding {
	id: string;
	finding_type: FindingType;
	severity: FindingSeverity;
	title: string;
	description: string;
	affected_assets: string[];
	evidence: string;
	technique_id: string | null;
	created_at: string;
}

/** Purdue level assignment method */
export type PurdueMethod = 'auto' | 'manual';

/** Purdue level assignment for a device */
export interface PurdueAssignment {
	ip_address: string;
	level: number;
	method: PurdueMethod;
	reason: string;
}

/** Anomaly type classification */
export type AnomalyType = 'polling_deviation' | 'role_reversal' | 'new_device' | 'unexpected_public_ip';

/** An anomaly score from analysis */
export interface AnomalyScore {
	anomaly_type: AnomalyType;
	severity: FindingSeverity;
	confidence: number;
	affected_asset: string;
	evidence: string;
}

/** Full analysis result from the backend */
export interface AnalysisResult {
	findings: Finding[];
	purdue_assignments: PurdueAssignment[];
	anomalies: AnomalyScore[];
	summary: AnalysisSummary;
}

/** Summary statistics from an analysis run */
export interface AnalysisSummary {
	total_findings: number;
	critical_count: number;
	high_count: number;
	medium_count: number;
	low_count: number;
	info_count: number;
	purdue_violations: number;
	anomaly_count: number;
	assets_analyzed: number;
	connections_analyzed: number;
	unencrypted_ot_percent: number;
}

// ─── Baseline Drift (Phase 11) ───────────────────────────

/** Full diff result between current state and a baseline session */
export interface BaselineDiff {
	baseline_session_name: string;
	new_assets: DriftAsset[];
	missing_assets: DriftAsset[];
	changed_assets: ChangedAsset[];
	new_connections: DriftConnection[];
	missing_connections: DriftConnection[];
	summary: DriftSummary;
}

/** A device in the drift report (new or missing) */
export interface DriftAsset {
	ip_address: string;
	mac_address: string | null;
	device_type: string;
	vendor: string | null;
	protocols: string[];
	confidence: number;
}

/** A device with changed properties */
export interface ChangedAsset {
	ip_address: string;
	changes: AssetChange[];
}

/** A single field change between baseline and current */
export interface AssetChange {
	field: string;
	baseline_value: string;
	current_value: string;
}

/** A connection in the drift report */
export interface DriftConnection {
	src_ip: string;
	dst_ip: string;
	src_port: number;
	dst_port: number;
	protocol: string;
}

/** Summary of drift statistics */
export interface DriftSummary {
	total_baseline_assets: number;
	total_current_assets: number;
	new_asset_count: number;
	missing_asset_count: number;
	changed_asset_count: number;
	new_connection_count: number;
	missing_connection_count: number;
	drift_score: number;
}

// ─── Theme (Phase 11) ────────────────────────────────────

/** Theme mode: dark, light, or follow system preference */
export type ThemeMode = 'dark' | 'light' | 'system';

/** Persistent user settings */
export interface UserSettings {
	theme: ThemeMode;
}

// ─── Timeline (Phase 11) ─────────────────────────────────

/** Timeline range for the scrubber */
export interface TimelineRange {
	earliest: string | null;
	latest: string | null;
	connection_count: number;
}

// ─── Plugins (Phase 11) ──────────────────────────────────

/** A plugin manifest */
export interface PluginManifest {
	name: string;
	version: string;
	plugin_type: string;
	description: string;
	author: string | null;
}
