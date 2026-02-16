/**
 * Tauri IPC wrapper — provides typed access to Rust backend commands.
 *
 * Each function here maps to a #[tauri::command] in the Rust backend.
 * This module is the ONLY place that calls tauri invoke() directly,
 * keeping the rest of the frontend decoupled from Tauri specifics.
 */

import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import type {
	NetworkInterface,
	ImportResult,
	TopologyGraph,
	Asset,
	Connection,
	ProtocolStats,
	PacketSummary,
	PacketEvent,
	CaptureStatsEvent,
	CaptureStatusInfo,
	StopCaptureResult,
	SignatureSummary,
	SignatureTestResult,
	DeepParseInfo,
	FunctionCodeStat,
	SessionInfo,
	AssetUpdate,
	PhysicalTopology,
	IngestImportResult,
	WiresharkInfo,
	FrameRow
} from '$lib/types';

// ─── System Commands ──────────────────────────────────────────

/** List all available network interfaces */
export async function listInterfaces(): Promise<NetworkInterface[]> {
	return invoke<NetworkInterface[]>('list_interfaces');
}

/** Get application version info */
export async function getAppInfo(): Promise<{ version: string; rust_version: string }> {
	return invoke('get_app_info');
}

// ─── PCAP Import ──────────────────────────────────────────────

/** Import one or more PCAP files and parse their contents */
export async function importPcap(paths: string[]): Promise<ImportResult> {
	return invoke<ImportResult>('import_pcap', { paths });
}

// ─── Topology ─────────────────────────────────────────────────

/** Get the current network topology graph */
export async function getTopology(): Promise<TopologyGraph> {
	return invoke<TopologyGraph>('get_topology');
}

// ─── Assets ───────────────────────────────────────────────────

/** Get all discovered assets */
export async function getAssets(): Promise<Asset[]> {
	return invoke<Asset[]>('get_assets');
}

/** Update an asset's editable fields (device type, hostname, notes, Purdue level, tags) */
export async function updateAsset(assetId: string, updates: AssetUpdate): Promise<Asset> {
	return invoke<Asset>('update_asset', { assetId, updates });
}

/** Bulk update assets (same fields applied to multiple assets) */
export async function bulkUpdateAssets(assetIds: string[], updates: AssetUpdate): Promise<number> {
	return invoke<number>('bulk_update_assets', { assetIds, updates });
}

// ─── Connections ──────────────────────────────────────────────

/** Get all observed connections */
export async function getConnections(): Promise<Connection[]> {
	return invoke<Connection[]>('get_connections');
}

/** Get packet summaries for a specific connection (for connection tree detail) */
export async function getConnectionPackets(connectionId: string): Promise<PacketSummary[]> {
	return invoke<PacketSummary[]>('get_connection_packets', { connectionId });
}

// ─── Statistics ───────────────────────────────────────────────

/** Get protocol breakdown statistics */
export async function getProtocolStats(): Promise<ProtocolStats[]> {
	return invoke<ProtocolStats[]>('get_protocol_stats');
}

// ─── Signatures (Phase 3) ─────────────────────────────────────

/** Get all loaded signatures */
export async function getSignatures(): Promise<SignatureSummary> {
	return invoke<SignatureSummary>('get_signatures');
}

/** Reload signatures from disk */
export async function reloadSignatures(): Promise<number> {
	return invoke<number>('reload_signatures');
}

/** Test a YAML signature against loaded PCAP data */
export async function testSignature(yaml: string): Promise<SignatureTestResult> {
	return invoke<SignatureTestResult>('test_signature', { yaml });
}

// ─── Deep Parse (Phase 4) ─────────────────────────────────────

/** Get deep parse details for a specific device */
export async function getDeepParseInfo(ipAddress: string): Promise<DeepParseInfo | null> {
	return invoke<DeepParseInfo | null>('get_deep_parse_info', { ipAddress });
}

/** Get function code distribution across all protocols */
export async function getFunctionCodeStats(): Promise<Record<string, FunctionCodeStat[]>> {
	return invoke<Record<string, FunctionCodeStat[]>>('get_function_code_stats');
}

// ─── Live Capture (Phase 5) ───────────────────────────────────

/** Start live packet capture on an interface */
export async function startCapture(interfaceName: string, bpfFilter?: string): Promise<void> {
	return invoke('start_capture', { interfaceName, bpfFilter: bpfFilter ?? null });
}

/** Stop live packet capture, optionally saving to a PCAP file */
export async function stopCapture(savePath?: string): Promise<StopCaptureResult> {
	return invoke<StopCaptureResult>('stop_capture', { savePath: savePath ?? null });
}

/** Pause live packet capture */
export async function pauseCapture(): Promise<void> {
	return invoke('pause_capture');
}

/** Resume a paused live capture */
export async function resumeCapture(): Promise<void> {
	return invoke('resume_capture');
}

/** Get current capture status */
export async function getCaptureStatus(): Promise<CaptureStatusInfo> {
	return invoke<CaptureStatusInfo>('get_capture_status');
}

// ─── Event Listeners ──────────────────────────────────────────

/** Listen for real-time packet events during live capture */
export async function onPacketEvent(callback: (event: PacketEvent) => void) {
	return listen<PacketEvent>('packet-event', (event) => callback(event.payload));
}

/** Listen for capture statistics updates */
export async function onCaptureStats(callback: (stats: CaptureStatsEvent) => void) {
	return listen<CaptureStatsEvent>('capture-stats', (event) => callback(event.payload));
}

/** Listen for capture error events */
export async function onCaptureError(callback: (error: string) => void) {
	return listen<string>('capture-error', (event) => callback(event.payload));
}

// ─── Sessions (Phase 6) ──────────────────────────────────

/** Save current state as a named session */
export async function saveSession(name: string, description?: string): Promise<SessionInfo> {
	return invoke<SessionInfo>('save_session', { name, description: description ?? null });
}

/** Load a saved session by ID, replacing current state */
export async function loadSession(sessionId: string): Promise<SessionInfo> {
	return invoke<SessionInfo>('load_session', { sessionId });
}

/** List all saved sessions */
export async function listSessions(): Promise<SessionInfo[]> {
	return invoke<SessionInfo[]>('list_sessions');
}

/** Delete a saved session */
export async function deleteSession(sessionId: string): Promise<void> {
	return invoke('delete_session', { sessionId });
}

/** Export a session to a .kkj ZIP archive */
export async function exportSessionArchive(sessionId: string, outputPath: string): Promise<string> {
	return invoke<string>('export_session_archive', { sessionId, outputPath });
}

/** Import a session from a .kkj ZIP archive */
export async function importSessionArchive(archivePath: string): Promise<SessionInfo> {
	return invoke<SessionInfo>('import_session_archive', { archivePath });
}

// ─── Physical Topology (Phase 7) ─────────────────────────────────

/** Import a Cisco IOS running-config file */
export async function importCiscoConfig(path: string): Promise<PhysicalTopology> {
	return invoke<PhysicalTopology>('import_cisco_config', { path });
}

/** Import a show mac address-table output file */
export async function importMacTable(path: string, switchHostname: string): Promise<PhysicalTopology> {
	return invoke<PhysicalTopology>('import_mac_table', { path, switchHostname });
}

/** Import a show cdp neighbors detail output file */
export async function importCdpNeighbors(path: string, switchHostname: string): Promise<PhysicalTopology> {
	return invoke<PhysicalTopology>('import_cdp_neighbors', { path, switchHostname });
}

/** Import a show arp output file */
export async function importArpTable(path: string): Promise<PhysicalTopology> {
	return invoke<PhysicalTopology>('import_arp_table', { path });
}

/** Get the current physical topology */
export async function getPhysicalTopology(): Promise<PhysicalTopology> {
	return invoke<PhysicalTopology>('get_physical_topology');
}

/** Clear all physical topology data */
export async function clearPhysicalTopology(): Promise<void> {
	return invoke('clear_physical_topology');
}

// ─── External Tool Import (Phase 8) ─────────────────────────────

/** Import Zeek TSV log files (conn.log, modbus.log, dnp3.log, s7comm.log) */
export async function importZeekLogs(paths: string[]): Promise<IngestImportResult> {
	return invoke<IngestImportResult>('import_zeek_logs', { paths });
}

/** Import a Suricata eve.json file */
export async function importSuricataEve(path: string): Promise<IngestImportResult> {
	return invoke<IngestImportResult>('import_suricata_eve', { path });
}

/** Import an Nmap XML file (-oX output). WARNING: Active scan data. */
export async function importNmapXml(path: string): Promise<IngestImportResult> {
	return invoke<IngestImportResult>('import_nmap_xml', { path });
}

/** Import a Masscan JSON file (-oJ output). WARNING: Active scan data. */
export async function importMasscanJson(path: string): Promise<IngestImportResult> {
	return invoke<IngestImportResult>('import_masscan_json', { path });
}

// ─── Wireshark Integration (Phase 8) ────────────────────────────

/** Detect Wireshark installation */
export async function detectWireshark(): Promise<WiresharkInfo> {
	return invoke<WiresharkInfo>('detect_wireshark');
}

/** Open Wireshark with a filter for a specific connection */
export async function openInWireshark(connectionId: string): Promise<void> {
	return invoke('open_in_wireshark', { connectionId });
}

/** Open Wireshark filtered to a specific IP address */
export async function openWiresharkForNode(ipAddress: string): Promise<void> {
	return invoke('open_wireshark_for_node', { ipAddress });
}

/** Get packet frames for a connection (View Frames dialog) */
export async function getConnectionFrames(connectionId: string): Promise<FrameRow[]> {
	return invoke<FrameRow[]>('get_connection_frames', { connectionId });
}

/** Export connection frames as CSV text */
export async function exportFramesCsv(connectionId: string): Promise<string> {
	return invoke<string>('export_frames_csv', { connectionId });
}

/** Save connection frames CSV to a file */
export async function saveFramesCsv(connectionId: string, outputPath: string): Promise<void> {
	return invoke('save_frames_csv', { connectionId, outputPath });
}
