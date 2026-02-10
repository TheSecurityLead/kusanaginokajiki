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
	CaptureStatsEvent
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

/** Update an asset's metadata (device type, notes, Purdue level, tags) */
export async function updateAsset(
	assetId: string,
	updates: Partial<Pick<Asset, 'device_type' | 'notes' | 'purdue_level' | 'tags'>>
): Promise<Asset> {
	return invoke<Asset>('update_asset', { assetId, updates });
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

// ─── Live Capture (Phase 5) ───────────────────────────────────

/** Start live packet capture on an interface */
export async function startCapture(interfaceName: string, bpfFilter?: string): Promise<void> {
	return invoke('start_capture', { interfaceName, bpfFilter: bpfFilter ?? null });
}

/** Stop live packet capture */
export async function stopCapture(): Promise<void> {
	return invoke('stop_capture');
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
