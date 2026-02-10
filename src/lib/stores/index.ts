/**
 * GRASSMARLIN Reborn — Svelte Stores
 *
 * Central state management using Svelte 5 runes-compatible writable stores.
 * These stores are populated by Tauri commands and events.
 */

import { writable, derived } from 'svelte/store';
import type {
	NetworkInterface,
	Asset,
	Connection,
	TopologyGraph,
	ProtocolStats,
	CaptureStatus,
	CaptureStatsEvent,
	IcsProtocol
} from '$lib/types';

// ─── Core Application State ──────────────────────────────────

/** Available network interfaces */
export const interfaces = writable<NetworkInterface[]>([]);

/** Discovered assets (devices on the network) */
export const assets = writable<Asset[]>([]);

/** Observed connections between assets */
export const connections = writable<Connection[]>([]);

/** Network topology graph for visualization */
export const topology = writable<TopologyGraph>({ nodes: [], edges: [] });

/** Protocol statistics */
export const protocolStats = writable<ProtocolStats[]>([]);

// ─── Capture State ────────────────────────────────────────────

/** Current capture status */
export const captureStatus = writable<CaptureStatus>('idle');

/** Live capture statistics */
export const captureStats = writable<CaptureStatsEvent>({
	packets_captured: 0,
	packets_per_second: 0,
	bytes_captured: 0,
	active_connections: 0,
	elapsed_seconds: 0
});

// ─── UI State ─────────────────────────────────────────────────

/** Currently selected asset ID (for detail panel) */
export const selectedAssetId = writable<string | null>(null);

/** Currently active view/tab */
export type ViewTab = 'topology' | 'inventory' | 'capture' | 'settings';
export const activeTab = writable<ViewTab>('topology');

/** Search/filter text for asset inventory */
export const assetFilter = writable<string>('');

/** Protocol filter (null = show all) */
export const protocolFilter = writable<IcsProtocol | null>(null);

// ─── Derived Stores ───────────────────────────────────────────

/** Total count of discovered assets */
export const assetCount = derived(assets, ($assets) => $assets.length);

/** Total count of connections */
export const connectionCount = derived(connections, ($connections) => $connections.length);

/** Currently selected asset object */
export const selectedAsset = derived(
	[assets, selectedAssetId],
	([$assets, $selectedAssetId]) => {
		if (!$selectedAssetId) return null;
		return $assets.find((a) => a.id === $selectedAssetId) ?? null;
	}
);

/** Filtered assets based on search text and protocol filter */
export const filteredAssets = derived(
	[assets, assetFilter, protocolFilter],
	([$assets, $filter, $protocol]) => {
		let result = $assets;

		if ($filter) {
			const lower = $filter.toLowerCase();
			result = result.filter(
				(a) =>
					a.ip_address.includes(lower) ||
					a.mac_address?.toLowerCase().includes(lower) ||
					a.hostname?.toLowerCase().includes(lower) ||
					a.vendor?.toLowerCase().includes(lower) ||
					a.device_type.includes(lower) ||
					a.notes.toLowerCase().includes(lower)
			);
		}

		if ($protocol) {
			result = result.filter((a) => a.protocols.includes($protocol));
		}

		return result;
	}
);

/** OT-specific assets only (excludes IT devices) */
export const otAssets = derived(assets, ($assets) =>
	$assets.filter((a) => a.device_type !== 'it_device' && a.device_type !== 'unknown')
);
