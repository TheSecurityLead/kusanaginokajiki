/**
 * Kusanagi Kajiki — Svelte Stores
 *
 * Central state management using Svelte 5 runes-compatible writable stores.
 * These stores are populated by Tauri commands and events.
 */

import { writable, derived } from 'svelte/store';
import type {
	NetworkInterface,
	Asset,
	Connection,
	ConnectionTreeNode,
	TopologyGraph,
	ProtocolStats,
	CaptureStatus,
	CaptureStatsEvent,
	IcsProtocol,
	TopologyTab,
	FilteredViewConfig,
	WatchViewConfig,
	GroupingMode,
	SignatureSummary,
	SessionInfo,
	PhysicalTopology,
	Finding,
	PurdueAssignment,
	AnomalyScore,
	AnalysisSummary,
	BaselineDiff,
	ThemeMode,
	TimelineRange
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

/** Loaded signature information */
export const signatureSummary = writable<SignatureSummary>({ total_count: 0, signatures: [] });

// ─── Session State (Phase 6) ─────────────────────────────

/** All saved sessions */
export const sessions = writable<SessionInfo[]>([]);

/** Currently loaded session info (null if no session loaded) */
export const currentSession = writable<SessionInfo | null>(null);

// ─── Physical Topology State (Phase 7) ───────────────────

/** Physical topology from Cisco config/CAM/CDP/ARP imports */
export const physicalTopology = writable<PhysicalTopology>({
	switches: [],
	links: [],
	device_locations: {}
});

/** Currently selected device IP in physical view (for cross-reference) */
export const physicalHighlightIp = writable<string | null>(null);

// ─── Security Analysis State (Phase 10) ──────────────────

/** Security findings from last analysis run */
export const findings = writable<Finding[]>([]);

/** Purdue level assignments from last analysis run */
export const purdueAssignments = writable<PurdueAssignment[]>([]);

/** Anomaly scores from last analysis run */
export const anomalies = writable<AnomalyScore[]>([]);

/** Analysis summary from last analysis run */
export const analysisSummary = writable<AnalysisSummary | null>(null);

// ─── Baseline Drift State (Phase 11) ─────────────────────

/** Last computed baseline diff (null if not run) */
export const baselineDiff = writable<BaselineDiff | null>(null);

// ─── Theme State (Phase 11) ──────────────────────────────

/** Current theme mode */
export const themeMode = writable<ThemeMode>('dark');

// ─── Timeline State (Phase 11) ───────────────────────────

/** Timeline range from loaded data */
export const timelineRange = writable<TimelineRange | null>(null);

/** Current timeline position as a fraction (0.0 = earliest, 1.0 = latest) */
export const timelinePosition = writable<number>(1.0);

/** Whether timeline playback is active */
export const timelinePlaying = writable<boolean>(false);

/** Whether the timeline scrubber is enabled (filtering active) */
export const timelineEnabled = writable<boolean>(false);

// ─── Capture State ────────────────────────────────────────────

/** Current capture status */
export const captureStatus = writable<CaptureStatus>('idle');

/** Live capture statistics */
export const captureStats = writable<CaptureStatsEvent>({
	packets_captured: 0,
	packets_per_second: 0,
	bytes_captured: 0,
	active_connections: 0,
	asset_count: 0,
	elapsed_seconds: 0
});

// ─── UI State ─────────────────────────────────────────────────

/** Currently selected asset ID (for detail panel) */
export const selectedAssetId = writable<string | null>(null);

/** Currently active view/tab */
export type ViewTab = 'topology' | 'physical' | 'inventory' | 'capture' | 'signatures' | 'protocol_stats' | 'export' | 'analysis' | 'settings';
export const activeTab = writable<ViewTab>('topology');

/** Search/filter text for asset inventory */
export const assetFilter = writable<string>('');

/** Protocol filter (null = show all) */
export const protocolFilter = writable<IcsProtocol | null>(null);

// ─── Topology View State (Phase 2) ──────────────────────────

/** How nodes are grouped/clustered in the logical view */
export const groupingMode = writable<GroupingMode>('subnet');

/** All open topology sub-tabs */
export const topologyTabs = writable<TopologyTab[]>([
	{ id: 'logical', type: 'logical', label: 'Logical View', closeable: false },
	{ id: 'mesh', type: 'mesh', label: 'Mesh View', closeable: false }
]);

/** Which topology sub-tab is currently active */
export const activeTopologyTabId = writable<string>('logical');

/** Counter for generating unique tab IDs */
let nextTabId = 1;

/** Add a filtered view tab */
export function addFilteredView(hiddenNodeIds: string[] = []): string {
	const id = `filtered-${nextTabId++}`;
	const tab: FilteredViewConfig = {
		id,
		type: 'filtered',
		label: `Filtered ${nextTabId - 1}`,
		closeable: true,
		hiddenNodeIds
	};
	topologyTabs.update((tabs) => [...tabs, tab]);
	activeTopologyTabId.set(id);
	return id;
}

/** Add a watch tab for a specific node */
export function addWatchTab(targetNodeId: string, depth = 2): string {
	const id = `watch-${nextTabId++}`;
	const tab: WatchViewConfig = {
		id,
		type: 'watch',
		label: `Watch ${targetNodeId}`,
		closeable: true,
		targetNodeId,
		depth
	};
	topologyTabs.update((tabs) => [...tabs, tab]);
	activeTopologyTabId.set(id);
	return id;
}

/** Close a topology sub-tab */
export function closeTopologyTab(tabId: string) {
	topologyTabs.update((tabs) => tabs.filter((t) => t.id !== tabId));
	// If the closed tab was active, switch to logical view
	activeTopologyTabId.update((current) => (current === tabId ? 'logical' : current));
}

/** Update a watch tab's depth */
export function updateWatchDepth(tabId: string, depth: number) {
	topologyTabs.update((tabs) =>
		tabs.map((t) => (t.id === tabId && t.type === 'watch' ? { ...t, depth } as WatchViewConfig : t))
	);
}

/** Toggle node visibility in a filtered view */
export function toggleNodeInFilter(tabId: string, nodeId: string) {
	topologyTabs.update((tabs) =>
		tabs.map((t) => {
			if (t.id !== tabId || t.type !== 'filtered') return t;
			const ft = t as FilteredViewConfig;
			const hidden = ft.hiddenNodeIds.includes(nodeId)
				? ft.hiddenNodeIds.filter((id) => id !== nodeId)
				: [...ft.hiddenNodeIds, nodeId];
			return { ...ft, hiddenNodeIds: hidden };
		})
	);
}

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

/** Connection tree: groups connections by source IP, with asset metadata */
export const connectionTree = derived(
	[assets, connections],
	([$assets, $connections]): ConnectionTreeNode[] => {
		if ($connections.length === 0) return [];

		// Build a map of IP → asset info for quick lookup
		const assetMap = new Map($assets.map((a) => [a.ip_address, a]));

		// Group connections by source IP
		const grouped = new Map<string, Connection[]>();
		for (const conn of $connections) {
			const existing = grouped.get(conn.src_ip);
			if (existing) {
				existing.push(conn);
			} else {
				grouped.set(conn.src_ip, [conn]);
			}
		}

		// Build tree nodes
		const nodes: ConnectionTreeNode[] = [];
		for (const [ip, conns] of grouped) {
			const asset = assetMap.get(ip);
			nodes.push({
				ip,
				device_type: (asset?.device_type as ConnectionTreeNode['device_type']) ?? 'unknown',
				mac_address: asset?.mac_address ?? null,
				packet_count: conns.reduce((sum, c) => sum + c.packet_count, 0),
				connections: conns.sort((a, b) => b.packet_count - a.packet_count)
			});
		}

		// Sort: OT devices first, then by packet count
		nodes.sort((a, b) => {
			const aOt = a.device_type !== 'it_device' && a.device_type !== 'unknown';
			const bOt = b.device_type !== 'it_device' && b.device_type !== 'unknown';
			if (aOt !== bOt) return bOt ? 1 : -1;
			return b.packet_count - a.packet_count;
		});

		return nodes;
	}
);

/** Set of IPs that are "new" in the baseline diff (for LogicalView highlighting) */
export const driftNewIps = derived(baselineDiff, ($diff) => {
	if (!$diff) return new Set<string>();
	return new Set($diff.new_assets.map((a) => a.ip_address));
});

/** Set of IPs that are "missing" in the baseline diff */
export const driftMissingIps = derived(baselineDiff, ($diff) => {
	if (!$diff) return new Set<string>();
	return new Set($diff.missing_assets.map((a) => a.ip_address));
});

/** Set of IPs that are "changed" in the baseline diff */
export const driftChangedIps = derived(baselineDiff, ($diff) => {
	if (!$diff) return new Set<string>();
	return new Set($diff.changed_assets.map((a) => a.ip_address));
});
