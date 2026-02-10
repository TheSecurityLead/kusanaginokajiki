/**
 * Kusanagi Kajiki — Graph Utilities (Phase 2)
 *
 * Client-side graph operations on TopologyGraph data.
 * Computes N-degree neighbors, filters nodes, and builds groupings
 * without requiring backend round-trips.
 */

import type { TopologyGraph, TopologyNode, TopologyEdge } from '$lib/types';

/**
 * Build an adjacency list from topology edges for efficient traversal.
 * Returns a Map where each node ID maps to the set of node IDs it connects to.
 */
function buildAdjacencyList(edges: TopologyEdge[]): Map<string, Set<string>> {
	const adj = new Map<string, Set<string>>();
	for (const edge of edges) {
		if (!adj.has(edge.source)) adj.set(edge.source, new Set());
		if (!adj.has(edge.target)) adj.set(edge.target, new Set());
		adj.get(edge.source)!.add(edge.target);
		adj.get(edge.target)!.add(edge.source);
	}
	return adj;
}

/**
 * Get all nodes within N hops of a target node using BFS.
 * Returns the subgraph (nodes + edges where both endpoints are in the result set).
 */
export function getNeighborSubgraph(
	graph: TopologyGraph,
	targetNodeId: string,
	depth: number
): TopologyGraph {
	const adj = buildAdjacencyList(graph.edges);
	const visited = new Set<string>();
	// BFS queue: [nodeId, currentDepth]
	const queue: [string, number][] = [[targetNodeId, 0]];
	visited.add(targetNodeId);

	while (queue.length > 0) {
		const [nodeId, d] = queue.shift()!;
		if (d >= depth) continue;
		const neighbors = adj.get(nodeId);
		if (!neighbors) continue;
		for (const neighbor of neighbors) {
			if (!visited.has(neighbor)) {
				visited.add(neighbor);
				queue.push([neighbor, d + 1]);
			}
		}
	}

	const nodes = graph.nodes.filter((n) => visited.has(n.id));
	const edges = graph.edges.filter((e) => visited.has(e.source) && visited.has(e.target));
	return { nodes, edges };
}

/**
 * Filter a topology graph by removing hidden nodes and their dangling edges.
 */
export function filterGraph(graph: TopologyGraph, hiddenNodeIds: Set<string>): TopologyGraph {
	const nodes = graph.nodes.filter((n) => !hiddenNodeIds.has(n.id));
	const visibleIds = new Set(nodes.map((n) => n.id));
	const edges = graph.edges.filter((e) => visibleIds.has(e.source) && visibleIds.has(e.target));
	return { nodes, edges };
}

/**
 * Compute edge width on a log scale based on packet count.
 * Returns a value between minWidth and maxWidth.
 */
export function edgeWidth(packetCount: number, minWidth = 1, maxWidth = 8): number {
	if (packetCount <= 1) return minWidth;
	// log scale: log2(count) normalized to range
	const logVal = Math.log2(packetCount);
	const maxLog = 20; // ~1M packets
	const ratio = Math.min(logVal / maxLog, 1);
	return minWidth + ratio * (maxWidth - minWidth);
}

/** Protocol → color mapping (matches CSS design tokens) */
export const PROTOCOL_COLORS: Record<string, string> = {
	modbus: '#f59e0b',
	dnp3: '#10b981',
	ethernet_ip: '#8b5cf6',
	bacnet: '#06b6d4',
	s7comm: '#ef4444',
	opc_ua: '#ec4899',
	profinet: '#f97316',
	iec104: '#84cc16',
	mqtt: '#14b8a6',
	hart_ip: '#a855f7',
	foundation_fieldbus: '#d946ef',
	ge_srtp: '#0ea5e9',
	wonderware_suitelink: '#e11d48',
	http: '#475569',
	https: '#64748b',
	dns: '#78716c',
	ssh: '#57534e',
	rdp: '#71717a',
	snmp: '#6b7280',
	unknown: '#64748b'
};

/** Device type → color mapping (matches CSS design tokens) */
export const DEVICE_COLORS: Record<string, string> = {
	plc: '#f59e0b',
	rtu: '#10b981',
	hmi: '#3b82f6',
	historian: '#8b5cf6',
	engineering_workstation: '#06b6d4',
	scada_server: '#ec4899',
	it_device: '#475569',
	unknown: '#64748b'
};

/** Device type → display label */
export const DEVICE_LABELS: Record<string, string> = {
	plc: 'PLC',
	rtu: 'RTU',
	hmi: 'HMI',
	historian: 'Historian',
	engineering_workstation: 'Eng. WS',
	scada_server: 'SCADA Server',
	it_device: 'IT Device',
	unknown: 'Unknown'
};

/** Check if a protocol is an OT protocol */
export function isOtProtocol(proto: string): boolean {
	const otProtocols = new Set([
		'modbus',
		'dnp3',
		'ethernet_ip',
		'bacnet',
		's7comm',
		'opc_ua',
		'profinet',
		'iec104',
		'mqtt',
		'hart_ip',
		'foundation_fieldbus',
		'ge_srtp',
		'wonderware_suitelink'
	]);
	return otProtocols.has(proto);
}

/**
 * Determine the primary protocol for a node (for protocol-based grouping).
 * Prefers OT protocols over IT protocols.
 */
export function primaryProtocol(node: TopologyNode): string {
	const ot = node.protocols.filter((p) => isOtProtocol(p));
	if (ot.length > 0) return ot[0];
	if (node.protocols.length > 0) return node.protocols[0];
	return 'unknown';
}

/**
 * Determine group parent ID for a node based on the active grouping mode.
 */
export function getGroupId(
	node: TopologyNode,
	mode: 'subnet' | 'protocol' | 'device_role' | 'vendor' | 'none'
): string | null {
	switch (mode) {
		case 'subnet':
			return `group:${node.subnet}`;
		case 'protocol':
			return `group:${primaryProtocol(node)}`;
		case 'device_role':
			return `group:${node.device_type}`;
		case 'vendor':
			return `group:${node.vendor ?? 'Unknown'}`;
		case 'none':
			return null;
	}
}

/**
 * Get display label for a group parent node.
 */
export function getGroupLabel(
	groupId: string,
	mode: 'subnet' | 'protocol' | 'device_role' | 'vendor' | 'none'
): string {
	const value = groupId.replace('group:', '');
	switch (mode) {
		case 'subnet':
			return value;
		case 'protocol':
			return (value.charAt(0).toUpperCase() + value.slice(1)).replace('_', '/');
		case 'device_role':
			return DEVICE_LABELS[value] ?? value;
		case 'vendor':
			return value;
		case 'none':
			return value;
	}
}
