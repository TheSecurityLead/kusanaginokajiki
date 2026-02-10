<script lang="ts">
	import { connectionTree, selectedAssetId } from '$lib/stores';
	import { getConnectionPackets } from '$lib/utils/tauri';
	import type { Connection, PacketSummary, DeviceType } from '$lib/types';

	const deviceTypeLabels: Record<DeviceType, string> = {
		plc: 'PLC',
		rtu: 'RTU',
		hmi: 'HMI',
		historian: 'Historian',
		engineering_workstation: 'Eng. WS',
		scada_server: 'SCADA Server',
		it_device: 'IT Device',
		unknown: 'Unknown'
	};

	const deviceTypeColors: Record<DeviceType, string> = {
		plc: '#f59e0b',
		rtu: '#10b981',
		hmi: '#3b82f6',
		historian: '#8b5cf6',
		engineering_workstation: '#06b6d4',
		scada_server: '#ec4899',
		it_device: '#475569',
		unknown: '#64748b'
	};

	// Track which tree nodes are expanded
	let expandedNodes = $state<Set<string>>(new Set());
	let expandedConns = $state<Set<string>>(new Set());
	// Cache packet summaries for expanded connections
	let packetCache = $state<Map<string, PacketSummary[]>>(new Map());
	let loadingConns = $state<Set<string>>(new Set());

	function toggleNode(ip: string) {
		const next = new Set(expandedNodes);
		if (next.has(ip)) {
			next.delete(ip);
		} else {
			next.add(ip);
		}
		expandedNodes = next;
	}

	async function toggleConnection(conn: Connection) {
		const next = new Set(expandedConns);
		if (next.has(conn.id)) {
			next.delete(conn.id);
			expandedConns = next;
			return;
		}

		next.add(conn.id);
		expandedConns = next;

		// Fetch packet summaries if not cached
		if (!packetCache.has(conn.id)) {
			const loading = new Set(loadingConns);
			loading.add(conn.id);
			loadingConns = loading;
			try {
				const packets = await getConnectionPackets(conn.id);
				const cache = new Map(packetCache);
				cache.set(conn.id, packets);
				packetCache = cache;
			} catch (err) {
				console.error('Failed to fetch packets for', conn.id, err);
			} finally {
				const done = new Set(loadingConns);
				done.delete(conn.id);
				loadingConns = done;
			}
		}
	}

	function selectNode(ip: string) {
		selectedAssetId.set(ip);
	}

	function formatBytes(bytes: number): string {
		if (bytes < 1024) return `${bytes} B`;
		if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
		return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
	}

	function formatTime(iso: string): string {
		try {
			const d = new Date(iso);
			return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
		} catch {
			return iso;
		}
	}
</script>

<div class="tree-container">
	<div class="tree-header">
		<span class="tree-title">CONNECTION TREE</span>
		<span class="tree-count">{$connectionTree.length} nodes</span>
	</div>

	<div class="tree-content">
		{#if $connectionTree.length === 0}
			<div class="tree-empty">
				No connections. Import a PCAP file to populate the tree.
			</div>
		{:else}
			{#each $connectionTree as node}
				{@const isExpanded = expandedNodes.has(node.ip)}
				{@const isSelected = $selectedAssetId === node.ip}
				<div class="tree-node">
					<!-- Node header (IP) -->
					<button
						class="node-header"
						class:expanded={isExpanded}
						class:selected={isSelected}
						onclick={() => { toggleNode(node.ip); selectNode(node.ip); }}
					>
						<span class="expand-icon">{isExpanded ? '\u25BC' : '\u25B6'}</span>
						<span
							class="device-dot"
							style="background: {deviceTypeColors[node.device_type]}"
						></span>
						<span class="node-ip">{node.ip}</span>
						<span class="node-meta">
							<span
								class="node-type"
								style="color: {deviceTypeColors[node.device_type]}"
							>{deviceTypeLabels[node.device_type]}</span>
							<span class="node-pkt">{node.connections.length} conn</span>
						</span>
					</button>

					<!-- Expanded: connections for this node -->
					{#if isExpanded}
						<div class="node-connections">
							{#each node.connections as conn}
								{@const isConnExpanded = expandedConns.has(conn.id)}
								<div class="conn-entry">
									<button
										class="conn-header"
										class:expanded={isConnExpanded}
										onclick={() => toggleConnection(conn)}
									>
										<span class="expand-icon small">{isConnExpanded ? '\u25BC' : '\u25B6'}</span>
										<span class="conn-arrow">
											:{conn.src_port} → {conn.dst_ip}:{conn.dst_port}
										</span>
										<span class="conn-proto">{conn.protocol}</span>
										<span class="conn-count">{conn.packet_count.toLocaleString()}</span>
									</button>

									<!-- Connection metadata -->
									{#if isConnExpanded}
										<div class="conn-details">
											<div class="conn-meta-row">
												<span class="meta-label">Transport</span>
												<span class="meta-value">{conn.transport.toUpperCase()}</span>
											</div>
											<div class="conn-meta-row">
												<span class="meta-label">Bytes</span>
												<span class="meta-value">{formatBytes(conn.byte_count)}</span>
											</div>
											{#if conn.origin_files.length > 0}
												<div class="conn-meta-row">
													<span class="meta-label">Files</span>
													<span class="meta-value">{conn.origin_files.join(', ')}</span>
												</div>
											{/if}

											<!-- Packet summaries -->
											{#if loadingConns.has(conn.id)}
												<div class="packet-loading">Loading packets...</div>
											{:else if packetCache.has(conn.id)}
												{@const packets = packetCache.get(conn.id) ?? []}
												<div class="packet-list">
													<div class="packet-header-row">
														<span>Time</span>
														<span>Size</span>
														<span>Protocol</span>
														<span>Source</span>
													</div>
													{#each packets.slice(0, 50) as pkt}
														<div class="packet-row">
															<span class="pkt-time">{formatTime(pkt.timestamp)}</span>
															<span class="pkt-size">{pkt.length}</span>
															<span class="pkt-proto">{pkt.protocol}</span>
															<span class="pkt-file">{pkt.origin_file}</span>
														</div>
													{/each}
													{#if packets.length > 50}
														<div class="packet-more">
															...and {packets.length - 50} more packets
														</div>
													{/if}
												</div>
											{/if}
										</div>
									{/if}
								</div>
							{/each}
						</div>
					{/if}
				</div>
			{/each}
		{/if}
	</div>
</div>

<style>
	.tree-container {
		display: flex;
		flex-direction: column;
		height: 100%;
		background: var(--gm-bg-secondary);
		border-right: 1px solid var(--gm-border);
		width: 100%;
	}

	.tree-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 10px 12px;
		border-bottom: 1px solid var(--gm-border);
	}

	.tree-title {
		font-size: 10px;
		font-weight: 600;
		letter-spacing: 1.5px;
		color: var(--gm-text-muted);
	}

	.tree-count {
		font-size: 10px;
		color: var(--gm-text-muted);
	}

	.tree-content {
		flex: 1;
		overflow-y: auto;
		padding: 4px 0;
	}

	.tree-empty {
		padding: 20px 12px;
		font-size: 11px;
		color: var(--gm-text-muted);
		text-align: center;
		line-height: 1.5;
	}

	/* ── Node (IP) ─────────────────────────────────── */

	.tree-node {
		border-bottom: 1px solid rgba(45, 58, 79, 0.3);
	}

	.node-header {
		display: flex;
		align-items: center;
		gap: 6px;
		width: 100%;
		padding: 7px 10px;
		background: transparent;
		border: none;
		color: var(--gm-text-primary);
		font-family: inherit;
		font-size: 11px;
		cursor: pointer;
		text-align: left;
		transition: background 0.1s;
	}

	.node-header:hover {
		background: var(--gm-bg-hover);
	}

	.node-header.selected {
		background: rgba(59, 130, 246, 0.1);
	}

	.expand-icon {
		font-size: 8px;
		width: 12px;
		color: var(--gm-text-muted);
		flex-shrink: 0;
	}

	.expand-icon.small {
		font-size: 7px;
		width: 10px;
	}

	.device-dot {
		width: 8px;
		height: 8px;
		border-radius: 50%;
		flex-shrink: 0;
	}

	.node-ip {
		font-weight: 600;
		flex-shrink: 0;
	}

	.node-meta {
		display: flex;
		gap: 8px;
		margin-left: auto;
		flex-shrink: 0;
	}

	.node-type {
		font-size: 9px;
		font-weight: 600;
	}

	.node-pkt {
		font-size: 9px;
		color: var(--gm-text-muted);
		font-variant-numeric: tabular-nums;
	}

	/* ── Connections ────────────────────────────────── */

	.node-connections {
		padding-left: 16px;
		background: rgba(0, 0, 0, 0.15);
	}

	.conn-entry {
		border-top: 1px solid rgba(45, 58, 79, 0.2);
	}

	.conn-header {
		display: flex;
		align-items: center;
		gap: 6px;
		width: 100%;
		padding: 5px 8px;
		background: transparent;
		border: none;
		color: var(--gm-text-secondary);
		font-family: inherit;
		font-size: 10px;
		cursor: pointer;
		text-align: left;
		transition: background 0.1s;
	}

	.conn-header:hover {
		background: var(--gm-bg-hover);
	}

	.conn-arrow {
		flex: 1;
		min-width: 0;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.conn-proto {
		font-size: 9px;
		font-weight: 600;
		color: var(--gm-modbus);
		flex-shrink: 0;
	}

	.conn-count {
		font-size: 9px;
		color: var(--gm-text-muted);
		font-variant-numeric: tabular-nums;
		flex-shrink: 0;
	}

	/* ── Connection details + packet list ──────────── */

	.conn-details {
		padding: 4px 8px 8px 28px;
		background: rgba(0, 0, 0, 0.1);
	}

	.conn-meta-row {
		display: flex;
		justify-content: space-between;
		font-size: 9px;
		padding: 2px 0;
	}

	.meta-label {
		color: var(--gm-text-muted);
	}

	.meta-value {
		color: var(--gm-text-secondary);
		font-weight: 500;
		text-align: right;
		max-width: 180px;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.packet-loading {
		font-size: 9px;
		color: var(--gm-text-muted);
		padding: 6px 0;
	}

	.packet-list {
		margin-top: 6px;
		border-top: 1px solid rgba(45, 58, 79, 0.3);
		padding-top: 4px;
	}

	.packet-header-row {
		display: grid;
		grid-template-columns: 1fr 50px 70px 1fr;
		gap: 4px;
		font-size: 8px;
		color: var(--gm-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.5px;
		padding: 2px 0;
		font-weight: 600;
	}

	.packet-row {
		display: grid;
		grid-template-columns: 1fr 50px 70px 1fr;
		gap: 4px;
		font-size: 9px;
		color: var(--gm-text-secondary);
		padding: 1px 0;
	}

	.pkt-time {
		color: var(--gm-text-muted);
	}

	.pkt-size {
		text-align: right;
		font-variant-numeric: tabular-nums;
	}

	.pkt-proto {
		font-weight: 500;
	}

	.pkt-file {
		color: var(--gm-text-muted);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.packet-more {
		font-size: 9px;
		color: var(--gm-text-muted);
		padding: 4px 0;
		font-style: italic;
	}
</style>
