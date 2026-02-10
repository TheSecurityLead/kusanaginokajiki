<script lang="ts">
	import { protocolStats } from '$lib/stores';
	import { getProtocolStats, getFunctionCodeStats } from '$lib/utils/tauri';
	import type { FunctionCodeStat } from '$lib/types';
	import { onMount } from 'svelte';

	let functionCodeStats = $state<Record<string, FunctionCodeStat[]>>({});
	let loading = $state(false);
	let activeProtocol = $state<string | null>(null);

	const protocolColors: Record<string, string> = {
		Modbus: 'var(--gm-modbus, #f59e0b)',
		Dnp3: 'var(--gm-dnp3, #10b981)',
		EthernetIp: 'var(--gm-ethernet-ip, #8b5cf6)',
		Bacnet: 'var(--gm-bacnet, #06b6d4)',
		S7comm: 'var(--gm-s7comm, #ef4444)',
		OpcUa: 'var(--gm-opc-ua, #ec4899)',
		Profinet: '#6366f1',
		Iec104: '#14b8a6',
		Mqtt: '#84cc16',
		HartIp: '#f97316',
		FoundationFieldbus: '#a855f7',
		GeSrtp: '#e879f9',
		WonderwareSuitelink: '#fb923c',
		Http: '#475569',
		Https: '#64748b',
		Dns: '#78716c',
		Ssh: '#525252',
		Rdp: '#737373',
		Snmp: '#a1a1aa',
		Unknown: '#374151'
	};

	onMount(async () => {
		await refresh();
	});

	async function refresh() {
		loading = true;
		try {
			const [stats, fcStats] = await Promise.all([
				getProtocolStats(),
				getFunctionCodeStats()
			]);
			protocolStats.set(stats);
			functionCodeStats = fcStats;
		} catch (err) {
			console.warn('Failed to load protocol stats:', err);
		}
		loading = false;
	}

	// Compute max packet count for bar sizing
	function maxPackets(stats: typeof $protocolStats): number {
		return Math.max(1, ...stats.map((s) => s.packet_count));
	}

	function formatBytes(bytes: number): string {
		if (bytes < 1024) return `${bytes} B`;
		if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
		return `${(bytes / 1048576).toFixed(1)} MB`;
	}

	function getColor(protocol: string): string {
		return protocolColors[protocol] ?? '#374151';
	}
</script>

<div class="stats-container">
	<div class="stats-toolbar">
		<h2 class="view-title">Protocol Statistics</h2>
		<button class="refresh-btn" onclick={refresh} disabled={loading}>
			{loading ? 'Loading...' : 'Refresh'}
		</button>
	</div>

	{#if $protocolStats.length === 0}
		<div class="empty-state">
			<p>No protocol data available. Import a PCAP file to see statistics.</p>
		</div>
	{:else}
		<div class="stats-grid">
			<!-- Traffic Breakdown -->
			<div class="stats-panel">
				<h3 class="panel-title">Traffic by Protocol</h3>
				<div class="bar-chart">
					{#each $protocolStats as stat}
						{@const pct = (stat.packet_count / maxPackets($protocolStats)) * 100}
						<div class="bar-row">
							<div class="bar-label">{stat.protocol}</div>
							<div class="bar-track">
								<div
									class="bar-fill"
									style="width: {pct}%; background: {getColor(stat.protocol)}"
								></div>
							</div>
							<div class="bar-value">{stat.packet_count.toLocaleString()}</div>
						</div>
					{/each}
				</div>
			</div>

			<!-- Protocol Summary Table -->
			<div class="stats-panel">
				<h3 class="panel-title">Protocol Summary</h3>
				<table class="stats-table">
					<thead>
						<tr>
							<th>Protocol</th>
							<th>Packets</th>
							<th>Bytes</th>
							<th>Connections</th>
							<th>Devices</th>
						</tr>
					</thead>
					<tbody>
						{#each $protocolStats as stat}
							<tr
								class="stat-row"
								class:active={activeProtocol === stat.protocol}
								onclick={() =>
									(activeProtocol =
										activeProtocol === stat.protocol ? null : stat.protocol)}
							>
								<td>
									<span
										class="proto-dot"
										style="background: {getColor(stat.protocol)}"
									></span>
									{stat.protocol}
								</td>
								<td class="cell-numeric">{stat.packet_count.toLocaleString()}</td>
								<td class="cell-numeric">{formatBytes(stat.byte_count)}</td>
								<td class="cell-numeric">{stat.connection_count}</td>
								<td class="cell-numeric">{stat.unique_devices}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>

			<!-- Function Code Distribution -->
			{#if Object.keys(functionCodeStats).length > 0}
				<div class="stats-panel wide">
					<h3 class="panel-title">Function Code Distribution</h3>
					<div class="fc-grid">
						{#each Object.entries(functionCodeStats) as [protocol, fcs]}
							<div class="fc-section">
								<h4 class="fc-protocol-title" style="color: {getColor(protocol === 'modbus' ? 'Modbus' : 'Dnp3')}">
									{protocol === 'modbus' ? 'Modbus TCP' : 'DNP3'}
								</h4>
								<table class="fc-table">
									<thead>
										<tr>
											<th>FC</th>
											<th>Name</th>
											<th>Count</th>
											<th>Type</th>
										</tr>
									</thead>
									<tbody>
										{#each fcs as fc}
											<tr class:write-fc={fc.is_write}>
												<td class="cell-fc">{fc.code}</td>
												<td>{fc.name}</td>
												<td class="cell-numeric">{fc.count.toLocaleString()}</td>
												<td>
													{#if fc.is_write}
														<span class="fc-badge write">Write</span>
													{:else}
														<span class="fc-badge read">Read</span>
													{/if}
												</td>
											</tr>
										{/each}
									</tbody>
								</table>
							</div>
						{/each}
					</div>
				</div>
			{/if}
		</div>
	{/if}
</div>

<style>
	.stats-container {
		display: flex;
		flex-direction: column;
		height: 100%;
		overflow: auto;
	}

	.stats-toolbar {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 10px 16px;
		border-bottom: 1px solid var(--gm-border);
		background: var(--gm-bg-secondary);
		flex-shrink: 0;
	}

	.view-title {
		font-size: 13px;
		font-weight: 600;
		letter-spacing: 1px;
		text-transform: uppercase;
		color: var(--gm-text-primary);
		margin: 0;
	}

	.refresh-btn {
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 4px;
		padding: 5px 12px;
		color: var(--gm-text-secondary);
		font-family: inherit;
		font-size: 11px;
		cursor: pointer;
		transition: all 0.15s;
	}

	.refresh-btn:hover:not(:disabled) {
		background: var(--gm-bg-hover);
		color: var(--gm-text-primary);
	}

	.refresh-btn:disabled {
		opacity: 0.5;
		cursor: default;
	}

	.empty-state {
		display: flex;
		align-items: center;
		justify-content: center;
		height: 100%;
		color: var(--gm-text-muted);
		font-size: 12px;
	}

	.stats-grid {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 16px;
		padding: 16px;
	}

	.stats-panel {
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 6px;
		padding: 14px;
	}

	.stats-panel.wide {
		grid-column: 1 / -1;
	}

	.panel-title {
		font-size: 11px;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.5px;
		color: var(--gm-text-muted);
		margin: 0 0 12px;
	}

	/* ── Bar Chart ──────────────────────────────── */

	.bar-chart {
		display: flex;
		flex-direction: column;
		gap: 6px;
	}

	.bar-row {
		display: flex;
		align-items: center;
		gap: 8px;
	}

	.bar-label {
		width: 120px;
		font-size: 10px;
		color: var(--gm-text-secondary);
		text-align: right;
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}

	.bar-track {
		flex: 1;
		height: 16px;
		background: rgba(255, 255, 255, 0.03);
		border-radius: 3px;
		overflow: hidden;
	}

	.bar-fill {
		height: 100%;
		border-radius: 3px;
		min-width: 2px;
		transition: width 0.3s ease;
	}

	.bar-value {
		width: 70px;
		font-size: 10px;
		color: var(--gm-text-muted);
		font-variant-numeric: tabular-nums;
		text-align: right;
	}

	/* ── Summary Table ─────────────────────────── */

	.stats-table {
		width: 100%;
		border-collapse: collapse;
		font-size: 11px;
	}

	.stats-table th {
		font-size: 10px;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.3px;
		color: var(--gm-text-muted);
		text-align: left;
		padding: 6px 10px;
		border-bottom: 1px solid var(--gm-border);
	}

	.stats-table td {
		padding: 6px 10px;
		color: var(--gm-text-secondary);
		border-bottom: 1px solid rgba(45, 58, 79, 0.3);
	}

	.stat-row {
		cursor: pointer;
		transition: background 0.1s;
	}

	.stat-row:hover {
		background: rgba(255, 255, 255, 0.02);
	}

	.stat-row.active {
		background: rgba(59, 130, 246, 0.08);
	}

	.proto-dot {
		display: inline-block;
		width: 8px;
		height: 8px;
		border-radius: 50%;
		margin-right: 6px;
		vertical-align: middle;
	}

	.cell-numeric {
		text-align: right;
		font-variant-numeric: tabular-nums;
	}

	/* ── Function Code Distribution ──────────── */

	.fc-grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
		gap: 16px;
	}

	.fc-section {
		min-width: 0;
	}

	.fc-protocol-title {
		font-size: 12px;
		font-weight: 600;
		margin: 0 0 8px;
	}

	.fc-table {
		width: 100%;
		border-collapse: collapse;
		font-size: 10px;
	}

	.fc-table th {
		font-size: 9px;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.3px;
		color: var(--gm-text-muted);
		text-align: left;
		padding: 4px 8px;
		border-bottom: 1px solid var(--gm-border);
	}

	.fc-table td {
		padding: 4px 8px;
		color: var(--gm-text-secondary);
		border-bottom: 1px solid rgba(45, 58, 79, 0.3);
	}

	.cell-fc {
		font-weight: 600;
		color: var(--gm-text-primary);
		width: 30px;
	}

	.write-fc td {
		color: var(--gm-text-primary);
	}

	.fc-badge {
		font-size: 8px;
		font-weight: 600;
		padding: 1px 5px;
		border-radius: 3px;
		letter-spacing: 0.3px;
	}

	.fc-badge.write {
		color: #ef4444;
		background: rgba(239, 68, 68, 0.15);
	}

	.fc-badge.read {
		color: #10b981;
		background: rgba(16, 185, 129, 0.15);
	}
</style>
