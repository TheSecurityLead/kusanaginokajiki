<script lang="ts">
	import { onMount } from 'svelte';
	import { getConnectionStats, getPatternAnomalies } from '$lib/utils/tauri';
	import type { ConnectionStats, PatternAnomaly } from '$lib/types';

	// ── State ─────────────────────────────────────────────────────

	let stats = $state<ConnectionStats[]>([]);
	let anomalies = $state<PatternAnomaly[]>([]);
	let loading = $state(false);
	let error = $state<string | null>(null);

	// Filters
	let anomaliesOnly = $state(false);
	let protocolFilter = $state('');

	// Sorting
	let sortCol = $state<keyof ConnectionStats>('packet_count');
	let sortAsc = $state(false);

	// Expanded row for histogram
	let expandedKey = $state<string | null>(null);

	// Pagination
	const PAGE_SIZE = 50;
	let currentPage = $state(0);

	// ── Data Loading ──────────────────────────────────────────────

	async function load() {
		loading = true;
		error = null;
		currentPage = 0;
		try {
			const [s, a] = await Promise.all([getConnectionStats(), getPatternAnomalies()]);
			stats = s;
			anomalies = a;
		} catch (e) {
			error = String(e);
		} finally {
			loading = false;
		}
	}

	onMount(load);

	// ── Derived / Helpers ─────────────────────────────────────────

	/** Build a unique key for a connection row */
	function rowKey(s: ConnectionStats): string {
		return `${s.src_ip}|${s.dst_ip}|${s.port}|${s.protocol}`;
	}

	/**
	 * Pre-computed anomaly lookup map: connection key → anomaly list.
	 * O(1) per lookup instead of O(anomalies) per row.
	 */
	let anomalyMap = $derived(
		anomalies.reduce((map, a) => {
			const key = `${a.src_ip}|${a.dst_ip}|${a.port}`;
			const existing = map.get(key);
			if (existing) {
				existing.push(a);
			} else {
				map.set(key, [a]);
			}
			return map;
		}, new Map<string, typeof anomalies>())
	);

	/** Count anomalies matching a connection — O(1) via pre-computed map */
	function anomalyCount(s: ConnectionStats): number {
		return (anomalyMap.get(`${s.src_ip}|${s.dst_ip}|${s.port}`) ?? []).length;
	}

	/** Get anomalies for a connection — O(1) via pre-computed map */
	function getRowAnomalies(s: ConnectionStats): typeof anomalies {
		return anomalyMap.get(`${s.src_ip}|${s.dst_ip}|${s.port}`) ?? [];
	}

	/** All unique protocols in loaded stats */
	let protocols = $derived([...new Set(stats.map((s) => s.protocol))].sort());

	/** Filtered + sorted rows (all pages) */
	let filteredRows = $derived(
		stats
			.filter((s) => {
				if (protocolFilter && s.protocol !== protocolFilter) return false;
				if (anomaliesOnly && anomalyCount(s) === 0) return false;
				return true;
			})
			.slice()
			.sort((a, b) => {
				const av = a[sortCol];
				const bv = b[sortCol];
				if (typeof av === 'number' && typeof bv === 'number') {
					return sortAsc ? av - bv : bv - av;
				}
				const as_ = String(av);
				const bs_ = String(bv);
				return sortAsc ? as_.localeCompare(bs_) : bs_.localeCompare(as_);
			})
	);

	/** Current page of rows — only these are rendered in the DOM */
	let rows = $derived(
		filteredRows.slice(currentPage * PAGE_SIZE, (currentPage + 1) * PAGE_SIZE)
	);

	let totalPages = $derived(Math.max(1, Math.ceil(filteredRows.length / PAGE_SIZE)));

	function setSort(col: keyof ConnectionStats) {
		if (sortCol === col) {
			sortAsc = !sortAsc;
		} else {
			sortCol = col;
			sortAsc = false;
		}
		currentPage = 0;
	}

	function toggleExpand(key: string) {
		expandedKey = expandedKey === key ? null : key;
	}

	/** Format bytes to human-readable string */
	function fmtBytes(n: number): string {
		if (n < 1024) return `${n} B`;
		if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
		return `${(n / 1048576).toFixed(1)} MB`;
	}

	/** Format a duration in seconds */
	function fmtDuration(s: number): string {
		if (s < 1) return `${(s * 1000).toFixed(0)} ms`;
		if (s < 60) return `${s.toFixed(1)} s`;
		return `${(s / 60).toFixed(1)} min`;
	}

	/** Severity colour */
	function severityColor(sev: string): string {
		switch (sev) {
			case 'critical':
				return '#ef4444';
			case 'high':
				return '#f97316';
			case 'medium':
				return '#f59e0b';
			default:
				return '#64748b';
		}
	}

	/** Anomaly type display label */
	function anomalyLabel(type: string): string {
		switch (type) {
			case 'one_off_connection':
				return 'One-off';
			case 'high_frequency':
				return 'High freq';
			case 'irregular_polling':
				return 'Irregular';
			case 'burst_traffic':
				return 'Burst';
			default:
				return type;
		}
	}

	/**
	 * Build a simple SVG bar chart (10 bins) of interval distribution.
	 * Returns bin heights (0–1 normalised) and bin edges (ms).
	 */
	function buildHistogram(
		s: ConnectionStats
	): { bins: number[]; edges: number[]; maxCount: number } {
		if (s.packet_count < 2 || s.max_interval_ms <= 0) {
			return { bins: [], edges: [], maxCount: 0 };
		}
		const numBins = 10;
		const lo = s.min_interval_ms;
		const hi = s.max_interval_ms;
		const step = (hi - lo) / numBins || 1;
		const bins = new Array<number>(numBins).fill(0);
		// Approximate: we don't have raw data, so we model a normal distribution
		// using mean and std from stats.  We sample synthetic interval data.
		const mean = s.avg_interval_ms;
		const std = s.std_interval_ms || 0.001;
		const sampleCount = Math.min(s.packet_count - 1, 200);
		for (let i = 0; i < sampleCount; i++) {
			// Box-Muller transform for synthetic normal sample
			const u1 = Math.random();
			const u2 = Math.random();
			const z = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
			const v = mean + std * z;
			const binIdx = Math.floor((v - lo) / step);
			if (binIdx >= 0 && binIdx < numBins) bins[binIdx]++;
		}
		const maxCount = Math.max(...bins, 1);
		const edges = Array.from({ length: numBins + 1 }, (_, i) => lo + i * step);
		return { bins, edges, maxCount };
	}
</script>

<div class="cp-container">
	<!-- Toolbar -->
	<div class="cp-toolbar">
		<div class="toolbar-section">
			<h2 class="view-title">Communication Patterns</h2>
			<span class="toolbar-sep"></span>
			<span class="row-count">{filteredRows.length.toLocaleString()} / {stats.length.toLocaleString()} connections</span>
		</div>
		<div class="toolbar-section">
			<label class="filter-label">
				Protocol:
				<select
					class="filter-select"
					value={protocolFilter}
					onchange={(e) => (protocolFilter = (e.target as HTMLSelectElement).value)}
				>
					<option value="">All</option>
					{#each protocols as p}
						<option value={p}>{p}</option>
					{/each}
				</select>
			</label>
			<label class="toggle-label">
				<input
					type="checkbox"
					class="toggle-cb"
					bind:checked={anomaliesOnly}
				/>
				Anomalies only
			</label>
			<button class="tool-btn" onclick={load}>Refresh</button>
		</div>
	</div>

	<!-- Anomaly summary bar (if any) -->
	{#if anomalies.length > 0}
		<div class="anomaly-bar">
			<span class="anomaly-bar-label">&#9888; {anomalies.length} pattern anomal{anomalies.length === 1 ? 'y' : 'ies'} detected</span>
			{#each [...new Set(anomalies.map((a) => a.severity))].sort() as sev}
				<span class="anomaly-badge" style="border-color: {severityColor(sev)}; color: {severityColor(sev)}">
					{anomalies.filter((a) => a.severity === sev).length} {sev}
				</span>
			{/each}
		</div>
	{/if}

	<!-- Main content -->
	{#if loading}
		<div class="empty-state">
			<div class="spinner"></div>
			<p>Loading pattern data…</p>
		</div>
	{:else if error}
		<div class="empty-state error-state">
			<p>&#9888; {error}</p>
			<button class="tool-btn" onclick={load}>Retry</button>
		</div>
	{:else if stats.length === 0}
		<div class="empty-state">
			<div class="empty-icon">&#8771;</div>
			<h3>No Pattern Data</h3>
			<p>Import a PCAP file or run a live capture to see communication patterns.</p>
		</div>
	{:else}
		<div class="table-wrapper">
			<table class="cp-table">
				<thead>
					<tr>
						{#each [
							['src_ip', 'Source IP'],
							['dst_ip', 'Destination IP'],
							['protocol', 'Protocol'],
							['port', 'Port'],
							['packet_count', 'Packets'],
							['byte_count', 'Bytes'],
							['duration_secs', 'Duration'],
							['avg_interval_ms', 'Avg Interval'],
							['std_interval_ms', 'Std Dev'],
							['is_periodic', 'Periodic'],
							['packets_per_sec', 'Pkt/s'],
						] as [col, label]}
							<th
								class="sortable"
								class:active={sortCol === col}
								onclick={() => setSort(col as keyof ConnectionStats)}
							>
								{label}
								{#if sortCol === col}
									<span class="sort-arrow">{sortAsc ? '↑' : '↓'}</span>
								{/if}
							</th>
						{/each}
						<th>Anomalies</th>
					</tr>
				</thead>
				<tbody>
					{#each rows as s (rowKey(s))}
						{@const key = rowKey(s)}
						{@const aCount = anomalyCount(s)}
						{@const rowAnomalies = getRowAnomalies(s)}
						<tr
							class="data-row"
							class:anomalous={aCount > 0}
							class:expanded={expandedKey === key}
							onclick={() => toggleExpand(key)}
						>
							<td class="mono">{s.src_ip}</td>
							<td class="mono">{s.dst_ip}</td>
							<td><span class="proto-badge">{s.protocol}</span></td>
							<td class="num">{s.port}</td>
							<td class="num">{s.packet_count.toLocaleString()}</td>
							<td class="num">{fmtBytes(s.byte_count)}</td>
							<td class="num">{fmtDuration(s.duration_secs)}</td>
							<td class="num">{s.avg_interval_ms.toFixed(1)} ms</td>
							<td class="num">{s.std_interval_ms.toFixed(1)} ms</td>
							<td class="center">{s.is_periodic ? '✓' : '✗'}</td>
							<td class="num">{s.packets_per_sec.toFixed(1)}</td>
							<td class="center">
								{#if aCount > 0}
									<span class="anomaly-count">{aCount}</span>
								{/if}
							</td>
						</tr>
						{#if expandedKey === key}
							<tr class="detail-row">
								<td colspan="12">
									<div class="detail-panel">
										<!-- Interval histogram (synthetic approximation from stats) -->
										{#if s.packet_count >= 2}
											{@const hist = buildHistogram(s)}
											<div class="histogram-section">
												<h4 class="detail-heading">Interval Distribution (approximated from stats)</h4>
												{#if hist.bins.length > 0}
													<svg class="histogram-svg" viewBox="0 0 200 60" preserveAspectRatio="none">
														{#each hist.bins as count, i}
															{@const barH = (count / hist.maxCount) * 50}
															<rect
																x={i * 20 + 1}
																y={58 - barH}
																width="18"
																height={barH}
																fill={barH > 0 ? '#10b981' : 'transparent'}
																opacity="0.8"
															/>
														{/each}
													</svg>
													<div class="hist-labels">
														<span>{s.min_interval_ms.toFixed(0)} ms</span>
														<span>{s.max_interval_ms.toFixed(0)} ms</span>
													</div>
												{/if}
												<div class="stat-grid">
													<div class="stat-item">
														<span class="stat-label">Min</span>
														<span class="stat-value">{s.min_interval_ms.toFixed(2)} ms</span>
													</div>
													<div class="stat-item">
														<span class="stat-label">Avg</span>
														<span class="stat-value">{s.avg_interval_ms.toFixed(2)} ms</span>
													</div>
													<div class="stat-item">
														<span class="stat-label">Std Dev</span>
														<span class="stat-value">{s.std_interval_ms.toFixed(2)} ms</span>
													</div>
													<div class="stat-item">
														<span class="stat-label">Max</span>
														<span class="stat-value">{s.max_interval_ms.toFixed(2)} ms</span>
													</div>
													<div class="stat-item">
														<span class="stat-label">CV</span>
														<span class="stat-value">
															{s.avg_interval_ms > 0
																? (s.std_interval_ms / s.avg_interval_ms).toFixed(2)
																: '—'}
														</span>
													</div>
													<div class="stat-item">
														<span class="stat-label">Periodic</span>
														<span class="stat-value" class:green={s.is_periodic}>
															{s.is_periodic ? 'Yes' : 'No'}
														</span>
													</div>
												</div>
											</div>
										{/if}

										<!-- Anomalies for this row -->
										{#if rowAnomalies.length > 0}
											<div class="anomaly-section">
												<h4 class="detail-heading">Anomalies</h4>
												{#each rowAnomalies as a}
													<div class="anomaly-item" style="border-left-color: {severityColor(a.severity)}">
														<span class="anomaly-type" style="color: {severityColor(a.severity)}">
															{anomalyLabel(a.anomaly_type)}
														</span>
														<span class="anomaly-desc">{a.description}</span>
													</div>
												{/each}
											</div>
										{/if}
									</div>
								</td>
							</tr>
						{/if}
					{/each}
				</tbody>
			</table>
		</div>
		{#if totalPages > 1}
			<div class="pagination-bar">
				<button
					class="page-btn"
					disabled={currentPage === 0}
					onclick={() => { currentPage = 0; }}
				>«</button>
				<button
					class="page-btn"
					disabled={currentPage === 0}
					onclick={() => { currentPage -= 1; }}
				>‹</button>
				<span class="page-info">
					Page {currentPage + 1} of {totalPages}
					&nbsp;·&nbsp;
					rows {(currentPage * PAGE_SIZE + 1).toLocaleString()}–{Math.min((currentPage + 1) * PAGE_SIZE, filteredRows.length).toLocaleString()}
					of {filteredRows.length.toLocaleString()}
				</span>
				<button
					class="page-btn"
					disabled={currentPage >= totalPages - 1}
					onclick={() => { currentPage += 1; }}
				>›</button>
				<button
					class="page-btn"
					disabled={currentPage >= totalPages - 1}
					onclick={() => { currentPage = totalPages - 1; }}
				>»</button>
			</div>
		{/if}
	{/if}
</div>

<style>
	.cp-container {
		display: flex;
		flex-direction: column;
		height: 100%;
		overflow: hidden;
		font-size: 12px;
	}

	/* ── Toolbar ─────────────────────────────────── */

	.cp-toolbar {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 8px 16px;
		border-bottom: 1px solid var(--gm-border);
		background: var(--gm-bg-secondary);
		flex-shrink: 0;
	}

	.toolbar-section {
		display: flex;
		align-items: center;
		gap: 10px;
	}

	.toolbar-sep {
		width: 1px;
		height: 18px;
		background: var(--gm-border);
	}

	.view-title {
		font-size: 13px;
		font-weight: 600;
		letter-spacing: 1px;
		text-transform: uppercase;
		color: var(--gm-text-primary);
		margin: 0;
	}

	.row-count {
		font-size: 11px;
		color: var(--gm-text-muted);
	}

	.filter-label,
	.toggle-label {
		display: flex;
		align-items: center;
		gap: 6px;
		font-size: 11px;
		color: var(--gm-text-secondary);
	}

	.filter-select {
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 4px;
		color: var(--gm-text-primary);
		font-family: inherit;
		font-size: 11px;
		padding: 3px 8px;
		cursor: pointer;
	}

	.toggle-cb {
		cursor: pointer;
	}

	.tool-btn {
		padding: 5px 12px;
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 4px;
		color: var(--gm-text-secondary);
		font-family: inherit;
		font-size: 11px;
		cursor: pointer;
		transition: all 0.15s;
	}

	.tool-btn:hover {
		background: var(--gm-bg-hover);
		color: var(--gm-text-primary);
	}

	/* ── Anomaly Summary Bar ─────────────────────── */

	.anomaly-bar {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 6px 16px;
		background: rgba(245, 158, 11, 0.08);
		border-bottom: 1px solid rgba(245, 158, 11, 0.2);
		flex-shrink: 0;
	}

	.anomaly-bar-label {
		font-size: 11px;
		color: #f59e0b;
		font-weight: 600;
	}

	.anomaly-badge {
		font-size: 10px;
		padding: 1px 7px;
		border: 1px solid;
		border-radius: 10px;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.5px;
	}

	/* ── Empty / Error States ────────────────────── */

	.empty-state {
		flex: 1;
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		gap: 12px;
		color: var(--gm-text-muted);
		text-align: center;
	}

	.empty-icon {
		font-size: 48px;
		opacity: 0.3;
	}

	.empty-state h3 {
		font-size: 14px;
		font-weight: 600;
		color: var(--gm-text-secondary);
		margin: 0;
	}

	.empty-state p {
		font-size: 12px;
		margin: 0;
	}

	.error-state {
		color: #ef4444;
	}

	.spinner {
		width: 28px;
		height: 28px;
		border: 3px solid var(--gm-border);
		border-top-color: #10b981;
		border-radius: 50%;
		animation: spin 0.8s linear infinite;
	}

	@keyframes spin {
		to { transform: rotate(360deg); }
	}

	/* ── Table ───────────────────────────────────── */

	.table-wrapper {
		flex: 1;
		overflow: auto;
	}

	.cp-table {
		width: 100%;
		border-collapse: collapse;
		font-size: 11px;
	}

	.cp-table thead {
		position: sticky;
		top: 0;
		background: var(--gm-bg-secondary);
		z-index: 1;
	}

	.cp-table th {
		padding: 8px 10px;
		text-align: left;
		font-size: 10px;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.8px;
		color: var(--gm-text-muted);
		border-bottom: 1px solid var(--gm-border);
		white-space: nowrap;
	}

	.cp-table th.sortable {
		cursor: pointer;
		user-select: none;
	}

	.cp-table th.sortable:hover {
		color: var(--gm-text-secondary);
	}

	.cp-table th.active {
		color: #10b981;
	}

	.sort-arrow {
		margin-left: 4px;
		font-size: 10px;
	}

	.cp-table td {
		padding: 6px 10px;
		border-bottom: 1px solid rgba(51, 65, 85, 0.4);
		color: var(--gm-text-secondary);
		white-space: nowrap;
	}

	.data-row {
		cursor: pointer;
		transition: background 0.1s;
	}

	.data-row:hover {
		background: var(--gm-bg-hover);
	}

	.data-row.anomalous td {
		background: rgba(245, 158, 11, 0.05);
	}

	.data-row.anomalous:hover td {
		background: rgba(245, 158, 11, 0.1);
	}

	.data-row.expanded td {
		border-bottom: none;
	}

	.mono {
		font-family: 'JetBrains Mono', monospace;
		font-size: 10px;
	}

	.num {
		text-align: right;
	}

	.center {
		text-align: center;
	}

	.proto-badge {
		font-size: 9px;
		font-weight: 600;
		padding: 2px 6px;
		border-radius: 3px;
		background: rgba(16, 185, 129, 0.15);
		color: #10b981;
		letter-spacing: 0.5px;
	}

	.anomaly-count {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		width: 18px;
		height: 18px;
		border-radius: 50%;
		background: rgba(245, 158, 11, 0.2);
		color: #f59e0b;
		font-size: 10px;
		font-weight: 700;
	}

	/* ── Detail / Expanded Row ───────────────────── */

	.detail-row td {
		padding: 0;
		border-bottom: 1px solid var(--gm-border);
	}

	.detail-panel {
		padding: 12px 16px;
		background: var(--gm-bg-panel);
		display: flex;
		gap: 24px;
		flex-wrap: wrap;
	}

	.detail-heading {
		font-size: 10px;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.8px;
		color: var(--gm-text-muted);
		margin: 0 0 8px 0;
	}

	.histogram-section,
	.anomaly-section {
		flex: 1;
		min-width: 200px;
	}

	.histogram-svg {
		width: 100%;
		height: 60px;
		display: block;
		border-bottom: 1px solid var(--gm-border);
		margin-bottom: 4px;
	}

	.hist-labels {
		display: flex;
		justify-content: space-between;
		font-size: 9px;
		color: var(--gm-text-muted);
		margin-bottom: 10px;
	}

	.stat-grid {
		display: grid;
		grid-template-columns: repeat(3, 1fr);
		gap: 8px;
	}

	.stat-item {
		display: flex;
		flex-direction: column;
		gap: 2px;
	}

	.stat-label {
		font-size: 9px;
		text-transform: uppercase;
		letter-spacing: 0.8px;
		color: var(--gm-text-muted);
	}

	.stat-value {
		font-size: 11px;
		font-family: 'JetBrains Mono', monospace;
		color: var(--gm-text-primary);
	}

	.stat-value.green {
		color: #10b981;
	}

	.anomaly-item {
		padding: 6px 8px;
		border-left: 3px solid;
		background: rgba(51, 65, 85, 0.3);
		margin-bottom: 4px;
		border-radius: 0 4px 4px 0;
		display: flex;
		gap: 10px;
		align-items: baseline;
	}

	.anomaly-type {
		font-size: 10px;
		font-weight: 700;
		white-space: nowrap;
		text-transform: uppercase;
		letter-spacing: 0.5px;
	}

	.anomaly-desc {
		font-size: 11px;
		color: var(--gm-text-secondary);
		line-height: 1.4;
	}

	/* ── Pagination ──────────────────────────────── */

	.pagination-bar {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 6px;
		padding: 8px 16px;
		border-top: 1px solid var(--gm-border);
		background: var(--gm-bg-secondary);
		flex-shrink: 0;
	}

	.page-btn {
		padding: 3px 10px;
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 4px;
		color: var(--gm-text-secondary);
		font-family: inherit;
		font-size: 12px;
		cursor: pointer;
		transition: all 0.15s;
	}

	.page-btn:hover:not(:disabled) {
		background: var(--gm-bg-hover);
		color: var(--gm-text-primary);
	}

	.page-btn:disabled {
		opacity: 0.4;
		cursor: not-allowed;
	}

	.page-info {
		font-size: 11px;
		color: var(--gm-text-muted);
		white-space: nowrap;
	}
</style>
