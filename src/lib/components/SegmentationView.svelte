<script lang="ts">
	import { segmentationReport } from '$lib/stores';
	import type {
		SegmentationReport,
		PolicyGroup,
		Zone,
		ZonePairPolicy,
		EnforcementFormat,
		SimulationResult,
		BlockedConnection
	} from '$lib/types';
	import { runSegmentation, exportEnforcementConfig } from '$lib/utils/tauri';

	type SubTab = 'groups' | 'zones' | 'matrix' | 'enforcement' | 'simulation';

	let activeTab = $state<SubTab>('groups');
	let isRunning = $state(false);
	let error = $state<string | null>(null);
	let report = $state<SegmentationReport | null>(null);

	// Enforcement export
	let selectedFormat = $state<EnforcementFormat>('cisco_ios_acl');
	let exportedContent = $state<string>('');
	let isExporting = $state(false);

	// Subscribe to cached report from store.
	segmentationReport.subscribe((v) => {
		report = v;
	});

	async function handleRunSegmentation() {
		isRunning = true;
		error = null;
		try {
			const result = await runSegmentation();
			report = result;
			segmentationReport.set(result);
		} catch (e) {
			error = String(e);
		} finally {
			isRunning = false;
		}
	}

	async function handleExport() {
		isExporting = true;
		exportedContent = '';
		try {
			exportedContent = await exportEnforcementConfig(selectedFormat);
		} catch (e) {
			error = String(e);
		} finally {
			isExporting = false;
		}
	}

	function copyToClipboard(text: string) {
		navigator.clipboard.writeText(text).catch(() => {});
	}

	function slLabel(sl: string): string {
		const map: Record<string, string> = {
			sl1: 'SL1',
			sl2: 'SL2',
			sl3: 'SL3',
			sl4: 'SL4'
		};
		return map[sl] ?? sl.toUpperCase();
	}

	function slClass(sl: string): string {
		const map: Record<string, string> = {
			sl1: 'sl1',
			sl2: 'sl2',
			sl3: 'sl3',
			sl4: 'sl4'
		};
		return map[sl] ?? '';
	}

	function riskClass(risk: string): string {
		if (risk === 'high') return 'high';
		if (risk === 'medium') return 'medium';
		return 'low';
	}

	function scorePercent(v: number): string {
		return (v * 100).toFixed(1) + '%';
	}

	function blockedPercent(s: SimulationResult): string {
		return s.blocked_percent.toFixed(1) + '%';
	}

	function zoneNameById(id: string): string {
		if (!report) return id;
		return report.zone_model.zones.find((z) => z.id === id)?.name ?? id;
	}
</script>

<div class="segmentation-view">
	<div class="view-header">
		<h2>Microsegmentation</h2>
		<p class="subtitle">IEC 62443 Zone/Conduit model · Least-privilege matrix · Policy enforcement</p>
		<button
			class="run-btn"
			onclick={handleRunSegmentation}
			disabled={isRunning}
		>
			{#if isRunning}
				Running analysis…
			{:else}
				{report ? 'Re-run Analysis' : 'Run Segmentation Analysis'}
			{/if}
		</button>
	</div>

	{#if error}
		<div class="error-banner">{error}</div>
	{/if}

	{#if report}
		<!-- Sub-tab bar -->
		<div class="sub-tabs">
			{#each [
				{ id: 'groups', label: 'Policy Groups' },
				{ id: 'zones', label: 'Zones & Conduits' },
				{ id: 'matrix', label: 'Comm Matrix' },
				{ id: 'enforcement', label: 'Enforcement' },
				{ id: 'simulation', label: 'Simulation' }
			] as tab}
				<button
					class="sub-tab"
					class:active={activeTab === tab.id}
					onclick={() => (activeTab = tab.id as SubTab)}
				>
					{tab.label}
				</button>
			{/each}
		</div>

		<!-- ── Tab: Policy Groups (15A) ─────────────────────────── -->
		{#if activeTab === 'groups'}
			<div class="tab-content">
				<div class="summary-row">
					<span class="metric">{report.policy_groups.length} <small>groups</small></span>
					<span class="metric">{new Set(report.policy_groups.flatMap(g => g.member_ips)).size} <small>classified assets</small></span>
				</div>
				<div class="card-grid">
					{#each report.policy_groups as group}
						<div class="group-card">
							<div class="group-header">
								<span class="group-name">{group.name}</span>
								<span class="sl-badge {slClass(group.security_level)}">{slLabel(group.security_level)}</span>
							</div>
							<div class="group-meta">
								<span>Purdue L{group.purdue_level ?? '?'}</span>
								<span>·</span>
								<span>{group.device_category.replace(/_/g, ' ')}</span>
								<span>·</span>
								<span class="criticality {group.criticality}">{group.criticality}</span>
							</div>
							<div class="member-ips">
								{#each group.member_ips as ip}
									<span class="ip-pill">{ip}</span>
								{/each}
							</div>
						</div>
					{/each}
				</div>
			</div>

		<!-- ── Tab: Zones & Conduits (15B) ─────────────────────── -->
		{:else if activeTab === 'zones'}
			<div class="tab-content">
				<div class="summary-row">
					<span class="metric">{report.zone_model.zones.length} <small>zones</small></span>
					<span class="metric">{report.zone_model.conduits.length} <small>conduits</small></span>
					<span class="metric">{(report.zone_model.zone_score * 100).toFixed(0)}% <small>zone score</small></span>
				</div>
				{#if report.zone_model.recommendations.length > 0}
					<div class="recommendations">
						<h3>Recommendations</h3>
						<ul>
							{#each report.zone_model.recommendations as rec}
								<li>{rec}</li>
							{/each}
						</ul>
					</div>
				{/if}
				<h3>Zones</h3>
				<table class="data-table">
					<thead>
						<tr>
							<th>Name</th>
							<th>Security Level</th>
							<th>Purdue Levels</th>
							<th>Assets</th>
						</tr>
					</thead>
					<tbody>
						{#each report.zone_model.zones as zone}
							<tr>
								<td>{zone.name}</td>
								<td><span class="sl-badge {slClass(zone.security_level)}">{slLabel(zone.security_level)}</span></td>
								<td>{zone.purdue_levels.map(l => 'L' + l).join(', ') || '—'}</td>
								<td>{zone.asset_count}</td>
							</tr>
						{/each}
					</tbody>
				</table>
				{#if report.zone_model.conduits.length > 0}
					<h3>Conduits</h3>
					<table class="data-table">
						<thead>
							<tr>
								<th>From Zone</th>
								<th>To Zone</th>
								<th>Direction</th>
								<th>Rules</th>
								<th>Cross-Purdue</th>
							</tr>
						</thead>
						<tbody>
							{#each report.zone_model.conduits as conduit}
								<tr class={conduit.cross_purdue_risk ? 'row-warning' : ''}>
									<td>{zoneNameById(conduit.src_zone_id)}</td>
									<td>{zoneNameById(conduit.dst_zone_id)}</td>
									<td>{conduit.direction}</td>
									<td>{conduit.rules.length}</td>
									<td>{conduit.cross_purdue_risk ? '⚠ Yes' : '—'}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				{/if}
			</div>

		<!-- ── Tab: Communication Matrix (15C) ─────────────────── -->
		{:else if activeTab === 'matrix'}
			<div class="tab-content">
				<div class="summary-row">
					<span class="metric">{report.communication_matrix.zone_pairs.length} <small>zone pairs</small></span>
					<span class="metric">{report.communication_matrix.coverage_percent.toFixed(1)}% <small>coverage</small></span>
					<span class="metric">{report.communication_matrix.default_action} <small>default</small></span>
				</div>
				{#each report.communication_matrix.zone_pairs as pair}
					<div class="zone-pair">
						<div class="zone-pair-header">
							<span class="zone-name">{zoneNameById(pair.src_zone_id)}</span>
							<span class="arrow">→</span>
							<span class="zone-name">{zoneNameById(pair.dst_zone_id)}</span>
							<span class="rule-count">{pair.rules.length} rule{pair.rules.length !== 1 ? 's' : ''}</span>
						</div>
						<table class="rule-table">
							<thead>
								<tr><th>Protocol</th><th>Port</th><th>Risk</th><th>Justification</th><th>Packets</th></tr>
							</thead>
							<tbody>
								{#each pair.rules as rule}
									<tr>
										<td>{rule.protocol}</td>
										<td>{rule.dst_port ?? 'any'}</td>
										<td><span class="risk-badge {riskClass(rule.risk)}">{rule.risk}</span></td>
										<td class="justification">{rule.justification}</td>
										<td>{rule.packet_count.toLocaleString()}</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>
				{/each}
			</div>

		<!-- ── Tab: Enforcement Config (15D) ───────────────────── -->
		{:else if activeTab === 'enforcement'}
			<div class="tab-content">
				<div class="enforcement-controls">
					<label for="fmt-select">Format:</label>
					<select id="fmt-select" bind:value={selectedFormat}>
						<option value="cisco_ios_acl">Cisco IOS ACL</option>
						<option value="cisco_asa_acl">Cisco ASA ACL</option>
						<option value="generic_firewall_table">Generic Firewall Table (TSV)</option>
						<option value="suricata_rules">Suricata Rules</option>
						<option value="json_policy">JSON Policy</option>
					</select>
					<button onclick={handleExport} disabled={isExporting}>
						{isExporting ? 'Exporting…' : 'Export'}
					</button>
					{#if exportedContent}
						<button onclick={() => copyToClipboard(exportedContent)}>Copy</button>
					{/if}
				</div>
				<div class="enforcement-summary">
					{#each report.enforcement_configs as cfg}
						<div class="cfg-chip" class:active={cfg.format === selectedFormat}>
							<span>{cfg.format.replace(/_/g, ' ')}</span>
							<span class="rule-count">{cfg.rule_count} rules</span>
						</div>
					{/each}
				</div>
				{#if exportedContent}
					<pre class="config-output">{exportedContent}</pre>
				{/if}
			</div>

		<!-- ── Tab: Simulation (15E) ────────────────────────────── -->
		{:else if activeTab === 'simulation'}
			{@const sim = report.simulation}
			<div class="tab-content">
				<div class="sim-metrics">
					<div class="sim-metric">
						<div class="metric-value green">{sim.allowed.toLocaleString()}</div>
						<div class="metric-label">Allowed</div>
					</div>
					<div class="sim-metric">
						<div class="metric-value {sim.blocked > 0 ? 'red' : 'green'}">{sim.blocked.toLocaleString()}</div>
						<div class="metric-label">Blocked ({blockedPercent(sim)})</div>
					</div>
					<div class="sim-metric">
						<div class="metric-value">{scorePercent(sim.risk_reduction_score)}</div>
						<div class="metric-label">Risk Reduction</div>
					</div>
					<div class="sim-metric">
						<div class="metric-value">{scorePercent(sim.deployment_score)}</div>
						<div class="metric-label">Deployment Score</div>
					</div>
				</div>

				{#if sim.zone_block_summaries.length > 0}
					<h3>Blocked by Zone Pair</h3>
					<table class="data-table">
						<thead>
							<tr><th>From Zone</th><th>To Zone</th><th>Blocked Flows</th></tr>
						</thead>
						<tbody>
							{#each sim.zone_block_summaries as zbs}
								<tr>
									<td>{zoneNameById(zbs.src_zone_id)}</td>
									<td>{zoneNameById(zbs.dst_zone_id)}</td>
									<td class="count">{zbs.blocked_count}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				{/if}

				{#if sim.critical_blocks.length > 0}
					<h3>Critical Blocks <span class="count-badge">{sim.critical_blocks.length}</span></h3>
					<table class="data-table">
						<thead>
							<tr><th>Source</th><th>Destination</th><th>Protocol:Port</th><th>Reason</th></tr>
						</thead>
						<tbody>
							{#each sim.critical_blocks as block}
								<tr>
									<td>{block.src_ip}</td>
									<td>{block.dst_ip}</td>
									<td>{block.protocol}:{block.dst_port}</td>
									<td class="reason">{block.reason}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				{/if}

				{#if sim.false_positive_candidates.length > 0}
					<h3>False Positive Candidates <span class="count-badge fp">{sim.false_positive_candidates.length}</span></h3>
					<p class="hint">These periodic, read-only, allowlisted connections are likely safe — review before enforcement.</p>
					<table class="data-table">
						<thead>
							<tr><th>Source</th><th>Destination</th><th>Protocol:Port</th></tr>
						</thead>
						<tbody>
							{#each sim.false_positive_candidates as fp}
								<tr>
									<td>{fp.src_ip}</td>
									<td>{fp.dst_ip}</td>
									<td>{fp.protocol}:{fp.dst_port}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				{/if}

				{#if sim.allowed === 0 && sim.blocked === 0}
					<p class="hint">No traffic data to simulate. Import a PCAP or run live capture first.</p>
				{/if}
			</div>
		{/if}

	{:else if !isRunning}
		<div class="empty-state">
			<p>No segmentation analysis has been run yet.</p>
			<p>Click <strong>Run Segmentation Analysis</strong> to generate IEC 62443 zone recommendations,
			a least-privilege communication matrix, enforcement configurations, and a policy simulation.</p>
			<p class="hint">Requires at least one PCAP import or live capture session with discovered assets.</p>
		</div>
	{/if}
</div>

<style>
	.segmentation-view {
		padding: 1.5rem;
		max-width: 1200px;
	}

	.view-header {
		margin-bottom: 1.5rem;
	}

	.view-header h2 {
		margin: 0 0 0.25rem;
		font-size: 1.4rem;
	}

	.subtitle {
		color: var(--text-muted, #888);
		margin: 0 0 1rem;
		font-size: 0.85rem;
	}

	.run-btn {
		background: var(--accent, #0ea5e9);
		color: white;
		border: none;
		padding: 0.5rem 1.2rem;
		border-radius: 4px;
		cursor: pointer;
		font-size: 0.9rem;
	}

	.run-btn:disabled {
		opacity: 0.6;
		cursor: default;
	}

	.error-banner {
		background: var(--severity-critical-bg, #3b1a1a);
		border: 1px solid var(--severity-critical, #ef4444);
		border-radius: 4px;
		padding: 0.75rem 1rem;
		margin-bottom: 1rem;
		color: var(--severity-critical, #ef4444);
	}

	.sub-tabs {
		display: flex;
		gap: 0.25rem;
		border-bottom: 1px solid var(--border, #333);
		margin-bottom: 1.5rem;
	}

	.sub-tab {
		background: none;
		border: none;
		border-bottom: 2px solid transparent;
		padding: 0.5rem 1rem;
		cursor: pointer;
		color: var(--text-muted, #888);
		font-size: 0.9rem;
		margin-bottom: -1px;
	}

	.sub-tab.active {
		color: var(--text, #eee);
		border-bottom-color: var(--accent, #0ea5e9);
	}

	.tab-content {
		animation: fadeIn 0.15s ease;
	}

	@keyframes fadeIn {
		from { opacity: 0; }
		to { opacity: 1; }
	}

	.summary-row {
		display: flex;
		gap: 2rem;
		margin-bottom: 1.5rem;
	}

	.metric {
		font-size: 1.4rem;
		font-weight: 600;
	}

	.metric small {
		font-size: 0.75rem;
		font-weight: 400;
		color: var(--text-muted, #888);
		margin-left: 0.25rem;
	}

	/* Policy Groups */
	.card-grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
		gap: 1rem;
	}

	.group-card {
		background: var(--surface-2, #1e1e1e);
		border: 1px solid var(--border, #333);
		border-radius: 6px;
		padding: 1rem;
	}

	.group-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 0.5rem;
	}

	.group-name {
		font-weight: 600;
		font-size: 0.95rem;
	}

	.group-meta {
		font-size: 0.8rem;
		color: var(--text-muted, #888);
		display: flex;
		gap: 0.4rem;
		margin-bottom: 0.75rem;
	}

	.member-ips {
		display: flex;
		flex-wrap: wrap;
		gap: 0.3rem;
	}

	.ip-pill {
		background: var(--surface-3, #2a2a2a);
		padding: 0.1rem 0.5rem;
		border-radius: 3px;
		font-size: 0.78rem;
		font-family: monospace;
	}

	/* Badges */
	.sl-badge {
		font-size: 0.72rem;
		font-weight: 700;
		padding: 0.15rem 0.4rem;
		border-radius: 3px;
		letter-spacing: 0.03em;
	}

	.sl-badge.sl3, .sl-badge.sl4 {
		background: var(--purdue-l1, #22c55e22);
		color: var(--purdue-l1-text, #22c55e);
		border: 1px solid var(--purdue-l1, #22c55e44);
	}

	.sl-badge.sl2 {
		background: #ca8a0422;
		color: #ca8a04;
		border: 1px solid #ca8a0444;
	}

	.sl-badge.sl1 {
		background: #64748b22;
		color: #94a3b8;
		border: 1px solid #64748b44;
	}

	.risk-badge {
		font-size: 0.72rem;
		font-weight: 700;
		padding: 0.1rem 0.4rem;
		border-radius: 3px;
	}

	.risk-badge.high { background: #ef444422; color: #ef4444; border: 1px solid #ef444444; }
	.risk-badge.medium { background: #f9731622; color: #f97316; border: 1px solid #f9731644; }
	.risk-badge.low { background: #22c55e22; color: #22c55e; border: 1px solid #22c55e44; }

	.criticality.critical { color: #ef4444; }
	.criticality.high { color: #f97316; }
	.criticality.medium { color: #eab308; }
	.criticality.low { color: #22c55e; }

	/* Tables */
	.data-table {
		width: 100%;
		border-collapse: collapse;
		margin-bottom: 1.5rem;
		font-size: 0.85rem;
	}

	.data-table th {
		text-align: left;
		padding: 0.5rem 0.75rem;
		border-bottom: 1px solid var(--border, #333);
		color: var(--text-muted, #888);
		font-weight: 500;
	}

	.data-table td {
		padding: 0.4rem 0.75rem;
		border-bottom: 1px solid var(--border-subtle, #222);
	}

	.data-table .count { text-align: right; font-variant-numeric: tabular-nums; }

	.row-warning td { color: #f97316; }

	/* Zone pairs */
	.zone-pair {
		margin-bottom: 1.5rem;
		border: 1px solid var(--border, #333);
		border-radius: 6px;
		overflow: hidden;
	}

	.zone-pair-header {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.6rem 1rem;
		background: var(--surface-2, #1e1e1e);
		font-size: 0.9rem;
	}

	.zone-name { font-weight: 600; }
	.arrow { color: var(--text-muted, #888); }
	.rule-count { margin-left: auto; color: var(--text-muted, #888); font-size: 0.8rem; }

	.rule-table {
		width: 100%;
		border-collapse: collapse;
		font-size: 0.83rem;
	}

	.rule-table th {
		text-align: left;
		padding: 0.4rem 0.75rem;
		border-bottom: 1px solid var(--border, #333);
		color: var(--text-muted, #888);
		font-weight: 500;
	}

	.rule-table td {
		padding: 0.35rem 0.75rem;
		border-bottom: 1px solid var(--border-subtle, #222);
	}

	.rule-table .justification {
		color: var(--text-muted, #888);
		font-size: 0.8rem;
	}

	/* Enforcement */
	.enforcement-controls {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		margin-bottom: 1rem;
	}

	.enforcement-controls select {
		background: var(--surface-2, #1e1e1e);
		border: 1px solid var(--border, #333);
		color: var(--text, #eee);
		padding: 0.4rem 0.6rem;
		border-radius: 4px;
		font-size: 0.9rem;
	}

	.enforcement-controls button {
		background: var(--surface-2, #1e1e1e);
		border: 1px solid var(--border, #333);
		color: var(--text, #eee);
		padding: 0.4rem 0.8rem;
		border-radius: 4px;
		cursor: pointer;
		font-size: 0.9rem;
	}

	.enforcement-controls button:disabled { opacity: 0.6; cursor: default; }

	.enforcement-summary {
		display: flex;
		gap: 0.5rem;
		flex-wrap: wrap;
		margin-bottom: 1rem;
	}

	.cfg-chip {
		background: var(--surface-2, #1e1e1e);
		border: 1px solid var(--border, #333);
		border-radius: 4px;
		padding: 0.3rem 0.6rem;
		font-size: 0.8rem;
		display: flex;
		gap: 0.5rem;
		align-items: center;
	}

	.cfg-chip.active {
		border-color: var(--accent, #0ea5e9);
		color: var(--accent, #0ea5e9);
	}

	.config-output {
		background: var(--surface-2, #1e1e1e);
		border: 1px solid var(--border, #333);
		border-radius: 4px;
		padding: 1rem;
		font-family: monospace;
		font-size: 0.8rem;
		overflow-x: auto;
		max-height: 500px;
		overflow-y: auto;
		white-space: pre;
	}

	/* Simulation */
	.sim-metrics {
		display: flex;
		gap: 2rem;
		margin-bottom: 2rem;
	}

	.sim-metric {
		text-align: center;
	}

	.metric-value {
		font-size: 2rem;
		font-weight: 700;
		font-variant-numeric: tabular-nums;
	}

	.metric-value.green { color: #22c55e; }
	.metric-value.red { color: #ef4444; }

	.metric-label {
		font-size: 0.8rem;
		color: var(--text-muted, #888);
	}

	.count-badge {
		background: #ef444422;
		color: #ef4444;
		border-radius: 3px;
		padding: 0.1rem 0.4rem;
		font-size: 0.8rem;
		font-weight: 600;
	}

	.count-badge.fp {
		background: #ca8a0422;
		color: #ca8a04;
	}

	.reason { color: var(--text-muted, #888); font-size: 0.82rem; }

	/* Recommendations */
	.recommendations {
		background: #ca8a0411;
		border: 1px solid #ca8a0444;
		border-radius: 4px;
		padding: 0.75rem 1rem;
		margin-bottom: 1.5rem;
	}

	.recommendations h3 { margin: 0 0 0.5rem; font-size: 0.9rem; color: #ca8a04; }
	.recommendations ul { margin: 0; padding-left: 1.2rem; font-size: 0.85rem; }
	.recommendations li { margin-bottom: 0.25rem; }

	/* Empty state */
	.empty-state {
		text-align: center;
		padding: 3rem 2rem;
		color: var(--text-muted, #888);
		max-width: 500px;
		margin: 0 auto;
	}

	.empty-state p { margin-bottom: 0.75rem; }
	.hint { font-size: 0.82rem; color: var(--text-muted, #888); }

	h3 {
		margin: 1.5rem 0 0.75rem;
		font-size: 1rem;
		font-weight: 600;
	}
</style>
