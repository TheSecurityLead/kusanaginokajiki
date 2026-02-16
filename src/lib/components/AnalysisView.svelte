<script lang="ts">
	import { onMount } from 'svelte';
	import {
		assets, findings, purdueAssignments, anomalies,
		analysisSummary, activeTab, selectedAssetId
	} from '$lib/stores';
	import type { ViewTab } from '$lib/stores';
	import type {
		Finding, PurdueAssignment, AnomalyScore, AnalysisResult, FindingSeverity
	} from '$lib/types';
	import { runAnalysis, getFindings, getPurdueAssignments, getAnomalies, getAssets } from '$lib/utils/tauri';
	import BaselineDriftView from './BaselineDriftView.svelte';

	let activeSection = $state<'findings' | 'purdue' | 'anomalies' | 'summary' | 'drift'>('summary');
	let isRunning = $state(false);
	let lastRunTime = $state<string | null>(null);
	let error = $state<string | null>(null);

	// Severity display helpers
	const severityOrder: FindingSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];
	const severityColors: Record<FindingSeverity, string> = {
		critical: 'var(--gm-severity-critical)',
		high: 'var(--gm-severity-high)',
		medium: 'var(--gm-severity-medium)',
		low: 'var(--gm-severity-low)',
		info: 'var(--gm-severity-info)'
	};

	const purdueLabels: Record<number, string> = {
		0: 'L0 — Process',
		1: 'L1 — Basic Control',
		2: 'L2 — Supervisory',
		3: 'L3 — Site Operations',
		4: 'L4 — Enterprise IT',
		5: 'L5 — Enterprise Network'
	};

	const purdueColors: Record<number, string> = {
		0: 'var(--gm-purdue-l0)',
		1: 'var(--gm-purdue-l1)',
		2: 'var(--gm-purdue-l2)',
		3: 'var(--gm-purdue-l3)',
		4: 'var(--gm-purdue-l4)',
		5: 'var(--gm-purdue-l5)'
	};

	onMount(async () => {
		// Load previous results if available
		try {
			const [f, p, a] = await Promise.all([
				getFindings(),
				getPurdueAssignments(),
				getAnomalies()
			]);
			findings.set(f);
			purdueAssignments.set(p);
			anomalies.set(a);
		} catch {
			// No previous results
		}
	});

	async function handleRunAnalysis() {
		isRunning = true;
		error = null;
		try {
			const result: AnalysisResult = await runAnalysis();
			findings.set(result.findings);
			purdueAssignments.set(result.purdue_assignments);
			anomalies.set(result.anomalies);
			analysisSummary.set(result.summary);
			lastRunTime = new Date().toLocaleTimeString();

			// Refresh assets (Purdue levels may have been auto-assigned)
			const updatedAssets = await getAssets();
			assets.set(updatedAssets);
		} catch (e) {
			error = String(e);
		} finally {
			isRunning = false;
		}
	}

	function navigateToAsset(ip: string) {
		selectedAssetId.set(ip);
		activeTab.set('inventory' as ViewTab);
	}

	function getSeverityIcon(severity: FindingSeverity): string {
		switch (severity) {
			case 'critical': return '!!';
			case 'high': return '!';
			case 'medium': return '~';
			case 'low': return '-';
			case 'info': return 'i';
		}
	}

	function getTypeLabel(type: string): string {
		switch (type) {
			case 'attack_technique': return 'ATT&CK';
			case 'purdue_violation': return 'Purdue';
			case 'anomaly': return 'Anomaly';
			default: return type;
		}
	}

	// Derived: group purdue assignments by level
	function groupByLevel(assignments: PurdueAssignment[]): Map<number, PurdueAssignment[]> {
		const map = new Map<number, PurdueAssignment[]>();
		for (const a of assignments) {
			const list = map.get(a.level) ?? [];
			list.push(a);
			map.set(a.level, list);
		}
		return map;
	}
</script>

<div class="analysis-container">
	<!-- Header -->
	<div class="analysis-header">
		<div class="header-left">
			<h2 class="header-title">Security Analysis</h2>
			{#if lastRunTime}
				<span class="last-run">Last run: {lastRunTime}</span>
			{/if}
		</div>
		<button
			class="run-btn"
			onclick={handleRunAnalysis}
			disabled={isRunning || $assets.length === 0}
		>
			{#if isRunning}
				Analyzing...
			{:else}
				Run Analysis
			{/if}
		</button>
	</div>

	{#if error}
		<div class="error-banner">{error}</div>
	{/if}

	{#if $assets.length === 0}
		<div class="empty-state">
			<div class="empty-icon">⚑</div>
			<p>Import PCAPs or start a live capture first, then run security analysis.</p>
		</div>
	{:else}
		<!-- Section tabs -->
		<div class="section-tabs">
			<button class="section-tab" class:active={activeSection === 'summary'} onclick={() => activeSection = 'summary'}>
				Summary
			</button>
			<button class="section-tab" class:active={activeSection === 'findings'} onclick={() => activeSection = 'findings'}>
				Findings
				{#if $findings.length > 0}
					<span class="tab-badge">{$findings.length}</span>
				{/if}
			</button>
			<button class="section-tab" class:active={activeSection === 'purdue'} onclick={() => activeSection = 'purdue'}>
				Purdue Model
			</button>
			<button class="section-tab" class:active={activeSection === 'anomalies'} onclick={() => activeSection = 'anomalies'}>
				Anomalies
				{#if $anomalies.length > 0}
					<span class="tab-badge">{$anomalies.length}</span>
				{/if}
			</button>
			<button class="section-tab" class:active={activeSection === 'drift'} onclick={() => activeSection = 'drift'}>
				Baseline Drift
			</button>
		</div>

		<!-- Content area -->
		<div class="section-content">
			{#if activeSection === 'summary'}
				<!-- Summary Dashboard -->
				{#if $analysisSummary}
					<div class="summary-grid">
						<div class="summary-card">
							<div class="card-label">Total Findings</div>
							<div class="card-value">{$analysisSummary.total_findings}</div>
						</div>
						<div class="summary-card severity-critical">
							<div class="card-label">Critical</div>
							<div class="card-value">{$analysisSummary.critical_count}</div>
						</div>
						<div class="summary-card severity-high">
							<div class="card-label">High</div>
							<div class="card-value">{$analysisSummary.high_count}</div>
						</div>
						<div class="summary-card severity-medium">
							<div class="card-label">Medium</div>
							<div class="card-value">{$analysisSummary.medium_count}</div>
						</div>
						<div class="summary-card">
							<div class="card-label">Assets Analyzed</div>
							<div class="card-value">{$analysisSummary.assets_analyzed}</div>
						</div>
						<div class="summary-card">
							<div class="card-label">Connections</div>
							<div class="card-value">{$analysisSummary.connections_analyzed}</div>
						</div>
						<div class="summary-card">
							<div class="card-label">Purdue Violations</div>
							<div class="card-value">{$analysisSummary.purdue_violations}</div>
						</div>
						<div class="summary-card">
							<div class="card-label">Unencrypted OT</div>
							<div class="card-value">{$analysisSummary.unencrypted_ot_percent}%</div>
						</div>
					</div>

					<!-- Severity breakdown bar -->
					{#if $analysisSummary.total_findings > 0}
						<div class="severity-bar-section">
							<h3 class="subsection-title">Severity Distribution</h3>
							<div class="severity-bar">
								{#each severityOrder as sev}
									{@const count = $analysisSummary[`${sev}_count` as keyof typeof $analysisSummary] as number}
									{#if count > 0}
										<div
											class="severity-segment"
											style="width: {(count / $analysisSummary.total_findings) * 100}%; background: {severityColors[sev]}"
											title="{sev}: {count}"
										></div>
									{/if}
								{/each}
							</div>
							<div class="severity-legend">
								{#each severityOrder as sev}
									{@const count = $analysisSummary[`${sev}_count` as keyof typeof $analysisSummary] as number}
									{#if count > 0}
										<span class="legend-item">
											<span class="legend-dot" style="background: {severityColors[sev]}"></span>
											{sev} ({count})
										</span>
									{/if}
								{/each}
							</div>
						</div>
					{/if}
				{:else}
					<div class="empty-section">
						<p>Click "Run Analysis" to analyze the current network data for security findings.</p>
					</div>
				{/if}

			{:else if activeSection === 'findings'}
				<!-- Findings List -->
				{#if $findings.length === 0}
					<div class="empty-section">
						<p>No findings yet. Run analysis to detect security issues.</p>
					</div>
				{:else}
					<div class="findings-list">
						{#each $findings as finding}
							<div class="finding-card severity-border-{finding.severity}">
								<div class="finding-header">
									<span
										class="severity-badge"
										style="background: {severityColors[finding.severity]}"
									>
										{getSeverityIcon(finding.severity)} {finding.severity.toUpperCase()}
									</span>
									<span class="finding-type">{getTypeLabel(finding.finding_type)}</span>
									{#if finding.technique_id}
										<span class="technique-id">{finding.technique_id}</span>
									{/if}
								</div>
								<h3 class="finding-title">{finding.title}</h3>
								<p class="finding-desc">{finding.description}</p>
								<div class="finding-evidence">
									<span class="evidence-label">Evidence:</span>
									{finding.evidence}
								</div>
								<div class="finding-assets">
									<span class="assets-label">Affected:</span>
									{#each finding.affected_assets as ip}
										<button class="asset-link" onclick={() => navigateToAsset(ip)}>
											{ip}
										</button>
									{/each}
								</div>
							</div>
						{/each}
					</div>
				{/if}

			{:else if activeSection === 'purdue'}
				<!-- Purdue Model Overview -->
				{#if $purdueAssignments.length === 0}
					<div class="empty-section">
						<p>No Purdue assignments yet. Run analysis to auto-assign Purdue levels.</p>
					</div>
				{:else}
					<div class="purdue-overview">
						{#each [5, 4, 3, 2, 1, 0] as level}
							{@const levelAssets = $purdueAssignments.filter(a => a.level === level)}
							{#if levelAssets.length > 0}
								<div class="purdue-level">
									<div class="purdue-level-header" style="border-left: 3px solid {purdueColors[level]}">
										<span class="purdue-level-label" style="color: {purdueColors[level]}">
											{purdueLabels[level] ?? `L${level}`}
										</span>
										<span class="purdue-level-count">{levelAssets.length} devices</span>
									</div>
									<div class="purdue-devices">
										{#each levelAssets as assignment}
											<div class="purdue-device">
												<button class="device-ip" onclick={() => navigateToAsset(assignment.ip_address)}>
													{assignment.ip_address}
												</button>
												<span class="device-method" class:manual={assignment.method === 'manual'}>
													{assignment.method}
												</span>
												<span class="device-reason">{assignment.reason}</span>
											</div>
										{/each}
									</div>
								</div>
							{/if}
						{/each}
					</div>

					<!-- Violation highlights -->
					{@const violations = $findings.filter(f => f.finding_type === 'purdue_violation')}
					{#if violations.length > 0}
						<div class="violations-section">
							<h3 class="subsection-title">Cross-Zone Violations ({violations.length})</h3>
							{#each violations as v}
								<div class="violation-card">
									<span class="severity-badge" style="background: {severityColors[v.severity]}">
										{v.severity.toUpperCase()}
									</span>
									<span class="violation-text">{v.title}</span>
								</div>
							{/each}
						</div>
					{/if}
				{/if}

			{:else if activeSection === 'anomalies'}
				<!-- Anomaly List -->
				{#if $anomalies.length === 0}
					<div class="empty-section">
						<p>No anomalies detected. Run analysis to check for behavioral deviations.</p>
					</div>
				{:else}
					<div class="anomaly-list">
						{#each $anomalies as anomaly}
							<div class="anomaly-card">
								<div class="anomaly-header">
									<span
										class="severity-badge"
										style="background: {severityColors[anomaly.severity]}"
									>
										{anomaly.severity.toUpperCase()}
									</span>
									<span class="anomaly-type">{anomaly.anomaly_type.replace(/_/g, ' ')}</span>
									<span class="anomaly-confidence">
										{Math.round(anomaly.confidence * 100)}% confidence
									</span>
								</div>
								<div class="anomaly-evidence">{anomaly.evidence}</div>
								<button class="asset-link" onclick={() => navigateToAsset(anomaly.affected_asset)}>
									{anomaly.affected_asset}
								</button>
							</div>
						{/each}
					</div>
				{/if}

			{:else if activeSection === 'drift'}
				<BaselineDriftView />
			{/if}
		</div>
	{/if}
</div>

<style>
	.analysis-container {
		height: 100%;
		display: flex;
		flex-direction: column;
		overflow: hidden;
	}

	/* ── Header ─────────────────────────────────────── */

	.analysis-header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 16px 20px;
		border-bottom: 1px solid var(--gm-border);
		flex-shrink: 0;
	}

	.header-left {
		display: flex;
		align-items: center;
		gap: 16px;
	}

	.header-title {
		font-size: 15px;
		font-weight: 600;
		color: var(--gm-text-primary);
		margin: 0;
	}

	.last-run {
		font-size: 10px;
		color: var(--gm-text-muted);
	}

	.run-btn {
		padding: 8px 20px;
		background: linear-gradient(135deg, #10b981, #059669);
		border: none;
		border-radius: 6px;
		color: #0a0e17;
		font-family: inherit;
		font-size: 12px;
		font-weight: 600;
		cursor: pointer;
		transition: all 0.15s;
	}

	.run-btn:hover:not(:disabled) {
		filter: brightness(1.1);
	}

	.run-btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	/* ── Error / Empty State ─────────────────────────── */

	.error-banner {
		margin: 12px 20px;
		padding: 10px 14px;
		background: rgba(239, 68, 68, 0.1);
		border: 1px solid rgba(239, 68, 68, 0.3);
		border-radius: 6px;
		color: #ef4444;
		font-size: 11px;
	}

	.empty-state {
		flex: 1;
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		color: var(--gm-text-muted);
		gap: 12px;
	}

	.empty-icon {
		font-size: 36px;
		opacity: 0.4;
	}

	.empty-section {
		padding: 40px 20px;
		text-align: center;
		color: var(--gm-text-muted);
		font-size: 12px;
	}

	/* ── Section Tabs ────────────────────────────────── */

	.section-tabs {
		display: flex;
		border-bottom: 1px solid var(--gm-border);
		flex-shrink: 0;
		background: var(--gm-bg-secondary);
	}

	.section-tab {
		padding: 10px 18px;
		background: transparent;
		border: none;
		border-bottom: 2px solid transparent;
		color: var(--gm-text-muted);
		font-family: inherit;
		font-size: 11px;
		font-weight: 500;
		cursor: pointer;
		display: flex;
		align-items: center;
		gap: 6px;
		transition: all 0.15s;
	}

	.section-tab:hover {
		color: var(--gm-text-secondary);
	}

	.section-tab.active {
		color: var(--gm-text-primary);
		border-bottom-color: #10b981;
	}

	.tab-badge {
		background: rgba(239, 68, 68, 0.2);
		color: #ef4444;
		padding: 1px 6px;
		border-radius: 8px;
		font-size: 9px;
		font-weight: 700;
	}

	/* ── Section Content ─────────────────────────────── */

	.section-content {
		flex: 1;
		overflow-y: auto;
		padding: 16px 20px;
	}

	.section-content:has(.drift-container) {
		padding: 0;
		overflow: hidden;
	}

	/* ── Summary Dashboard ───────────────────────────── */

	.summary-grid {
		display: grid;
		grid-template-columns: repeat(4, 1fr);
		gap: 12px;
		margin-bottom: 24px;
	}

	.summary-card {
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 8px;
		padding: 14px;
		text-align: center;
	}

	.summary-card.severity-critical {
		border-color: var(--gm-severity-critical);
	}

	.summary-card.severity-high {
		border-color: var(--gm-severity-high);
	}

	.summary-card.severity-medium {
		border-color: var(--gm-severity-medium);
	}

	.card-label {
		font-size: 10px;
		color: var(--gm-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.5px;
		margin-bottom: 6px;
	}

	.card-value {
		font-size: 22px;
		font-weight: 700;
		color: var(--gm-text-primary);
	}

	/* ── Severity Bar ────────────────────────────────── */

	.severity-bar-section {
		margin-bottom: 24px;
	}

	.subsection-title {
		font-size: 12px;
		font-weight: 600;
		color: var(--gm-text-secondary);
		margin: 0 0 10px;
	}

	.severity-bar {
		display: flex;
		height: 12px;
		border-radius: 6px;
		overflow: hidden;
		background: var(--gm-bg-panel);
	}

	.severity-segment {
		transition: width 0.3s ease;
	}

	.severity-legend {
		display: flex;
		gap: 14px;
		margin-top: 8px;
	}

	.legend-item {
		display: flex;
		align-items: center;
		gap: 4px;
		font-size: 10px;
		color: var(--gm-text-secondary);
		text-transform: capitalize;
	}

	.legend-dot {
		width: 8px;
		height: 8px;
		border-radius: 50%;
	}

	/* ── Findings ─────────────────────────────────────── */

	.findings-list {
		display: flex;
		flex-direction: column;
		gap: 12px;
	}

	.finding-card {
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 8px;
		padding: 14px;
	}

	.finding-card.severity-border-critical { border-left: 3px solid var(--gm-severity-critical); }
	.finding-card.severity-border-high { border-left: 3px solid var(--gm-severity-high); }
	.finding-card.severity-border-medium { border-left: 3px solid var(--gm-severity-medium); }
	.finding-card.severity-border-low { border-left: 3px solid var(--gm-severity-low); }
	.finding-card.severity-border-info { border-left: 3px solid var(--gm-severity-info); }

	.finding-header {
		display: flex;
		align-items: center;
		gap: 8px;
		margin-bottom: 8px;
	}

	.severity-badge {
		display: inline-flex;
		align-items: center;
		gap: 3px;
		padding: 2px 8px;
		border-radius: 4px;
		font-size: 9px;
		font-weight: 700;
		color: #0a0e17;
		letter-spacing: 0.5px;
	}

	.finding-type {
		font-size: 10px;
		color: var(--gm-text-muted);
		background: var(--gm-bg-hover);
		padding: 2px 6px;
		border-radius: 3px;
	}

	.technique-id {
		font-size: 10px;
		color: #10b981;
		font-weight: 600;
	}

	.finding-title {
		font-size: 13px;
		font-weight: 600;
		color: var(--gm-text-primary);
		margin: 0 0 6px;
	}

	.finding-desc {
		font-size: 11px;
		color: var(--gm-text-secondary);
		margin: 0 0 8px;
		line-height: 1.5;
	}

	.finding-evidence {
		font-size: 10px;
		color: var(--gm-text-muted);
		background: var(--gm-bg-secondary);
		padding: 8px;
		border-radius: 4px;
		margin-bottom: 8px;
		font-style: italic;
	}

	.evidence-label, .assets-label {
		font-weight: 600;
		color: var(--gm-text-secondary);
		font-style: normal;
	}

	.finding-assets {
		display: flex;
		align-items: center;
		gap: 6px;
		flex-wrap: wrap;
		font-size: 10px;
	}

	.asset-link {
		background: rgba(16, 185, 129, 0.1);
		border: 1px solid rgba(16, 185, 129, 0.3);
		border-radius: 4px;
		color: #10b981;
		padding: 2px 8px;
		font-family: inherit;
		font-size: 10px;
		cursor: pointer;
		transition: all 0.15s;
	}

	.asset-link:hover {
		background: rgba(16, 185, 129, 0.2);
	}

	/* ── Purdue Model ────────────────────────────────── */

	.purdue-overview {
		display: flex;
		flex-direction: column;
		gap: 16px;
	}

	.purdue-level {
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 8px;
		overflow: hidden;
	}

	.purdue-level-header {
		padding: 10px 14px;
		background: var(--gm-bg-secondary);
		display: flex;
		align-items: center;
		justify-content: space-between;
	}

	.purdue-level-label {
		font-size: 12px;
		font-weight: 600;
	}

	.purdue-level-count {
		font-size: 10px;
		color: var(--gm-text-muted);
	}

	.purdue-devices {
		padding: 4px 8px;
	}

	.purdue-device {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 6px 8px;
		border-bottom: 1px solid var(--gm-border);
	}

	.purdue-device:last-child {
		border-bottom: none;
	}

	.device-ip {
		background: none;
		border: none;
		color: #10b981;
		font-family: inherit;
		font-size: 11px;
		font-weight: 600;
		cursor: pointer;
		padding: 0;
		min-width: 120px;
	}

	.device-ip:hover {
		text-decoration: underline;
	}

	.device-method {
		font-size: 9px;
		padding: 1px 6px;
		border-radius: 3px;
		background: var(--gm-bg-hover);
		color: var(--gm-text-muted);
		text-transform: uppercase;
	}

	.device-method.manual {
		background: rgba(59, 130, 246, 0.15);
		color: #3b82f6;
	}

	.device-reason {
		font-size: 10px;
		color: var(--gm-text-muted);
		flex: 1;
	}

	/* ── Violations ───────────────────────────────────── */

	.violations-section {
		margin-top: 24px;
	}

	.violation-card {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 10px 14px;
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 6px;
		margin-bottom: 8px;
	}

	.violation-text {
		font-size: 11px;
		color: var(--gm-text-secondary);
	}

	/* ── Anomalies ────────────────────────────────────── */

	.anomaly-list {
		display: flex;
		flex-direction: column;
		gap: 10px;
	}

	.anomaly-card {
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 8px;
		padding: 14px;
	}

	.anomaly-header {
		display: flex;
		align-items: center;
		gap: 8px;
		margin-bottom: 8px;
	}

	.anomaly-type {
		font-size: 11px;
		color: var(--gm-text-secondary);
		text-transform: capitalize;
	}

	.anomaly-confidence {
		font-size: 10px;
		color: var(--gm-text-muted);
		margin-left: auto;
	}

	.anomaly-evidence {
		font-size: 11px;
		color: var(--gm-text-muted);
		margin-bottom: 8px;
		line-height: 1.4;
	}
</style>
