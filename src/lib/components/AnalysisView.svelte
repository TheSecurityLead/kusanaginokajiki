<script lang="ts">
	import { onMount } from 'svelte';
	import {
		assets, findings, purdueAssignments, anomalies,
		analysisSummary, activeTab, selectedAssetId
	} from '$lib/stores';
	import type { ViewTab } from '$lib/stores';
	import type {
		Finding, PurdueAssignment, AnomalyScore, AnalysisResult, FindingSeverity, SwitchSecurityFinding,
		MalwareFinding, ComplianceMapping, ComplianceStatus
	} from '$lib/types';
	import { runAnalysis, getFindings, getPurdueAssignments, getAnomalies, getAssets, getSwitchSecurityFindings, getCorrelatedAlerts, clearAlerts, getMalwareFindings, getComplianceReport } from '$lib/utils/tauri';
	import { assetCount } from '$lib/stores';
	import type { CorrelatedAlert } from '$lib/types';
	import BaselineDriftView from './BaselineDriftView.svelte';

	let activeSection = $state<'findings' | 'purdue' | 'anomalies' | 'summary' | 'drift' | 'switch_security' | 'external_alerts' | 'malware' | 'compliance'>('summary');
	let switchFindings = $state<SwitchSecurityFinding[]>([]);
	let loadingSwitchFindings = $state(false);
	let correlatedAlerts = $state<CorrelatedAlert[]>([]);
	let loadingAlerts = $state(false);

	async function loadCorrelatedAlerts() {
		loadingAlerts = true;
		try {
			correlatedAlerts = await getCorrelatedAlerts();
		} catch {
			correlatedAlerts = [];
		} finally {
			loadingAlerts = false;
		}
	}

	async function handleClearAlerts() {
		await clearAlerts();
		correlatedAlerts = [];
	}

	function alertSeverityLabel(severity: number): string {
		if (severity === 1) return 'HIGH';
		if (severity === 2) return 'MED';
		return 'LOW';
	}

	function alertSeverityClass(severity: number): string {
		if (severity === 1) return 'high';
		if (severity === 2) return 'medium';
		return 'low';
	}

	async function loadSwitchFindings() {
		loadingSwitchFindings = true;
		try {
			switchFindings = await getSwitchSecurityFindings();
		} catch {
			switchFindings = [];
		} finally {
			loadingSwitchFindings = false;
		}
	}
	let isRunning = $state(false);
	let lastRunTime = $state<string | null>(null);
	let error = $state<string | null>(null);

	// ─── ICS Malware Signatures ──────────────────────────
	let malwareFindings = $state<MalwareFinding[]>([]);
	let loadingMalware = $state(false);

	async function loadMalwareFindings() {
		loadingMalware = true;
		try {
			malwareFindings = await getMalwareFindings();
		} catch (e) {
			error = `Malware detection failed: ${e}`;
		} finally {
			loadingMalware = false;
		}
	}

	// ─── Compliance Framework Mapping ───────────────────
	let complianceFramework = $state<'iec62443' | 'nist80082' | 'nerccip'>('iec62443');
	let complianceMappings = $state<ComplianceMapping[]>([]);
	let loadingCompliance = $state(false);

	async function loadComplianceReport() {
		loadingCompliance = true;
		try {
			complianceMappings = await getComplianceReport(complianceFramework);
		} catch (e) {
			error = `Compliance mapping failed: ${e}`;
		} finally {
			loadingCompliance = false;
		}
	}

	function complianceStatusClass(status: ComplianceStatus): string {
		if (status === 'gap') return 'status-gap';
		if (status === 'partial') return 'status-partial';
		if (status === 'met') return 'status-met';
		return 'status-na';
	}

	function complianceStatusLabel(status: ComplianceStatus): string {
		if (status === 'gap') return 'GAP';
		if (status === 'partial') return 'PARTIAL';
		if (status === 'met') return 'MET';
		return 'N/A';
	}

	function malwareSeverityClass(s: string): string {
		if (s === 'critical') return 'sev-critical';
		if (s === 'high') return 'sev-high';
		if (s === 'medium') return 'sev-medium';
		return 'sev-low';
	}

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
			const assetPage = await getAssets(0, 200);
			assets.set(assetPage.assets);
			assetCount.set(assetPage.total);
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
			<button class="section-tab" class:active={activeSection === 'switch_security'}
				onclick={() => { activeSection = 'switch_security'; loadSwitchFindings(); }}>
				Switch Security
				{#if switchFindings.length > 0}
					<span class="tab-badge">{switchFindings.length}</span>
				{/if}
			</button>
			<button class="section-tab" class:active={activeSection === 'external_alerts'}
				onclick={() => { activeSection = 'external_alerts'; loadCorrelatedAlerts(); }}>
				Ext. Alerts
				{#if correlatedAlerts.length > 0}
					<span class="tab-badge">{correlatedAlerts.length}</span>
				{/if}
			</button>
			<button class="section-tab" class:active={activeSection === 'malware'}
				onclick={() => { activeSection = 'malware'; loadMalwareFindings(); }}>
				Malware
				{#if malwareFindings.length > 0}
					<span class="tab-badge tab-badge-critical">{malwareFindings.length}</span>
				{/if}
			</button>
			<button class="section-tab" class:active={activeSection === 'compliance'}
				onclick={() => { activeSection = 'compliance'; loadComplianceReport(); }}>
				Compliance
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

			{:else if activeSection === 'switch_security'}
				<!-- Switch Port Security Findings -->
				{#if loadingSwitchFindings}
					<div class="empty-panel">
						<div class="empty-icon">&#x23F3;</div>
						<p>Assessing switch security...</p>
					</div>
				{:else if switchFindings.length === 0}
					<div class="empty-panel">
						<div class="empty-icon">&#x1F512;</div>
						<p>No switch security findings. Import a PCAP with managed switch traffic, LLDP frames, or ring redundancy protocols, then click Refresh.</p>
						<button class="run-btn" onclick={loadSwitchFindings} style="margin-top: 8px">Refresh</button>
					</div>
				{:else}
					<div class="switch-findings-list">
						{#each switchFindings as sf}
							<div class="switch-finding sev-{sf.severity}">
								<div class="sf-header">
									<span class="sf-severity sev-badge-{sf.severity}">{sf.severity.toUpperCase()}</span>
									<span class="sf-title">{sf.title}</span>
								</div>
								<p class="sf-description">{sf.description}</p>
								{#if sf.affected_assets.length > 0}
									<div class="sf-detail">
										<span class="sf-label">Affected</span>
										<span class="sf-value">{sf.affected_assets.join(', ')}</span>
									</div>
								{/if}
								<div class="sf-detail">
									<span class="sf-label">Evidence</span>
									<span class="sf-value">{sf.evidence}</span>
								</div>
								<div class="sf-remediation">
									<span class="sf-label">&#x1F527; Remediation</span>
									<p class="sf-rem-text">{sf.remediation}</p>
								</div>
							</div>
						{/each}
					</div>
				{/if}
			{:else if activeSection === 'external_alerts'}
				<!-- External IDS/SIEM Alerts -->
				<div class="ext-alerts-header">
					<span class="ext-alerts-count">{correlatedAlerts.length} alert{correlatedAlerts.length !== 1 ? 's' : ''}</span>
					{#if correlatedAlerts.length > 0}
						<button class="clear-btn" onclick={handleClearAlerts}>Clear All</button>
					{/if}
					<button class="run-btn" onclick={loadCorrelatedAlerts} disabled={loadingAlerts}>
						{loadingAlerts ? 'Loading...' : 'Refresh'}
					</button>
				</div>
				{#if loadingAlerts}
					<div class="empty-panel"><p>Loading alerts...</p></div>
				{:else if correlatedAlerts.length === 0}
					<div class="empty-panel">
						<div class="empty-icon">&#x1F514;</div>
						<p>No external alerts. Import Suricata eve.json or Wazuh alert export via the Capture tab.</p>
					</div>
				{:else}
					<div class="alert-list">
						{#each correlatedAlerts as alert}
							<div class="alert-row sev-{alertSeverityClass(alert.severity)}">
								<div class="alert-row-header">
									<span class="alert-sev sev-badge-{alertSeverityClass(alert.severity)}">{alertSeverityLabel(alert.severity)}</span>
									<span class="alert-source source-badge">{alert.source}</span>
									<span class="alert-sig">{alert.signature}</span>
									<span class="alert-ts">{new Date(alert.timestamp).toLocaleString()}</span>
								</div>
								<div class="alert-flow">
									<span class="flow-ip">
										{alert.src_ip}{alert.src_port ? ':' + alert.src_port : ''}
										{#if alert.src_hostname}<span class="flow-name">({alert.src_hostname})</span>{/if}
										{#if alert.src_device_type}<span class="flow-dtype">[{alert.src_device_type}]</span>{/if}
									</span>
									<span class="flow-arrow">→</span>
									<span class="flow-ip">
										{alert.dst_ip}{alert.dst_port ? ':' + alert.dst_port : ''}
										{#if alert.dst_hostname}<span class="flow-name">({alert.dst_hostname})</span>{/if}
										{#if alert.dst_device_type}<span class="flow-dtype">[{alert.dst_device_type}]</span>{/if}
									</span>
								</div>
								<div class="alert-meta">
									<span class="alert-cat">{alert.category}</span>
									{#if alert.src_purdue_level !== null || alert.dst_purdue_level !== null}
										<span class="alert-purdue">
											L{alert.src_purdue_level ?? '?'} → L{alert.dst_purdue_level ?? '?'}
										</span>
									{/if}
								</div>
							</div>
						{/each}
					</div>
				{/if}
			{:else if activeSection === 'malware'}
				<!-- ICS Malware Behavioral Signatures -->
				<div class="ext-alerts-header">
					<span class="ext-alerts-count">{malwareFindings.length} match{malwareFindings.length !== 1 ? 'es' : ''}</span>
					<button class="run-btn" onclick={loadMalwareFindings} disabled={loadingMalware}>
						{loadingMalware ? 'Scanning...' : 'Refresh'}
					</button>
				</div>
				{#if loadingMalware}
					<div class="empty-panel"><p>Running malware signature scan...</p></div>
				{:else if malwareFindings.length === 0}
					<div class="empty-panel">
						<div class="empty-icon">&#x1F9EC;</div>
						<p>No ICS malware behavioral patterns detected.</p>
						<p class="empty-sub">Detects: FrostyGoop, PIPEDREAM/INCONTROLLER, Industroyer2</p>
					</div>
				{:else}
					<div class="alert-list">
						{#each malwareFindings as mf}
							<div class="alert-row">
								<div class="alert-row-header">
									<span class="alert-sev sev-badge-{mf.severity}">{mf.severity.toUpperCase()}</span>
									<span class="malware-name">{mf.malware_name}</span>
									<span class="malware-confidence conf-{mf.confidence}">{mf.confidence} confidence</span>
									<span class="alert-source source-badge">{mf.attack_techniques.join(', ')}</span>
								</div>
								<div class="malware-pattern">{mf.pattern_description}</div>
								<div class="alert-flow">
									<span class="flow-ip">{mf.source_ip}</span>
									<span class="flow-arrow">→</span>
									<span class="flow-ip">{mf.target_ips.slice(0, 3).join(', ')}{mf.target_ips.length > 3 ? ` +${mf.target_ips.length - 3} more` : ''}</span>
								</div>
								<div class="alert-cat">{mf.evidence}</div>
							</div>
						{/each}
					</div>
				{/if}

			{:else if activeSection === 'compliance'}
				<!-- Compliance Framework Mapping -->
				<div class="compliance-header">
					<span class="ext-alerts-count">Compliance Mapping</span>
					<select class="framework-select" bind:value={complianceFramework}
						onchange={loadComplianceReport}>
						<option value="iec62443">IEC 62443</option>
						<option value="nist80082">NIST 800-82 Rev 3</option>
						<option value="nerccip">NERC CIP</option>
					</select>
					<button class="run-btn" onclick={loadComplianceReport} disabled={loadingCompliance}>
						{loadingCompliance ? 'Loading...' : 'Refresh'}
					</button>
				</div>
				{#if loadingCompliance}
					<div class="empty-panel"><p>Generating compliance report...</p></div>
				{:else if complianceMappings.length === 0}
					<div class="empty-panel">
						<div class="empty-icon">&#x1F4CB;</div>
						<p>Select a framework above to generate a compliance mapping.</p>
						<p class="empty-sub">Run analysis first for best results.</p>
					</div>
				{:else}
					<div class="compliance-summary">
						<span class="cs-gap">&#x274C; {complianceMappings.filter(m => m.status === 'gap').length} Gap</span>
						<span class="cs-partial">&#x26A0; {complianceMappings.filter(m => m.status === 'partial').length} Partial</span>
						<span class="cs-met">&#x2705; {complianceMappings.filter(m => m.status === 'met').length} Met</span>
						<span class="cs-na">&#x2B1C; {complianceMappings.filter(m => m.status === 'not_assessed').length} N/A</span>
					</div>
					<div class="compliance-list">
						{#each complianceMappings as mapping}
							<div class="compliance-row cs-row-{mapping.status}">
								<div class="compliance-req-header">
									<span class="req-id">{mapping.requirement_id}</span>
									<span class="req-name">{mapping.requirement_name}</span>
									<span class="status-badge {complianceStatusClass(mapping.status)}">
										{complianceStatusLabel(mapping.status)}
									</span>
								</div>
								<div class="compliance-evidence">{mapping.evidence}</div>
							</div>
						{/each}
					</div>
				{/if}
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

	/* ── Switch Security Tab ─────────────────────────── */

	.empty-panel {
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		padding: 40px;
		text-align: center;
		color: var(--gm-text-muted);
		gap: 10px;
	}

	.switch-findings-list {
		display: flex;
		flex-direction: column;
		gap: 12px;
		padding: 4px;
	}

	.switch-finding {
		background: var(--gm-bg-secondary);
		border: 1px solid var(--gm-border);
		border-left: 4px solid var(--gm-border);
		border-radius: 6px;
		padding: 12px 14px;
		display: flex;
		flex-direction: column;
		gap: 6px;
	}

	.switch-finding.sev-critical { border-left-color: var(--gm-severity-critical); }
	.switch-finding.sev-high     { border-left-color: var(--gm-severity-high); }
	.switch-finding.sev-medium   { border-left-color: var(--gm-severity-medium); }
	.switch-finding.sev-low      { border-left-color: var(--gm-severity-low); }

	.sf-header {
		display: flex;
		align-items: center;
		gap: 8px;
	}

	.sf-severity {
		font-size: 9px;
		font-weight: 700;
		padding: 2px 6px;
		border-radius: 3px;
		letter-spacing: 0.5px;
		flex-shrink: 0;
	}

	.sev-badge-critical { background: var(--gm-severity-critical); color: #fff; }
	.sev-badge-high     { background: var(--gm-severity-high); color: #fff; }
	.sev-badge-medium   { background: var(--gm-severity-medium); color: #fff; }
	.sev-badge-low      { background: var(--gm-severity-low); color: #fff; }

	.sf-title {
		font-size: 13px;
		font-weight: 600;
		color: var(--gm-text-primary);
	}

	.sf-description {
		font-size: 12px;
		color: var(--gm-text-secondary);
		line-height: 1.4;
		margin: 0;
	}

	.sf-detail {
		display: flex;
		gap: 8px;
		font-size: 11px;
	}

	.sf-label {
		color: var(--gm-text-muted);
		font-size: 10px;
		font-weight: 600;
		text-transform: uppercase;
		min-width: 60px;
		flex-shrink: 0;
	}

	.sf-value {
		color: var(--gm-text-secondary);
		font-family: 'JetBrains Mono', monospace;
		font-size: 10px;
	}

	.sf-remediation {
		background: var(--gm-bg-panel);
		border-radius: 4px;
		padding: 8px 10px;
		margin-top: 4px;
		display: flex;
		flex-direction: column;
		gap: 4px;
	}

	.sf-rem-text {
		font-size: 11px;
		color: var(--gm-text-secondary);
		line-height: 1.4;
		margin: 0;
	}

	/* ── External Alerts ──────────────────────────────── */

	.ext-alerts-header {
		display: flex;
		align-items: center;
		gap: 10px;
		margin-bottom: 12px;
		flex-shrink: 0;
	}

	.ext-alerts-count {
		font-size: 11px;
		color: var(--gm-text-muted);
		flex: 1;
	}

	.clear-btn {
		padding: 4px 10px;
		background: transparent;
		border: 1px solid var(--gm-border);
		border-radius: 4px;
		color: var(--gm-text-muted);
		font-family: inherit;
		font-size: 11px;
		cursor: pointer;
	}

	.clear-btn:hover {
		border-color: #ef4444;
		color: #ef4444;
	}

	.alert-list {
		display: flex;
		flex-direction: column;
		gap: 8px;
	}

	.alert-row {
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-left: 3px solid var(--gm-border);
		border-radius: 6px;
		padding: 10px 14px;
		display: flex;
		flex-direction: column;
		gap: 6px;
	}

	.alert-row.sev-high     { border-left-color: var(--gm-severity-high); }
	.alert-row.sev-medium   { border-left-color: var(--gm-severity-medium); }
	.alert-row.sev-low      { border-left-color: var(--gm-severity-low); }

	.alert-row-header {
		display: flex;
		align-items: center;
		gap: 8px;
		flex-wrap: wrap;
	}

	.alert-sev {
		font-size: 9px;
		font-weight: 700;
		padding: 2px 6px;
		border-radius: 3px;
		flex-shrink: 0;
	}

	.source-badge {
		font-size: 9px;
		padding: 2px 6px;
		border-radius: 3px;
		background: rgba(99, 102, 241, 0.2);
		color: #a5b4fc;
		font-weight: 600;
		flex-shrink: 0;
	}

	.alert-sig {
		font-size: 11px;
		color: var(--gm-text-primary);
		font-weight: 500;
		flex: 1;
	}

	.alert-ts {
		font-size: 10px;
		color: var(--gm-text-muted);
		font-family: 'JetBrains Mono', monospace;
		flex-shrink: 0;
	}

	.alert-flow {
		display: flex;
		align-items: center;
		gap: 8px;
		font-size: 11px;
		font-family: 'JetBrains Mono', monospace;
		color: var(--gm-text-secondary);
		flex-wrap: wrap;
	}

	.flow-arrow {
		color: var(--gm-text-muted);
	}

	.flow-name {
		color: var(--gm-text-muted);
		font-size: 10px;
	}

	.flow-dtype {
		color: var(--gm-text-muted);
		font-size: 10px;
	}

	.alert-meta {
		display: flex;
		gap: 12px;
		font-size: 10px;
	}

	.alert-cat {
		color: var(--gm-text-muted);
		text-transform: lowercase;
	}

	.alert-purdue {
		color: var(--gm-purdue-l3);
		font-weight: 600;
	}

	/* ── Malware Signatures ─────────────────────────── */

	.malware-name {
		font-weight: 700;
		font-size: 12px;
		color: var(--gm-text-primary);
	}

	.malware-pattern {
		font-size: 11px;
		color: var(--gm-text-secondary);
		margin: 2px 0 4px 0;
		font-style: italic;
	}

	.malware-confidence {
		font-size: 10px;
		padding: 1px 6px;
		border-radius: 4px;
		text-transform: uppercase;
		font-weight: 600;
	}

	.conf-high    { background: rgba(239,68,68,0.15); color: #ef4444; }
	.conf-medium  { background: rgba(245,158,11,0.15); color: #f59e0b; }
	.conf-low     { background: rgba(100,116,139,0.15); color: #64748b; }

	.tab-badge-critical {
		background: var(--gm-severity-critical) !important;
	}

	.empty-sub {
		font-size: 10px;
		color: var(--gm-text-muted);
		margin-top: 4px;
	}

	/* ── Compliance Framework Mapping ───────────────── */

	.compliance-header {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 8px 0;
		flex-wrap: wrap;
	}

	.framework-select {
		background: var(--gm-bg-secondary);
		border: 1px solid var(--gm-border);
		color: var(--gm-text-primary);
		border-radius: 4px;
		padding: 4px 8px;
		font-size: 12px;
		cursor: pointer;
	}

	.compliance-summary {
		display: flex;
		gap: 16px;
		padding: 8px 0;
		font-size: 12px;
		font-weight: 600;
		flex-wrap: wrap;
	}

	.cs-gap     { color: #ef4444; }
	.cs-partial { color: #f59e0b; }
	.cs-met     { color: #10b981; }
	.cs-na      { color: var(--gm-text-muted); }

	.compliance-list {
		display: flex;
		flex-direction: column;
		gap: 6px;
		overflow-y: auto;
		padding-bottom: 8px;
	}

	.compliance-row {
		padding: 10px 12px;
		border-radius: 6px;
		border-left: 3px solid transparent;
		background: var(--gm-bg-secondary);
	}

	.cs-row-gap         { border-left-color: #ef4444; }
	.cs-row-partial     { border-left-color: #f59e0b; }
	.cs-row-met         { border-left-color: #10b981; }
	.cs-row-not_assessed { border-left-color: var(--gm-border); }

	.compliance-req-header {
		display: flex;
		align-items: center;
		gap: 8px;
		margin-bottom: 4px;
		flex-wrap: wrap;
	}

	.req-id {
		font-family: monospace;
		font-size: 11px;
		background: var(--gm-bg-tertiary);
		padding: 1px 6px;
		border-radius: 4px;
		white-space: nowrap;
		color: var(--gm-text-muted);
	}

	.req-name {
		font-weight: 600;
		font-size: 12px;
		flex: 1;
	}

	.status-badge {
		display: inline-block;
		padding: 1px 8px;
		border-radius: 4px;
		font-size: 10px;
		font-weight: 700;
		letter-spacing: 0.05em;
		text-transform: uppercase;
		white-space: nowrap;
	}

	.status-gap     { background: rgba(239,68,68,0.15); color: #ef4444; }
	.status-partial { background: rgba(245,158,11,0.15); color: #f59e0b; }
	.status-met     { background: rgba(16,185,129,0.15); color: #10b981; }
	.status-na      { background: rgba(100,116,139,0.15); color: #64748b; }

	.compliance-evidence {
		font-size: 11px;
		color: var(--gm-text-secondary);
		line-height: 1.5;
	}
</style>
