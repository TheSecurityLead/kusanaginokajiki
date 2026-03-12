<script lang="ts">
	import { assetCount, connectionCount } from '$lib/stores';
	import type { ReportConfig, Finding, AllowlistEntry } from '$lib/types';
	import {
		exportAssetsCsv,
		exportConnectionsCsv,
		exportTopologyJson,
		exportAssetsJson,
		generatePdfReport,
		exportSbom,
		exportStixBundle,
		saveTopologyImage,
		getFindings,
		generateCommunicationAllowlist,
		exportAllowlistCsv,
		exportFirewallRules
	} from '$lib/utils/tauri';

	// ─── PDF Report Config ───────────────────────────────
	let assessorName = $state('');
	let clientName = $state('');
	let assessmentDate = $state(new Date().toISOString().slice(0, 10));
	let reportTitle = $state('');
	let includeExecSummary = $state(true);
	let includeAssetInventory = $state(true);
	let includeProtocolAnalysis = $state(true);
	let includeFindings = $state(true);
	let includeRecommendations = $state(true);

	// ─── SBOM format ────────────────────────────────────
	let sbomFormat = $state<'csv' | 'json'>('json');

	// ─── Status/feedback ────────────────────────────────
	let statusMessage = $state('');
	let statusType = $state<'success' | 'error' | 'info'>('info');
	let busyAction = $state<string | null>(null);

	function showStatus(msg: string, type: 'success' | 'error' | 'info' = 'info') {
		statusMessage = msg;
		statusType = type;
		if (type !== 'error') {
			setTimeout(() => { statusMessage = ''; }, 6000);
		}
	}

	async function saveDialog(title: string, defaultName: string, filterName: string, extensions: string[]): Promise<string | null> {
		const { save } = await import('@tauri-apps/plugin-dialog');
		return save({
			title,
			defaultPath: defaultName,
			filters: [
				{ name: filterName, extensions },
				{ name: 'All Files', extensions: ['*'] }
			]
		});
	}

	// ─── Export handlers ────────────────────────────────

	async function handleExportAssetsCsv() {
		try {
			busyAction = 'assets_csv';
			const path = await saveDialog('Export Assets CSV', 'assets.csv', 'CSV Files', ['csv']);
			if (!path) { busyAction = null; return; }
			const result = await exportAssetsCsv(path);
			showStatus(result, 'success');
		} catch (err) {
			showStatus(`CSV export failed: ${err}`, 'error');
		} finally {
			busyAction = null;
		}
	}

	async function handleExportConnectionsCsv() {
		try {
			busyAction = 'conn_csv';
			const path = await saveDialog('Export Connections CSV', 'connections.csv', 'CSV Files', ['csv']);
			if (!path) { busyAction = null; return; }
			const result = await exportConnectionsCsv(path);
			showStatus(result, 'success');
		} catch (err) {
			showStatus(`CSV export failed: ${err}`, 'error');
		} finally {
			busyAction = null;
		}
	}

	async function handleExportTopologyJson() {
		try {
			busyAction = 'topo_json';
			const path = await saveDialog('Export Topology JSON', 'topology.json', 'JSON Files', ['json']);
			if (!path) { busyAction = null; return; }
			const result = await exportTopologyJson(path);
			showStatus(result, 'success');
		} catch (err) {
			showStatus(`JSON export failed: ${err}`, 'error');
		} finally {
			busyAction = null;
		}
	}

	async function handleExportAssetsJson() {
		try {
			busyAction = 'assets_json';
			const path = await saveDialog('Export Assets JSON', 'assets.json', 'JSON Files', ['json']);
			if (!path) { busyAction = null; return; }
			const result = await exportAssetsJson(path);
			showStatus(result, 'success');
		} catch (err) {
			showStatus(`JSON export failed: ${err}`, 'error');
		} finally {
			busyAction = null;
		}
	}

	async function handleGeneratePdf() {
		if (!assessorName.trim() || !clientName.trim()) {
			showStatus('Assessor Name and Client Name are required', 'error');
			return;
		}
		try {
			busyAction = 'pdf';
			const config: ReportConfig = {
				assessor_name: assessorName.trim(),
				client_name: clientName.trim(),
				assessment_date: assessmentDate || undefined,
				title: reportTitle.trim() || undefined,
				include_executive_summary: includeExecSummary,
				include_asset_inventory: includeAssetInventory,
				include_protocol_analysis: includeProtocolAnalysis,
				include_findings: includeFindings,
				include_recommendations: includeRecommendations
			};
			const defaultName = `${clientName.trim().replace(/\s+/g, '_')}_ICS_Assessment_${assessmentDate}.pdf`;
			const path = await saveDialog('Save PDF Report', defaultName, 'PDF Files', ['pdf']);
			if (!path) { busyAction = null; return; }
			const result = await generatePdfReport(config, path);
			showStatus(result, 'success');
		} catch (err) {
			showStatus(`PDF generation failed: ${err}`, 'error');
		} finally {
			busyAction = null;
		}
	}

	async function handleExportSbom() {
		try {
			busyAction = 'sbom';
			const ext = sbomFormat === 'csv' ? 'csv' : 'json';
			const path = await saveDialog('Export SBOM', `sbom.${ext}`, `${ext.toUpperCase()} Files`, [ext]);
			if (!path) { busyAction = null; return; }
			const result = await exportSbom(sbomFormat, path);
			showStatus(result, 'success');
		} catch (err) {
			showStatus(`SBOM export failed: ${err}`, 'error');
		} finally {
			busyAction = null;
		}
	}

	async function handleExportStix() {
		try {
			busyAction = 'stix';
			const path = await saveDialog('Export STIX Bundle', 'stix_bundle.json', 'JSON Files', ['json']);
			if (!path) { busyAction = null; return; }
			const result = await exportStixBundle(path);
			showStatus(result, 'success');
		} catch (err) {
			showStatus(`STIX export failed: ${err}`, 'error');
		} finally {
			busyAction = null;
		}
	}

	async function handleExportTopologyImage(format: 'png' | 'svg') {
		try {
			busyAction = `image_${format}`;
			// Capture the Cytoscape canvas from the DOM if it exists
			const cyContainer = document.querySelector('.cy-container canvas') as HTMLCanvasElement | null;
			if (!cyContainer && format === 'png') {
				showStatus('No topology graph visible. Navigate to the Topology tab first, then return here to export.', 'error');
				busyAction = null;
				return;
			}

			let imageData: string;
			if (format === 'png' && cyContainer) {
				imageData = cyContainer.toDataURL('image/png').replace(/^data:image\/png;base64,/, '');
			} else if (format === 'svg') {
				// For SVG, try to get from Cytoscape's SVG export or use a placeholder
				const svgEl = document.querySelector('.cy-container svg');
				if (svgEl) {
					imageData = btoa(new XMLSerializer().serializeToString(svgEl));
				} else {
					showStatus('No topology graph visible. Navigate to the Topology tab first, then return here to export.', 'error');
					busyAction = null;
					return;
				}
			} else {
				showStatus('No topology graph available for export.', 'error');
				busyAction = null;
				return;
			}

			const ext = format;
			const path = await saveDialog(`Save Topology ${format.toUpperCase()}`, `topology.${ext}`, `${format.toUpperCase()} Files`, [ext]);
			if (!path) { busyAction = null; return; }
			const result = await saveTopologyImage(imageData, path);
			showStatus(result, 'success');
		} catch (err) {
			showStatus(`Image export failed: ${err}`, 'error');
		} finally {
			busyAction = null;
		}
	}

	let hasData = $derived($assetCount > 0 || $connectionCount > 0);

	// ─── Remediation Priority ────────────────────────────
	let remediationItems = $state<Array<{rank: number; severity: string; title: string; description: string; assets: string[]; remediation: string; technique: string | null}>>([]);
	let showRemediationTable = $state(false);
	let loadingRemediation = $state(false);

	function remediationFor(finding: Finding): string {
		const t = finding.technique_id ?? '';
		const title = finding.title.toLowerCase();
		if (t === 'T0855') return 'Restrict write access, implement application whitelisting per IEC 62443-3-3 SR 3.3';
		if (t === 'T0886') return 'Implement network segmentation between Purdue levels using firewalls/DMZ';
		if (t === 'T0843') return 'Enable program download protection, require authentication for S7 program transfers';
		if (t === 'T0816') return 'Restrict PLC stop commands to authorized engineering workstations only';
		if (t === 'T0836') return 'Enable firmware verification, implement change management for firmware updates';
		if (t === 'T0846') return 'Investigate and block unauthorized device from accessing OT network';
		if (t === 'T0814') return 'Restrict diagnostic commands (FC8) to authorized engineering workstations';
		if (t === 'T0856') return 'Configure authorized master list; block unsolicited DNP3 from unknown sources';
		if (t === 'T0811') return 'Block DeviceCommunicationControl from unauthorized hosts';
		if (title.includes('flat network')) return 'Implement network segmentation per IEC 62443-2-1 and NIST SP 800-82';
		if (title.includes('cleartext') || title.includes('unencrypted')) return 'Evaluate encrypted protocol alternatives: OPC UA with TLS, DNP3-SA, or TLS-wrapped tunnels';
		if (title.includes('internet') || title.includes('public ip')) return 'Remove public IP or place device behind NAT/DMZ; verify firewall rules immediately';
		return 'Review finding and apply vendor-recommended hardening guidelines';
	}

	async function loadRemediationList() {
		loadingRemediation = true;
		try {
			const findings = await getFindings();
			const sorted = [...findings].sort((a, b) => {
				const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
				return (order[a.severity] ?? 5) - (order[b.severity] ?? 5);
			});
			remediationItems = sorted.map((f, i) => ({
				rank: i + 1,
				severity: f.severity,
				title: f.title,
				description: f.description,
				assets: f.affected_assets,
				remediation: remediationFor(f),
				technique: f.technique_id ?? null,
			}));
			showRemediationTable = true;
		} catch (err) {
			showStatus(`Failed to load findings: ${err}`, 'error');
		}
		loadingRemediation = false;
	}

	async function exportRemediationCsv() {
		const header = 'Rank,Severity,Title,Affected Assets,Remediation,ATT&CK Technique';
		const rows = remediationItems.map(r =>
			`${r.rank},"${r.severity}","${r.title.replace(/"/g, '""')}","${r.assets.join('; ')}","${r.remediation.replace(/"/g, '""')}","${r.technique ?? ''}"`
		);
		const csv = [header, ...rows].join('\n');
		try {
			busyAction = 'remediation_csv';
			await navigator.clipboard.writeText(csv);
			showStatus('Remediation CSV copied to clipboard (paste into a .csv file)', 'info');
		} catch (err) {
			showStatus(`Export failed: ${err}`, 'error');
		}
		busyAction = null;
	}

	// ─── Communication Allowlist ─────────────────────────
	let allowlistEntries = $state<AllowlistEntry[]>([]);
	let showAllowlist = $state(false);
	let loadingAllowlist = $state(false);

	async function loadAllowlist() {
		loadingAllowlist = true;
		try {
			allowlistEntries = await generateCommunicationAllowlist();
			showAllowlist = true;
		} catch (err) {
			showStatus(`Failed to generate allowlist: ${err}`, 'error');
		}
		loadingAllowlist = false;
	}

	async function handleExportAllowlistCsv() {
		try {
			busyAction = 'allowlist_csv';
			const path = await saveDialog('Export Communication Allowlist', 'allowlist.csv', 'CSV Files', ['csv']);
			if (!path) { busyAction = null; return; }
			const result = await exportAllowlistCsv(path);
			showStatus(`Allowlist exported: ${result}`, 'success');
		} catch (err) {
			showStatus(`Allowlist export failed: ${err}`, 'error');
		} finally {
			busyAction = null;
		}
	}

	async function handleExportFirewallRules() {
		try {
			busyAction = 'fw_rules';
			const path = await saveDialog('Export Firewall Rules', 'firewall_rules.txt', 'Text Files', ['txt']);
			if (!path) { busyAction = null; return; }
			const result = await exportFirewallRules(path);
			showStatus(`Firewall rules exported: ${result}`, 'success');
		} catch (err) {
			showStatus(`Firewall rules export failed: ${err}`, 'error');
		} finally {
			busyAction = null;
		}
	}

	function classificationClass(c: string): string {
		if (c === 'operational') return 'cls-operational';
		if (c === 'management') return 'cls-management';
		if (c === 'monitoring') return 'cls-monitoring';
		return 'cls-it';
	}
</script>

<div class="export-container">
	<div class="export-toolbar">
		<h2 class="view-title">Export & Reporting</h2>
	</div>

	<div class="export-content">
		<!-- Status message -->
		{#if statusMessage}
			<div class="status-banner" class:success={statusType === 'success'} class:error={statusType === 'error'} class:info={statusType === 'info'}>
				<span>{statusMessage}</span>
				<button class="status-dismiss" onclick={() => statusMessage = ''}>&times;</button>
			</div>
		{/if}

		{#if !hasData}
			<div class="empty-state">
				<p>No data to export. Import PCAPs or start a live capture first.</p>
			</div>
		{/if}

		<!-- ── CSV / JSON Exports ────────────────────────── -->
		<section class="export-section">
			<h3 class="section-title">Data Exports</h3>
			<p class="section-desc">Export raw asset and connection data for external analysis.</p>

			<div class="export-grid">
				<div class="export-card">
					<div class="card-header">
						<span class="card-icon">CSV</span>
						<span class="card-label">Assets</span>
					</div>
					<p class="card-desc">{$assetCount} assets — IP, MAC, vendor, protocols, Purdue level, confidence</p>
					<button
						class="action-btn primary"
						disabled={!hasData || busyAction !== null}
						onclick={handleExportAssetsCsv}
					>
						{busyAction === 'assets_csv' ? 'Exporting...' : 'Export Assets CSV'}
					</button>
				</div>

				<div class="export-card">
					<div class="card-header">
						<span class="card-icon">CSV</span>
						<span class="card-label">Connections</span>
					</div>
					<p class="card-desc">{$connectionCount} connections — source, destination, protocol, packets, bytes</p>
					<button
						class="action-btn primary"
						disabled={!hasData || busyAction !== null}
						onclick={handleExportConnectionsCsv}
					>
						{busyAction === 'conn_csv' ? 'Exporting...' : 'Export Connections CSV'}
					</button>
				</div>

				<div class="export-card">
					<div class="card-header">
						<span class="card-icon">JSON</span>
						<span class="card-label">Topology</span>
					</div>
					<p class="card-desc">Full topology with assets, connections, protocol stats, and metadata</p>
					<button
						class="action-btn primary"
						disabled={!hasData || busyAction !== null}
						onclick={handleExportTopologyJson}
					>
						{busyAction === 'topo_json' ? 'Exporting...' : 'Export Topology JSON'}
					</button>
				</div>

				<div class="export-card">
					<div class="card-header">
						<span class="card-icon">JSON</span>
						<span class="card-label">Assets</span>
					</div>
					<p class="card-desc">Asset inventory with all fields — vendor, OUI, country, confidence</p>
					<button
						class="action-btn primary"
						disabled={!hasData || busyAction !== null}
						onclick={handleExportAssetsJson}
					>
						{busyAction === 'assets_json' ? 'Exporting...' : 'Export Assets JSON'}
					</button>
				</div>
			</div>
		</section>

		<!-- ── Topology Image Export ─────────────────────── -->
		<section class="export-section">
			<h3 class="section-title">Topology Image</h3>
			<p class="section-desc">Export the logical topology graph as an image. The topology must be visible in the Topology tab first.</p>
			<div class="btn-row">
				<button
					class="action-btn primary"
					disabled={busyAction !== null}
					onclick={() => handleExportTopologyImage('png')}
				>
					{busyAction === 'image_png' ? 'Capturing...' : 'Export as PNG'}
				</button>
				<button
					class="action-btn primary"
					disabled={busyAction !== null}
					onclick={() => handleExportTopologyImage('svg')}
				>
					{busyAction === 'image_svg' ? 'Capturing...' : 'Export as SVG'}
				</button>
			</div>
		</section>

		<!-- ── PDF Report ────────────────────────────────── -->
		<section class="export-section">
			<h3 class="section-title">PDF Assessment Report</h3>
			<p class="section-desc">Generate a professional ICS/SCADA assessment report with executive summary, asset inventory, protocol analysis, and findings.</p>

			<div class="form-grid">
				<div class="form-row">
					<label class="form-label" for="assessor">Assessor Name <span class="required">*</span></label>
					<input
						type="text"
						id="assessor"
						class="form-input"
						placeholder="e.g., Jane Smith"
						bind:value={assessorName}
					/>
				</div>
				<div class="form-row">
					<label class="form-label" for="client">Client Name <span class="required">*</span></label>
					<input
						type="text"
						id="client"
						class="form-input"
						placeholder="e.g., ACME Power Plant"
						bind:value={clientName}
					/>
				</div>
				<div class="form-row">
					<label class="form-label" for="date">Assessment Date</label>
					<input
						type="date"
						id="date"
						class="form-input"
						bind:value={assessmentDate}
					/>
				</div>
				<div class="form-row">
					<label class="form-label" for="title">Report Title</label>
					<input
						type="text"
						id="title"
						class="form-input"
						placeholder="ICS Network Assessment Report"
						bind:value={reportTitle}
					/>
				</div>
			</div>

			<div class="checkbox-group">
				<h4 class="checkbox-title">Include Sections</h4>
				<label class="checkbox-row">
					<input type="checkbox" bind:checked={includeExecSummary} />
					<span>Executive Summary</span>
				</label>
				<label class="checkbox-row">
					<input type="checkbox" bind:checked={includeAssetInventory} />
					<span>Asset Inventory</span>
				</label>
				<label class="checkbox-row">
					<input type="checkbox" bind:checked={includeProtocolAnalysis} />
					<span>Protocol Analysis</span>
				</label>
				<label class="checkbox-row">
					<input type="checkbox" bind:checked={includeFindings} />
					<span>Findings</span>
				</label>
				<label class="checkbox-row">
					<input type="checkbox" bind:checked={includeRecommendations} />
					<span>Recommendations</span>
				</label>
			</div>

			<button
				class="action-btn accent"
				disabled={!hasData || busyAction !== null}
				onclick={handleGeneratePdf}
			>
				{busyAction === 'pdf' ? 'Generating PDF...' : 'Generate PDF Report'}
			</button>
		</section>

		<!-- ── SBOM Export ────────────────────────────────── -->
		<section class="export-section">
			<h3 class="section-title">SBOM (CISA BOD 23-01)</h3>
			<p class="section-desc">Export a Software Bill of Materials listing all discovered OT/IT assets with vendor, firmware, and Purdue zone classification.</p>

			<div class="format-selector">
				<label class="radio-row">
					<input type="radio" name="sbom-format" value="json" bind:group={sbomFormat} />
					<span>JSON</span>
				</label>
				<label class="radio-row">
					<input type="radio" name="sbom-format" value="csv" bind:group={sbomFormat} />
					<span>CSV</span>
				</label>
			</div>

			<button
				class="action-btn primary"
				disabled={!hasData || busyAction !== null}
				onclick={handleExportSbom}
			>
				{busyAction === 'sbom' ? 'Exporting...' : `Export SBOM (${sbomFormat.toUpperCase()})`}
			</button>
		</section>

		<!-- ── STIX 2.1 Bundle ───────────────────────────── -->
		<section class="export-section">
			<h3 class="section-title">STIX 2.1 Bundle</h3>
			<p class="section-desc">Export a STIX 2.1 compliant bundle with Identity, Infrastructure, IPv4/MAC observables, Network-Traffic, and Relationship objects for threat intelligence sharing.</p>

			<button
				class="action-btn primary"
				disabled={!hasData || busyAction !== null}
				onclick={handleExportStix}
			>
				{busyAction === 'stix' ? 'Exporting...' : 'Export STIX 2.1 Bundle'}
			</button>
		</section>

		<!-- ── Remediation Priority List ─────────────────── -->
		<section class="export-section">
			<h3 class="section-title">Remediation Priority List</h3>
			<p class="section-desc">
				Ranked list of security findings with remediation guidance, sorted by severity.
			</p>
			<div class="btn-row">
				<button class="action-btn primary" onclick={loadRemediationList} disabled={loadingRemediation || busyAction !== null}>
					{loadingRemediation ? 'Loading...' : 'Generate List'}
				</button>
				{#if remediationItems.length > 0}
					<button class="action-btn primary" onclick={exportRemediationCsv} disabled={busyAction === 'remediation_csv'}>
						{busyAction === 'remediation_csv' ? 'Copying...' : 'Copy CSV'}
					</button>
				{/if}
			</div>

			{#if showRemediationTable && remediationItems.length > 0}
				<div class="remediation-table-wrap">
					<table class="remediation-table">
						<thead>
							<tr>
								<th class="col-rank">#</th>
								<th class="col-sev">Severity</th>
								<th class="col-title">Finding</th>
								<th class="col-assets">Assets</th>
								<th class="col-remedy">Remediation</th>
								<th class="col-tech">ATT&amp;CK</th>
							</tr>
						</thead>
						<tbody>
							{#each remediationItems as item}
								<tr class="remediation-row">
									<td class="col-rank">{item.rank}</td>
									<td>
										<span class="sev-badge sev-{item.severity}">{item.severity}</span>
									</td>
									<td class="col-title">
										<div class="finding-title">{item.title}</div>
									</td>
									<td class="col-assets">
										{#each item.assets.slice(0, 3) as ip}
											<div class="asset-ip">{ip}</div>
										{/each}
										{#if item.assets.length > 3}
											<div class="asset-more">+{item.assets.length - 3} more</div>
										{/if}
									</td>
									<td class="col-remedy">{item.remediation}</td>
									<td class="col-tech">
										{#if item.technique}
											<code class="technique-id">{item.technique}</code>
										{/if}
									</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{:else if showRemediationTable}
				<p class="no-findings">No findings available. Run analysis first.</p>
			{/if}
		</section>

		<!-- ── Communication Allowlist ───────────────────── -->
		<section class="export-section">
			<h3 class="section-title">Communication Allowlist</h3>
			<p class="section-desc">
				Every observed legitimate flow with frequency, classification, and firewall-ready export.
				Run analysis first for best classification results.
			</p>

			<div class="export-actions">
				<button class="action-btn primary" onclick={loadAllowlist} disabled={loadingAllowlist || !hasData}>
					{loadingAllowlist ? 'Generating...' : 'Generate Allowlist'}
				</button>
				{#if allowlistEntries.length > 0}
					<button class="action-btn" onclick={handleExportAllowlistCsv} disabled={busyAction === 'allowlist_csv'}>
						{busyAction === 'allowlist_csv' ? 'Exporting...' : 'Export CSV'}
					</button>
					<button class="action-btn" onclick={handleExportFirewallRules} disabled={busyAction === 'fw_rules'}>
						{busyAction === 'fw_rules' ? 'Exporting...' : 'Export Firewall Rules'}
					</button>
				{/if}
			</div>

			{#if showAllowlist && allowlistEntries.length > 0}
				<div class="allowlist-wrap">
					<div class="allowlist-summary">
						{allowlistEntries.length} flows ·
						{allowlistEntries.filter(e => e.classification === 'operational').length} operational ·
						{allowlistEntries.filter(e => e.classification === 'management').length} management ·
						{allowlistEntries.filter(e => e.classification === 'monitoring').length} monitoring ·
						{allowlistEntries.filter(e => e.classification === 'it').length} IT
					</div>
					<table class="allowlist-table">
						<thead>
							<tr>
								<th>Source</th>
								<th>Destination</th>
								<th>Protocol</th>
								<th>Port</th>
								<th>Frequency</th>
								<th>Class</th>
								<th>Justification</th>
							</tr>
						</thead>
						<tbody>
							{#each allowlistEntries as entry}
								<tr class="allowlist-row">
									<td class="col-ip">{entry.src_ip}</td>
									<td class="col-ip">{entry.dst_ip}</td>
									<td class="col-proto">{entry.protocol}</td>
									<td class="col-port">{entry.dst_port}</td>
									<td class="col-freq">{entry.frequency}</td>
									<td class="col-class">
										<span class="cls-badge {classificationClass(entry.classification)}">
											{entry.classification}
										</span>
									</td>
									<td class="col-just">{entry.justification}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{:else if showAllowlist}
				<p class="no-findings">No connections to allowlist. Import a PCAP first.</p>
			{/if}
		</section>
	</div>
</div>

<style>
	.export-container {
		display: flex;
		flex-direction: column;
		height: 100%;
	}

	.export-toolbar {
		padding: 10px 16px;
		border-bottom: 1px solid var(--gm-border);
		background: var(--gm-bg-secondary);
	}

	.view-title {
		font-size: 13px;
		font-weight: 600;
		letter-spacing: 1px;
		text-transform: uppercase;
		color: var(--gm-text-primary);
		margin: 0;
	}

	.export-content {
		flex: 1;
		overflow-y: auto;
		padding: 20px 24px;
		display: flex;
		flex-direction: column;
		gap: 20px;
		max-width: 800px;
	}

	/* ── Status Banner ──────────────────────────────── */

	.status-banner {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 10px 14px;
		border-radius: 6px;
		font-size: 11px;
		font-weight: 500;
	}

	.status-banner.success {
		background: rgba(16, 185, 129, 0.1);
		border: 1px solid rgba(16, 185, 129, 0.25);
		color: #10b981;
	}

	.status-banner.error {
		background: rgba(239, 68, 68, 0.1);
		border: 1px solid rgba(239, 68, 68, 0.25);
		color: #ef4444;
	}

	.status-banner.info {
		background: rgba(59, 130, 246, 0.1);
		border: 1px solid rgba(59, 130, 246, 0.25);
		color: #3b82f6;
	}

	.status-dismiss {
		background: none;
		border: none;
		color: inherit;
		font-size: 16px;
		cursor: pointer;
		padding: 0 4px;
		opacity: 0.7;
	}

	.status-dismiss:hover {
		opacity: 1;
	}

	/* ── Empty State ────────────────────────────────── */

	.empty-state {
		background: var(--gm-bg-secondary);
		border: 1px solid var(--gm-border);
		border-radius: 8px;
		padding: 24px;
		text-align: center;
		color: var(--gm-text-muted);
		font-size: 12px;
	}

	/* ── Section Cards ──────────────────────────────── */

	.export-section {
		background: var(--gm-bg-secondary);
		border: 1px solid var(--gm-border);
		border-radius: 8px;
		padding: 20px;
	}

	.section-title {
		font-size: 13px;
		font-weight: 600;
		color: var(--gm-text-primary);
		margin: 0 0 4px 0;
		letter-spacing: 0.5px;
	}

	.section-desc {
		font-size: 11px;
		color: var(--gm-text-muted);
		margin: 0 0 16px 0;
		line-height: 1.5;
	}

	/* ── Data Export Grid ───────────────────────────── */

	.export-grid {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 12px;
	}

	.export-card {
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 6px;
		padding: 14px;
		display: flex;
		flex-direction: column;
		gap: 8px;
	}

	.card-header {
		display: flex;
		align-items: center;
		gap: 8px;
	}

	.card-icon {
		font-size: 9px;
		font-weight: 700;
		letter-spacing: 0.5px;
		padding: 2px 6px;
		border-radius: 3px;
		background: rgba(16, 185, 129, 0.15);
		color: #10b981;
	}

	.card-label {
		font-size: 12px;
		font-weight: 600;
		color: var(--gm-text-primary);
	}

	.card-desc {
		font-size: 10px;
		color: var(--gm-text-muted);
		margin: 0;
		line-height: 1.5;
	}

	/* ── Buttons ────────────────────────────────────── */

	.action-btn {
		padding: 8px 16px;
		border-radius: 6px;
		font-family: inherit;
		font-size: 11px;
		font-weight: 600;
		cursor: pointer;
		transition: all 0.15s;
		border: 1px solid transparent;
	}

	.action-btn:disabled {
		opacity: 0.4;
		cursor: not-allowed;
	}

	.action-btn.primary {
		background: rgba(59, 130, 246, 0.1);
		border-color: rgba(59, 130, 246, 0.2);
		color: #3b82f6;
	}

	.action-btn.primary:hover:not(:disabled) {
		background: rgba(59, 130, 246, 0.2);
	}

	.action-btn.accent {
		background: rgba(16, 185, 129, 0.15);
		border-color: rgba(16, 185, 129, 0.3);
		color: #10b981;
		font-size: 12px;
		padding: 10px 20px;
	}

	.action-btn.accent:hover:not(:disabled) {
		background: rgba(16, 185, 129, 0.25);
	}

	.btn-row {
		display: flex;
		gap: 10px;
	}

	/* ── PDF Form ───────────────────────────────────── */

	.form-grid {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 12px;
		margin-bottom: 16px;
	}

	.form-row {
		display: flex;
		flex-direction: column;
		gap: 4px;
	}

	.form-label {
		font-size: 11px;
		color: var(--gm-text-secondary);
		font-weight: 500;
	}

	.required {
		color: #ef4444;
	}

	.form-input {
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 4px;
		padding: 7px 10px;
		color: var(--gm-text-primary);
		font-family: inherit;
		font-size: 11px;
		outline: none;
	}

	.form-input:focus {
		border-color: var(--gm-border-active);
	}

	/* ── Checkboxes ─────────────────────────────────── */

	.checkbox-group {
		margin-bottom: 16px;
	}

	.checkbox-title {
		font-size: 11px;
		font-weight: 600;
		color: var(--gm-text-secondary);
		margin: 0 0 8px 0;
	}

	.checkbox-row {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 4px 0;
		font-size: 11px;
		color: var(--gm-text-secondary);
		cursor: pointer;
	}

	.checkbox-row input[type="checkbox"] {
		accent-color: #10b981;
	}

	/* ── Radio / Format Selector ────────────────────── */

	.format-selector {
		display: flex;
		gap: 16px;
		margin-bottom: 12px;
	}

	.radio-row {
		display: flex;
		align-items: center;
		gap: 6px;
		font-size: 11px;
		color: var(--gm-text-secondary);
		cursor: pointer;
	}

	.radio-row input[type="radio"] {
		accent-color: #10b981;
	}

	/* ── Remediation Priority Table ─────────────────────── */

	.remediation-table-wrap {
		overflow-x: auto;
		margin-top: 16px;
	}

	.remediation-table {
		width: 100%;
		border-collapse: collapse;
		font-size: 11px;
	}

	.remediation-table th {
		text-align: left;
		padding: 8px 10px;
		background: var(--gm-bg-secondary);
		border-bottom: 2px solid var(--gm-border);
		color: var(--gm-text-muted);
		font-weight: 600;
		text-transform: uppercase;
		font-size: 10px;
		letter-spacing: 0.05em;
	}

	.remediation-table td {
		padding: 8px 10px;
		border-bottom: 1px solid var(--gm-border);
		vertical-align: top;
	}

	.remediation-row:hover td { background: var(--gm-bg-tertiary); }

	.col-rank {
		width: 40px;
		text-align: center;
		font-weight: 700;
		color: var(--gm-text-muted);
	}

	.col-sev { width: 90px; }
	.col-assets { width: 130px; }
	.col-tech { width: 100px; }

	.sev-badge {
		display: inline-block;
		padding: 2px 8px;
		border-radius: 4px;
		font-size: 10px;
		font-weight: 700;
		text-transform: uppercase;
	}

	.sev-badge.sev-critical { background: rgba(239, 68, 68, 0.13); color: #ef4444; }
	.sev-badge.sev-high { background: rgba(249, 115, 22, 0.13); color: #f97316; }
	.sev-badge.sev-medium { background: rgba(245, 158, 11, 0.13); color: #f59e0b; }
	.sev-badge.sev-low { background: rgba(16, 185, 129, 0.13); color: #10b981; }
	.sev-badge.sev-info { background: rgba(59, 130, 246, 0.13); color: #3b82f6; }

	.finding-title {
		font-weight: 500;
		color: var(--gm-text-primary);
	}

	.asset-ip {
		font-family: monospace;
		color: var(--gm-accent, #38bdf8);
		font-size: 10px;
	}

	.asset-more {
		color: var(--gm-text-muted);
		font-size: 10px;
	}

	.col-remedy {
		font-size: 11px;
		color: var(--gm-text-secondary);
	}

	.technique-id {
		font-family: monospace;
		font-size: 11px;
		background: var(--gm-bg-secondary);
		padding: 2px 6px;
		border-radius: 4px;
		color: var(--gm-accent, #38bdf8);
	}

	.no-findings {
		color: var(--gm-text-muted);
		font-size: 11px;
		margin-top: 12px;
	}

	/* ── Communication Allowlist ──────────────────────────── */
	.allowlist-wrap {
		overflow-x: auto;
		margin-top: 12px;
		border-radius: 6px;
		border: 1px solid var(--gm-border);
	}

	.allowlist-summary {
		padding: 6px 12px;
		font-size: 11px;
		color: var(--gm-text-muted);
		background: var(--gm-bg-secondary);
		border-bottom: 1px solid var(--gm-border);
	}

	.allowlist-table {
		width: 100%;
		border-collapse: collapse;
		font-size: 11px;
	}

	.allowlist-table th {
		padding: 6px 10px;
		text-align: left;
		font-weight: 600;
		color: var(--gm-text-muted);
		background: var(--gm-bg-secondary);
		border-bottom: 1px solid var(--gm-border);
		white-space: nowrap;
	}

	.allowlist-table td {
		padding: 5px 10px;
		border-bottom: 1px solid var(--gm-border-subtle, var(--gm-border));
		vertical-align: middle;
	}

	.allowlist-row:hover td { background: var(--gm-bg-tertiary); }

	.col-ip { font-family: monospace; font-size: 11px; white-space: nowrap; }
	.col-proto { white-space: nowrap; font-weight: 600; }
	.col-port { width: 55px; text-align: right; font-family: monospace; }
	.col-freq { white-space: nowrap; color: var(--gm-text-secondary); }
	.col-class { width: 110px; }
	.col-just { color: var(--gm-text-secondary); font-size: 11px; }

	.cls-badge {
		display: inline-block;
		padding: 1px 7px;
		border-radius: 4px;
		font-size: 10px;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.04em;
	}

	.cls-operational { background: rgba(16,185,129,0.15); color: #10b981; }
	.cls-management  { background: rgba(59,130,246,0.15); color: #3b82f6; }
	.cls-monitoring  { background: rgba(245,158,11,0.15); color: #f59e0b; }
	.cls-it          { background: rgba(100,116,139,0.15); color: #64748b; }
</style>
