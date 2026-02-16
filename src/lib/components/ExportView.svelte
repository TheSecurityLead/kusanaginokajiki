<script lang="ts">
	import { assetCount, connectionCount } from '$lib/stores';
	import type { ReportConfig } from '$lib/types';
	import {
		exportAssetsCsv,
		exportConnectionsCsv,
		exportTopologyJson,
		exportAssetsJson,
		generatePdfReport,
		exportSbom,
		exportStixBundle,
		saveTopologyImage
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
</style>
