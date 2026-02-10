<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { signatureSummary } from '$lib/stores';
	import { getSignatures, reloadSignatures, testSignature } from '$lib/utils/tauri';
	import type { SignatureTestResult } from '$lib/types';

	// CodeMirror loaded dynamically (heavy dependency)
	let editorContainer: HTMLDivElement;
	let editorView: any = null;

	// UI state
	let testResult = $state<SignatureTestResult | null>(null);
	let testError = $state<string | null>(null);
	let testing = $state(false);
	let reloading = $state(false);
	let selectedSignature = $state<string | null>(null);

	const defaultYaml = `name: "my_custom_signature"
description: "Description of what this signature matches"
vendor: "Vendor Name"
product_family: "Product Family"
protocol: modbus
filters:
  - field: tcp.dst_port
    value: 502
  - field: payload
    pattern: "\\\\x00\\\\x00"
confidence: 4
role: slave
device_type: plc
payloads: []
`;

	async function initEditor() {
		const { EditorView, basicSetup } = await import('codemirror');
		const { EditorState } = await import('@codemirror/state');
		const { yaml } = await import('@codemirror/lang-yaml');
		const { oneDark } = await import('@codemirror/theme-one-dark');

		const state = EditorState.create({
			doc: defaultYaml,
			extensions: [basicSetup, yaml(), oneDark, EditorView.lineWrapping]
		});

		editorView = new EditorView({
			state,
			parent: editorContainer
		});
	}

	function getEditorContent(): string {
		if (!editorView) return '';
		return editorView.state.doc.toString();
	}

	function setEditorContent(content: string) {
		if (!editorView) return;
		const { EditorState } = editorView.state.constructor;
		editorView.dispatch({
			changes: {
				from: 0,
				to: editorView.state.doc.length,
				insert: content
			}
		});
	}

	async function handleTest() {
		testing = true;
		testError = null;
		testResult = null;

		try {
			const yaml = getEditorContent();
			if (!yaml.trim()) {
				testError = 'Editor is empty';
				return;
			}
			testResult = await testSignature(yaml);
		} catch (err: any) {
			testError = err.toString();
		} finally {
			testing = false;
		}
	}

	async function handleReload() {
		reloading = true;
		try {
			const count = await reloadSignatures();
			const summary = await getSignatures();
			signatureSummary.set(summary);
			testError = null;
			testResult = null;
		} catch (err: any) {
			testError = `Reload failed: ${err}`;
		} finally {
			reloading = false;
		}
	}

	async function loadSignatures() {
		try {
			const summary = await getSignatures();
			signatureSummary.set(summary);
		} catch (err) {
			console.warn('Failed to load signatures:', err);
		}
	}

	function selectSignature(name: string) {
		selectedSignature = name;
		const sig = $signatureSummary.signatures.find((s) => s.name === name);
		if (sig) {
			// Build a YAML representation from the signature info
			const yamlStr = `name: "${sig.name}"
description: "${sig.description}"
${sig.vendor ? `vendor: "${sig.vendor}"` : '# vendor: null'}
${sig.product_family ? `product_family: "${sig.product_family}"` : '# product_family: null'}
${sig.protocol ? `protocol: ${sig.protocol}` : '# protocol: null'}
confidence: ${sig.confidence}
${sig.role ? `role: ${sig.role}` : '# role: null'}
${sig.device_type ? `device_type: ${sig.device_type}` : '# device_type: null'}
filters: []
payloads: []
`;
			setEditorContent(yamlStr);
		}
	}

	const confidenceColors: Record<number, string> = {
		5: '#10b981',
		4: '#3b82f6',
		3: '#f59e0b',
		2: '#f97316',
		1: '#ef4444'
	};

	onMount(async () => {
		await initEditor();
		await loadSignatures();
	});

	onDestroy(() => {
		editorView?.destroy();
	});
</script>

<div class="sig-editor-container">
	<!-- Toolbar -->
	<div class="sig-toolbar">
		<h2 class="view-title">Signature Editor</h2>
		<div class="toolbar-controls">
			<span class="sig-count">{$signatureSummary.total_count} signatures loaded</span>
			<button class="tool-btn" onclick={handleReload} disabled={reloading}>
				{reloading ? 'Reloading...' : 'Reload'}
			</button>
			<button class="tool-btn test-btn" onclick={handleTest} disabled={testing}>
				{testing ? 'Testing...' : 'Test Signature'}
			</button>
		</div>
	</div>

	<div class="sig-content">
		<!-- Signature List (left panel) -->
		<div class="sig-list-panel">
			<div class="sig-list-header">Loaded Signatures</div>
			<div class="sig-list">
				{#each $signatureSummary.signatures as sig}
					<button
						class="sig-list-item"
						class:active={selectedSignature === sig.name}
						onclick={() => selectSignature(sig.name)}
					>
						<div class="sig-item-name">{sig.name}</div>
						<div class="sig-item-meta">
							<span
								class="confidence-dot"
								style="background: {confidenceColors[sig.confidence] ?? '#64748b'}"
								title="Confidence: {sig.confidence}"
							></span>
							{#if sig.vendor}
								<span class="sig-item-vendor">{sig.vendor}</span>
							{/if}
							{#if sig.protocol}
								<span class="sig-item-proto">{sig.protocol}</span>
							{/if}
						</div>
					</button>
				{/each}
				{#if $signatureSummary.signatures.length === 0}
					<div class="sig-list-empty">No signatures loaded</div>
				{/if}
			</div>
		</div>

		<!-- Editor + Results (right panel) -->
		<div class="sig-editor-panel">
			<div class="editor-wrapper" bind:this={editorContainer}></div>

			<!-- Test Results -->
			{#if testError}
				<div class="test-results error">
					<div class="result-header">Error</div>
					<p>{testError}</p>
				</div>
			{/if}

			{#if testResult}
				<div class="test-results" class:success={testResult.match_count > 0}>
					<div class="result-header">
						Test Results: {testResult.match_count} match{testResult.match_count !== 1 ? 'es' : ''}
					</div>
					{#if testResult.matches.length > 0}
						<table class="result-table">
							<thead>
								<tr>
									<th>#</th>
									<th>Source</th>
									<th>Destination</th>
									<th>Confidence</th>
								</tr>
							</thead>
							<tbody>
								{#each testResult.matches.slice(0, 50) as m}
									<tr>
										<td>{m.packet_index}</td>
										<td>{m.src_ip}:{m.src_port}</td>
										<td>{m.dst_ip}:{m.dst_port}</td>
										<td>
											<span
												class="confidence-badge"
												style="color: {confidenceColors[m.confidence] ?? '#64748b'};
												       background: {(confidenceColors[m.confidence] ?? '#64748b')}18"
											>
												{m.confidence}/5
											</span>
										</td>
									</tr>
								{/each}
							</tbody>
						</table>
						{#if testResult.matches.length > 50}
							<p class="result-note">Showing first 50 of {testResult.matches.length} matches</p>
						{/if}
					{:else}
						<p class="result-note">No matches found against loaded PCAP data. Import a PCAP first, then test.</p>
					{/if}
				</div>
			{/if}
		</div>
	</div>
</div>

<style>
	.sig-editor-container {
		display: flex;
		flex-direction: column;
		height: 100%;
	}

	.sig-toolbar {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 10px 16px;
		border-bottom: 1px solid var(--gm-border);
		background: var(--gm-bg-secondary);
		gap: 16px;
	}

	.view-title {
		font-size: 13px;
		font-weight: 600;
		letter-spacing: 1px;
		text-transform: uppercase;
		color: var(--gm-text-primary);
		margin: 0;
		white-space: nowrap;
	}

	.toolbar-controls {
		display: flex;
		align-items: center;
		gap: 10px;
	}

	.sig-count {
		font-size: 10px;
		color: var(--gm-text-muted);
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

	.tool-btn:hover:not(:disabled) {
		background: var(--gm-bg-hover);
		color: var(--gm-text-primary);
		border-color: var(--gm-border-active);
	}

	.tool-btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.test-btn {
		background: rgba(16, 185, 129, 0.1);
		border-color: rgba(16, 185, 129, 0.3);
		color: #10b981;
	}

	.test-btn:hover:not(:disabled) {
		background: rgba(16, 185, 129, 0.2);
		border-color: rgba(16, 185, 129, 0.5);
	}

	/* ── Content Layout ────────────────────────── */

	.sig-content {
		display: flex;
		flex: 1;
		min-height: 0;
		overflow: hidden;
	}

	/* ── Signature List Panel ──────────────────── */

	.sig-list-panel {
		width: 260px;
		min-width: 200px;
		flex-shrink: 0;
		display: flex;
		flex-direction: column;
		border-right: 1px solid var(--gm-border);
		background: var(--gm-bg-secondary);
	}

	.sig-list-header {
		padding: 8px 12px;
		font-size: 10px;
		font-weight: 600;
		letter-spacing: 0.5px;
		text-transform: uppercase;
		color: var(--gm-text-muted);
		border-bottom: 1px solid var(--gm-border);
	}

	.sig-list {
		flex: 1;
		overflow-y: auto;
	}

	.sig-list-item {
		display: block;
		width: 100%;
		padding: 8px 12px;
		background: none;
		border: none;
		border-bottom: 1px solid rgba(45, 58, 79, 0.3);
		text-align: left;
		cursor: pointer;
		transition: background 0.1s;
	}

	.sig-list-item:hover {
		background: var(--gm-bg-hover);
	}

	.sig-list-item.active {
		background: rgba(59, 130, 246, 0.1);
		border-left: 2px solid #3b82f6;
	}

	.sig-item-name {
		font-size: 11px;
		font-weight: 500;
		color: var(--gm-text-primary);
		margin-bottom: 3px;
		font-family: inherit;
	}

	.sig-item-meta {
		display: flex;
		align-items: center;
		gap: 6px;
		font-size: 9px;
		color: var(--gm-text-muted);
	}

	.confidence-dot {
		width: 6px;
		height: 6px;
		border-radius: 50%;
		flex-shrink: 0;
	}

	.sig-item-vendor {
		color: var(--gm-text-secondary);
	}

	.sig-item-proto {
		background: rgba(100, 116, 139, 0.15);
		padding: 1px 5px;
		border-radius: 2px;
	}

	.sig-list-empty {
		padding: 20px 12px;
		text-align: center;
		color: var(--gm-text-muted);
		font-size: 11px;
	}

	/* ── Editor Panel ──────────────────────────── */

	.sig-editor-panel {
		flex: 1;
		display: flex;
		flex-direction: column;
		min-width: 0;
		overflow: hidden;
	}

	.editor-wrapper {
		flex: 1;
		min-height: 200px;
		overflow: auto;
	}

	/* Style CodeMirror to fit the panel */
	.editor-wrapper :global(.cm-editor) {
		height: 100%;
		font-size: 12px;
	}

	.editor-wrapper :global(.cm-scroller) {
		overflow: auto;
	}

	/* ── Test Results ──────────────────────────── */

	.test-results {
		border-top: 1px solid var(--gm-border);
		padding: 10px 16px;
		max-height: 250px;
		overflow-y: auto;
		background: var(--gm-bg-secondary);
	}

	.test-results.error {
		border-top-color: #ef4444;
	}

	.test-results.success {
		border-top-color: #10b981;
	}

	.result-header {
		font-size: 11px;
		font-weight: 600;
		color: var(--gm-text-primary);
		margin-bottom: 8px;
	}

	.test-results.error .result-header {
		color: #ef4444;
	}

	.test-results.success .result-header {
		color: #10b981;
	}

	.test-results p {
		font-size: 11px;
		color: var(--gm-text-secondary);
		margin: 4px 0;
	}

	.result-table {
		width: 100%;
		border-collapse: collapse;
		font-size: 10px;
	}

	.result-table th {
		text-align: left;
		padding: 4px 8px;
		color: var(--gm-text-muted);
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.3px;
		border-bottom: 1px solid var(--gm-border);
	}

	.result-table td {
		padding: 4px 8px;
		color: var(--gm-text-secondary);
		border-bottom: 1px solid rgba(45, 58, 79, 0.3);
	}

	.confidence-badge {
		font-size: 9px;
		font-weight: 600;
		padding: 1px 6px;
		border-radius: 3px;
	}

	.result-note {
		font-style: italic;
		font-size: 10px !important;
		color: var(--gm-text-muted) !important;
	}
</style>
