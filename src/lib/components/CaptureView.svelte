<script lang="ts">
	import { interfaces, captureStatus, captureStats, assets, connections, topology } from '$lib/stores';
	import {
		importPcap, getAssets, getConnections, getTopology, getProtocolStats,
		startCapture, stopCapture, pauseCapture, resumeCapture,
		onCaptureStats, onCaptureError
	} from '$lib/utils/tauri';
	import { protocolStats } from '$lib/stores';
	import type { FileImportResult, CaptureStatsEvent } from '$lib/types';
	import { onMount, onDestroy } from 'svelte';

	// ── PCAP Import State ─────────────────────────────────
	let importStatus = $state<'idle' | 'importing' | 'done' | 'error'>('idle');
	let importMessage = $state('');
	let fileResults = $state<FileImportResult[]>([]);
	let totalStats = $state({ packets: 0, assets: 0, connections: 0, ms: 0, files: 0 });

	// ── Live Capture State ────────────────────────────────
	let selectedInterface = $state('');
	let bpfFilter = $state('');
	let captureError = $state('');
	let stopResult = $state<{ packets: number; bytes: number; elapsed: number; saved: boolean; path: string | null } | null>(null);

	// Event listener cleanup functions
	let unlistenStats: (() => void) | null = null;
	let unlistenError: (() => void) | null = null;
	let refreshInterval: ReturnType<typeof setInterval> | null = null;

	onMount(() => {
		// Set up event listeners for live capture
		setupEventListeners();
	});

	onDestroy(() => {
		cleanupListeners();
	});

	async function setupEventListeners() {
		unlistenStats = await onCaptureStats((stats: CaptureStatsEvent) => {
			captureStats.set(stats);
		});

		unlistenError = await onCaptureError((error: string) => {
			captureError = error;
			captureStatus.set('error');
			cleanupRefreshInterval();
		});
	}

	function cleanupListeners() {
		unlistenStats?.();
		unlistenError?.();
		cleanupRefreshInterval();
	}

	function cleanupRefreshInterval() {
		if (refreshInterval) {
			clearInterval(refreshInterval);
			refreshInterval = null;
		}
	}

	// Start a periodic data refresh while capturing (every 500ms)
	function startDataRefresh() {
		cleanupRefreshInterval();
		refreshInterval = setInterval(async () => {
			try {
				const [newAssets, newConnections, newTopology, newStats] = await Promise.all([
					getAssets(),
					getConnections(),
					getTopology(),
					getProtocolStats()
				]);
				assets.set(newAssets);
				connections.set(newConnections);
				topology.set(newTopology);
				protocolStats.set(newStats);
			} catch (err) {
				console.error('Data refresh error:', err);
			}
		}, 500);
	}

	// ── PCAP Import ──────────────────────────────────────
	async function handleImportPcap() {
		try {
			const { open } = await import('@tauri-apps/plugin-dialog');
			const selected = await open({
				title: 'Import PCAP Files',
				multiple: true,
				filters: [
					{ name: 'PCAP Files', extensions: ['pcap', 'pcapng', 'cap'] },
					{ name: 'All Files', extensions: ['*'] }
				]
			});

			if (!selected || selected.length === 0) return;
			const paths: string[] = selected;
			if (paths.length === 0) return;

			importStatus = 'importing';
			const fileCount = paths.length;
			importMessage = `Importing ${fileCount} file${fileCount > 1 ? 's' : ''}...`;
			fileResults = [];

			const result = await importPcap(paths);

			importStatus = 'done';
			fileResults = result.per_file;
			totalStats = {
				packets: result.packet_count,
				assets: result.asset_count,
				connections: result.connection_count,
				ms: result.duration_ms,
				files: result.file_count
			};
			importMessage = `Imported ${result.packet_count.toLocaleString()} packets from ${result.file_count} file${result.file_count > 1 ? 's' : ''} → ${result.asset_count} assets, ${result.connection_count} connections (${result.duration_ms}ms)`;

			const [newAssets, newConnections, newTopology, newStats] = await Promise.all([
				getAssets(),
				getConnections(),
				getTopology(),
				getProtocolStats()
			]);

			assets.set(newAssets);
			connections.set(newConnections);
			topology.set(newTopology);
			protocolStats.set(newStats);
		} catch (err) {
			importStatus = 'error';
			importMessage = `Import failed: ${err}`;
			console.error('PCAP import error:', err);
		}
	}

	// ── Live Capture Controls ─────────────────────────────
	async function handleStartCapture() {
		if (!selectedInterface) return;
		captureError = '';
		stopResult = null;

		try {
			const filter = bpfFilter.trim() || undefined;
			await startCapture(selectedInterface, filter);
			captureStatus.set('capturing');
			captureStats.set({
				packets_captured: 0,
				packets_per_second: 0,
				bytes_captured: 0,
				active_connections: 0,
				asset_count: 0,
				elapsed_seconds: 0
			});
			startDataRefresh();
		} catch (err) {
			captureError = `${err}`;
			captureStatus.set('error');
		}
	}

	async function handleStopCapture() {
		try {
			// Show save dialog
			const { save } = await import('@tauri-apps/plugin-dialog');
			const savePath = await save({
				title: 'Save Capture as PCAP',
				defaultPath: `capture_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.pcap`,
				filters: [
					{ name: 'PCAP Files', extensions: ['pcap'] },
					{ name: 'All Files', extensions: ['*'] }
				]
			});

			const result = await stopCapture(savePath ?? undefined);
			captureStatus.set('idle');
			cleanupRefreshInterval();
			stopResult = {
				packets: Number(result.packets_captured),
				bytes: Number(result.bytes_captured),
				elapsed: result.elapsed_seconds,
				saved: result.pcap_saved,
				path: result.pcap_path
			};

			// Do one final data refresh
			const [newAssets, newConnections, newTopology, newStats] = await Promise.all([
				getAssets(),
				getConnections(),
				getTopology(),
				getProtocolStats()
			]);
			assets.set(newAssets);
			connections.set(newConnections);
			topology.set(newTopology);
			protocolStats.set(newStats);
		} catch (err) {
			captureError = `Stop failed: ${err}`;
		}
	}

	async function handlePauseResume() {
		try {
			if ($captureStatus === 'paused') {
				await resumeCapture();
				captureStatus.set('capturing');
				startDataRefresh();
			} else {
				await pauseCapture();
				captureStatus.set('paused');
				cleanupRefreshInterval();
			}
		} catch (err) {
			captureError = `${err}`;
		}
	}

	function formatBytes(bytes: number): string {
		if (bytes < 1024) return `${bytes} B`;
		if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
		if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
		return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
	}

	function formatDuration(seconds: number): string {
		const h = Math.floor(seconds / 3600);
		const m = Math.floor((seconds % 3600) / 60);
		const s = Math.floor(seconds % 60);
		if (h > 0) return `${h}h ${m}m ${s}s`;
		if (m > 0) return `${m}m ${s}s`;
		return `${s}s`;
	}

	const isCapturing = $derived($captureStatus === 'capturing' || $captureStatus === 'paused');
</script>

<div class="capture-container">
	<div class="capture-toolbar">
		<h2 class="view-title">Capture & Import</h2>
	</div>

	<div class="capture-content">
		<!-- PCAP Import Section -->
		<section class="capture-section">
			<h3 class="section-title">PCAP Import</h3>
			<p class="section-desc">
				Import one or more PCAP/PCAPNG files captured from an OT network. Multiple files can be
				selected simultaneously — all traffic is merged into a single topology with per-file attribution.
			</p>

			<button class="action-btn primary" onclick={handleImportPcap} disabled={importStatus === 'importing' || isCapturing}>
				{importStatus === 'importing' ? 'Importing...' : 'Import PCAP Files'}
			</button>

			{#if importMessage}
				<div
					class="import-result"
					class:success={importStatus === 'done'}
					class:error={importStatus === 'error'}
					class:loading={importStatus === 'importing'}
				>
					{importMessage}
				</div>
			{/if}

			{#if fileResults.length > 1}
				<div class="file-results">
					<h4 class="subsection-title">Per-File Results</h4>
					{#each fileResults as file}
						<div class="file-result-row" class:file-ok={file.status === 'ok'} class:file-err={file.status !== 'ok'}>
							<span class="file-name">{file.filename}</span>
							<span class="file-packets">
								{#if file.status === 'ok'}
									{file.packet_count.toLocaleString()} packets
								{:else}
									{file.status}
								{/if}
							</span>
						</div>
					{/each}
				</div>
			{/if}

			{#if importStatus === 'done'}
				<div class="import-stats-grid">
					<div class="import-stat">
						<span class="import-stat-value">{totalStats.files}</span>
						<span class="import-stat-label">Files</span>
					</div>
					<div class="import-stat">
						<span class="import-stat-value">{totalStats.packets.toLocaleString()}</span>
						<span class="import-stat-label">Packets</span>
					</div>
					<div class="import-stat">
						<span class="import-stat-value">{totalStats.assets}</span>
						<span class="import-stat-label">Assets</span>
					</div>
					<div class="import-stat">
						<span class="import-stat-value">{totalStats.connections}</span>
						<span class="import-stat-label">Connections</span>
					</div>
				</div>
			{/if}
		</section>

		<!-- Live Capture Section -->
		<section class="capture-section">
			<h3 class="section-title">Live Capture</h3>
			<p class="section-desc">
				Capture packets in real-time from a network interface. Requires elevated privileges
				(root/admin or CAP_NET_RAW capability). Operates in passive mode only — never transmits.
			</p>

			{#if !isCapturing}
				<!-- Interface Selector -->
				<div class="capture-form">
					<div class="form-group">
						<label class="form-label" for="interface-select">Interface</label>
						<select
							id="interface-select"
							class="form-select"
							bind:value={selectedInterface}
							disabled={isCapturing}
						>
							<option value="">Select interface...</option>
							{#each $interfaces as iface}
								<option value={iface.name}>
									{iface.name}
									{#if iface.description}— {iface.description}{/if}
									{#if iface.addresses.length > 0}({iface.addresses[0].addr}){/if}
								</option>
							{/each}
						</select>
					</div>

					<div class="form-group">
						<label class="form-label" for="bpf-filter">BPF Filter (optional)</label>
						<input
							id="bpf-filter"
							class="form-input"
							type="text"
							placeholder="e.g., tcp port 502 or host 192.168.1.0/24"
							bind:value={bpfFilter}
							disabled={isCapturing}
						/>
					</div>

					<button
						class="action-btn capture-start"
						onclick={handleStartCapture}
						disabled={!selectedInterface || isCapturing}
					>
						Start Capture
					</button>
				</div>
			{/if}

			{#if isCapturing}
				<!-- Capture Controls -->
				<div class="capture-controls">
					<div class="capture-status-bar">
						<span class="capture-indicator" class:paused={$captureStatus === 'paused'}>
							{$captureStatus === 'paused' ? 'PAUSED' : 'CAPTURING'}
						</span>
						<span class="capture-interface">{selectedInterface}</span>
						{#if bpfFilter}
							<span class="capture-filter">filter: {bpfFilter}</span>
						{/if}
					</div>

					<div class="capture-buttons">
						<button class="action-btn capture-pause" onclick={handlePauseResume}>
							{$captureStatus === 'paused' ? 'Resume' : 'Pause'}
						</button>
						<button class="action-btn capture-stop" onclick={handleStopCapture}>
							Stop & Save
						</button>
					</div>
				</div>

				<!-- Live Stats -->
				<div class="stats-grid">
					<div class="stat-card">
						<span class="stat-value">{$captureStats.packets_captured.toLocaleString()}</span>
						<span class="stat-label">Packets</span>
					</div>
					<div class="stat-card">
						<span class="stat-value">{$captureStats.packets_per_second.toLocaleString()}</span>
						<span class="stat-label">PPS</span>
					</div>
					<div class="stat-card">
						<span class="stat-value">{formatBytes($captureStats.bytes_captured)}</span>
						<span class="stat-label">Data</span>
					</div>
					<div class="stat-card">
						<span class="stat-value">{$captureStats.active_connections}</span>
						<span class="stat-label">Connections</span>
					</div>
					<div class="stat-card">
						<span class="stat-value">{$captureStats.asset_count}</span>
						<span class="stat-label">Assets</span>
					</div>
					<div class="stat-card">
						<span class="stat-value">{formatDuration($captureStats.elapsed_seconds)}</span>
						<span class="stat-label">Elapsed</span>
					</div>
				</div>
			{/if}

			<!-- Error Display -->
			{#if captureError}
				<div class="capture-error">
					<strong>Error:</strong>
					<pre class="error-detail">{captureError}</pre>
				</div>
			{/if}

			<!-- Stop Result -->
			{#if stopResult}
				<div class="stop-result">
					<div class="stop-summary">
						Captured {stopResult.packets.toLocaleString()} packets
						({formatBytes(stopResult.bytes)}) in {formatDuration(stopResult.elapsed)}
					</div>
					{#if stopResult.saved}
						<div class="stop-saved">Saved to: {stopResult.path}</div>
					{/if}
				</div>
			{/if}

			<!-- Interface List (when not capturing) -->
			{#if !isCapturing && $interfaces.length > 0}
				<div class="interface-list">
					<h4 class="subsection-title">Available Interfaces</h4>
					{#each $interfaces as iface}
						<div
							class="interface-card"
							class:up={iface.flags.is_up}
							class:loopback={iface.flags.is_loopback}
							class:selected={selectedInterface === iface.name}
							onclick={() => { selectedInterface = iface.name; }}
							role="button"
							tabindex="0"
							onkeydown={(e) => { if (e.key === 'Enter') selectedInterface = iface.name; }}
						>
							<div class="iface-name">{iface.name}</div>
							{#if iface.description}
								<div class="iface-desc">{iface.description}</div>
							{/if}
							<div class="iface-addrs">
								{#each iface.addresses as addr}
									<span class="iface-addr">{addr.addr}</span>
								{/each}
							</div>
							<div class="iface-flags">
								{#if iface.flags.is_up}<span class="flag up">UP</span>{/if}
								{#if iface.flags.is_loopback}<span class="flag lo">LOOPBACK</span>{/if}
								{#if iface.flags.is_running}<span class="flag run">RUNNING</span>{/if}
							</div>
						</div>
					{/each}
				</div>
			{:else if !isCapturing}
				<div class="interface-list">
					<h4 class="subsection-title">Available Interfaces</h4>
					<div class="no-interfaces">
						No interfaces detected. This is expected during development in the browser.
						Interfaces will appear when running as a Tauri desktop app.
					</div>
				</div>
			{/if}
		</section>
	</div>
</div>

<style>
	.capture-container {
		display: flex;
		flex-direction: column;
		height: 100%;
	}

	.capture-toolbar {
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

	.capture-content {
		flex: 1;
		overflow-y: auto;
		padding: 20px 24px;
		display: flex;
		flex-direction: column;
		gap: 28px;
	}

	.capture-section {
		background: var(--gm-bg-secondary);
		border: 1px solid var(--gm-border);
		border-radius: 8px;
		padding: 20px;
	}

	.section-title {
		font-size: 13px;
		font-weight: 600;
		color: var(--gm-text-primary);
		margin: 0 0 8px 0;
		letter-spacing: 0.5px;
	}

	.section-desc {
		font-size: 11px;
		color: var(--gm-text-muted);
		margin: 0 0 16px 0;
		line-height: 1.6;
	}

	.action-btn {
		padding: 10px 20px;
		border: 1px solid var(--gm-border);
		border-radius: 6px;
		font-family: inherit;
		font-size: 12px;
		font-weight: 600;
		cursor: pointer;
		transition: all 0.15s;
	}

	.action-btn.primary {
		background: rgba(16, 185, 129, 0.15);
		border-color: rgba(16, 185, 129, 0.3);
		color: #10b981;
	}

	.action-btn.primary:hover:not(:disabled) {
		background: rgba(16, 185, 129, 0.25);
		border-color: #10b981;
	}

	.action-btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.import-result {
		margin-top: 12px;
		padding: 10px 14px;
		border-radius: 6px;
		font-size: 11px;
		line-height: 1.5;
	}

	.import-result.success {
		background: rgba(16, 185, 129, 0.1);
		border: 1px solid rgba(16, 185, 129, 0.2);
		color: #10b981;
	}

	.import-result.error {
		background: rgba(239, 68, 68, 0.1);
		border: 1px solid rgba(239, 68, 68, 0.2);
		color: #ef4444;
	}

	.import-result.loading {
		background: rgba(59, 130, 246, 0.1);
		border: 1px solid rgba(59, 130, 246, 0.2);
		color: #3b82f6;
	}

	/* ── Per-file results ──────────────────────────── */

	.file-results {
		margin-top: 16px;
	}

	.file-result-row {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 6px 10px;
		font-size: 11px;
		border-radius: 4px;
		margin-bottom: 3px;
	}

	.file-result-row.file-ok {
		background: rgba(16, 185, 129, 0.05);
		color: var(--gm-text-secondary);
	}

	.file-result-row.file-err {
		background: rgba(239, 68, 68, 0.05);
		color: #ef4444;
	}

	.file-name {
		font-weight: 500;
	}

	.file-packets {
		font-variant-numeric: tabular-nums;
		color: var(--gm-text-muted);
	}

	/* ── Import stats ──────────────────────────────── */

	.import-stats-grid {
		display: grid;
		grid-template-columns: repeat(4, 1fr);
		gap: 10px;
		margin-top: 16px;
	}

	.import-stat {
		display: flex;
		flex-direction: column;
		align-items: center;
		padding: 10px;
		background: var(--gm-bg-panel);
		border-radius: 6px;
	}

	.import-stat-value {
		font-size: 16px;
		font-weight: 700;
		color: #10b981;
		font-variant-numeric: tabular-nums;
	}

	.import-stat-label {
		font-size: 9px;
		color: var(--gm-text-muted);
		text-transform: uppercase;
		letter-spacing: 1px;
		margin-top: 2px;
	}

	/* ── Live Capture Form ─────────────────────────── */

	.capture-form {
		display: flex;
		flex-direction: column;
		gap: 12px;
	}

	.form-group {
		display: flex;
		flex-direction: column;
		gap: 4px;
	}

	.form-label {
		font-size: 10px;
		font-weight: 600;
		color: var(--gm-text-secondary);
		text-transform: uppercase;
		letter-spacing: 0.5px;
	}

	.form-select, .form-input {
		padding: 8px 12px;
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 6px;
		color: var(--gm-text-primary);
		font-family: inherit;
		font-size: 12px;
	}

	.form-select:focus, .form-input:focus {
		outline: none;
		border-color: rgba(16, 185, 129, 0.5);
	}

	.form-input::placeholder {
		color: var(--gm-text-muted);
	}

	.action-btn.capture-start {
		background: rgba(16, 185, 129, 0.15);
		border-color: rgba(16, 185, 129, 0.3);
		color: #10b981;
		align-self: flex-start;
	}

	.action-btn.capture-start:hover:not(:disabled) {
		background: rgba(16, 185, 129, 0.25);
		border-color: #10b981;
	}

	/* ── Capture Controls ──────────────────────────── */

	.capture-controls {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 16px;
	}

	.capture-status-bar {
		display: flex;
		align-items: center;
		gap: 10px;
	}

	.capture-indicator {
		font-size: 10px;
		font-weight: 700;
		letter-spacing: 1px;
		padding: 3px 8px;
		border-radius: 4px;
		background: rgba(16, 185, 129, 0.2);
		color: #10b981;
		animation: pulse-glow 2s ease-in-out infinite;
	}

	.capture-indicator.paused {
		background: rgba(245, 158, 11, 0.2);
		color: #f59e0b;
		animation: none;
	}

	@keyframes pulse-glow {
		0%, 100% { opacity: 1; }
		50% { opacity: 0.6; }
	}

	.capture-interface {
		font-size: 11px;
		color: var(--gm-text-secondary);
		font-weight: 500;
	}

	.capture-filter {
		font-size: 10px;
		color: var(--gm-text-muted);
		padding: 2px 6px;
		background: var(--gm-bg-panel);
		border-radius: 3px;
	}

	.capture-buttons {
		display: flex;
		gap: 8px;
	}

	.action-btn.capture-pause {
		background: rgba(245, 158, 11, 0.15);
		border-color: rgba(245, 158, 11, 0.3);
		color: #f59e0b;
		padding: 6px 14px;
		font-size: 11px;
	}

	.action-btn.capture-pause:hover {
		background: rgba(245, 158, 11, 0.25);
		border-color: #f59e0b;
	}

	.action-btn.capture-stop {
		background: rgba(239, 68, 68, 0.15);
		border-color: rgba(239, 68, 68, 0.3);
		color: #ef4444;
		padding: 6px 14px;
		font-size: 11px;
	}

	.action-btn.capture-stop:hover {
		background: rgba(239, 68, 68, 0.25);
		border-color: #ef4444;
	}

	/* ── Error & Result ────────────────────────────── */

	.capture-error {
		margin-top: 12px;
		padding: 10px 14px;
		background: rgba(239, 68, 68, 0.1);
		border: 1px solid rgba(239, 68, 68, 0.2);
		border-radius: 6px;
		color: #ef4444;
		font-size: 11px;
	}

	.error-detail {
		margin: 6px 0 0;
		font-size: 10px;
		white-space: pre-wrap;
		font-family: inherit;
		line-height: 1.5;
	}

	.stop-result {
		margin-top: 12px;
		padding: 10px 14px;
		background: rgba(16, 185, 129, 0.1);
		border: 1px solid rgba(16, 185, 129, 0.2);
		border-radius: 6px;
		font-size: 11px;
		color: #10b981;
	}

	.stop-summary {
		font-weight: 500;
	}

	.stop-saved {
		margin-top: 4px;
		font-size: 10px;
		color: var(--gm-text-secondary);
	}

	/* ── Interface List ──────────────────────────────── */

	.subsection-title {
		font-size: 11px;
		font-weight: 600;
		color: var(--gm-text-secondary);
		letter-spacing: 1px;
		text-transform: uppercase;
		margin: 0 0 10px 0;
	}

	.interface-list {
		margin-top: 16px;
	}

	.no-interfaces {
		font-size: 11px;
		color: var(--gm-text-muted);
		padding: 12px;
		background: var(--gm-bg-panel);
		border-radius: 6px;
		line-height: 1.5;
	}

	.interface-card {
		padding: 10px 14px;
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 6px;
		margin-bottom: 6px;
		cursor: pointer;
		transition: border-color 0.15s;
	}

	.interface-card:hover {
		border-color: rgba(16, 185, 129, 0.3);
	}

	.interface-card.selected {
		border-color: #10b981;
		background: rgba(16, 185, 129, 0.05);
	}

	.iface-name {
		font-size: 12px;
		font-weight: 600;
		color: var(--gm-text-primary);
	}

	.iface-desc {
		font-size: 10px;
		color: var(--gm-text-muted);
		margin-top: 2px;
	}

	.iface-addrs {
		display: flex;
		gap: 8px;
		margin-top: 6px;
	}

	.iface-addr {
		font-size: 10px;
		color: var(--gm-text-secondary);
		background: var(--gm-bg-primary);
		padding: 2px 8px;
		border-radius: 3px;
	}

	.iface-flags {
		display: flex;
		gap: 6px;
		margin-top: 6px;
	}

	.flag {
		font-size: 9px;
		font-weight: 600;
		letter-spacing: 0.5px;
		padding: 1px 6px;
		border-radius: 3px;
	}

	.flag.up { background: rgba(16, 185, 129, 0.15); color: #10b981; }
	.flag.lo { background: rgba(100, 116, 139, 0.15); color: #94a3b8; }
	.flag.run { background: rgba(59, 130, 246, 0.15); color: #3b82f6; }

	/* ── Stats Grid ──────────────────────────────────── */

	.stats-grid {
		display: grid;
		grid-template-columns: repeat(3, 1fr);
		gap: 10px;
	}

	.stat-card {
		display: flex;
		flex-direction: column;
		align-items: center;
		padding: 12px;
		background: var(--gm-bg-panel);
		border-radius: 6px;
	}

	.stat-value {
		font-size: 18px;
		font-weight: 700;
		color: #10b981;
		font-variant-numeric: tabular-nums;
	}

	.stat-label {
		font-size: 9px;
		color: var(--gm-text-muted);
		text-transform: uppercase;
		letter-spacing: 1px;
		margin-top: 4px;
	}
</style>
