<script lang="ts">
	import { interfaces, captureStatus, captureStats, assets, connections, topology, sessions, currentSession } from '$lib/stores';
	import {
		importPcap, getAssets, getConnections, getTopology, getProtocolStats,
		startCapture, stopCapture, pauseCapture, resumeCapture,
		onCaptureStats, onCaptureError,
		saveSession, loadSession, listSessions, deleteSession,
		exportSessionArchive, importSessionArchive,
		importZeekLogs, importSuricataEve, importNmapXml, importMasscanJson
	} from '$lib/utils/tauri';
	import { protocolStats } from '$lib/stores';
	import type { FileImportResult, CaptureStatsEvent, SessionInfo, IngestImportResult } from '$lib/types';
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

	// ── Session State ──────────────────────────────────
	let sessionName = $state('');
	let sessionDesc = $state('');
	let sessionMessage = $state('');
	let sessionMessageType = $state<'success' | 'error' | ''>('');
	let showSaveForm = $state(false);
	let confirmDeleteId = $state<string | null>(null);

	// ── External Tool Import State ────────────────────────
	let ingestStatus = $state<'idle' | 'importing' | 'done' | 'error'>('idle');
	let ingestMessage = $state('');
	let lastIngestResult = $state<IngestImportResult | null>(null);

	// Event listener cleanup functions
	let unlistenStats: (() => void) | null = null;
	let unlistenError: (() => void) | null = null;
	let refreshInterval: ReturnType<typeof setInterval> | null = null;

	onMount(() => {
		// Set up event listeners for live capture
		setupEventListeners();
		// Load session list
		refreshSessions();
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

	// ── Session Management ──────────────────────────────
	async function refreshSessions() {
		try {
			const list = await listSessions();
			sessions.set(list);
		} catch {
			// DB may not be available in dev mode
		}
	}

	async function handleSaveSession() {
		if (!sessionName.trim()) return;
		try {
			const info = await saveSession(sessionName.trim(), sessionDesc.trim() || undefined);
			currentSession.set(info);
			sessionMessage = `Session "${info.name}" saved (${info.asset_count} assets, ${info.connection_count} connections)`;
			sessionMessageType = 'success';
			showSaveForm = false;
			sessionName = '';
			sessionDesc = '';
			await refreshSessions();
		} catch (err) {
			sessionMessage = `Save failed: ${err}`;
			sessionMessageType = 'error';
		}
	}

	async function handleLoadSession(id: string) {
		try {
			const info = await loadSession(id);
			currentSession.set(info);
			// Refresh all data stores
			const [newAssets, newConnections, newTopology, newStats] = await Promise.all([
				getAssets(), getConnections(), getTopology(), getProtocolStats()
			]);
			assets.set(newAssets);
			connections.set(newConnections);
			topology.set(newTopology);
			protocolStats.set(newStats);
			sessionMessage = `Session "${info.name}" loaded`;
			sessionMessageType = 'success';
		} catch (err) {
			sessionMessage = `Load failed: ${err}`;
			sessionMessageType = 'error';
		}
	}

	async function handleDeleteSession(id: string) {
		try {
			await deleteSession(id);
			if ($currentSession?.id === id) {
				currentSession.set(null);
			}
			confirmDeleteId = null;
			sessionMessage = 'Session deleted';
			sessionMessageType = 'success';
			await refreshSessions();
		} catch (err) {
			sessionMessage = `Delete failed: ${err}`;
			sessionMessageType = 'error';
		}
	}

	async function handleExportSession(session: SessionInfo) {
		try {
			const { save } = await import('@tauri-apps/plugin-dialog');
			const path = await save({
				title: 'Export Session Archive',
				defaultPath: `${session.name.replace(/[^a-zA-Z0-9_-]/g, '_')}.kkj`,
				filters: [
					{ name: 'Kusanagi Kajiki Archive', extensions: ['kkj'] },
					{ name: 'All Files', extensions: ['*'] }
				]
			});
			if (!path) return;
			await exportSessionArchive(session.id, path);
			sessionMessage = `Exported to ${path}`;
			sessionMessageType = 'success';
		} catch (err) {
			sessionMessage = `Export failed: ${err}`;
			sessionMessageType = 'error';
		}
	}

	async function handleImportArchive() {
		try {
			const { open } = await import('@tauri-apps/plugin-dialog');
			const selected = await open({
				title: 'Import Session Archive',
				multiple: false,
				filters: [
					{ name: 'Kusanagi Kajiki Archive', extensions: ['kkj'] },
					{ name: 'All Files', extensions: ['*'] }
				]
			});
			if (!selected) return;
			const path = typeof selected === 'string' ? selected : selected[0];
			if (!path) return;
			const info = await importSessionArchive(path);
			currentSession.set(info);
			// Refresh all data stores
			const [newAssets, newConnections, newTopology, newStats] = await Promise.all([
				getAssets(), getConnections(), getTopology(), getProtocolStats()
			]);
			assets.set(newAssets);
			connections.set(newConnections);
			topology.set(newTopology);
			protocolStats.set(newStats);
			sessionMessage = `Imported "${info.name}" (${info.asset_count} assets)`;
			sessionMessageType = 'success';
			await refreshSessions();
		} catch (err) {
			sessionMessage = `Import failed: ${err}`;
			sessionMessageType = 'error';
		}
	}

	// ── External Tool Import Handlers ────────────────────
	async function handleImportZeek() {
		try {
			const { open } = await import('@tauri-apps/plugin-dialog');
			const selected = await open({
				title: 'Import Zeek Logs',
				multiple: true,
				filters: [
					{ name: 'Zeek Logs', extensions: ['log'] },
					{ name: 'All Files', extensions: ['*'] }
				]
			});
			if (!selected || selected.length === 0) return;
			const paths: string[] = selected;
			if (paths.length === 0) return;

			ingestStatus = 'importing';
			ingestMessage = `Importing ${paths.length} Zeek log file${paths.length > 1 ? 's' : ''}...`;
			lastIngestResult = null;

			const result = await importZeekLogs(paths);
			lastIngestResult = result;
			ingestStatus = 'done';
			ingestMessage = `Zeek: ${result.new_assets} new + ${result.updated_assets} updated assets, ${result.connection_count} connections (${result.duration_ms}ms)`;

			await refreshStores();
		} catch (err) {
			ingestStatus = 'error';
			ingestMessage = `Zeek import failed: ${err}`;
		}
	}

	async function handleImportSuricata() {
		try {
			const { open } = await import('@tauri-apps/plugin-dialog');
			const selected = await open({
				title: 'Import Suricata eve.json',
				multiple: false,
				filters: [
					{ name: 'JSON Files', extensions: ['json'] },
					{ name: 'All Files', extensions: ['*'] }
				]
			});
			if (!selected) return;
			const path = typeof selected === 'string' ? selected : selected[0];
			if (!path) return;

			ingestStatus = 'importing';
			ingestMessage = 'Importing Suricata eve.json...';
			lastIngestResult = null;

			const result = await importSuricataEve(path);
			lastIngestResult = result;
			ingestStatus = 'done';
			ingestMessage = `Suricata: ${result.new_assets} new + ${result.updated_assets} updated assets, ${result.connection_count} connections, ${result.alert_count} alerts (${result.duration_ms}ms)`;

			await refreshStores();
		} catch (err) {
			ingestStatus = 'error';
			ingestMessage = `Suricata import failed: ${err}`;
		}
	}

	async function handleImportNmap() {
		try {
			const { open } = await import('@tauri-apps/plugin-dialog');
			const selected = await open({
				title: 'Import Nmap XML',
				multiple: false,
				filters: [
					{ name: 'XML Files', extensions: ['xml'] },
					{ name: 'All Files', extensions: ['*'] }
				]
			});
			if (!selected) return;
			const path = typeof selected === 'string' ? selected : selected[0];
			if (!path) return;

			ingestStatus = 'importing';
			ingestMessage = 'Importing Nmap XML...';
			lastIngestResult = null;

			const result = await importNmapXml(path);
			lastIngestResult = result;
			ingestStatus = 'done';
			ingestMessage = `Nmap: ${result.new_assets} new + ${result.updated_assets} updated assets (${result.duration_ms}ms) [ACTIVE SCAN]`;

			await refreshStores();
		} catch (err) {
			ingestStatus = 'error';
			ingestMessage = `Nmap import failed: ${err}`;
		}
	}

	async function handleImportMasscan() {
		try {
			const { open } = await import('@tauri-apps/plugin-dialog');
			const selected = await open({
				title: 'Import Masscan JSON',
				multiple: false,
				filters: [
					{ name: 'JSON Files', extensions: ['json'] },
					{ name: 'All Files', extensions: ['*'] }
				]
			});
			if (!selected) return;
			const path = typeof selected === 'string' ? selected : selected[0];
			if (!path) return;

			ingestStatus = 'importing';
			ingestMessage = 'Importing Masscan JSON...';
			lastIngestResult = null;

			const result = await importMasscanJson(path);
			lastIngestResult = result;
			ingestStatus = 'done';
			ingestMessage = `Masscan: ${result.new_assets} new + ${result.updated_assets} updated assets (${result.duration_ms}ms) [ACTIVE SCAN]`;

			await refreshStores();
		} catch (err) {
			ingestStatus = 'error';
			ingestMessage = `Masscan import failed: ${err}`;
		}
	}

	async function refreshStores() {
		const [newAssets, newConnections, newTopology, newStats] = await Promise.all([
			getAssets(), getConnections(), getTopology(), getProtocolStats()
		]);
		assets.set(newAssets);
		connections.set(newConnections);
		topology.set(newTopology);
		protocolStats.set(newStats);
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

		<!-- External Tool Import Section -->
		<section class="capture-section">
			<h3 class="section-title">External Tool Import</h3>
			<p class="section-desc">
				Import results from Zeek, Suricata, Nmap, or Masscan. Passive tool data (Zeek, Suricata)
				is merged naturally. Active scan data (Nmap, Masscan) is tagged — this tool never performs scans.
			</p>

			<div class="ingest-grid">
				<div class="ingest-card">
					<div class="ingest-card-header">
						<span class="ingest-card-title">Zeek (Bro)</span>
						<span class="ingest-badge passive">PASSIVE</span>
					</div>
					<p class="ingest-card-desc">conn.log, modbus.log, dnp3.log, s7comm.log</p>
					<button class="action-btn primary" onclick={handleImportZeek} disabled={ingestStatus === 'importing' || isCapturing}>
						Import Zeek Logs
					</button>
				</div>

				<div class="ingest-card">
					<div class="ingest-card-header">
						<span class="ingest-card-title">Suricata</span>
						<span class="ingest-badge passive">PASSIVE</span>
					</div>
					<p class="ingest-card-desc">eve.json — flows, alerts, protocol metadata</p>
					<button class="action-btn primary" onclick={handleImportSuricata} disabled={ingestStatus === 'importing' || isCapturing}>
						Import eve.json
					</button>
				</div>

				<div class="ingest-card">
					<div class="ingest-card-header">
						<span class="ingest-card-title">Nmap</span>
						<span class="ingest-badge active">ACTIVE SCAN</span>
					</div>
					<p class="ingest-card-desc">XML output (-oX) — hosts, ports, services, OS</p>
					<button class="action-btn warning" onclick={handleImportNmap} disabled={ingestStatus === 'importing' || isCapturing}>
						Import Nmap XML
					</button>
				</div>

				<div class="ingest-card">
					<div class="ingest-card-header">
						<span class="ingest-card-title">Masscan</span>
						<span class="ingest-badge active">ACTIVE SCAN</span>
					</div>
					<p class="ingest-card-desc">JSON output (-oJ) — IP, ports, banners</p>
					<button class="action-btn warning" onclick={handleImportMasscan} disabled={ingestStatus === 'importing' || isCapturing}>
						Import Masscan JSON
					</button>
				</div>
			</div>

			{#if ingestMessage}
				<div
					class="import-result"
					class:success={ingestStatus === 'done'}
					class:error={ingestStatus === 'error'}
					class:loading={ingestStatus === 'importing'}
				>
					{ingestMessage}
				</div>
			{/if}

			{#if lastIngestResult && ingestStatus === 'done'}
				<div class="import-stats-grid">
					<div class="import-stat">
						<span class="import-stat-value">{lastIngestResult.new_assets}</span>
						<span class="import-stat-label">New Assets</span>
					</div>
					<div class="import-stat">
						<span class="import-stat-value">{lastIngestResult.updated_assets}</span>
						<span class="import-stat-label">Updated</span>
					</div>
					<div class="import-stat">
						<span class="import-stat-value">{lastIngestResult.connection_count}</span>
						<span class="import-stat-label">Connections</span>
					</div>
					<div class="import-stat">
						<span class="import-stat-value">{lastIngestResult.alert_count}</span>
						<span class="import-stat-label">Alerts</span>
					</div>
				</div>
				{#if lastIngestResult.errors.length > 0}
					<div class="ingest-errors">
						<h4 class="subsection-title">Errors</h4>
						{#each lastIngestResult.errors as err}
							<div class="ingest-error-row">{err}</div>
						{/each}
					</div>
				{/if}
			{/if}
		</section>

		<!-- Session Management Section -->
		<section class="capture-section">
			<h3 class="section-title">Sessions</h3>
			<p class="section-desc">
				Save and load analysis sessions. Sessions preserve assets, connections, topology, and deep parse data.
				Export as .kkj archives for sharing or backup.
			</p>

			{#if $currentSession}
				<div class="current-session">
					<span class="session-current-label">Current:</span>
					<span class="session-current-name">{$currentSession.name}</span>
					<span class="session-current-stats">
						{$currentSession.asset_count} assets, {$currentSession.connection_count} connections
					</span>
				</div>
			{/if}

			{#if sessionMessage}
				<div class="session-message" class:success={sessionMessageType === 'success'} class:error={sessionMessageType === 'error'}>
					{sessionMessage}
				</div>
			{/if}

			<div class="session-actions">
				{#if !showSaveForm}
					<button class="action-btn primary" onclick={() => { showSaveForm = true; sessionMessage = ''; }} disabled={isCapturing}>
						Save Session
					</button>
				{/if}
				<button class="action-btn secondary" onclick={handleImportArchive} disabled={isCapturing}>
					Import Archive
				</button>
			</div>

			{#if showSaveForm}
				<div class="save-form">
					<div class="form-group">
						<label class="form-label" for="session-name">Session Name</label>
						<input
							id="session-name"
							class="form-input"
							type="text"
							placeholder="e.g., Plant Floor Assessment 2026-02"
							bind:value={sessionName}
						/>
					</div>
					<div class="form-group">
						<label class="form-label" for="session-desc">Description (optional)</label>
						<input
							id="session-desc"
							class="form-input"
							type="text"
							placeholder="e.g., Initial baseline of SCADA network"
							bind:value={sessionDesc}
						/>
					</div>
					<div class="save-form-actions">
						<button class="action-btn primary" onclick={handleSaveSession} disabled={!sessionName.trim()}>
							Save
						</button>
						<button class="action-btn secondary" onclick={() => { showSaveForm = false; }}>
							Cancel
						</button>
					</div>
				</div>
			{/if}

			{#if $sessions.length > 0}
				<div class="session-list">
					<h4 class="subsection-title">Saved Sessions</h4>
					{#each $sessions as session}
						<div class="session-card" class:active={$currentSession?.id === session.id}>
							<div class="session-info">
								<div class="session-name">{session.name}</div>
								{#if session.description}
									<div class="session-desc-text">{session.description}</div>
								{/if}
								<div class="session-meta">
									{session.asset_count} assets, {session.connection_count} connections
									&middot; {new Date(session.created_at).toLocaleDateString()}
								</div>
							</div>
							<div class="session-card-actions">
								<button
									class="session-btn load"
									onclick={() => handleLoadSession(session.id)}
									disabled={isCapturing}
									title="Load session"
								>Load</button>
								<button
									class="session-btn export"
									onclick={() => handleExportSession(session)}
									title="Export as .kkj archive"
								>Export</button>
								{#if confirmDeleteId === session.id}
									<button
										class="session-btn confirm-delete"
										onclick={() => handleDeleteSession(session.id)}
									>Confirm</button>
									<button
										class="session-btn cancel-delete"
										onclick={() => { confirmDeleteId = null; }}
									>Cancel</button>
								{:else}
									<button
										class="session-btn delete"
										onclick={() => { confirmDeleteId = session.id; }}
										title="Delete session"
									>Delete</button>
								{/if}
							</div>
						</div>
					{/each}
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

	/* ── Session Management ──────────────────────────── */

	.current-session {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 8px 12px;
		background: rgba(16, 185, 129, 0.08);
		border: 1px solid rgba(16, 185, 129, 0.2);
		border-radius: 6px;
		margin-bottom: 12px;
		font-size: 11px;
	}

	.session-current-label {
		color: var(--gm-text-muted);
		font-size: 10px;
		text-transform: uppercase;
		letter-spacing: 0.5px;
	}

	.session-current-name {
		color: #10b981;
		font-weight: 600;
	}

	.session-current-stats {
		color: var(--gm-text-muted);
		font-size: 10px;
		margin-left: auto;
	}

	.session-message {
		padding: 8px 12px;
		border-radius: 6px;
		font-size: 11px;
		margin-bottom: 12px;
	}

	.session-message.success {
		background: rgba(16, 185, 129, 0.1);
		border: 1px solid rgba(16, 185, 129, 0.2);
		color: #10b981;
	}

	.session-message.error {
		background: rgba(239, 68, 68, 0.1);
		border: 1px solid rgba(239, 68, 68, 0.2);
		color: #ef4444;
	}

	.session-actions {
		display: flex;
		gap: 8px;
		margin-bottom: 16px;
	}

	.action-btn.secondary {
		background: rgba(100, 116, 139, 0.15);
		border-color: rgba(100, 116, 139, 0.3);
		color: var(--gm-text-secondary);
	}

	.action-btn.secondary:hover:not(:disabled) {
		background: rgba(100, 116, 139, 0.25);
		border-color: var(--gm-text-muted);
	}

	.save-form {
		display: flex;
		flex-direction: column;
		gap: 10px;
		padding: 14px;
		background: var(--gm-bg-panel);
		border-radius: 6px;
		margin-bottom: 16px;
	}

	.save-form-actions {
		display: flex;
		gap: 8px;
	}

	.session-list {
		margin-top: 4px;
	}

	.session-card {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 10px 14px;
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 6px;
		margin-bottom: 6px;
	}

	.session-card.active {
		border-color: rgba(16, 185, 129, 0.3);
		background: rgba(16, 185, 129, 0.05);
	}

	.session-info {
		flex: 1;
		min-width: 0;
	}

	.session-name {
		font-size: 12px;
		font-weight: 600;
		color: var(--gm-text-primary);
	}

	.session-desc-text {
		font-size: 10px;
		color: var(--gm-text-muted);
		margin-top: 2px;
	}

	.session-meta {
		font-size: 10px;
		color: var(--gm-text-muted);
		margin-top: 4px;
	}

	.session-card-actions {
		display: flex;
		gap: 4px;
		flex-shrink: 0;
		margin-left: 12px;
	}

	.session-btn {
		padding: 4px 10px;
		border: 1px solid var(--gm-border);
		border-radius: 4px;
		font-family: inherit;
		font-size: 10px;
		font-weight: 500;
		cursor: pointer;
		transition: all 0.15s;
		background: transparent;
	}

	.session-btn.load {
		color: #3b82f6;
		border-color: rgba(59, 130, 246, 0.3);
	}

	.session-btn.load:hover:not(:disabled) {
		background: rgba(59, 130, 246, 0.15);
	}

	.session-btn.export {
		color: #8b5cf6;
		border-color: rgba(139, 92, 246, 0.3);
	}

	.session-btn.export:hover {
		background: rgba(139, 92, 246, 0.15);
	}

	.session-btn.delete {
		color: #ef4444;
		border-color: rgba(239, 68, 68, 0.3);
	}

	.session-btn.delete:hover {
		background: rgba(239, 68, 68, 0.15);
	}

	.session-btn.confirm-delete {
		color: #fff;
		background: #ef4444;
		border-color: #ef4444;
	}

	.session-btn.cancel-delete {
		color: var(--gm-text-muted);
	}

	.session-btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	/* ── External Tool Import ─────────────────────── */

	.ingest-grid {
		display: grid;
		grid-template-columns: repeat(2, 1fr);
		gap: 12px;
		margin-bottom: 12px;
	}

	.ingest-card {
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 6px;
		padding: 12px;
	}

	.ingest-card-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 6px;
	}

	.ingest-card-title {
		font-size: 12px;
		font-weight: 600;
		color: var(--gm-text-primary);
	}

	.ingest-badge {
		font-size: 8px;
		font-weight: 700;
		letter-spacing: 0.5px;
		padding: 2px 6px;
		border-radius: 3px;
	}

	.ingest-badge.passive {
		background: rgba(16, 185, 129, 0.15);
		color: #10b981;
	}

	.ingest-badge.active {
		background: rgba(245, 158, 11, 0.15);
		color: #f59e0b;
	}

	.ingest-card-desc {
		font-size: 10px;
		color: var(--gm-text-muted);
		margin: 0 0 10px 0;
		line-height: 1.4;
	}

	.action-btn.warning {
		background: rgba(245, 158, 11, 0.15);
		border-color: rgba(245, 158, 11, 0.3);
		color: #f59e0b;
	}

	.action-btn.warning:hover:not(:disabled) {
		background: rgba(245, 158, 11, 0.25);
		border-color: #f59e0b;
	}

	.ingest-errors {
		margin-top: 12px;
	}

	.ingest-error-row {
		font-size: 10px;
		color: #ef4444;
		padding: 4px 8px;
		background: rgba(239, 68, 68, 0.05);
		border-radius: 4px;
		margin-bottom: 3px;
	}
</style>
