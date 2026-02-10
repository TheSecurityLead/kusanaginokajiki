<script lang="ts">
	import { interfaces, captureStatus, captureStats, assets, connections, topology } from '$lib/stores';
	import { importPcap, getAssets, getConnections, getTopology, getProtocolStats } from '$lib/utils/tauri';
	import { protocolStats } from '$lib/stores';

	let importStatus = $state<'idle' | 'importing' | 'done' | 'error'>('idle');
	let importMessage = $state('');
	let selectedFile = $state('');

	async function handleImportPcap() {
		try {
			// Use Tauri dialog to pick a file
			const { open } = await import('@tauri-apps/plugin-dialog');
			const filePath = await open({
				title: 'Import PCAP File',
				filters: [
					{ name: 'PCAP Files', extensions: ['pcap', 'pcapng', 'cap'] },
					{ name: 'All Files', extensions: ['*'] }
				]
			});

			if (!filePath) return; // User cancelled

			selectedFile = typeof filePath === 'string' ? filePath : filePath.path;
			importStatus = 'importing';
			importMessage = `Importing ${selectedFile.split('/').pop() ?? selectedFile}...`;

			const result = await importPcap(selectedFile);

			importStatus = 'done';
			importMessage = `Imported ${result.packet_count.toLocaleString()} packets → ${result.asset_count} assets, ${result.connection_count} connections (${result.duration_ms}ms)`;

			// Refresh all stores with new data
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
				Import a PCAP or PCAPNG file captured from an OT network. The file will be parsed
				for ICS protocol traffic and assets will be discovered automatically.
			</p>

			<button class="action-btn primary" onclick={handleImportPcap} disabled={importStatus === 'importing'}>
				{importStatus === 'importing' ? '⏳ Importing...' : '📁 Import PCAP File'}
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
		</section>

		<!-- Live Capture Section -->
		<section class="capture-section">
			<h3 class="section-title">Live Capture</h3>
			<p class="section-desc">
				Capture packets in real-time from a network interface. Requires elevated privileges
				(root/admin or CAP_NET_RAW capability).
			</p>

			<div class="interface-list">
				<h4 class="subsection-title">Available Interfaces</h4>
				{#if $interfaces.length === 0}
					<div class="no-interfaces">
						No interfaces detected. This is expected during development in the browser.
						Interfaces will appear when running as a Tauri desktop app.
					</div>
				{:else}
					{#each $interfaces as iface}
						<div class="interface-card" class:up={iface.flags.is_up} class:loopback={iface.flags.is_loopback}>
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
				{/if}
			</div>

			<p class="phase-note">
				⚠️ Live capture will be available in Phase 4. For now, use PCAP import above.
			</p>
		</section>

		<!-- Capture Stats (visible during live capture) -->
		{#if $captureStatus === 'capturing'}
			<section class="capture-section stats">
				<h3 class="section-title">Live Statistics</h3>
				<div class="stats-grid">
					<div class="stat-card">
						<span class="stat-value">{$captureStats.packets_captured.toLocaleString()}</span>
						<span class="stat-label">Packets</span>
					</div>
					<div class="stat-card">
						<span class="stat-value">{$captureStats.packets_per_second}</span>
						<span class="stat-label">PPS</span>
					</div>
					<div class="stat-card">
						<span class="stat-value">{($captureStats.bytes_captured / 1024 / 1024).toFixed(1)} MB</span>
						<span class="stat-label">Data</span>
					</div>
					<div class="stat-card">
						<span class="stat-value">{$captureStats.active_connections}</span>
						<span class="stat-label">Connections</span>
					</div>
				</div>
			</section>
		{/if}
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

	.phase-note {
		font-size: 10px;
		color: var(--gm-text-muted);
		margin-top: 16px;
		padding: 8px 12px;
		background: rgba(245, 158, 11, 0.08);
		border: 1px solid rgba(245, 158, 11, 0.15);
		border-radius: 4px;
	}

	/* ── Stats Grid ──────────────────────────────────── */

	.stats-grid {
		display: grid;
		grid-template-columns: repeat(4, 1fr);
		gap: 12px;
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
	}

	.stat-label {
		font-size: 9px;
		color: var(--gm-text-muted);
		text-transform: uppercase;
		letter-spacing: 1px;
		margin-top: 4px;
	}
</style>
