<script lang="ts">
	import { onMount } from 'svelte';
	import type {
		BaselineDiff, SessionInfo, DriftAsset, ChangedAsset, DriftConnection
	} from '$lib/types';
	import { sessions, baselineDiff } from '$lib/stores';
	import { listSessions, compareSessions } from '$lib/utils/tauri';

	let selectedSessionId = $state<string>('');
	let isComparing = $state(false);
	let error = $state<string | null>(null);
	let lastCompareTime = $state<string | null>(null);

	onMount(async () => {
		try {
			const list = await listSessions();
			sessions.set(list);
		} catch {
			// No sessions available
		}
	});

	async function handleCompare() {
		if (!selectedSessionId) return;
		isComparing = true;
		error = null;
		try {
			const result: BaselineDiff = await compareSessions(selectedSessionId);
			baselineDiff.set(result);
			lastCompareTime = new Date().toLocaleTimeString();
		} catch (e) {
			error = String(e);
		} finally {
			isComparing = false;
		}
	}

	function formatDriftScore(score: number): string {
		return Math.round(score * 100).toString();
	}

	function getDriftScoreColor(score: number): string {
		if (score >= 0.5) return '#ef4444';
		if (score >= 0.25) return '#f59e0b';
		return '#10b981';
	}

	function getDriftScoreLabel(score: number): string {
		if (score >= 0.5) return 'High Drift';
		if (score >= 0.25) return 'Moderate Drift';
		if (score > 0) return 'Low Drift';
		return 'No Drift';
	}
</script>

<div class="drift-container">
	<!-- Header -->
	<div class="drift-header">
		<div class="header-left">
			<h2 class="header-title">Baseline Drift</h2>
			{#if lastCompareTime}
				<span class="last-run">Last compared: {lastCompareTime}</span>
			{/if}
		</div>
		<div class="header-controls">
			<select
				class="session-select"
				bind:value={selectedSessionId}
				disabled={isComparing}
			>
				<option value="">-- Select baseline session --</option>
				{#each $sessions as session}
					<option value={session.id}>
						{session.name} ({session.asset_count} assets, {session.connection_count} conns)
					</option>
				{/each}
			</select>
			<button
				class="compare-btn"
				onclick={handleCompare}
				disabled={isComparing || !selectedSessionId}
			>
				{#if isComparing}
					Comparing...
				{:else}
					Compare
				{/if}
			</button>
		</div>
	</div>

	{#if error}
		<div class="error-banner">{error}</div>
	{/if}

	{#if $sessions.length === 0}
		<div class="empty-state">
			<div class="empty-icon">~</div>
			<p>No saved sessions available. Save a session first to use as a baseline.</p>
		</div>
	{:else if !$baselineDiff}
		<div class="empty-state">
			<div class="empty-icon">~</div>
			<p>Select a baseline session and click "Compare" to detect drift from the saved baseline.</p>
		</div>
	{:else}
		{@const diff = $baselineDiff}
		{@const summary = diff.summary}

		<!-- Drift Score Bar -->
		<div class="drift-score-section">
			<div class="drift-score-header">
				<span class="drift-score-label">Drift Score</span>
				<span
					class="drift-score-value"
					style="color: {getDriftScoreColor(summary.drift_score)}"
				>
					{formatDriftScore(summary.drift_score)}%
				</span>
				<span
					class="drift-score-tag"
					style="background: {getDriftScoreColor(summary.drift_score)}"
				>
					{getDriftScoreLabel(summary.drift_score)}
				</span>
			</div>
			<div class="drift-bar-track">
				<div
					class="drift-bar-fill"
					style="width: {Math.min(summary.drift_score * 100, 100)}%; background: {getDriftScoreColor(summary.drift_score)}"
				></div>
			</div>
			<div class="drift-bar-labels">
				<span>0%</span>
				<span>100%</span>
			</div>
		</div>

		<!-- Summary Stats -->
		<div class="summary-grid">
			<div class="summary-card">
				<div class="card-label">Baseline Assets</div>
				<div class="card-value">{summary.total_baseline_assets}</div>
			</div>
			<div class="summary-card">
				<div class="card-label">Current Assets</div>
				<div class="card-value">{summary.total_current_assets}</div>
			</div>
			<div class="summary-card card-new">
				<div class="card-label">New Devices</div>
				<div class="card-value">{summary.new_asset_count}</div>
			</div>
			<div class="summary-card card-missing">
				<div class="card-label">Missing Devices</div>
				<div class="card-value">{summary.missing_asset_count}</div>
			</div>
			<div class="summary-card card-changed">
				<div class="card-label">Changed Devices</div>
				<div class="card-value">{summary.changed_asset_count}</div>
			</div>
			<div class="summary-card">
				<div class="card-label">New Connections</div>
				<div class="card-value">{summary.new_connection_count}</div>
			</div>
			<div class="summary-card">
				<div class="card-label">Missing Connections</div>
				<div class="card-value">{summary.missing_connection_count}</div>
			</div>
			<div class="summary-card">
				<div class="card-label">Baseline</div>
				<div class="card-value-small">{diff.baseline_session_name}</div>
			</div>
		</div>

		<!-- Sections -->
		<div class="drift-sections">
			<!-- New Devices -->
			{#if diff.new_assets.length > 0}
				<div class="drift-section">
					<h3 class="section-title section-new">
						New Devices ({diff.new_assets.length})
					</h3>
					<div class="device-list">
						{#each diff.new_assets as asset}
							<div class="device-card device-new">
								<div class="device-ip">{asset.ip_address}</div>
								<div class="device-meta">
									<span class="device-type">{asset.device_type}</span>
									{#if asset.vendor}
										<span class="device-vendor">{asset.vendor}</span>
									{/if}
									{#if asset.mac_address}
										<span class="device-mac">{asset.mac_address}</span>
									{/if}
								</div>
								{#if asset.protocols.length > 0}
									<div class="device-protocols">
										{#each asset.protocols as proto}
											<span class="protocol-tag">{proto}</span>
										{/each}
									</div>
								{/if}
							</div>
						{/each}
					</div>
				</div>
			{/if}

			<!-- Missing Devices -->
			{#if diff.missing_assets.length > 0}
				<div class="drift-section">
					<h3 class="section-title section-missing">
						Missing Devices ({diff.missing_assets.length})
					</h3>
					<div class="device-list">
						{#each diff.missing_assets as asset}
							<div class="device-card device-missing">
								<div class="device-ip">{asset.ip_address}</div>
								<div class="device-meta">
									<span class="device-type">{asset.device_type}</span>
									{#if asset.vendor}
										<span class="device-vendor">{asset.vendor}</span>
									{/if}
									{#if asset.mac_address}
										<span class="device-mac">{asset.mac_address}</span>
									{/if}
								</div>
								{#if asset.protocols.length > 0}
									<div class="device-protocols">
										{#each asset.protocols as proto}
											<span class="protocol-tag">{proto}</span>
										{/each}
									</div>
								{/if}
							</div>
						{/each}
					</div>
				</div>
			{/if}

			<!-- Changed Devices -->
			{#if diff.changed_assets.length > 0}
				<div class="drift-section">
					<h3 class="section-title section-changed">
						Changed Devices ({diff.changed_assets.length})
					</h3>
					<div class="device-list">
						{#each diff.changed_assets as asset}
							<div class="device-card device-changed">
								<div class="device-ip">{asset.ip_address}</div>
								<div class="change-table">
									{#each asset.changes as change}
										<div class="change-row">
											<span class="change-field">{change.field}</span>
											<span class="change-baseline" title="Baseline value">{change.baseline_value}</span>
											<span class="change-arrow">&rarr;</span>
											<span class="change-current" title="Current value">{change.current_value}</span>
										</div>
									{/each}
								</div>
							</div>
						{/each}
					</div>
				</div>
			{/if}

			<!-- New Connections -->
			{#if diff.new_connections.length > 0}
				<div class="drift-section">
					<h3 class="section-title section-new">
						New Connections ({diff.new_connections.length})
					</h3>
					<div class="connection-list">
						{#each diff.new_connections as conn}
							<div class="connection-card connection-new">
								<span class="conn-src">{conn.src_ip}:{conn.src_port}</span>
								<span class="conn-arrow">&rarr;</span>
								<span class="conn-dst">{conn.dst_ip}:{conn.dst_port}</span>
								<span class="conn-proto">{conn.protocol}</span>
							</div>
						{/each}
					</div>
				</div>
			{/if}

			<!-- Missing Connections -->
			{#if diff.missing_connections.length > 0}
				<div class="drift-section">
					<h3 class="section-title section-missing">
						Missing Connections ({diff.missing_connections.length})
					</h3>
					<div class="connection-list">
						{#each diff.missing_connections as conn}
							<div class="connection-card connection-missing">
								<span class="conn-src">{conn.src_ip}:{conn.src_port}</span>
								<span class="conn-arrow">&rarr;</span>
								<span class="conn-dst">{conn.dst_ip}:{conn.dst_port}</span>
								<span class="conn-proto">{conn.protocol}</span>
							</div>
						{/each}
					</div>
				</div>
			{/if}

			<!-- No drift detected -->
			{#if diff.new_assets.length === 0 && diff.missing_assets.length === 0 && diff.changed_assets.length === 0 && diff.new_connections.length === 0 && diff.missing_connections.length === 0}
				<div class="no-drift">
					<p>No drift detected. The current network state matches the baseline.</p>
				</div>
			{/if}
		</div>
	{/if}
</div>

<style>
	.drift-container {
		height: 100%;
		display: flex;
		flex-direction: column;
		overflow: hidden;
	}

	/* -- Header ------------------------------------------- */

	.drift-header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 16px 20px;
		border-bottom: 1px solid var(--gm-border);
		flex-shrink: 0;
		gap: 16px;
	}

	.header-left {
		display: flex;
		align-items: center;
		gap: 16px;
		flex-shrink: 0;
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

	.header-controls {
		display: flex;
		align-items: center;
		gap: 10px;
		flex-shrink: 1;
		min-width: 0;
	}

	.session-select {
		padding: 7px 10px;
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 6px;
		color: var(--gm-text-primary);
		font-family: inherit;
		font-size: 11px;
		min-width: 260px;
		max-width: 400px;
		cursor: pointer;
	}

	.session-select:focus {
		outline: none;
		border-color: #10b981;
	}

	.session-select:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.compare-btn {
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
		white-space: nowrap;
	}

	.compare-btn:hover:not(:disabled) {
		filter: brightness(1.1);
	}

	.compare-btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	/* -- Error / Empty State ------------------------------- */

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

	.empty-state p {
		font-size: 12px;
		text-align: center;
		max-width: 400px;
		line-height: 1.6;
	}

	/* -- Drift Score -------------------------------------- */

	.drift-score-section {
		padding: 16px 20px;
		border-bottom: 1px solid var(--gm-border);
		flex-shrink: 0;
	}

	.drift-score-header {
		display: flex;
		align-items: center;
		gap: 10px;
		margin-bottom: 8px;
	}

	.drift-score-label {
		font-size: 12px;
		font-weight: 600;
		color: var(--gm-text-secondary);
	}

	.drift-score-value {
		font-size: 18px;
		font-weight: 700;
	}

	.drift-score-tag {
		padding: 2px 8px;
		border-radius: 4px;
		font-size: 9px;
		font-weight: 700;
		color: #0a0e17;
		letter-spacing: 0.5px;
		text-transform: uppercase;
	}

	.drift-bar-track {
		height: 10px;
		background: var(--gm-bg-panel);
		border-radius: 5px;
		overflow: hidden;
	}

	.drift-bar-fill {
		height: 100%;
		border-radius: 5px;
		transition: width 0.4s ease;
		min-width: 2px;
	}

	.drift-bar-labels {
		display: flex;
		justify-content: space-between;
		margin-top: 4px;
		font-size: 9px;
		color: var(--gm-text-muted);
	}

	/* -- Summary Grid ------------------------------------- */

	.summary-grid {
		display: grid;
		grid-template-columns: repeat(4, 1fr);
		gap: 12px;
		padding: 16px 20px;
		border-bottom: 1px solid var(--gm-border);
		flex-shrink: 0;
	}

	.summary-card {
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 8px;
		padding: 14px;
		text-align: center;
	}

	.summary-card.card-new {
		border-color: #10b981;
	}

	.summary-card.card-missing {
		border-color: #ef4444;
	}

	.summary-card.card-changed {
		border-color: #f59e0b;
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

	.card-value-small {
		font-size: 11px;
		font-weight: 600;
		color: var(--gm-text-secondary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	/* -- Drift Sections ----------------------------------- */

	.drift-sections {
		flex: 1;
		overflow-y: auto;
		padding: 16px 20px;
	}

	.drift-section {
		margin-bottom: 24px;
	}

	.section-title {
		font-size: 13px;
		font-weight: 600;
		margin: 0 0 10px;
		padding-left: 10px;
		border-left: 3px solid var(--gm-border);
	}

	.section-title.section-new {
		color: #10b981;
		border-left-color: #10b981;
	}

	.section-title.section-missing {
		color: #ef4444;
		border-left-color: #ef4444;
	}

	.section-title.section-changed {
		color: #f59e0b;
		border-left-color: #f59e0b;
	}

	/* -- Device Cards ------------------------------------- */

	.device-list {
		display: flex;
		flex-direction: column;
		gap: 8px;
	}

	.device-card {
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 8px;
		padding: 12px 14px;
	}

	.device-card.device-new {
		border-left: 3px solid #10b981;
	}

	.device-card.device-missing {
		border-left: 3px solid #ef4444;
	}

	.device-card.device-changed {
		border-left: 3px solid #f59e0b;
	}

	.device-ip {
		font-size: 12px;
		font-weight: 600;
		color: var(--gm-text-primary);
		margin-bottom: 6px;
	}

	.device-meta {
		display: flex;
		align-items: center;
		gap: 10px;
		margin-bottom: 6px;
	}

	.device-type {
		font-size: 10px;
		padding: 1px 6px;
		border-radius: 3px;
		background: var(--gm-bg-hover);
		color: var(--gm-text-secondary);
		text-transform: capitalize;
	}

	.device-vendor {
		font-size: 10px;
		color: var(--gm-text-muted);
	}

	.device-mac {
		font-size: 10px;
		color: var(--gm-text-muted);
	}

	.device-protocols {
		display: flex;
		gap: 6px;
		flex-wrap: wrap;
	}

	.protocol-tag {
		font-size: 9px;
		padding: 1px 6px;
		border-radius: 3px;
		background: rgba(16, 185, 129, 0.1);
		color: #10b981;
		text-transform: uppercase;
		letter-spacing: 0.3px;
	}

	/* -- Change Table ------------------------------------- */

	.change-table {
		margin-top: 6px;
	}

	.change-row {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 4px 0;
		border-bottom: 1px solid var(--gm-border);
		font-size: 10px;
	}

	.change-row:last-child {
		border-bottom: none;
	}

	.change-field {
		font-weight: 600;
		color: var(--gm-text-secondary);
		min-width: 100px;
		text-transform: capitalize;
	}

	.change-baseline {
		color: #ef4444;
		background: rgba(239, 68, 68, 0.08);
		padding: 1px 6px;
		border-radius: 3px;
		max-width: 200px;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.change-arrow {
		color: var(--gm-text-muted);
		flex-shrink: 0;
	}

	.change-current {
		color: #10b981;
		background: rgba(16, 185, 129, 0.08);
		padding: 1px 6px;
		border-radius: 3px;
		max-width: 200px;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	/* -- Connection Cards --------------------------------- */

	.connection-list {
		display: flex;
		flex-direction: column;
		gap: 6px;
	}

	.connection-card {
		display: flex;
		align-items: center;
		gap: 8px;
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 6px;
		padding: 8px 12px;
		font-size: 11px;
	}

	.connection-card.connection-new {
		border-left: 3px solid #10b981;
	}

	.connection-card.connection-missing {
		border-left: 3px solid #ef4444;
	}

	.conn-src {
		color: var(--gm-text-primary);
		font-weight: 600;
	}

	.conn-arrow {
		color: var(--gm-text-muted);
	}

	.conn-dst {
		color: var(--gm-text-primary);
		font-weight: 600;
	}

	.conn-proto {
		margin-left: auto;
		font-size: 9px;
		padding: 1px 6px;
		border-radius: 3px;
		background: var(--gm-bg-hover);
		color: var(--gm-text-secondary);
		text-transform: uppercase;
		letter-spacing: 0.3px;
	}

	/* -- No Drift ----------------------------------------- */

	.no-drift {
		padding: 40px 20px;
		text-align: center;
		color: var(--gm-text-muted);
		font-size: 12px;
	}
</style>
