<script lang="ts">
	import { filteredAssets, assetFilter, selectedAssetId, selectedAsset, protocolFilter } from '$lib/stores';
	import { getDeepParseInfo } from '$lib/utils/tauri';
	import type { DeviceType, IcsProtocol, DeepParseInfo } from '$lib/types';

	const deviceTypeLabels: Record<DeviceType, string> = {
		plc: 'PLC',
		rtu: 'RTU',
		hmi: 'HMI',
		historian: 'Historian',
		engineering_workstation: 'Eng. WS',
		scada_server: 'SCADA Server',
		it_device: 'IT Device',
		unknown: 'Unknown'
	};

	const deviceTypeColors: Record<DeviceType, string> = {
		plc: '#f59e0b',
		rtu: '#10b981',
		hmi: '#3b82f6',
		historian: '#8b5cf6',
		engineering_workstation: '#06b6d4',
		scada_server: '#ec4899',
		it_device: '#475569',
		unknown: '#64748b'
	};

	const protocols: IcsProtocol[] = ['modbus', 'dnp3', 'ethernet_ip', 'bacnet', 's7comm', 'opc_ua'];

	const confidenceLabels: Record<number, string> = {
		0: '—',
		1: 'Port',
		2: 'Pattern',
		3: 'MAC OUI',
		4: 'Payload',
		5: 'Deep'
	};

	const confidenceColors: Record<number, string> = {
		5: 'var(--gm-confidence-5, #10b981)',
		4: 'var(--gm-confidence-4, #3b82f6)',
		3: 'var(--gm-confidence-3, #f59e0b)',
		2: 'var(--gm-confidence-2, #f97316)',
		1: 'var(--gm-confidence-1, #ef4444)',
		0: '#64748b'
	};

	let deepParseInfo = $state<DeepParseInfo | null>(null);
	let loadingDeepParse = $state(false);
	let lastLoadedIp = $state<string | null>(null);

	// Load deep parse info when selected asset changes
	$effect(() => {
		const asset = $selectedAsset;
		if (asset && asset.ip_address !== lastLoadedIp) {
			lastLoadedIp = asset.ip_address;
			loadDeepParseInfo(asset.ip_address);
		} else if (!asset) {
			deepParseInfo = null;
			lastLoadedIp = null;
		}
	});

	async function loadDeepParseInfo(ip: string) {
		loadingDeepParse = true;
		try {
			deepParseInfo = await getDeepParseInfo(ip);
		} catch (err) {
			console.warn('Failed to load deep parse info:', err);
			deepParseInfo = null;
		}
		loadingDeepParse = false;
	}

	function handleFilterInput(event: Event) {
		const target = event.target as HTMLInputElement;
		assetFilter.set(target.value);
	}

	function formatInterval(ms: number): string {
		if (ms < 1000) return `${ms.toFixed(0)}ms`;
		return `${(ms / 1000).toFixed(1)}s`;
	}
</script>

<div class="inventory-container">
	<div class="inventory-toolbar">
		<h2 class="view-title">Asset Inventory</h2>
		<div class="toolbar-controls">
			<input
				type="text"
				class="search-input"
				placeholder="Filter by IP, MAC, vendor, hostname..."
				oninput={handleFilterInput}
			/>
			<select class="protocol-select" onchange={(e) => {
				const val = (e.target as HTMLSelectElement).value;
				protocolFilter.set(val === 'all' ? null : val as IcsProtocol);
			}}>
				<option value="all">All Protocols</option>
				{#each protocols as proto}
					<option value={proto}>{proto.toUpperCase()}</option>
				{/each}
			</select>
			<span class="result-count">{$filteredAssets.length} assets</span>
		</div>
	</div>

	<div class="inventory-body">
		<div class="table-container">
			{#if $filteredAssets.length === 0}
				<div class="empty-state">
					<p>No assets discovered yet. Import a PCAP file to get started.</p>
				</div>
			{:else}
				<table class="asset-table">
					<thead>
						<tr>
							<th>IP Address</th>
							<th>MAC Address</th>
							<th>Type</th>
							<th>Confidence</th>
							<th>Vendor</th>
							<th>Product</th>
							<th>Protocols</th>
							<th>Packets</th>
							<th>First Seen</th>
						</tr>
					</thead>
					<tbody>
						{#each $filteredAssets as asset}
							<tr
								class="asset-row"
								class:selected={$selectedAssetId === asset.id}
								onclick={() => selectedAssetId.set(
									$selectedAssetId === asset.id ? null : asset.id
								)}
							>
								<td class="cell-ip">{asset.ip_address}</td>
								<td class="cell-mac">{asset.mac_address ?? '—'}</td>
								<td>
									<span
										class="device-badge"
										style="color: {deviceTypeColors[asset.device_type]};
										       background: {deviceTypeColors[asset.device_type]}18"
									>
										{deviceTypeLabels[asset.device_type]}
									</span>
								</td>
								<td>
									{#if asset.confidence > 0}
										<span
											class="confidence-badge"
											style="color: {confidenceColors[asset.confidence] ?? '#64748b'};
											       background: {(confidenceColors[asset.confidence] ?? '#64748b')}18"
											title="{confidenceLabels[asset.confidence] ?? '?'} ({asset.confidence}/5)"
										>
											{asset.confidence}/5
										</span>
									{:else}
										<span class="confidence-none">—</span>
									{/if}
								</td>
								<td class="cell-vendor">{asset.vendor ?? '—'}</td>
								<td class="cell-vendor">{asset.product_family ?? '—'}</td>
								<td class="cell-protocols">
									{#each asset.protocols as proto}
										<span class="proto-tag">{proto}</span>
									{/each}
								</td>
								<td class="cell-numeric">{asset.packet_count.toLocaleString()}</td>
								<td class="cell-time">{new Date(asset.first_seen).toLocaleString()}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			{/if}
		</div>

		<!-- Deep Parse Detail Panel -->
		{#if $selectedAsset}
			<div class="detail-panel">
				<div class="detail-header">
					<h3 class="detail-title">{$selectedAsset.ip_address}</h3>
					<button class="detail-close" onclick={() => selectedAssetId.set(null)}>&times;</button>
				</div>

				<div class="detail-body">
					<!-- Basic Info -->
					<div class="detail-section">
						<div class="detail-row">
							<span class="detail-label">Type</span>
							<span class="detail-value">{deviceTypeLabels[$selectedAsset.device_type] ?? $selectedAsset.device_type}</span>
						</div>
						{#if $selectedAsset.vendor}
							<div class="detail-row">
								<span class="detail-label">Vendor</span>
								<span class="detail-value">{$selectedAsset.vendor}</span>
							</div>
						{/if}
						{#if $selectedAsset.product_family}
							<div class="detail-row">
								<span class="detail-label">Product</span>
								<span class="detail-value">{$selectedAsset.product_family}</span>
							</div>
						{/if}
						<div class="detail-row">
							<span class="detail-label">Confidence</span>
							<span class="detail-value">
								{#if $selectedAsset.confidence > 0}
									{$selectedAsset.confidence}/5 ({confidenceLabels[$selectedAsset.confidence]})
								{:else}
									—
								{/if}
							</span>
						</div>
					</div>

					{#if loadingDeepParse}
						<div class="detail-loading">Loading deep parse data...</div>
					{:else if deepParseInfo}
						<!-- Modbus Detail -->
						{#if deepParseInfo.modbus}
							<div class="detail-section">
								<h4 class="section-title" style="color: var(--gm-modbus, #f59e0b)">Modbus TCP</h4>
								<div class="detail-row">
									<span class="detail-label">Role</span>
									<span class="detail-value role-badge">{deepParseInfo.modbus.role}</span>
								</div>
								{#if deepParseInfo.modbus.unit_ids.length > 0}
									<div class="detail-row">
										<span class="detail-label">Unit IDs</span>
										<span class="detail-value">{deepParseInfo.modbus.unit_ids.join(', ')}</span>
									</div>
								{/if}

								<!-- Device Identification (FC 43/14) -->
								{#if deepParseInfo.modbus.device_id}
									<div class="detail-subsection">
										<h5 class="subsection-title">Device Identification (FC 43)</h5>
										{#if deepParseInfo.modbus.device_id.vendor_name}
											<div class="detail-row">
												<span class="detail-label">Vendor</span>
												<span class="detail-value highlight">{deepParseInfo.modbus.device_id.vendor_name}</span>
											</div>
										{/if}
										{#if deepParseInfo.modbus.device_id.product_code}
											<div class="detail-row">
												<span class="detail-label">Product</span>
												<span class="detail-value highlight">{deepParseInfo.modbus.device_id.product_code}</span>
											</div>
										{/if}
										{#if deepParseInfo.modbus.device_id.revision}
											<div class="detail-row">
												<span class="detail-label">Revision</span>
												<span class="detail-value">{deepParseInfo.modbus.device_id.revision}</span>
											</div>
										{/if}
										{#if deepParseInfo.modbus.device_id.product_name}
											<div class="detail-row">
												<span class="detail-label">Product Name</span>
												<span class="detail-value">{deepParseInfo.modbus.device_id.product_name}</span>
											</div>
										{/if}
										{#if deepParseInfo.modbus.device_id.model_name}
											<div class="detail-row">
												<span class="detail-label">Model</span>
												<span class="detail-value">{deepParseInfo.modbus.device_id.model_name}</span>
											</div>
										{/if}
									</div>
								{/if}

								<!-- Function Codes -->
								{#if deepParseInfo.modbus.function_codes.length > 0}
									<div class="detail-subsection">
										<h5 class="subsection-title">Function Codes</h5>
										<div class="fc-list">
											{#each deepParseInfo.modbus.function_codes as fc}
												<div class="fc-item" class:write={fc.is_write}>
													<span class="fc-code">FC {fc.code}</span>
													<span class="fc-name">{fc.name}</span>
													<span class="fc-count">{fc.count.toLocaleString()}</span>
												</div>
											{/each}
										</div>
									</div>
								{/if}

								<!-- Register Ranges -->
								{#if deepParseInfo.modbus.register_ranges.length > 0}
									<div class="detail-subsection">
										<h5 class="subsection-title">Register Ranges</h5>
										<div class="reg-list">
											{#each deepParseInfo.modbus.register_ranges as reg}
												<div class="reg-item">
													<span class="reg-range">{reg.start}-{reg.start + reg.count - 1}</span>
													<span class="reg-type">{reg.register_type}</span>
													<span class="reg-count">{reg.access_count}x</span>
												</div>
											{/each}
										</div>
									</div>
								{/if}

								<!-- Relationships -->
								{#if deepParseInfo.modbus.relationships.length > 0}
									<div class="detail-subsection">
										<h5 class="subsection-title">Relationships</h5>
										{#each deepParseInfo.modbus.relationships as rel}
											<div class="rel-item">
												<span class="rel-role">{rel.remote_role}</span>
												<span class="rel-ip">{rel.remote_ip}</span>
												{#if rel.unit_ids.length > 0}
													<span class="rel-uids">UID: {rel.unit_ids.join(',')}</span>
												{/if}
												<span class="rel-pkts">{rel.packet_count} pkts</span>
											</div>
										{/each}
									</div>
								{/if}

								<!-- Polling Intervals -->
								{#if deepParseInfo.modbus.polling_intervals.length > 0}
									<div class="detail-subsection">
										<h5 class="subsection-title">Polling Intervals</h5>
										{#each deepParseInfo.modbus.polling_intervals as poll}
											<div class="poll-item">
												<span class="poll-target">{poll.remote_ip} FC{poll.function_code}</span>
												<span class="poll-interval">
													avg {formatInterval(poll.avg_interval_ms)}
													<span class="poll-range">({formatInterval(poll.min_interval_ms)}-{formatInterval(poll.max_interval_ms)})</span>
												</span>
											</div>
										{/each}
									</div>
								{/if}
							</div>
						{/if}

						<!-- DNP3 Detail -->
						{#if deepParseInfo.dnp3}
							<div class="detail-section">
								<h4 class="section-title" style="color: var(--gm-dnp3, #10b981)">DNP3</h4>
								<div class="detail-row">
									<span class="detail-label">Role</span>
									<span class="detail-value role-badge">{deepParseInfo.dnp3.role}</span>
								</div>
								{#if deepParseInfo.dnp3.addresses.length > 0}
									<div class="detail-row">
										<span class="detail-label">Addresses</span>
										<span class="detail-value">{deepParseInfo.dnp3.addresses.join(', ')}</span>
									</div>
								{/if}
								{#if deepParseInfo.dnp3.has_unsolicited}
									<div class="detail-row">
										<span class="detail-label">Unsolicited</span>
										<span class="detail-value" style="color: #f59e0b">Yes (FC 130 detected)</span>
									</div>
								{/if}

								<!-- Function Codes -->
								{#if deepParseInfo.dnp3.function_codes.length > 0}
									<div class="detail-subsection">
										<h5 class="subsection-title">Function Codes</h5>
										<div class="fc-list">
											{#each deepParseInfo.dnp3.function_codes as fc}
												<div class="fc-item" class:write={fc.is_write}>
													<span class="fc-code">FC {fc.code}</span>
													<span class="fc-name">{fc.name}</span>
													<span class="fc-count">{fc.count.toLocaleString()}</span>
												</div>
											{/each}
										</div>
									</div>
								{/if}

								<!-- Relationships -->
								{#if deepParseInfo.dnp3.relationships.length > 0}
									<div class="detail-subsection">
										<h5 class="subsection-title">Relationships</h5>
										{#each deepParseInfo.dnp3.relationships as rel}
											<div class="rel-item">
												<span class="rel-role">{rel.remote_role}</span>
												<span class="rel-ip">{rel.remote_ip}</span>
												<span class="rel-pkts">{rel.packet_count} pkts</span>
											</div>
										{/each}
									</div>
								{/if}
							</div>
						{/if}
					{/if}
				</div>
			</div>
		{/if}
	</div>
</div>

<style>
	.inventory-container {
		display: flex;
		flex-direction: column;
		height: 100%;
	}

	.inventory-toolbar {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 10px 16px;
		border-bottom: 1px solid var(--gm-border);
		background: var(--gm-bg-secondary);
		gap: 16px;
		flex-shrink: 0;
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
		flex: 1;
		justify-content: flex-end;
	}

	.search-input {
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 4px;
		padding: 6px 12px;
		color: var(--gm-text-primary);
		font-family: inherit;
		font-size: 11px;
		width: 280px;
		outline: none;
		transition: border-color 0.15s;
	}

	.search-input:focus {
		border-color: var(--gm-border-active);
	}

	.search-input::placeholder {
		color: var(--gm-text-muted);
	}

	.protocol-select {
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 4px;
		padding: 6px 8px;
		color: var(--gm-text-secondary);
		font-family: inherit;
		font-size: 11px;
		outline: none;
	}

	.result-count {
		font-size: 10px;
		color: var(--gm-text-muted);
		white-space: nowrap;
	}

	/* ── Body (table + detail panel) ─────────────── */

	.inventory-body {
		flex: 1;
		display: flex;
		overflow: hidden;
	}

	/* ── Table ────────────────────────────────────────── */

	.table-container {
		flex: 1;
		overflow: auto;
	}

	.empty-state {
		display: flex;
		align-items: center;
		justify-content: center;
		height: 100%;
		color: var(--gm-text-muted);
		font-size: 12px;
	}

	.asset-table {
		width: 100%;
		border-collapse: collapse;
		font-size: 11px;
	}

	.asset-table thead {
		position: sticky;
		top: 0;
		z-index: 1;
	}

	.asset-table th {
		background: var(--gm-bg-panel);
		color: var(--gm-text-muted);
		font-size: 10px;
		font-weight: 600;
		letter-spacing: 0.5px;
		text-transform: uppercase;
		text-align: left;
		padding: 8px 12px;
		border-bottom: 1px solid var(--gm-border);
		white-space: nowrap;
	}

	.asset-table td {
		padding: 7px 12px;
		border-bottom: 1px solid rgba(45, 58, 79, 0.5);
		color: var(--gm-text-secondary);
		white-space: nowrap;
	}

	.asset-row {
		cursor: pointer;
		transition: background 0.1s;
	}

	.asset-row:hover {
		background: var(--gm-bg-hover);
	}

	.asset-row.selected {
		background: rgba(59, 130, 246, 0.1);
	}

	.cell-ip {
		font-weight: 600;
		color: var(--gm-text-primary) !important;
	}

	.cell-mac {
		color: var(--gm-text-muted) !important;
		font-size: 10px;
	}

	.cell-vendor {
		font-size: 10px;
	}

	.cell-numeric {
		text-align: right;
		font-variant-numeric: tabular-nums;
	}

	.cell-time {
		font-size: 10px;
		color: var(--gm-text-muted) !important;
	}

	.device-badge {
		font-size: 10px;
		font-weight: 600;
		padding: 2px 8px;
		border-radius: 3px;
		letter-spacing: 0.3px;
	}

	.proto-tag {
		font-size: 9px;
		background: rgba(100, 116, 139, 0.15);
		color: var(--gm-text-secondary);
		padding: 1px 6px;
		border-radius: 3px;
		margin-right: 4px;
	}

	.confidence-badge {
		font-size: 9px;
		font-weight: 600;
		padding: 2px 6px;
		border-radius: 3px;
		letter-spacing: 0.3px;
	}

	.confidence-none {
		color: var(--gm-text-muted);
		font-size: 10px;
	}

	/* ── Detail Panel ─────────────────────────────── */

	.detail-panel {
		width: 340px;
		min-width: 300px;
		border-left: 1px solid var(--gm-border);
		background: var(--gm-bg-secondary);
		display: flex;
		flex-direction: column;
		overflow: hidden;
	}

	.detail-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 10px 14px;
		border-bottom: 1px solid var(--gm-border);
		flex-shrink: 0;
	}

	.detail-title {
		font-size: 13px;
		font-weight: 600;
		color: var(--gm-text-primary);
		margin: 0;
	}

	.detail-close {
		background: none;
		border: none;
		color: var(--gm-text-muted);
		font-size: 18px;
		cursor: pointer;
		padding: 0 4px;
		line-height: 1;
	}

	.detail-close:hover {
		color: var(--gm-text-primary);
	}

	.detail-body {
		flex: 1;
		overflow-y: auto;
		padding: 12px 14px;
	}

	.detail-section {
		margin-bottom: 16px;
	}

	.detail-row {
		display: flex;
		justify-content: space-between;
		align-items: baseline;
		padding: 3px 0;
		font-size: 11px;
	}

	.detail-label {
		color: var(--gm-text-muted);
		font-size: 10px;
		text-transform: uppercase;
		letter-spacing: 0.3px;
	}

	.detail-value {
		color: var(--gm-text-secondary);
		text-align: right;
	}

	.detail-value.highlight {
		color: var(--gm-text-primary);
		font-weight: 600;
	}

	.detail-loading {
		color: var(--gm-text-muted);
		font-size: 11px;
		padding: 16px 0;
		text-align: center;
	}

	.section-title {
		font-size: 11px;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.5px;
		margin: 0 0 8px;
		padding-bottom: 4px;
		border-bottom: 1px solid var(--gm-border);
	}

	.detail-subsection {
		margin-top: 10px;
	}

	.subsection-title {
		font-size: 10px;
		font-weight: 600;
		color: var(--gm-text-muted);
		margin: 0 0 6px;
		text-transform: uppercase;
		letter-spacing: 0.3px;
	}

	.role-badge {
		text-transform: capitalize;
		font-weight: 600;
	}

	/* ── Function Code List ───────────────────── */

	.fc-list {
		display: flex;
		flex-direction: column;
		gap: 3px;
	}

	.fc-item {
		display: flex;
		align-items: center;
		gap: 6px;
		font-size: 10px;
		padding: 2px 0;
	}

	.fc-item.write {
		color: var(--gm-text-primary);
	}

	.fc-code {
		font-weight: 600;
		width: 36px;
		color: var(--gm-text-secondary);
	}

	.fc-item.write .fc-code {
		color: #ef4444;
	}

	.fc-name {
		flex: 1;
		color: var(--gm-text-secondary);
	}

	.fc-count {
		color: var(--gm-text-muted);
		font-variant-numeric: tabular-nums;
	}

	/* ── Register Ranges ─────────────────────── */

	.reg-list {
		display: flex;
		flex-direction: column;
		gap: 3px;
	}

	.reg-item {
		display: flex;
		align-items: center;
		gap: 8px;
		font-size: 10px;
	}

	.reg-range {
		font-weight: 600;
		color: var(--gm-text-secondary);
		min-width: 60px;
	}

	.reg-type {
		color: var(--gm-text-muted);
		flex: 1;
		text-transform: capitalize;
	}

	.reg-count {
		color: var(--gm-text-muted);
		font-variant-numeric: tabular-nums;
	}

	/* ── Relationships ────────────────────────── */

	.rel-item {
		display: flex;
		align-items: center;
		gap: 6px;
		font-size: 10px;
		padding: 3px 0;
	}

	.rel-role {
		font-size: 8px;
		font-weight: 600;
		text-transform: uppercase;
		padding: 1px 5px;
		border-radius: 3px;
		background: rgba(100, 116, 139, 0.15);
		color: var(--gm-text-secondary);
		letter-spacing: 0.3px;
	}

	.rel-ip {
		font-weight: 600;
		color: var(--gm-text-secondary);
		flex: 1;
	}

	.rel-uids {
		color: var(--gm-text-muted);
		font-size: 9px;
	}

	.rel-pkts {
		color: var(--gm-text-muted);
		font-variant-numeric: tabular-nums;
	}

	/* ── Polling Intervals ────────────────────── */

	.poll-item {
		display: flex;
		justify-content: space-between;
		align-items: baseline;
		font-size: 10px;
		padding: 3px 0;
	}

	.poll-target {
		color: var(--gm-text-secondary);
	}

	.poll-interval {
		color: var(--gm-text-primary);
		font-weight: 600;
	}

	.poll-range {
		color: var(--gm-text-muted);
		font-weight: 400;
		font-size: 9px;
	}
</style>
