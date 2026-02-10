<script lang="ts">
	import { filteredAssets, assetFilter, selectedAssetId, protocolFilter } from '$lib/stores';
	import type { DeviceType, IcsProtocol } from '$lib/types';

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

	function handleFilterInput(event: Event) {
		const target = event.target as HTMLInputElement;
		assetFilter.set(target.value);
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
						<th>Vendor</th>
						<th>Protocols</th>
						<th>Packets</th>
						<th>First Seen</th>
						<th>Last Seen</th>
					</tr>
				</thead>
				<tbody>
					{#each $filteredAssets as asset}
						<tr
							class="asset-row"
							class:selected={$selectedAssetId === asset.id}
							onclick={() => selectedAssetId.set(asset.id)}
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
							<td class="cell-vendor">{asset.vendor ?? '—'}</td>
							<td class="cell-protocols">
								{#each asset.protocols as proto}
									<span class="proto-tag">{proto}</span>
								{/each}
							</td>
							<td class="cell-numeric">{asset.packet_count.toLocaleString()}</td>
							<td class="cell-time">{new Date(asset.first_seen).toLocaleString()}</td>
							<td class="cell-time">{new Date(asset.last_seen).toLocaleString()}</td>
						</tr>
					{/each}
				</tbody>
			</table>
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
</style>
