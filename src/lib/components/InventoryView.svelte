<script lang="ts">
	import { filteredAssets, assetFilter, selectedAssetId, selectedAsset, protocolFilter, assets } from '$lib/stores';
	import { getDeepParseInfo, getAssets, updateAsset, bulkUpdateAssets } from '$lib/utils/tauri';
	import type { DeviceType, IcsProtocol, DeepParseInfo, AssetUpdate, Asset } from '$lib/types';

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

	const deviceTypeOptions: DeviceType[] = ['plc', 'rtu', 'hmi', 'historian', 'engineering_workstation', 'scada_server', 'it_device', 'unknown'];

	const purdueLabels: Record<number, string> = {
		0: 'L0 — Process',
		1: 'L1 — Control',
		2: 'L2 — Supervisory',
		3: 'L3 — Operations',
		4: 'L4 — Enterprise',
		5: 'L5 — Internet/DMZ'
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

	// Country code → flag emoji mapping
	function countryFlag(code: string): string {
		const base = 0x1F1E6;
		const a = code.charCodeAt(0) - 65;
		const b = code.charCodeAt(1) - 65;
		return String.fromCodePoint(base + a) + String.fromCodePoint(base + b);
	}

	let deepParseInfo = $state<DeepParseInfo | null>(null);
	let loadingDeepParse = $state(false);
	let lastLoadedIp = $state<string | null>(null);

	// Editing state
	let isEditing = $state(false);
	let editDeviceType = $state<string>('');
	let editHostname = $state('');
	let editNotes = $state('');
	let editPurdueLevel = $state<number | null>(null);
	let editTags = $state('');
	let editSaving = $state(false);
	let editMessage = $state('');

	// Bulk selection
	let selectedIds = $state<Set<string>>(new Set());
	let showBulkPanel = $state(false);
	let bulkDeviceType = $state<string>('');
	let bulkPurdueLevel = $state<string>('');
	let bulkSaving = $state(false);

	// Load deep parse info when selected asset changes
	$effect(() => {
		const asset = $selectedAsset;
		if (asset && asset.ip_address !== lastLoadedIp) {
			lastLoadedIp = asset.ip_address;
			isEditing = false;
			editMessage = '';
			loadDeepParseInfo(asset.ip_address);
		} else if (!asset) {
			deepParseInfo = null;
			lastLoadedIp = null;
			isEditing = false;
			editMessage = '';
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

	function startEditing(asset: Asset) {
		editDeviceType = asset.device_type;
		editHostname = asset.hostname ?? '';
		editNotes = asset.notes;
		editPurdueLevel = asset.purdue_level ?? null;
		editTags = asset.tags.join(', ');
		editMessage = '';
		isEditing = true;
	}

	async function saveEdits() {
		const asset = $selectedAsset;
		if (!asset) return;
		editSaving = true;
		editMessage = '';

		const updates: AssetUpdate = {};
		if (editDeviceType !== asset.device_type) updates.device_type = editDeviceType;
		if (editHostname !== (asset.hostname ?? '')) updates.hostname = editHostname;
		if (editNotes !== asset.notes) updates.notes = editNotes;
		const newPurdue = editPurdueLevel ?? 255;
		const oldPurdue = asset.purdue_level ?? 255;
		if (newPurdue !== oldPurdue) updates.purdue_level = editPurdueLevel ?? 255;
		const newTags = editTags.split(',').map(t => t.trim()).filter(Boolean);
		if (JSON.stringify(newTags) !== JSON.stringify(asset.tags)) updates.tags = newTags;

		if (Object.keys(updates).length === 0) {
			isEditing = false;
			editSaving = false;
			return;
		}

		try {
			await updateAsset(asset.id, updates);
			// Refresh assets
			const refreshed = await getAssets();
			assets.set(refreshed);
			editMessage = 'Saved';
			isEditing = false;
		} catch (err) {
			editMessage = `Error: ${err}`;
		}
		editSaving = false;
	}

	function toggleSelect(id: string, event: MouseEvent) {
		event.stopPropagation();
		const next = new Set(selectedIds);
		if (next.has(id)) {
			next.delete(id);
		} else {
			next.add(id);
		}
		selectedIds = next;
		showBulkPanel = next.size > 0;
	}

	function selectAll() {
		if (selectedIds.size === $filteredAssets.length) {
			selectedIds = new Set();
			showBulkPanel = false;
		} else {
			selectedIds = new Set($filteredAssets.map(a => a.id));
			showBulkPanel = true;
		}
	}

	async function applyBulkUpdate() {
		if (selectedIds.size === 0) return;
		bulkSaving = true;
		const updates: AssetUpdate = {};
		if (bulkDeviceType) updates.device_type = bulkDeviceType;
		if (bulkPurdueLevel) updates.purdue_level = parseInt(bulkPurdueLevel);
		if (Object.keys(updates).length === 0) {
			bulkSaving = false;
			return;
		}
		try {
			await bulkUpdateAssets(Array.from(selectedIds), updates);
			const refreshed = await getAssets();
			assets.set(refreshed);
			selectedIds = new Set();
			showBulkPanel = false;
			bulkDeviceType = '';
			bulkPurdueLevel = '';
		} catch (err) {
			console.error('Bulk update failed:', err);
		}
		bulkSaving = false;
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

	<!-- Bulk Operations Bar -->
	{#if showBulkPanel}
		<div class="bulk-bar">
			<span class="bulk-count">{selectedIds.size} selected</span>
			<select class="bulk-select" bind:value={bulkDeviceType}>
				<option value="">Set Type...</option>
				{#each deviceTypeOptions as dt}
					<option value={dt}>{deviceTypeLabels[dt]}</option>
				{/each}
			</select>
			<select class="bulk-select" bind:value={bulkPurdueLevel}>
				<option value="">Set Purdue...</option>
				{#each [0,1,2,3,4,5] as level}
					<option value={level.toString()}>{purdueLabels[level]}</option>
				{/each}
			</select>
			<button class="bulk-apply" onclick={applyBulkUpdate} disabled={bulkSaving || (!bulkDeviceType && !bulkPurdueLevel)}>
				Apply
			</button>
			<button class="bulk-cancel" onclick={() => { selectedIds = new Set(); showBulkPanel = false; }}>
				Clear
			</button>
		</div>
	{/if}

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
							<th class="th-check">
								<input type="checkbox"
									checked={selectedIds.size === $filteredAssets.length && $filteredAssets.length > 0}
									onchange={selectAll}
								/>
							</th>
							<th>IP Address</th>
							<th>MAC Address</th>
							<th>Type</th>
							<th>Confidence</th>
							<th>Vendor</th>
							<th>OUI</th>
							<th>Product</th>
							<th>Protocols</th>
							<th>Country</th>
							<th>Packets</th>
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
								<td class="cell-check">
									<input type="checkbox"
										checked={selectedIds.has(asset.id)}
										onclick={(e) => toggleSelect(asset.id, e)}
									/>
								</td>
								<td class="cell-ip">
									{asset.ip_address}
									{#if asset.is_public_ip}
										<span class="public-badge" title="Public IP">PUB</span>
									{/if}
								</td>
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
								<td class="cell-vendor cell-oui">{asset.oui_vendor ?? '—'}</td>
								<td class="cell-vendor">{asset.product_family ?? '—'}</td>
								<td class="cell-protocols">
									{#each asset.protocols as proto}
										<span class="proto-tag">{proto}</span>
									{/each}
								</td>
								<td class="cell-country">
									{#if asset.country}
										<span title={asset.country}>{countryFlag(asset.country)}</span>
									{:else}
										—
									{/if}
								</td>
								<td class="cell-numeric">{asset.packet_count.toLocaleString()}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			{/if}
		</div>

		<!-- Detail Panel -->
		{#if $selectedAsset}
			<div class="detail-panel">
				<div class="detail-header">
					<h3 class="detail-title">{$selectedAsset.ip_address}</h3>
					<div class="detail-header-actions">
						{#if !isEditing}
							<button class="edit-btn" onclick={() => startEditing($selectedAsset!)} title="Edit asset">Edit</button>
						{/if}
						<button class="detail-close" onclick={() => selectedAssetId.set(null)}>&times;</button>
					</div>
				</div>

				<div class="detail-body">
					{#if editMessage}
						<div class="edit-message" class:success={editMessage === 'Saved'} class:error={editMessage.startsWith('Error')}>
							{editMessage}
						</div>
					{/if}

					<!-- Editable fields -->
					{#if isEditing}
						<div class="detail-section edit-section">
							<h4 class="section-title">Edit Asset</h4>
							<div class="edit-group">
								<label class="edit-label" for="edit-device-type">Device Type</label>
								<select id="edit-device-type" class="edit-select" bind:value={editDeviceType}>
									{#each deviceTypeOptions as dt}
										<option value={dt}>{deviceTypeLabels[dt]}</option>
									{/each}
								</select>
							</div>
							<div class="edit-group">
								<label class="edit-label" for="edit-hostname">Hostname</label>
								<input id="edit-hostname" class="edit-input" type="text" bind:value={editHostname} placeholder="e.g., PLC-BOILER-01" />
							</div>
							<div class="edit-group">
								<label class="edit-label" for="edit-purdue">Purdue Level</label>
								<select id="edit-purdue" class="edit-select" bind:value={editPurdueLevel}>
									<option value={null}>Not set</option>
									{#each [0,1,2,3,4,5] as level}
										<option value={level}>{purdueLabels[level]}</option>
									{/each}
								</select>
							</div>
							<div class="edit-group">
								<label class="edit-label" for="edit-tags">Tags (comma separated)</label>
								<input id="edit-tags" class="edit-input" type="text" bind:value={editTags} placeholder="e.g., critical, zone-a" />
							</div>
							<div class="edit-group">
								<label class="edit-label" for="edit-notes">Notes</label>
								<textarea id="edit-notes" class="edit-textarea" bind:value={editNotes} rows="3" placeholder="Freeform notes about this asset..."></textarea>
							</div>
							<div class="edit-actions">
								<button class="action-btn primary small" onclick={saveEdits} disabled={editSaving}>
									{editSaving ? 'Saving...' : 'Save'}
								</button>
								<button class="action-btn secondary small" onclick={() => { isEditing = false; editMessage = ''; }}>
									Cancel
								</button>
							</div>
						</div>
					{:else}
						<!-- Read-only basic info -->
						<div class="detail-section">
							<div class="detail-row">
								<span class="detail-label">Type</span>
								<span class="detail-value">{deviceTypeLabels[$selectedAsset.device_type] ?? $selectedAsset.device_type}</span>
							</div>
							{#if $selectedAsset.hostname}
								<div class="detail-row">
									<span class="detail-label">Hostname</span>
									<span class="detail-value">{$selectedAsset.hostname}</span>
								</div>
							{/if}
							{#if $selectedAsset.vendor}
								<div class="detail-row">
									<span class="detail-label">Vendor</span>
									<span class="detail-value">{$selectedAsset.vendor}</span>
								</div>
							{/if}
							{#if $selectedAsset.oui_vendor}
								<div class="detail-row">
									<span class="detail-label">OUI Vendor</span>
									<span class="detail-value">{$selectedAsset.oui_vendor}</span>
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
										<span
											class="confidence-badge"
											style="color: {confidenceColors[$selectedAsset.confidence] ?? '#64748b'};
											       background: {(confidenceColors[$selectedAsset.confidence] ?? '#64748b')}18"
										>
											{$selectedAsset.confidence}/5 ({confidenceLabels[$selectedAsset.confidence]})
										</span>
									{:else}
										—
									{/if}
								</span>
							</div>
							{#if $selectedAsset.purdue_level != null}
								<div class="detail-row">
									<span class="detail-label">Purdue</span>
									<span class="detail-value">{purdueLabels[$selectedAsset.purdue_level] ?? `L${$selectedAsset.purdue_level}`}</span>
								</div>
							{/if}
							{#if $selectedAsset.country}
								<div class="detail-row">
									<span class="detail-label">Country</span>
									<span class="detail-value">{countryFlag($selectedAsset.country)} {$selectedAsset.country}</span>
								</div>
							{/if}
							{#if $selectedAsset.is_public_ip}
								<div class="detail-row">
									<span class="detail-label">Public IP</span>
									<span class="detail-value finding">Yes — unexpected for OT</span>
								</div>
							{/if}
							{#if $selectedAsset.tags.length > 0}
								<div class="detail-row">
									<span class="detail-label">Tags</span>
									<span class="detail-value">
										{#each $selectedAsset.tags as tag}
											<span class="tag-badge">{tag}</span>
										{/each}
									</span>
								</div>
							{/if}
							{#if $selectedAsset.notes}
								<div class="detail-row notes-row">
									<span class="detail-label">Notes</span>
									<span class="detail-value notes-text">{$selectedAsset.notes}</span>
								</div>
							{/if}

							<!-- Confidence Breakdown -->
							{#if $selectedAsset.signature_matches.length > 0}
								<div class="detail-subsection">
									<h5 class="subsection-title">Confidence Breakdown</h5>
									{#each $selectedAsset.signature_matches as match}
										<div class="confidence-row">
											<span
												class="confidence-badge small"
												style="color: {confidenceColors[match.confidence] ?? '#64748b'};
												       background: {(confidenceColors[match.confidence] ?? '#64748b')}18"
											>{match.confidence}</span>
											<span class="match-name">{match.signature_name}</span>
											{#if match.vendor}
												<span class="match-vendor">{match.vendor}</span>
											{/if}
										</div>
									{/each}
								</div>
							{/if}
						</div>
					{/if}

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

	/* ── Bulk Operations Bar ──────────────────────── */

	.bulk-bar {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 8px 16px;
		background: rgba(59, 130, 246, 0.08);
		border-bottom: 1px solid rgba(59, 130, 246, 0.2);
		flex-shrink: 0;
	}

	.bulk-count {
		font-size: 11px;
		font-weight: 600;
		color: #3b82f6;
	}

	.bulk-select {
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 4px;
		padding: 4px 8px;
		color: var(--gm-text-secondary);
		font-family: inherit;
		font-size: 10px;
	}

	.bulk-apply {
		padding: 4px 12px;
		background: rgba(59, 130, 246, 0.15);
		border: 1px solid rgba(59, 130, 246, 0.3);
		border-radius: 4px;
		color: #3b82f6;
		font-family: inherit;
		font-size: 10px;
		font-weight: 600;
		cursor: pointer;
	}

	.bulk-apply:disabled { opacity: 0.5; cursor: not-allowed; }

	.bulk-cancel {
		padding: 4px 8px;
		background: none;
		border: 1px solid var(--gm-border);
		border-radius: 4px;
		color: var(--gm-text-muted);
		font-family: inherit;
		font-size: 10px;
		cursor: pointer;
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

	.th-check { width: 32px; }

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

	.cell-check { width: 32px; text-align: center; }

	.cell-ip {
		font-weight: 600;
		color: var(--gm-text-primary) !important;
	}

	.public-badge {
		font-size: 8px;
		font-weight: 700;
		padding: 1px 4px;
		border-radius: 3px;
		background: rgba(239, 68, 68, 0.15);
		color: #ef4444;
		margin-left: 4px;
		letter-spacing: 0.5px;
	}

	.cell-mac {
		color: var(--gm-text-muted) !important;
		font-size: 10px;
	}

	.cell-vendor { font-size: 10px; }
	.cell-oui { color: var(--gm-text-muted) !important; }
	.cell-country { text-align: center; }

	.cell-numeric {
		text-align: right;
		font-variant-numeric: tabular-nums;
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

	.confidence-badge.small {
		font-size: 8px;
		padding: 1px 5px;
	}

	.confidence-none {
		color: var(--gm-text-muted);
		font-size: 10px;
	}

	/* ── Detail Panel ─────────────────────────────── */

	.detail-panel {
		width: 360px;
		min-width: 320px;
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

	.detail-header-actions {
		display: flex;
		align-items: center;
		gap: 6px;
	}

	.detail-title {
		font-size: 13px;
		font-weight: 600;
		color: var(--gm-text-primary);
		margin: 0;
	}

	.edit-btn {
		padding: 3px 10px;
		background: rgba(59, 130, 246, 0.1);
		border: 1px solid rgba(59, 130, 246, 0.3);
		border-radius: 4px;
		color: #3b82f6;
		font-family: inherit;
		font-size: 10px;
		font-weight: 600;
		cursor: pointer;
	}

	.edit-btn:hover { background: rgba(59, 130, 246, 0.2); }

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

	.notes-row {
		flex-direction: column;
		gap: 4px;
	}

	.notes-text {
		text-align: left !important;
		white-space: pre-wrap;
		font-size: 10px;
		line-height: 1.5;
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

	.detail-value.finding {
		color: #ef4444;
		font-weight: 600;
	}

	.tag-badge {
		font-size: 9px;
		padding: 1px 6px;
		border-radius: 3px;
		background: rgba(139, 92, 246, 0.15);
		color: #8b5cf6;
		margin-left: 3px;
	}

	.detail-loading {
		color: var(--gm-text-muted);
		font-size: 11px;
		padding: 16px 0;
		text-align: center;
	}

	.edit-message {
		padding: 6px 10px;
		border-radius: 4px;
		font-size: 10px;
		margin-bottom: 10px;
	}

	.edit-message.success {
		background: rgba(16, 185, 129, 0.1);
		color: #10b981;
	}

	.edit-message.error {
		background: rgba(239, 68, 68, 0.1);
		color: #ef4444;
	}

	/* ── Edit Form ─────────────────────────────────── */

	.edit-section {
		background: var(--gm-bg-panel);
		padding: 12px;
		border-radius: 6px;
	}

	.edit-group {
		margin-bottom: 8px;
	}

	.edit-label {
		display: block;
		font-size: 9px;
		font-weight: 600;
		color: var(--gm-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.3px;
		margin-bottom: 3px;
	}

	.edit-input, .edit-select, .edit-textarea {
		width: 100%;
		padding: 5px 8px;
		background: var(--gm-bg-primary);
		border: 1px solid var(--gm-border);
		border-radius: 4px;
		color: var(--gm-text-primary);
		font-family: inherit;
		font-size: 11px;
		outline: none;
		box-sizing: border-box;
	}

	.edit-textarea {
		resize: vertical;
		min-height: 48px;
	}

	.edit-input:focus, .edit-select:focus, .edit-textarea:focus {
		border-color: rgba(59, 130, 246, 0.5);
	}

	.edit-actions {
		display: flex;
		gap: 6px;
		margin-top: 10px;
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

	.action-btn.small {
		padding: 5px 14px;
		font-size: 10px;
	}

	.action-btn.primary {
		background: rgba(16, 185, 129, 0.15);
		border-color: rgba(16, 185, 129, 0.3);
		color: #10b981;
	}

	.action-btn.primary:hover:not(:disabled) {
		background: rgba(16, 185, 129, 0.25);
	}

	.action-btn.secondary {
		background: rgba(100, 116, 139, 0.1);
		border-color: rgba(100, 116, 139, 0.3);
		color: var(--gm-text-secondary);
	}

	.action-btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	/* ── Confidence Breakdown ───────────────────── */

	.confidence-row {
		display: flex;
		align-items: center;
		gap: 6px;
		font-size: 10px;
		padding: 2px 0;
	}

	.match-name {
		color: var(--gm-text-secondary);
		flex: 1;
	}

	.match-vendor {
		color: var(--gm-text-muted);
		font-size: 9px;
	}

	/* ── Deep Parse sections ─────────────────────── */

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

	.fc-item.write { color: var(--gm-text-primary); }

	.fc-code {
		font-weight: 600;
		width: 36px;
		color: var(--gm-text-secondary);
	}

	.fc-item.write .fc-code { color: #ef4444; }

	.fc-name {
		flex: 1;
		color: var(--gm-text-secondary);
	}

	.fc-count {
		color: var(--gm-text-muted);
		font-variant-numeric: tabular-nums;
	}

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

	.poll-item {
		display: flex;
		justify-content: space-between;
		align-items: baseline;
		font-size: 10px;
		padding: 3px 0;
	}

	.poll-target { color: var(--gm-text-secondary); }

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
