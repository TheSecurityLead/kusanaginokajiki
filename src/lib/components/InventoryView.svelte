<script lang="ts">
	import { filteredAssets, assetFilter, selectedAssetId, selectedAsset, protocolFilter, assets, assetCount } from '$lib/stores';
	import { getDeepParseInfo, getAssets, getDataCounts, updateAsset, bulkUpdateAssets, getCredentialWarnings, getAlertsForIp, getCveWarnings, getDeviceZeekEvents } from '$lib/utils/tauri';
	import type { DeviceType, IcsProtocol, DeepParseInfo, AssetUpdate, Asset, EnipDetail, S7Detail, BacnetDetail, Iec104Detail, ProfinetDcpDetail, LldpDetail, DefaultCredential, CorrelatedAlert, CveMatch, DeviceZeekEvents } from '$lib/types';

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
	let bulkTag = $state('');
	let bulkNotes = $state('');
	let bulkSaving = $state(false);

	// Wireshark filter / toast state
	let toastMessage = $state('');
	let toastTimer: ReturnType<typeof setTimeout> | null = null;

	function showToast(msg: string) {
		toastMessage = msg;
		if (toastTimer) clearTimeout(toastTimer);
		toastTimer = setTimeout(() => { toastMessage = ''; }, 2000);
	}

	function copyWiresharkFilter(filter: string) {
		navigator.clipboard.writeText(filter).then(() => showToast('Copied!'));
	}

	function getOtPort(protocols: string[]): number | null {
		const portMap: Record<string, number> = {
			modbus: 502, dnp3: 20000, ethernet_ip: 44818,
			s7comm: 102, bacnet: 47808, iec104: 2404, profinet: 34964,
			opc_ua: 4840
		};
		for (const p of protocols) {
			const port = portMap[p.toLowerCase()];
			if (port) return port;
		}
		return null;
	}

	// Default credential warnings for selected asset
	let credWarnings = $state<DefaultCredential[]>([]);
	let loadingCreds = $state(false);

	// CVE warnings for selected asset
	let cveWarnings = $state<CveMatch[]>([]);
	let loadingCves = $state(false);

	// Zeek per-device events for selected asset
	let zeekEvents = $state<DeviceZeekEvents | null>(null);
	let loadingZeek = $state(false);
	let zeekEventsExpanded = $state(false);

	// IDS/SIEM alerts for selected asset
	let assetAlerts = $state<CorrelatedAlert[]>([]);

	$effect(() => {
		const asset = $selectedAsset;
		if (asset) {
			loadCredWarnings();
			loadCveWarnings(asset.ip_address);
			loadZeekEvents(asset.ip_address);
			loadAssetAlerts(asset.ip_address);
		} else {
			credWarnings = [];
			cveWarnings = [];
			zeekEvents = null;
			assetAlerts = [];
		}
	});

	async function loadAssetAlerts(ip: string) {
		try {
			assetAlerts = await getAlertsForIp(ip);
		} catch {
			assetAlerts = [];
		}
	}

	async function loadCredWarnings() {
		loadingCreds = true;
		try {
			const all = await getCredentialWarnings();
			const asset = $selectedAsset;
			if (asset) {
				const vendor = (asset.vendor ?? asset.oui_vendor ?? '').toLowerCase();
				const product = (asset.product_family ?? '').toLowerCase();
				// Filter client-side by vendor/product if we have them, otherwise show all
				if (vendor || product) {
					credWarnings = all.filter(cw => {
						const cwVendor = cw.vendor.toLowerCase();
						return vendor ? cwVendor.includes(vendor) || vendor.includes(cwVendor) : false;
					});
				} else {
					credWarnings = [];
				}
			} else {
				credWarnings = [];
			}
		} catch {
			credWarnings = [];
		}
		loadingCreds = false;
	}

	async function loadCveWarnings(ip: string) {
		loadingCves = true;
		try {
			cveWarnings = await getCveWarnings(ip);
		} catch {
			cveWarnings = [];
		}
		loadingCves = false;
	}

	async function loadZeekEvents(ip: string) {
		loadingZeek = true;
		try {
			const events = await getDeviceZeekEvents(ip);
			const total = events.conn_log_entries + events.modbus_events + events.dnp3_events +
				events.dns_queries + events.http_requests;
			zeekEvents = total > 0 ? events : null;
		} catch {
			zeekEvents = null;
		}
		loadingZeek = false;
	}

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
			const page = await getAssets(0, 200);
			assets.set(page.assets);
			assetCount.set(page.total);
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
		if (bulkTag.trim()) updates.tags = [bulkTag.trim()];
		if (bulkNotes.trim()) updates.notes = bulkNotes.trim();
		if (Object.keys(updates).length === 0) {
			bulkSaving = false;
			return;
		}
		try {
			await bulkUpdateAssets(Array.from(selectedIds), updates);
			const page = await getAssets(0, 200);
			assets.set(page.assets);
			assetCount.set(page.total);
			selectedIds = new Set();
			showBulkPanel = false;
			bulkDeviceType = '';
			bulkPurdueLevel = '';
			bulkTag = '';
			bulkNotes = '';
		} catch (err) {
			console.error('Bulk update failed:', err);
		}
		bulkSaving = false;
	}

	function handleFilterInput(event: Event) {
		const target = event.target as HTMLInputElement;
		assetFilter.set(target.value);
		invPage = 0;
	}

	function formatInterval(ms: number): string {
		if (ms < 1000) return `${ms.toFixed(0)}ms`;
		return `${(ms / 1000).toFixed(1)}s`;
	}

	// Pagination for the asset table — prevents DOM overload on large datasets.
	const INV_PAGE_SIZE = 50;
	let invPage = $state(0);

	// ── Sortable Columns ──────────────────────────────────────────
	type ColKey = 'ip' | 'mac' | 'type' | 'confidence' | 'vendor' | 'oui' | 'product' |
	              'protocols' | 'country' | 'packets' | 'purdue' | 'first_seen' | 'last_seen';

	const allColumns: { key: ColKey; label: string }[] = [
		{ key: 'ip', label: 'IP Address' },
		{ key: 'mac', label: 'MAC Address' },
		{ key: 'type', label: 'Type' },
		{ key: 'confidence', label: 'Confidence' },
		{ key: 'vendor', label: 'Vendor' },
		{ key: 'oui', label: 'OUI' },
		{ key: 'product', label: 'Product' },
		{ key: 'protocols', label: 'Protocols' },
		{ key: 'country', label: 'Country' },
		{ key: 'packets', label: 'Packets' },
		{ key: 'purdue', label: 'Purdue Level' },
		{ key: 'first_seen', label: 'First Seen' },
		{ key: 'last_seen', label: 'Last Seen' },
	];

	let visibleColumns = $state<Set<ColKey>>(new Set(['ip', 'mac', 'type', 'confidence', 'vendor', 'oui']));
	let showColumnPicker = $state(false);
	let sortColumn = $state<ColKey | ''>('');
	let sortDirection = $state<'asc' | 'desc'>('asc');

	function compareIps(a: string, b: string): number {
		const pa = a.split('.').map(Number);
		const pb = b.split('.').map(Number);
		for (let i = 0; i < 4; i++) {
			if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0);
		}
		return 0;
	}

	function toggleSort(key: ColKey) {
		if (sortColumn === key) {
			if (sortDirection === 'asc') {
				sortDirection = 'desc';
			} else {
				sortColumn = '';
				sortDirection = 'asc';
			}
		} else {
			sortColumn = key;
			sortDirection = 'asc';
		}
		invPage = 0;
	}

	function toggleColumnVisibility(key: ColKey) {
		const next = new Set(visibleColumns);
		if (next.has(key)) { next.delete(key); } else { next.add(key); }
		visibleColumns = next;
	}

	let sortedAssets = $derived.by(() => {
		const list = [...$filteredAssets];
		if (!sortColumn) return list;
		const dir = sortDirection === 'asc' ? 1 : -1;
		list.sort((a, b) => {
			switch (sortColumn) {
				case 'ip': return dir * compareIps(a.ip_address, b.ip_address);
				case 'mac': return dir * (a.mac_address ?? '').localeCompare(b.mac_address ?? '');
				case 'type': return dir * a.device_type.localeCompare(b.device_type);
				case 'confidence': return dir * (a.confidence - b.confidence);
				case 'vendor': return dir * (a.vendor ?? '').localeCompare(b.vendor ?? '');
				case 'oui': return dir * (a.oui_vendor ?? '').localeCompare(b.oui_vendor ?? '');
				case 'product': return dir * (a.product_family ?? '').localeCompare(b.product_family ?? '');
				case 'protocols': return dir * a.protocols.join(',').localeCompare(b.protocols.join(','));
				case 'country': return dir * (a.country ?? '').localeCompare(b.country ?? '');
				case 'packets': return dir * (a.packet_count - b.packet_count);
				case 'purdue': return dir * ((a.purdue_level ?? -1) - (b.purdue_level ?? -1));
				case 'first_seen': return dir * a.first_seen.localeCompare(b.first_seen);
				case 'last_seen': return dir * a.last_seen.localeCompare(b.last_seen);
				default: return 0;
			}
		});
		return list;
	});

	let invTotalPages = $derived(Math.max(1, Math.ceil(sortedAssets.length / INV_PAGE_SIZE)));
	let pagedAssets = $derived(
		sortedAssets.slice(invPage * INV_PAGE_SIZE, (invPage + 1) * INV_PAGE_SIZE)
	);

	// Reset to page 0 whenever the filter changes.
	$effect(() => {
		$filteredAssets; // track dependency
		invPage = 0;
	});
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
			<div class="col-picker-wrap">
				<button class="col-picker-btn" onclick={() => showColumnPicker = !showColumnPicker}>
					Columns ▾
				</button>
				{#if showColumnPicker}
					<div class="col-picker-dropdown">
						{#each allColumns as col}
							<label class="col-picker-item">
								<input type="checkbox"
									checked={visibleColumns.has(col.key)}
									onchange={() => toggleColumnVisibility(col.key)}
								/>
								{col.label}
							</label>
						{/each}
					</div>
				{/if}
			</div>
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
			<input class="bulk-input" type="text" placeholder="Add tag..." bind:value={bulkTag} />
			<input class="bulk-input" type="text" placeholder="Set notes..." bind:value={bulkNotes} />
			<button class="bulk-apply" onclick={applyBulkUpdate} disabled={bulkSaving || (!bulkDeviceType && !bulkPurdueLevel && !bulkTag.trim() && !bulkNotes.trim())}>
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
							{#if visibleColumns.has('ip')}
								<th class="sortable-th" class:sort-active={sortColumn === 'ip'} onclick={() => toggleSort('ip')}>
									IP Address {#if sortColumn === 'ip'}<span class="sort-arrow">{sortDirection === 'asc' ? '▲' : '▼'}</span>{/if}
								</th>
							{/if}
							{#if visibleColumns.has('mac')}
								<th class="sortable-th" class:sort-active={sortColumn === 'mac'} onclick={() => toggleSort('mac')}>
									MAC Address {#if sortColumn === 'mac'}<span class="sort-arrow">{sortDirection === 'asc' ? '▲' : '▼'}</span>{/if}
								</th>
							{/if}
							{#if visibleColumns.has('type')}
								<th class="sortable-th" class:sort-active={sortColumn === 'type'} onclick={() => toggleSort('type')}>
									Type {#if sortColumn === 'type'}<span class="sort-arrow">{sortDirection === 'asc' ? '▲' : '▼'}</span>{/if}
								</th>
							{/if}
							{#if visibleColumns.has('confidence')}
								<th class="sortable-th" class:sort-active={sortColumn === 'confidence'} onclick={() => toggleSort('confidence')}>
									Confidence {#if sortColumn === 'confidence'}<span class="sort-arrow">{sortDirection === 'asc' ? '▲' : '▼'}</span>{/if}
								</th>
							{/if}
							{#if visibleColumns.has('vendor')}
								<th class="sortable-th" class:sort-active={sortColumn === 'vendor'} onclick={() => toggleSort('vendor')}>
									Vendor {#if sortColumn === 'vendor'}<span class="sort-arrow">{sortDirection === 'asc' ? '▲' : '▼'}</span>{/if}
								</th>
							{/if}
							{#if visibleColumns.has('oui')}
								<th class="sortable-th" class:sort-active={sortColumn === 'oui'} onclick={() => toggleSort('oui')}>
									OUI {#if sortColumn === 'oui'}<span class="sort-arrow">{sortDirection === 'asc' ? '▲' : '▼'}</span>{/if}
								</th>
							{/if}
							{#if visibleColumns.has('product')}
								<th class="sortable-th" class:sort-active={sortColumn === 'product'} onclick={() => toggleSort('product')}>
									Product {#if sortColumn === 'product'}<span class="sort-arrow">{sortDirection === 'asc' ? '▲' : '▼'}</span>{/if}
								</th>
							{/if}
							{#if visibleColumns.has('protocols')}
								<th class="sortable-th" class:sort-active={sortColumn === 'protocols'} onclick={() => toggleSort('protocols')}>
									Protocols {#if sortColumn === 'protocols'}<span class="sort-arrow">{sortDirection === 'asc' ? '▲' : '▼'}</span>{/if}
								</th>
							{/if}
							{#if visibleColumns.has('country')}
								<th class="sortable-th" class:sort-active={sortColumn === 'country'} onclick={() => toggleSort('country')}>
									Country {#if sortColumn === 'country'}<span class="sort-arrow">{sortDirection === 'asc' ? '▲' : '▼'}</span>{/if}
								</th>
							{/if}
							{#if visibleColumns.has('packets')}
								<th class="sortable-th" class:sort-active={sortColumn === 'packets'} onclick={() => toggleSort('packets')}>
									Packets {#if sortColumn === 'packets'}<span class="sort-arrow">{sortDirection === 'asc' ? '▲' : '▼'}</span>{/if}
								</th>
							{/if}
							{#if visibleColumns.has('purdue')}
								<th class="sortable-th" class:sort-active={sortColumn === 'purdue'} onclick={() => toggleSort('purdue')}>
									Purdue {#if sortColumn === 'purdue'}<span class="sort-arrow">{sortDirection === 'asc' ? '▲' : '▼'}</span>{/if}
								</th>
							{/if}
							{#if visibleColumns.has('first_seen')}
								<th class="sortable-th" class:sort-active={sortColumn === 'first_seen'} onclick={() => toggleSort('first_seen')}>
									First Seen {#if sortColumn === 'first_seen'}<span class="sort-arrow">{sortDirection === 'asc' ? '▲' : '▼'}</span>{/if}
								</th>
							{/if}
							{#if visibleColumns.has('last_seen')}
								<th class="sortable-th" class:sort-active={sortColumn === 'last_seen'} onclick={() => toggleSort('last_seen')}>
									Last Seen {#if sortColumn === 'last_seen'}<span class="sort-arrow">{sortDirection === 'asc' ? '▲' : '▼'}</span>{/if}
								</th>
							{/if}
						</tr>
					</thead>
					<tbody>
						{#each pagedAssets as asset}
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
								{#if visibleColumns.has('ip')}
									<td class="cell-ip">
										{asset.ip_address}
										{#if asset.is_public_ip}
											<span class="public-badge" title="Public IP">PUB</span>
										{/if}
									</td>
								{/if}
								{#if visibleColumns.has('mac')}
									<td class="cell-mac">{asset.mac_address ?? '—'}</td>
								{/if}
								{#if visibleColumns.has('type')}
									<td>
										<span
											class="device-badge"
											style="color: {deviceTypeColors[asset.device_type]};
											       background: {deviceTypeColors[asset.device_type]}18"
										>
											{deviceTypeLabels[asset.device_type]}
										</span>
									</td>
								{/if}
								{#if visibleColumns.has('confidence')}
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
								{/if}
								{#if visibleColumns.has('vendor')}
									<td class="cell-vendor">{asset.vendor ?? '—'}</td>
								{/if}
								{#if visibleColumns.has('oui')}
									<td class="cell-vendor cell-oui">{asset.oui_vendor ?? '—'}</td>
								{/if}
								{#if visibleColumns.has('product')}
									<td class="cell-vendor">{asset.product_family ?? '—'}</td>
								{/if}
								{#if visibleColumns.has('protocols')}
									<td class="cell-protocols">
										{#each asset.protocols as proto}
											<span class="proto-tag">{proto}</span>
										{/each}
									</td>
								{/if}
								{#if visibleColumns.has('country')}
									<td class="cell-country">
										{#if asset.country}
											<span title={asset.country}>{countryFlag(asset.country)}</span>
										{:else}
											—
										{/if}
									</td>
								{/if}
								{#if visibleColumns.has('packets')}
									<td class="cell-numeric">{asset.packet_count.toLocaleString()}</td>
								{/if}
								{#if visibleColumns.has('purdue')}
									<td class="cell-numeric">
										{asset.purdue_level !== null && asset.purdue_level !== undefined ? `L${asset.purdue_level}` : '—'}
									</td>
								{/if}
								{#if visibleColumns.has('first_seen')}
									<td class="cell-date">{asset.first_seen.slice(0, 19).replace('T', ' ')}</td>
								{/if}
								{#if visibleColumns.has('last_seen')}
									<td class="cell-date">{asset.last_seen.slice(0, 19).replace('T', ' ')}</td>
								{/if}
							</tr>
						{/each}
					</tbody>
				</table>
				{#if invTotalPages > 1}
					<div class="inv-pagination">
						<button class="inv-page-btn" disabled={invPage === 0} onclick={() => { invPage = 0; }}>«</button>
						<button class="inv-page-btn" disabled={invPage === 0} onclick={() => { invPage -= 1; }}>‹</button>
						<span class="inv-page-info">
							{invPage + 1} / {invTotalPages}
							&nbsp;·&nbsp;
							{invPage * INV_PAGE_SIZE + 1}–{Math.min((invPage + 1) * INV_PAGE_SIZE, $filteredAssets.length)} of {$filteredAssets.length}
						</span>
						<button class="inv-page-btn" disabled={invPage >= invTotalPages - 1} onclick={() => { invPage += 1; }}>›</button>
						<button class="inv-page-btn" disabled={invPage >= invTotalPages - 1} onclick={() => { invPage = invTotalPages - 1; }}>»</button>
					</div>
				{/if}
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

					<!-- Wireshark Filters -->
					<div class="detail-section">
						<h4 class="section-title">Wireshark Filters</h4>
						<div class="filter-row">
							<code class="filter-code">ip.addr == {$selectedAsset.ip_address}</code>
							<button class="copy-btn" onclick={() => copyWiresharkFilter(`ip.addr == ${$selectedAsset!.ip_address}`)}>
								Copy
							</button>
						</div>
						{#if getOtPort($selectedAsset.protocols) !== null}
							{@const port = getOtPort($selectedAsset.protocols)}
							<div class="filter-row">
								<code class="filter-code">ip.addr == {$selectedAsset.ip_address} && tcp.port == {port}</code>
								<button class="copy-btn" onclick={() => copyWiresharkFilter(`ip.addr == ${$selectedAsset!.ip_address} && tcp.port == ${port}`)}>
									Copy
								</button>
							</div>
						{/if}
					</div>

					<!-- Default Credential Warnings -->
					{#if credWarnings.length > 0}
						<div class="detail-section cred-warning-section">
							<h4 class="section-title warning-title">⚠ Default Credentials Detected</h4>
							{#each credWarnings as cw}
								<div class="cred-warning-card">
									<div class="cred-row"><span class="cred-label">Protocol:</span> <span>{cw.protocol.toUpperCase()}</span></div>
									{#if cw.username}<div class="cred-row"><span class="cred-label">Username:</span> <code>{cw.username}</code></div>{/if}
									{#if cw.password}<div class="cred-row"><span class="cred-label">Password:</span> <code>{cw.password}</code></div>{/if}
									<div class="cred-row cred-source"><span class="cred-label">Source:</span> <span>{cw.source}</span></div>
									<button class="copy-btn cred-copy" onclick={() => navigator.clipboard.writeText(`${cw.username}:${cw.password}`)}>
										Copy Credentials
									</button>
								</div>
							{/each}
						</div>
					{/if}

					<!-- CVE Warnings -->
					{#if cveWarnings.length > 0}
						<div class="detail-section cve-warning-section">
							<h4 class="section-title cve-title">&#128308; Known Vulnerabilities ({cveWarnings.length})</h4>
							{#each cveWarnings as cve}
								<div class="cve-card">
									<div class="cve-header-row">
										<span class="cve-id">{cve.cve_id}</span>
										<span class="cve-cvss-badge sev-{cve.severity_label.toLowerCase()}">{cve.severity_label} {cve.cvss.toFixed(1)}</span>
										<span class="cve-conf conf-{cve.confidence}">{cve.confidence}</span>
									</div>
									<div class="cve-desc">{cve.description}</div>
									{#if cve.advisory}
										<div class="cve-row"><span class="cve-label">Advisory:</span> <span>{cve.advisory}</span></div>
									{/if}
									<div class="cve-row cve-remediation"><span class="cve-label">Fix:</span> <span>{cve.remediation}</span></div>
									<button class="copy-btn cve-copy" onclick={() => navigator.clipboard.writeText(cve.cve_id)}>
										Copy CVE ID
									</button>
								</div>
							{/each}
						</div>
					{/if}

					<!-- Zeek Per-Device Events -->
					{#if zeekEvents}
						<div class="detail-section zeek-section">
							<div class="zeek-header">
								<h4 class="section-title zeek-title">&#128269; Zeek Events</h4>
								<button class="zeek-expand-btn" onclick={() => { zeekEventsExpanded = !zeekEventsExpanded; }}>
									{zeekEventsExpanded ? 'Hide' : 'Show'} samples
								</button>
							</div>
							<div class="zeek-badges">
								{#if zeekEvents.conn_log_entries > 0}
									<span class="zeek-badge">conn: {zeekEvents.conn_log_entries}</span>
								{/if}
								{#if zeekEvents.modbus_events > 0}
									<span class="zeek-badge zeek-ot">modbus: {zeekEvents.modbus_events}</span>
								{/if}
								{#if zeekEvents.dnp3_events > 0}
									<span class="zeek-badge zeek-ot">dnp3: {zeekEvents.dnp3_events}</span>
								{/if}
								{#if zeekEvents.dns_queries > 0}
									<span class="zeek-badge">dns: {zeekEvents.dns_queries}</span>
								{/if}
								{#if zeekEvents.http_requests > 0}
									<span class="zeek-badge">http: {zeekEvents.http_requests}</span>
								{/if}
								<span class="zeek-badge zeek-peers">peers: {zeekEvents.unique_peers}</span>
								{#if zeekEvents.alert_count > 0}
									<span class="zeek-badge zeek-alert">alerts: {zeekEvents.alert_count}</span>
								{/if}
							</div>
							{#if zeekEventsExpanded && zeekEvents.sample_events.length > 0}
								<div class="zeek-events-list">
									{#each zeekEvents.sample_events as ev}
										<div class="zeek-event-row">
											<span class="zeek-ev-time">{ev.timestamp.slice(0, 19).replace('T', ' ')}</span>
											<span class="zeek-ev-type tag-{ev.log_type}">{ev.log_type}</span>
											<span class="zeek-ev-summary">{ev.summary}</span>
										</div>
									{/each}
								</div>
							{/if}
						</div>
					{/if}

					<!-- IDS/SIEM Alerts for this device -->
					{#if assetAlerts.length > 0}
						<div class="detail-section alert-section">
							<h4 class="section-title alert-title">&#128680; External Alerts ({assetAlerts.length})</h4>
							{#each assetAlerts as alert}
								<div class="asset-alert-row">
									<span class="alert-sev-badge sev-{alert.severity === 1 ? 'high' : alert.severity === 2 ? 'medium' : 'low'}">
										{alert.severity === 1 ? 'HIGH' : alert.severity === 2 ? 'MED' : 'LOW'}
									</span>
									<span class="alert-source-tag">{alert.source}</span>
									<span class="alert-sig-text">{alert.signature}</span>
								</div>
							{/each}
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

						<!-- EtherNet/IP Detail -->
						{#if deepParseInfo.enip}
							{@const enip = deepParseInfo.enip as EnipDetail}
							<div class="detail-section">
								<h4 class="section-title" style="color: var(--gm-ethernet-ip, #8b5cf6)">EtherNet/IP + CIP</h4>
								<div class="detail-row">
									<span class="detail-label">Role</span>
									<span class="detail-value role-badge">{enip.role}</span>
								</div>
								{#if enip.list_identity_requests}
									<div class="detail-row">
										<span class="detail-label">Discovery</span>
										<span class="detail-value" style="color: #f59e0b">ListIdentity requests observed</span>
									</div>
								{/if}
								{#if enip.cip_writes_to_assembly}
									<div class="detail-row">
										<span class="detail-label">CIP Writes</span>
										<span class="detail-value finding">Assembly object writes (T0855)</span>
									</div>
								{/if}
								{#if enip.cip_file_access}
									<div class="detail-row">
										<span class="detail-label">File Access</span>
										<span class="detail-value finding">CIP File class access (T0836)</span>
									</div>
								{/if}
							</div>
						{/if}

						<!-- S7comm Detail -->
						{#if deepParseInfo.s7}
							{@const s7 = deepParseInfo.s7 as S7Detail}
							<div class="detail-section">
								<h4 class="section-title" style="color: var(--gm-s7comm, #ef4444)">S7comm (Siemens)</h4>
								<div class="detail-row">
									<span class="detail-label">Role</span>
									<span class="detail-value role-badge">{s7.role}</span>
								</div>
								{#if s7.functions_seen.length > 0}
									<div class="detail-subsection">
										<h5 class="subsection-title">Functions Observed</h5>
										<div class="fc-list">
											{#each s7.functions_seen as fn}
												{@const isWrite = fn === 'WriteVar' || fn === 'PlcStop' || fn === 'Download' || fn === 'DownloadStart' || fn === 'DownloadEnd'}
												<div class="fc-item" class:write={isWrite}>
													<span class="fc-name">{fn.replace(/([A-Z])/g, ' $1').trim()}</span>
												</div>
											{/each}
										</div>
									</div>
								{/if}
							</div>
						{/if}

						<!-- BACnet Detail -->
						{#if deepParseInfo.bacnet}
							{@const bacnet = deepParseInfo.bacnet as BacnetDetail}
							<div class="detail-section">
								<h4 class="section-title" style="color: var(--gm-bacnet, #06b6d4)">BACnet/IP</h4>
								<div class="detail-row">
									<span class="detail-label">Role</span>
									<span class="detail-value role-badge">{bacnet.role}</span>
								</div>
								{#if bacnet.write_to_output}
									<div class="detail-row">
										<span class="detail-label">Output Writes</span>
										<span class="detail-value finding">WriteProperty to Output (T0855)</span>
									</div>
								{/if}
								{#if bacnet.write_to_notification_class}
									<div class="detail-row">
										<span class="detail-label">Alarm Suppress</span>
										<span class="detail-value finding">WriteProperty NotificationClass (T0856)</span>
									</div>
								{/if}
								{#if bacnet.reinitialize_device}
									<div class="detail-row">
										<span class="detail-label">Device Reset</span>
										<span class="detail-value finding">ReinitializeDevice (T0816)</span>
									</div>
								{/if}
								{#if bacnet.device_communication_control}
									<div class="detail-row">
										<span class="detail-label">Comm Control</span>
										<span class="detail-value finding">DeviceCommunicationControl (T0811)</span>
									</div>
								{/if}
							</div>
						{/if}

						<!-- IEC 104 Detail -->
						{#if deepParseInfo.iec104}
							{@const iec104 = deepParseInfo.iec104 as Iec104Detail}
							<div class="detail-section">
								<h4 class="section-title" style="color: #14b8a6">IEC 60870-5-104</h4>
								<div class="detail-row">
									<span class="detail-label">Role</span>
									<span class="detail-value role-badge">{iec104.role}</span>
								</div>
								{#if iec104.has_control_commands}
									<div class="detail-row">
										<span class="detail-label">Control Commands</span>
										<span class="detail-value finding">Command ASDUs detected (T0855)</span>
									</div>
								{/if}
								{#if iec104.has_reset_process}
									<div class="detail-row">
										<span class="detail-label">Reset Process</span>
										<span class="detail-value finding">Reset Process command (T0816)</span>
									</div>
								{/if}
								{#if iec104.has_interrogation}
									<div class="detail-row">
										<span class="detail-label">Interrogation</span>
										<span class="detail-value" style="color: #f59e0b">General Interrogation observed</span>
									</div>
								{/if}
							</div>
						{/if}

						<!-- PROFINET DCP Detail -->
						{#if deepParseInfo.profinet_dcp}
							{@const pndcp = deepParseInfo.profinet_dcp as ProfinetDcpDetail}
							<div class="detail-section">
								<h4 class="section-title" style="color: #6366f1">PROFINET DCP</h4>
								<div class="detail-row">
									<span class="detail-label">Role</span>
									<span class="detail-value role-badge">{pndcp.role.replace(/_/g, ' ')}</span>
								</div>
								{#if pndcp.device_name}
									<div class="detail-row">
										<span class="detail-label">Station Name</span>
										<span class="detail-value highlight">{pndcp.device_name}</span>
									</div>
								{/if}
							</div>
						{/if}

						<!-- LLDP Detail -->
						{#if deepParseInfo.lldp}
							{@const lldp = deepParseInfo.lldp as LldpDetail}
							<div class="detail-section">
								<h4 class="section-title" style="color: #38bdf8">LLDP Discovery</h4>
								{#if lldp.system_name}
									<div class="detail-row">
										<span class="detail-label">System Name</span>
										<span class="detail-value highlight">{lldp.system_name}</span>
									</div>
								{/if}
								{#if lldp.vendor}
									<div class="detail-row">
										<span class="detail-label">Vendor</span>
										<span class="detail-value">{lldp.vendor}</span>
									</div>
								{/if}
								{#if lldp.model}
									<div class="detail-row">
										<span class="detail-label">Model</span>
										<span class="detail-value highlight">{lldp.model}</span>
									</div>
								{/if}
								{#if lldp.firmware}
									<div class="detail-row">
										<span class="detail-label">Firmware</span>
										<span class="detail-value">{lldp.firmware}</span>
									</div>
								{/if}
								{#if lldp.capability_summary}
									<div class="detail-row">
										<span class="detail-label">Capabilities</span>
										<span class="detail-value">{lldp.capability_summary}</span>
									</div>
								{/if}
								{#if lldp.chassis_id}
									<div class="detail-row">
										<span class="detail-label">Chassis ID</span>
										<span class="detail-value">{lldp.chassis_id}</span>
									</div>
								{/if}
								{#if lldp.port_id}
									<div class="detail-row">
										<span class="detail-label">Port ID</span>
										<span class="detail-value">{lldp.port_id}</span>
									</div>
								{/if}
								{#if lldp.management_addresses.length > 0}
									<div class="detail-row">
										<span class="detail-label">Mgmt Addrs</span>
										<span class="detail-value">{lldp.management_addresses.join(', ')}</span>
									</div>
								{/if}
								{#if lldp.vlan_ids.length > 0}
									<div class="detail-row">
										<span class="detail-label">VLANs</span>
										<span class="detail-value">{lldp.vlan_ids.join(', ')}</span>
									</div>
								{/if}
								{#if lldp.system_description}
									<div class="detail-subsection">
										<h5 class="subsection-title">System Description</h5>
										<div class="lldp-description">{lldp.system_description}</div>
									</div>
								{/if}
							</div>
						{/if}

						{#if deepParseInfo.snmp}
							{@const snmp = deepParseInfo.snmp}
							<div class="detail-section">
								<h4 class="section-title" style="color: #a78bfa">SNMP Identity</h4>
								{#if snmp.sys_name}
									<div class="detail-row">
										<span class="detail-label">sysName</span>
										<span class="detail-value">{snmp.sys_name}</span>
									</div>
								{/if}
								{#if snmp.vendor}
									<div class="detail-row">
										<span class="detail-label">Vendor (OID)</span>
										<span class="detail-value">{snmp.vendor}</span>
									</div>
								{/if}
								{#if snmp.sys_location}
									<div class="detail-row">
										<span class="detail-label">Location</span>
										<span class="detail-value">{snmp.sys_location}</span>
									</div>
								{/if}
								{#if snmp.sys_contact}
									<div class="detail-row">
										<span class="detail-label">Contact</span>
										<span class="detail-value">{snmp.sys_contact}</span>
									</div>
								{/if}
								{#if snmp.sys_object_id}
									<div class="detail-row">
										<span class="detail-label">sysObjectID</span>
										<span class="detail-value" style="font-family: monospace; font-size: 0.75rem">{snmp.sys_object_id}</span>
									</div>
								{/if}
								{#if snmp.sys_uptime_cs != null}
									<div class="detail-row">
										<span class="detail-label">Uptime</span>
										<span class="detail-value">{(snmp.sys_uptime_cs / 100 / 3600).toFixed(1)} hours</span>
									</div>
								{/if}
								{#if snmp.sys_descr}
									<div class="detail-subsection">
										<h5 class="subsection-title">sysDescr</h5>
										<div class="lldp-description">{snmp.sys_descr}</div>
									</div>
								{/if}
							</div>
						{/if}
					{/if}
				</div>
			</div>
		{/if}
	</div>

	{#if toastMessage}
		<div class="copy-toast">{toastMessage}</div>
	{/if}
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

	/* ── Column Picker ───────────────────────────── */

	.col-picker-wrap {
		position: relative;
	}

	.col-picker-btn {
		padding: 5px 10px;
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 4px;
		color: var(--gm-text-secondary);
		font-family: inherit;
		font-size: 11px;
		cursor: pointer;
		white-space: nowrap;
		transition: all 0.15s;
	}

	.col-picker-btn:hover {
		background: var(--gm-bg-hover);
		color: var(--gm-text-primary);
	}

	.col-picker-dropdown {
		position: absolute;
		top: calc(100% + 4px);
		right: 0;
		z-index: 100;
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 6px;
		padding: 6px;
		min-width: 160px;
		box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
		display: flex;
		flex-direction: column;
		gap: 1px;
	}

	.col-picker-item {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 4px 8px;
		font-size: 11px;
		color: var(--gm-text-secondary);
		cursor: pointer;
		border-radius: 3px;
	}

	.col-picker-item:hover {
		background: var(--gm-bg-hover);
		color: var(--gm-text-primary);
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

	.sortable-th {
		cursor: pointer;
		user-select: none;
		transition: background 0.1s, color 0.1s;
	}

	.sortable-th:hover {
		background: var(--gm-bg-hover);
		color: var(--gm-text-primary);
	}

	.sort-active {
		color: var(--gm-text-primary) !important;
	}

	.sort-arrow {
		font-size: 8px;
		margin-left: 3px;
		vertical-align: middle;
	}

	.cell-date {
		font-size: 10px;
		color: var(--gm-text-muted);
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

	/* ── Wireshark Filters & Credentials ───────────────── */

	.filter-row {
		display: flex;
		align-items: center;
		gap: 8px;
		margin-bottom: 6px;
		flex-wrap: wrap;
	}

	.filter-code {
		font-size: 0.75rem;
		background: var(--gm-bg-tertiary, #0f172a);
		padding: 3px 8px;
		border-radius: 4px;
		flex: 1;
		min-width: 0;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		color: var(--gm-accent, #38bdf8);
	}

	.copy-btn {
		padding: 3px 10px;
		font-size: 0.7rem;
		background: var(--gm-bg-secondary, #1e293b);
		border: 1px solid var(--gm-border, #334155);
		border-radius: 4px;
		cursor: pointer;
		color: var(--gm-text-muted, #94a3b8);
		white-space: nowrap;
		flex-shrink: 0;
	}

	.copy-btn:hover {
		background: var(--gm-border, #334155);
		color: var(--gm-text-primary, #f1f5f9);
	}

	.copy-toast {
		position: fixed;
		bottom: 24px;
		right: 24px;
		background: var(--gm-accent, #38bdf8);
		color: #0f172a;
		padding: 8px 16px;
		border-radius: 6px;
		font-size: 0.85rem;
		font-weight: 600;
		z-index: 9999;
		pointer-events: none;
		animation: toast-in 0.15s ease;
	}

	@keyframes toast-in {
		from { opacity: 0; transform: translateY(8px); }
		to { opacity: 1; transform: translateY(0); }
	}

	.cred-warning-section {
		border: 1px solid rgba(245, 158, 11, 0.25);
		background: rgba(245, 158, 11, 0.04);
		border-radius: 6px;
		padding: 10px;
	}

	.warning-title { color: #f59e0b; }

	.cred-warning-card {
		background: var(--gm-bg-tertiary, #0f172a);
		border-radius: 6px;
		padding: 10px;
		margin-top: 8px;
	}

	.cred-row {
		display: flex;
		gap: 8px;
		font-size: 0.8rem;
		margin-bottom: 4px;
		align-items: baseline;
	}

	.cred-label {
		color: var(--gm-text-muted, #94a3b8);
		min-width: 70px;
		flex-shrink: 0;
	}

	.cred-source {
		color: var(--gm-text-muted, #94a3b8);
		font-size: 0.72rem;
	}

	.cred-copy { margin-top: 8px; }

	/* ── CVE Warnings ────────────────────────────────────── */

	.cve-warning-section {
		border: 1px solid rgba(239, 68, 68, 0.3);
		background: rgba(239, 68, 68, 0.04);
		border-radius: 6px;
		padding: 10px;
	}

	.cve-title { color: #ef4444; }

	.cve-card {
		background: var(--gm-bg-tertiary, #0f172a);
		border-radius: 6px;
		padding: 10px;
		margin-top: 8px;
	}

	.cve-header-row {
		display: flex;
		align-items: center;
		gap: 8px;
		margin-bottom: 6px;
	}

	.cve-id {
		font-weight: 700;
		font-size: 0.8rem;
		color: var(--gm-text-primary);
		font-family: 'JetBrains Mono', monospace;
	}

	.cve-cvss-badge {
		font-size: 0.7rem;
		font-weight: 700;
		padding: 1px 6px;
		border-radius: 4px;
	}

	.sev-critical { background: rgba(239, 68, 68, 0.2); color: #ef4444; }
	.sev-high     { background: rgba(249, 115, 22, 0.2); color: #f97316; }
	.sev-medium   { background: rgba(234, 179, 8, 0.2); color: #eab308; }
	.sev-low      { background: rgba(34, 197, 94, 0.2); color: #22c55e; }

	.cve-conf {
		font-size: 0.65rem;
		padding: 1px 5px;
		border-radius: 3px;
		margin-left: auto;
	}

	.conf-high   { background: rgba(99, 102, 241, 0.2); color: #818cf8; }
	.conf-medium { background: rgba(148, 163, 184, 0.1); color: #94a3b8; }
	.conf-low    { background: rgba(148, 163, 184, 0.08); color: #64748b; }

	.cve-desc {
		font-size: 0.78rem;
		color: var(--gm-text-secondary);
		margin-bottom: 4px;
		line-height: 1.4;
	}

	.cve-row {
		display: flex;
		gap: 6px;
		font-size: 0.75rem;
		color: var(--gm-text-secondary);
		align-items: baseline;
		margin-top: 2px;
	}

	.cve-label {
		color: var(--gm-text-muted);
		min-width: 60px;
		flex-shrink: 0;
	}

	.cve-remediation { font-style: italic; }

	.cve-copy { margin-top: 8px; }

	/* ── Zeek Events ─────────────────────────────────────── */

	.zeek-section {
		border: 1px solid rgba(56, 189, 248, 0.2);
		background: rgba(56, 189, 248, 0.03);
		border-radius: 6px;
		padding: 10px;
	}

	.zeek-header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		margin-bottom: 8px;
	}

	.zeek-title { color: #38bdf8; margin: 0; }

	.zeek-expand-btn {
		font-size: 0.7rem;
		padding: 2px 8px;
		background: rgba(56, 189, 248, 0.1);
		border: 1px solid rgba(56, 189, 248, 0.2);
		border-radius: 4px;
		color: #38bdf8;
		cursor: pointer;
		font-family: inherit;
	}

	.zeek-badges {
		display: flex;
		flex-wrap: wrap;
		gap: 4px;
		margin-bottom: 6px;
	}

	.zeek-badge {
		font-size: 0.68rem;
		padding: 2px 6px;
		border-radius: 4px;
		background: rgba(148, 163, 184, 0.1);
		color: var(--gm-text-muted);
		font-family: 'JetBrains Mono', monospace;
	}

	.zeek-ot    { background: rgba(249, 115, 22, 0.15); color: #fb923c; }
	.zeek-peers { background: rgba(99, 102, 241, 0.15); color: #a5b4fc; }
	.zeek-alert { background: rgba(239, 68, 68, 0.15); color: #fca5a5; }

	.zeek-events-list {
		margin-top: 8px;
		display: flex;
		flex-direction: column;
		gap: 3px;
		max-height: 200px;
		overflow-y: auto;
	}

	.zeek-event-row {
		display: flex;
		gap: 6px;
		align-items: baseline;
		font-size: 0.7rem;
		padding: 2px 0;
		border-bottom: 1px solid rgba(45, 58, 79, 0.3);
	}

	.zeek-ev-time {
		color: var(--gm-text-muted);
		white-space: nowrap;
		font-family: 'JetBrains Mono', monospace;
		flex-shrink: 0;
	}

	.zeek-ev-type {
		padding: 1px 5px;
		border-radius: 3px;
		font-weight: 600;
		flex-shrink: 0;
		background: rgba(148, 163, 184, 0.1);
		color: var(--gm-text-muted);
	}

	.tag-modbus { background: rgba(249, 115, 22, 0.15); color: #fb923c; }
	.tag-dnp3   { background: rgba(234, 179, 8, 0.15); color: #facc15; }
	.tag-s7comm { background: rgba(99, 102, 241, 0.15); color: #a5b4fc; }
	.tag-dns    { background: rgba(34, 197, 94, 0.12); color: #86efac; }
	.tag-http   { background: rgba(56, 189, 248, 0.12); color: #7dd3fc; }

	.zeek-ev-summary {
		color: var(--gm-text-secondary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	/* ── LLDP description block ─────────────────────────── */

	.lldp-description {
		font-size: 0.75rem;
		color: var(--gm-text-secondary);
		font-family: 'JetBrains Mono', monospace;
		background: var(--gm-bg-tertiary);
		border: 1px solid var(--gm-border);
		border-radius: 4px;
		padding: 6px 8px;
		white-space: pre-wrap;
		word-break: break-word;
		line-height: 1.5;
		margin-top: 4px;
	}

	/* ── Bulk Input Fields ──────────────────────────────── */

	.bulk-input {
		padding: 4px 8px;
		font-size: 0.8rem;
		background: var(--gm-bg-tertiary, #0f172a);
		border: 1px solid var(--gm-border, #334155);
		border-radius: 4px;
		color: var(--gm-text-primary, #f1f5f9);
		width: 120px;
	}

	/* ── Asset table pagination ─────────────────── */

	.inv-pagination {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 6px;
		padding: 8px 12px;
		border-top: 1px solid var(--gm-border, #334155);
		background: var(--gm-bg-secondary, #1e293b);
	}

	.inv-page-btn {
		padding: 3px 9px;
		background: var(--gm-bg-panel, #0f172a);
		border: 1px solid var(--gm-border, #334155);
		border-radius: 4px;
		color: var(--gm-text-secondary, #94a3b8);
		font-family: inherit;
		font-size: 12px;
		cursor: pointer;
		transition: all 0.15s;
	}

	.inv-page-btn:hover:not(:disabled) {
		background: var(--gm-bg-hover, #1e293b);
		color: var(--gm-text-primary, #f1f5f9);
	}

	.inv-page-btn:disabled {
		opacity: 0.4;
		cursor: not-allowed;
	}

	.inv-page-info {
		font-size: 11px;
		color: var(--gm-text-muted, #64748b);
		white-space: nowrap;
	}

	/* ── IDS/SIEM Alert Section ────────────────────── */

	.alert-section {
		border-color: rgba(239, 68, 68, 0.3) !important;
	}

	.alert-title {
		color: #ef4444 !important;
	}

	.asset-alert-row {
		display: flex;
		align-items: flex-start;
		gap: 6px;
		margin-bottom: 6px;
		flex-wrap: wrap;
	}

	.alert-sev-badge {
		font-size: 9px;
		font-weight: 700;
		padding: 2px 5px;
		border-radius: 3px;
		flex-shrink: 0;
	}

	.alert-sev-badge.sev-high   { background: var(--gm-severity-high);   color: #fff; }
	.alert-sev-badge.sev-medium { background: var(--gm-severity-medium); color: #fff; }
	.alert-sev-badge.sev-low    { background: var(--gm-severity-low);    color: #fff; }

	.alert-source-tag {
		font-size: 9px;
		padding: 2px 5px;
		border-radius: 3px;
		background: rgba(99, 102, 241, 0.2);
		color: #a5b4fc;
		font-weight: 600;
		flex-shrink: 0;
	}

	.alert-sig-text {
		font-size: 10px;
		color: var(--gm-text-secondary);
		line-height: 1.4;
	}
</style>
