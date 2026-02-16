<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { open } from '@tauri-apps/plugin-dialog';
	import {
		physicalTopology,
		physicalHighlightIp,
		selectedAssetId,
		activeTab,
		assets
	} from '$lib/stores';
	import type { PhysicalTopology, PhysicalSwitch, PhysicalPort } from '$lib/types';
	import {
		importCiscoConfig,
		importMacTable,
		importCdpNeighbors,
		importArpTable,
		getPhysicalTopology,
		clearPhysicalTopology
	} from '$lib/utils/tauri';

	let graphContainer: HTMLDivElement;
	let cy: any = null;

	// ── Import State ───────────────────────────────────
	let importType = $state<'config' | 'mac' | 'cdp' | 'arp'>('config');
	let switchHostname = $state('');
	let importError = $state('');
	let importSuccess = $state('');
	let importing = $state(false);

	// ── Detail Panel ────────────────────────────────────
	let selectedSwitch = $state<PhysicalSwitch | null>(null);
	let selectedPort = $state<PhysicalPort | null>(null);

	// ── Cytoscape ───────────────────────────────────────

	async function initCytoscape() {
		const cytoscape = (await import('cytoscape')).default;

		cy = cytoscape({
			container: graphContainer,
			style: [
				// Switch node (compound parent)
				{
					selector: 'node.switch',
					style: {
						'background-color': 'rgba(16, 185, 129, 0.08)',
						'background-opacity': 0.6,
						'border-color': '#10b981',
						'border-width': 2,
						'border-style': 'solid' as any,
						label: 'data(label)',
						color: '#e2e8f0',
						'font-size': '11px',
						'font-family': 'JetBrains Mono, monospace',
						'font-weight': '600' as any,
						'text-valign': 'top',
						'text-halign': 'center',
						'text-margin-y': -6,
						padding: '20px',
						shape: 'roundrectangle'
					}
				},
				// Port node
				{
					selector: 'node.port',
					style: {
						'background-color': '#1e293b',
						'border-color': 'data(color)',
						'border-width': 1.5,
						label: 'data(label)',
						color: '#94a3b8',
						'font-size': '8px',
						'font-family': 'JetBrains Mono, monospace',
						'text-valign': 'bottom',
						'text-margin-y': 4,
						width: 20,
						height: 20,
						'text-wrap': 'wrap' as any,
						'text-max-width': '80px'
					}
				},
				// Port with devices connected
				{
					selector: 'node.port.has-device',
					style: {
						'background-color': '#0f2942',
						'border-color': '#3b82f6',
						'border-width': 2,
						width: 24,
						height: 24
					}
				},
				// Port with CDP neighbor
				{
					selector: 'node.port.has-cdp',
					style: {
						'border-color': '#f59e0b',
						'border-width': 2
					}
				},
				// Shutdown port
				{
					selector: 'node.port.shutdown',
					style: {
						'background-color': '#1a1a2e',
						'border-color': '#374151',
						'border-style': 'dashed' as any,
						opacity: 0.5
					}
				},
				// Trunk port
				{
					selector: 'node.port.trunk',
					style: {
						'border-color': '#8b5cf6',
						shape: 'diamond'
					}
				},
				// Highlighted port (cross-reference)
				{
					selector: 'node.port.highlighted',
					style: {
						'background-color': '#1e3a5f',
						'border-color': '#ef4444',
						'border-width': 3,
						width: 28,
						height: 28
					}
				},
				// Selected node
				{
					selector: 'node:selected',
					style: {
						'border-color': '#3b82f6',
						'border-width': 3
					}
				},
				// CDP link edge (between switches)
				{
					selector: 'edge.cdp-link',
					style: {
						width: 2.5,
						'line-color': '#f59e0b',
						'line-style': 'solid' as any,
						'target-arrow-shape': 'none',
						'curve-style': 'bezier',
						opacity: 0.8,
						label: 'data(label)',
						color: '#f59e0b',
						'font-size': '8px',
						'text-rotation': 'autorotate' as any,
						'text-background-color': '#0a0e17',
						'text-background-opacity': 0.9,
						'text-background-padding': '2px' as any
					}
				},
				// Device connection edge (port → external device label)
				{
					selector: 'edge.device-link',
					style: {
						width: 1,
						'line-color': '#3b82f6',
						'line-style': 'dashed' as any,
						'target-arrow-shape': 'none',
						opacity: 0.5
					}
				}
			],
			layout: { name: 'preset' },
			minZoom: 0.1,
			maxZoom: 5,
			wheelSensitivity: 0.3
		});

		// Click on switch compound node → show details
		cy.on('tap', 'node.switch', (event: any) => {
			const hostname = event.target.data('hostname');
			let currentTopo: PhysicalTopology = { switches: [], links: [], device_locations: {} };
			physicalTopology.subscribe((t) => (currentTopo = t))();
			selectedSwitch = currentTopo.switches.find((s) => s.hostname === hostname) ?? null;
			selectedPort = null;
		});

		// Click on port → show port details
		cy.on('tap', 'node.port', (event: any) => {
			const portName = event.target.data('portName');
			const switchHostname = event.target.data('switchHostname');
			let currentTopo: PhysicalTopology = { switches: [], links: [], device_locations: {} };
			physicalTopology.subscribe((t) => (currentTopo = t))();
			const sw = currentTopo.switches.find((s) => s.hostname === switchHostname);
			if (sw) {
				selectedSwitch = sw;
				selectedPort = sw.ports.find((p) => p.name === portName) ?? null;
			}
		});

		// Background tap → deselect
		cy.on('tap', (event: any) => {
			if (event.target === cy) {
				selectedSwitch = null;
				selectedPort = null;
			}
		});
	}

	/** Build Cytoscape elements from the physical topology */
	function buildElements(topo: PhysicalTopology) {
		const elements: any[] = [];

		// Build asset map for cross-reference
		let currentAssets: any[] = [];
		assets.subscribe((a) => (currentAssets = a))();
		const assetMap = new Map(currentAssets.map((a: any) => [a.ip_address, a]));

		let highlightIp: string | null = null;
		physicalHighlightIp.subscribe((ip) => (highlightIp = ip))();

		for (const sw of topo.switches) {
			// Add switch as compound parent
			const switchId = `sw-${sw.hostname}`;
			let switchLabel = sw.hostname;
			if (sw.management_ip) {
				switchLabel += `\n${sw.management_ip}`;
			}

			elements.push({
				group: 'nodes',
				data: {
					id: switchId,
					label: switchLabel,
					hostname: sw.hostname
				},
				classes: 'switch'
			});

			// Add ports as child nodes
			// Only show physical ports (Gi, Fa, Te, Po) and SVIs with IPs
			const visiblePorts = sw.ports.filter((p) => {
				const name = p.name.toLowerCase();
				return (
					name.startsWith('gigabitethernet') ||
					name.startsWith('fastethernet') ||
					name.startsWith('tengigabitethernet') ||
					name.startsWith('port-channel') ||
					(name.startsWith('vlan') && p.ip_address)
				);
			});

			for (const port of visiblePorts) {
				const portId = `${switchId}-${port.short_name}`;
				const hasDevice = port.mac_addresses.length > 0 || port.ip_addresses.length > 0;
				const hasCdp = port.cdp_neighbor !== null;
				const isTrunk = port.mode === 'trunk';

				// Check if any device on this port is the highlighted one
				const isHighlighted = highlightIp !== null && port.ip_addresses.includes(highlightIp);

				let classes = 'port';
				if (hasDevice) classes += ' has-device';
				if (hasCdp) classes += ' has-cdp';
				if (port.shutdown) classes += ' shutdown';
				if (isTrunk) classes += ' trunk';
				if (isHighlighted) classes += ' highlighted';

				// Build label
				let label = port.short_name;
				if (port.description) {
					label += `\n${port.description}`;
				}
				if (port.ip_addresses.length > 0) {
					label += `\n${port.ip_addresses[0]}`;
				}

				let color = '#475569'; // default gray
				if (isHighlighted) color = '#ef4444';
				else if (hasCdp) color = '#f59e0b';
				else if (hasDevice) color = '#3b82f6';
				else if (isTrunk) color = '#8b5cf6';
				else if (port.shutdown) color = '#374151';

				elements.push({
					group: 'nodes',
					data: {
						id: portId,
						label,
						parent: switchId,
						portName: port.name,
						switchHostname: sw.hostname,
						color,
						vlans: port.vlans.join(', '),
						macCount: port.mac_addresses.length,
						ipCount: port.ip_addresses.length
					},
					classes
				});
			}
		}

		// Add CDP/LLDP inter-switch links
		const addedLinks = new Set<string>();
		for (const link of topo.links) {
			// Create a canonical key to avoid duplicating bidirectional links
			const key = [link.src_switch, link.dst_switch].sort().join('---');
			if (addedLinks.has(key)) continue;
			addedLinks.add(key);

			// Find the port nodes
			const srcPortId = `sw-${link.src_switch}-${shortenName(link.src_port)}`;
			const dstPortId = `sw-${link.dst_switch}-${shortenName(link.dst_port)}`;

			// Only add if both nodes exist
			const srcExists = elements.some((e) => e.data?.id === srcPortId);
			const dstExists = elements.some((e) => e.data?.id === dstPortId);

			if (srcExists && dstExists) {
				elements.push({
					group: 'edges',
					data: {
						id: `link-${link.src_switch}-${link.dst_switch}`,
						source: srcPortId,
						target: dstPortId,
						label: 'CDP'
					},
					classes: 'cdp-link'
				});
			}
		}

		return elements;
	}

	function shortenName(name: string): string {
		const prefixes: [string, string][] = [
			['TenGigabitEthernet', 'Te'],
			['GigabitEthernet', 'Gi'],
			['FastEthernet', 'Fa'],
			['Ethernet', 'Et'],
			['Loopback', 'Lo'],
			['Tunnel', 'Tu'],
			['Port-channel', 'Po'],
			['Vlan', 'Vl']
		];
		for (const [long, short] of prefixes) {
			if (name.startsWith(long)) {
				return short + name.slice(long.length);
			}
		}
		return name;
	}

	function runLayout() {
		if (!cy || cy.nodes().length === 0) return;

		cy.layout({
			name: 'grid',
			fit: true,
			padding: 50,
			avoidOverlap: true,
			avoidOverlapPadding: 10,
			condense: false,
			rows: undefined,
			cols: undefined,
			sort: (a: any, b: any) => {
				// Sort: switches first, then ports by name
				const aIsSwitch = a.hasClass('switch');
				const bIsSwitch = b.hasClass('switch');
				if (aIsSwitch !== bIsSwitch) return aIsSwitch ? -1 : 1;
				return (a.data('label') || '').localeCompare(b.data('label') || '');
			}
		}).run();
	}

	function updateGraph(topo: PhysicalTopology) {
		if (!cy) return;
		cy.elements().remove();
		if (topo.switches.length === 0) return;

		const elements = buildElements(topo);
		cy.add(elements);
		runLayout();
	}

	// ── Import Handlers ──────────────────────────────────

	async function handleImport() {
		importError = '';
		importSuccess = '';

		const result = await open({
			multiple: false,
			filters: [{ name: 'Text Files', extensions: ['txt', 'cfg', 'conf', 'log'] }]
		});

		if (!result) return;
		const filePath = result as string;

		importing = true;
		try {
			let topo: PhysicalTopology;

			switch (importType) {
				case 'config':
					topo = await importCiscoConfig(filePath);
					importSuccess = `Imported Cisco config from ${filePath.split(/[/\\]/).pop()}`;
					break;
				case 'mac':
					if (!switchHostname.trim()) {
						importError = 'Select a switch hostname for MAC table import';
						importing = false;
						return;
					}
					topo = await importMacTable(filePath, switchHostname.trim());
					importSuccess = `Imported MAC table for ${switchHostname}`;
					break;
				case 'cdp':
					if (!switchHostname.trim()) {
						importError = 'Select a switch hostname for CDP import';
						importing = false;
						return;
					}
					topo = await importCdpNeighbors(filePath, switchHostname.trim());
					importSuccess = `Imported CDP neighbors for ${switchHostname}`;
					break;
				case 'arp':
					topo = await importArpTable(filePath);
					importSuccess = `Imported ARP table from ${filePath.split(/[/\\]/).pop()}`;
					break;
			}

			physicalTopology.set(topo!);
		} catch (err) {
			importError = `Import failed: ${err}`;
		} finally {
			importing = false;
		}
	}

	async function handleClear() {
		try {
			await clearPhysicalTopology();
			physicalTopology.set({ switches: [], links: [], device_locations: {} });
			selectedSwitch = null;
			selectedPort = null;
			importSuccess = 'Physical topology cleared';
		} catch (err) {
			importError = `Clear failed: ${err}`;
		}
	}

	/** Navigate to logical view and highlight a device */
	function showInLogical(ip: string) {
		selectedAssetId.set(ip);
		activeTab.set('topology');
	}

	// ── Store Subscriptions ──────────────────────────────

	let currentTopo = $state<PhysicalTopology>({ switches: [], links: [], device_locations: {} });

	const unsubTopo = physicalTopology.subscribe((t) => {
		currentTopo = t;
		updateGraph(t);
	});

	const unsubHighlight = physicalHighlightIp.subscribe(() => {
		updateGraph(currentTopo);
	});

	onMount(async () => {
		await initCytoscape();
		// Load existing physical topology
		try {
			const topo = await getPhysicalTopology();
			physicalTopology.set(topo);
		} catch {
			// Expected in browser dev mode
		}
	});

	onDestroy(() => {
		unsubTopo();
		unsubHighlight();
		cy?.destroy();
	});

	// Available switch hostnames for dropdown
	let switchOptions = $derived(currentTopo.switches.map((s) => s.hostname));
</script>

<div class="physical-container">
	<!-- Toolbar -->
	<div class="physical-toolbar">
		<div class="toolbar-section">
			<h2 class="view-title">Physical View</h2>
			<span class="toolbar-sep"></span>
			<span class="switch-count">{currentTopo.switches.length} switches</span>
			<span class="link-count">{currentTopo.links.length} links</span>
			<span class="device-count">{Object.keys(currentTopo.device_locations).length} mapped devices</span>
		</div>
		<div class="toolbar-section">
			<button class="tool-btn" onclick={() => cy?.fit(undefined, 40)}>Fit</button>
			<button class="tool-btn" onclick={runLayout}>Relayout</button>
			<button class="tool-btn danger" onclick={handleClear}>Clear</button>
		</div>
	</div>

	<div class="physical-body">
		<!-- Import Panel (left side) -->
		<div class="import-panel">
			<h3 class="panel-title">Import Cisco Data</h3>

			<div class="import-form">
				<label class="import-label">
					Import Type:
					<select class="import-select" bind:value={importType}>
						<option value="config">Running Config</option>
						<option value="mac">MAC Address Table</option>
						<option value="cdp">CDP Neighbors</option>
						<option value="arp">ARP Table</option>
					</select>
				</label>

				{#if importType === 'mac' || importType === 'cdp'}
					<label class="import-label">
						Switch:
						{#if switchOptions.length > 0}
							<select class="import-select" bind:value={switchHostname}>
								<option value="">Select switch...</option>
								{#each switchOptions as hostname}
									<option value={hostname}>{hostname}</option>
								{/each}
							</select>
						{:else}
							<input
								class="import-input"
								type="text"
								placeholder="Import a config first"
								bind:value={switchHostname}
							/>
						{/if}
					</label>
				{/if}

				<button class="import-btn" onclick={handleImport} disabled={importing}>
					{importing ? 'Importing...' : 'Import File'}
				</button>
			</div>

			{#if importError}
				<div class="msg error">{importError}</div>
			{/if}
			{#if importSuccess}
				<div class="msg success">{importSuccess}</div>
			{/if}

			<div class="import-help">
				<h4>Import Order</h4>
				<ol>
					<li><strong>Running Config</strong> — creates the switch &amp; ports</li>
					<li><strong>MAC Address Table</strong> — maps MACs to ports</li>
					<li><strong>ARP Table</strong> — maps IPs to MACs</li>
					<li><strong>CDP Neighbors</strong> — discovers switch links</li>
				</ol>
			</div>

			<!-- Device Locations Summary -->
			{#if Object.keys(currentTopo.device_locations).length > 0}
				<div class="locations-panel">
					<h4>Device Locations</h4>
					<div class="locations-list">
						{#each Object.values(currentTopo.device_locations) as loc}
							<button class="location-item" onclick={() => showInLogical(loc.ip_address)}>
								<span class="loc-ip">{loc.ip_address}</span>
								<span class="loc-detail">
									{loc.switch_hostname} / {loc.port_name}
									{#if loc.vlan}
										<span class="loc-vlan">V{loc.vlan}</span>
									{/if}
								</span>
							</button>
						{/each}
					</div>
				</div>
			{/if}
		</div>

		<!-- Graph Area -->
		<div class="graph-wrapper">
			<div class="graph-area" bind:this={graphContainer}>
				{#if currentTopo.switches.length === 0}
					<div class="empty-state">
						<div class="empty-icon">&#x2B22;</div>
						<h3>No Physical Topology</h3>
						<p>Import a Cisco IOS running-config to build the physical topology.</p>
						<p class="hint">Use the import panel on the left to get started.</p>
					</div>
				{/if}
			</div>

			<!-- Detail Panel (right side, when something is selected) -->
			{#if selectedSwitch}
				<div class="detail-panel">
					<div class="detail-header">
						<h3>{selectedSwitch.hostname}</h3>
						<button class="detail-close" onclick={() => { selectedSwitch = null; selectedPort = null; }}>
							&times;
						</button>
					</div>

					{#if selectedPort}
						<!-- Port detail -->
						<div class="detail-section">
							<h4>{selectedPort.short_name}</h4>
							{#if selectedPort.description}
								<div class="detail-row">
									<span class="detail-label">Description</span>
									<span class="detail-value">{selectedPort.description}</span>
								</div>
							{/if}
							<div class="detail-row">
								<span class="detail-label">Mode</span>
								<span class="detail-value badge" class:badge-purple={selectedPort.mode === 'trunk'}>
									{selectedPort.mode}
								</span>
							</div>
							<div class="detail-row">
								<span class="detail-label">VLANs</span>
								<span class="detail-value">{selectedPort.vlans.join(', ') || 'none'}</span>
							</div>
							<div class="detail-row">
								<span class="detail-label">Status</span>
								<span class="detail-value" class:text-red={selectedPort.shutdown}>
									{selectedPort.shutdown ? 'shutdown' : 'up'}
								</span>
							</div>
							{#if selectedPort.speed}
								<div class="detail-row">
									<span class="detail-label">Speed</span>
									<span class="detail-value">{selectedPort.speed}</span>
								</div>
							{/if}
							{#if selectedPort.ip_address}
								<div class="detail-row">
									<span class="detail-label">IP</span>
									<span class="detail-value">{selectedPort.ip_address}/{selectedPort.subnet_mask}</span>
								</div>
							{/if}
						</div>

						<!-- Connected devices on this port -->
						{#if selectedPort.ip_addresses.length > 0}
							<div class="detail-section">
								<h4>Connected Devices</h4>
								{#each selectedPort.ip_addresses as ip}
									<button class="device-item" onclick={() => showInLogical(ip)}>
										{ip}
										<span class="show-logical">Show in Logical</span>
									</button>
								{/each}
							</div>
						{/if}

						{#if selectedPort.mac_addresses.length > 0}
							<div class="detail-section">
								<h4>MAC Addresses ({selectedPort.mac_addresses.length})</h4>
								{#each selectedPort.mac_addresses as mac}
									<div class="mac-item">{mac}</div>
								{/each}
							</div>
						{/if}

						{#if selectedPort.cdp_neighbor}
							<div class="detail-section">
								<h4>CDP Neighbor</h4>
								<div class="detail-row">
									<span class="detail-label">Device</span>
									<span class="detail-value">{selectedPort.cdp_neighbor.device_id}</span>
								</div>
								<div class="detail-row">
									<span class="detail-label">Port</span>
									<span class="detail-value">{selectedPort.cdp_neighbor.remote_port}</span>
								</div>
								{#if selectedPort.cdp_neighbor.platform}
									<div class="detail-row">
										<span class="detail-label">Platform</span>
										<span class="detail-value">{selectedPort.cdp_neighbor.platform}</span>
									</div>
								{/if}
								{#if selectedPort.cdp_neighbor.ip_address}
									<div class="detail-row">
										<span class="detail-label">IP</span>
										<span class="detail-value">{selectedPort.cdp_neighbor.ip_address}</span>
									</div>
								{/if}
							</div>
						{/if}
					{:else}
						<!-- Switch overview -->
						<div class="detail-section">
							{#if selectedSwitch.management_ip}
								<div class="detail-row">
									<span class="detail-label">Mgmt IP</span>
									<span class="detail-value">{selectedSwitch.management_ip}</span>
								</div>
							{/if}
							{#if selectedSwitch.ios_version}
								<div class="detail-row">
									<span class="detail-label">IOS Version</span>
									<span class="detail-value">{selectedSwitch.ios_version}</span>
								</div>
							{/if}
							<div class="detail-row">
								<span class="detail-label">Ports</span>
								<span class="detail-value">{selectedSwitch.ports.length}</span>
							</div>
							<div class="detail-row">
								<span class="detail-label">VLANs</span>
								<span class="detail-value">{Object.keys(selectedSwitch.vlans).length}</span>
							</div>
						</div>

						<!-- VLAN list -->
						{#if Object.keys(selectedSwitch.vlans).length > 0}
							<div class="detail-section">
								<h4>VLANs</h4>
								{#each Object.entries(selectedSwitch.vlans) as [id, name]}
									<div class="detail-row">
										<span class="detail-label">VLAN {id}</span>
										<span class="detail-value">{name}</span>
									</div>
								{/each}
							</div>
						{/if}

						<!-- Port summary -->
						<div class="detail-section">
							<h4>Ports</h4>
							<div class="port-grid">
								{#each selectedSwitch.ports.filter((p) => !p.name.startsWith('Vlan') && !p.name.startsWith('Loopback')) as port}
									<button
										class="port-chip"
										class:has-device={port.mac_addresses.length > 0 || port.ip_addresses.length > 0}
										class:is-shutdown={port.shutdown}
										class:is-trunk={port.mode === 'trunk'}
										onclick={() => (selectedPort = port)}
									>
										{port.short_name}
									</button>
								{/each}
							</div>
						</div>
					{/if}
				</div>
			{/if}
		</div>
	</div>

	<!-- Legend -->
	<div class="physical-legend">
		<span class="legend-title">PORTS</span>
		<span class="legend-item">
			<span class="legend-dot" style="background: #475569"></span> Empty
		</span>
		<span class="legend-item">
			<span class="legend-dot" style="background: #3b82f6"></span> Has Devices
		</span>
		<span class="legend-item">
			<span class="legend-dot" style="background: #f59e0b"></span> CDP Link
		</span>
		<span class="legend-item">
			<span class="legend-dot" style="background: #8b5cf6; border-radius: 2px"></span> Trunk
		</span>
		<span class="legend-item">
			<span class="legend-dot" style="background: #374151; opacity: 0.5"></span> Shutdown
		</span>
		<span class="legend-item">
			<span class="legend-dot" style="background: #ef4444"></span> Highlighted
		</span>
	</div>
</div>

<style>
	.physical-container {
		display: flex;
		flex-direction: column;
		height: 100%;
	}

	/* ── Toolbar ─────────────────────────────────── */

	.physical-toolbar {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 8px 16px;
		border-bottom: 1px solid var(--gm-border);
		background: var(--gm-bg-secondary);
		flex-shrink: 0;
	}

	.toolbar-section {
		display: flex;
		align-items: center;
		gap: 8px;
	}

	.toolbar-sep {
		width: 1px;
		height: 18px;
		background: var(--gm-border);
		margin: 0 4px;
	}

	.view-title {
		font-size: 13px;
		font-weight: 600;
		letter-spacing: 1px;
		text-transform: uppercase;
		color: var(--gm-text-primary);
		margin: 0;
	}

	.switch-count, .link-count, .device-count {
		font-size: 10px;
		color: var(--gm-text-muted);
		padding: 2px 8px;
		background: var(--gm-bg-panel);
		border-radius: 3px;
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

	.tool-btn:hover {
		background: var(--gm-bg-hover);
		color: var(--gm-text-primary);
	}

	.tool-btn.danger:hover {
		border-color: #ef4444;
		color: #ef4444;
	}

	/* ── Body Layout ─────────────────────────────── */

	.physical-body {
		flex: 1;
		display: flex;
		min-height: 0;
		overflow: hidden;
	}

	/* ── Import Panel ─────────────────────────────── */

	.import-panel {
		width: 260px;
		min-width: 220px;
		border-right: 1px solid var(--gm-border);
		background: var(--gm-bg-secondary);
		overflow-y: auto;
		padding: 12px;
		display: flex;
		flex-direction: column;
		gap: 12px;
	}

	.panel-title {
		font-size: 11px;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 1px;
		color: var(--gm-text-secondary);
		margin: 0;
	}

	.import-form {
		display: flex;
		flex-direction: column;
		gap: 8px;
	}

	.import-label {
		font-size: 10px;
		color: var(--gm-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.5px;
		display: flex;
		flex-direction: column;
		gap: 4px;
	}

	.import-select, .import-input {
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 4px;
		color: var(--gm-text-primary);
		font-family: inherit;
		font-size: 11px;
		padding: 6px 8px;
	}

	.import-btn {
		padding: 8px 12px;
		background: #10b981;
		border: none;
		border-radius: 4px;
		color: #0a0e17;
		font-family: inherit;
		font-size: 11px;
		font-weight: 600;
		cursor: pointer;
		transition: all 0.15s;
	}

	.import-btn:hover { background: #059669; }
	.import-btn:disabled { opacity: 0.5; cursor: not-allowed; }

	.msg {
		font-size: 10px;
		padding: 6px 8px;
		border-radius: 4px;
	}

	.msg.error { background: rgba(239, 68, 68, 0.15); color: #ef4444; }
	.msg.success { background: rgba(16, 185, 129, 0.15); color: #10b981; }

	.import-help {
		font-size: 10px;
		color: var(--gm-text-muted);
		line-height: 1.5;
	}

	.import-help h4 {
		font-size: 10px;
		color: var(--gm-text-secondary);
		margin: 0 0 4px 0;
		text-transform: uppercase;
		letter-spacing: 0.5px;
	}

	.import-help ol {
		margin: 0;
		padding-left: 16px;
	}

	.import-help li {
		margin-bottom: 4px;
	}

	/* ── Locations Panel ─────────────────────────── */

	.locations-panel h4 {
		font-size: 10px;
		color: var(--gm-text-secondary);
		margin: 0 0 6px 0;
		text-transform: uppercase;
		letter-spacing: 0.5px;
	}

	.locations-list {
		display: flex;
		flex-direction: column;
		gap: 2px;
		max-height: 200px;
		overflow-y: auto;
	}

	.location-item {
		display: flex;
		flex-direction: column;
		padding: 4px 8px;
		background: transparent;
		border: none;
		border-radius: 3px;
		cursor: pointer;
		text-align: left;
		font-family: inherit;
		transition: background 0.1s;
	}

	.location-item:hover { background: var(--gm-bg-hover); }

	.loc-ip {
		font-size: 11px;
		color: var(--gm-text-primary);
		font-weight: 500;
	}

	.loc-detail {
		font-size: 9px;
		color: var(--gm-text-muted);
	}

	.loc-vlan {
		padding: 0 4px;
		background: rgba(139, 92, 246, 0.2);
		border-radius: 2px;
		color: #a78bfa;
		font-size: 8px;
	}

	/* ── Graph ─────────────────────────────────────── */

	.graph-wrapper {
		flex: 1;
		display: flex;
		min-width: 0;
		position: relative;
	}

	.graph-area {
		flex: 1;
		position: relative;
		background: var(--gm-bg-primary);
		background-image: radial-gradient(circle, #1e293b 1px, transparent 1px);
		background-size: 24px 24px;
	}

	.empty-state {
		position: absolute;
		top: 50%;
		left: 50%;
		transform: translate(-50%, -50%);
		text-align: center;
		color: var(--gm-text-muted);
		z-index: 1;
	}

	.empty-icon {
		font-size: 48px;
		margin-bottom: 12px;
		opacity: 0.3;
	}

	.empty-state h3 {
		font-size: 14px;
		font-weight: 600;
		color: var(--gm-text-secondary);
		margin: 0 0 8px 0;
	}

	.empty-state p {
		font-size: 12px;
		margin: 4px 0;
		line-height: 1.5;
	}

	.hint { color: var(--gm-text-muted); }

	/* ── Detail Panel ──────────────────────────────── */

	.detail-panel {
		width: 280px;
		min-width: 240px;
		border-left: 1px solid var(--gm-border);
		background: var(--gm-bg-secondary);
		overflow-y: auto;
		padding: 0;
	}

	.detail-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 12px;
		border-bottom: 1px solid var(--gm-border);
	}

	.detail-header h3 {
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
		padding: 2px 6px;
		border-radius: 3px;
	}

	.detail-close:hover { background: var(--gm-bg-hover); color: var(--gm-text-primary); }

	.detail-section {
		padding: 10px 12px;
		border-bottom: 1px solid var(--gm-border);
	}

	.detail-section h4 {
		font-size: 10px;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.5px;
		color: var(--gm-text-secondary);
		margin: 0 0 8px 0;
	}

	.detail-row {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 3px 0;
		font-size: 11px;
	}

	.detail-label {
		color: var(--gm-text-muted);
		font-size: 10px;
	}

	.detail-value {
		color: var(--gm-text-primary);
	}

	.badge {
		padding: 1px 6px;
		border-radius: 3px;
		font-size: 10px;
		background: rgba(16, 185, 129, 0.15);
		color: #10b981;
	}

	.badge-purple {
		background: rgba(139, 92, 246, 0.15);
		color: #a78bfa;
	}

	.text-red { color: #ef4444; }

	.device-item {
		display: flex;
		justify-content: space-between;
		align-items: center;
		width: 100%;
		padding: 4px 8px;
		background: transparent;
		border: none;
		border-radius: 3px;
		color: var(--gm-text-primary);
		font-family: inherit;
		font-size: 11px;
		cursor: pointer;
		text-align: left;
		transition: background 0.1s;
	}

	.device-item:hover { background: var(--gm-bg-hover); }

	.show-logical {
		font-size: 9px;
		color: #3b82f6;
		opacity: 0;
		transition: opacity 0.1s;
	}

	.device-item:hover .show-logical { opacity: 1; }

	.mac-item {
		font-size: 10px;
		color: var(--gm-text-muted);
		font-family: 'JetBrains Mono', monospace;
		padding: 2px 0;
	}

	/* ── Port Grid ──────────────────────────────────── */

	.port-grid {
		display: flex;
		flex-wrap: wrap;
		gap: 4px;
	}

	.port-chip {
		padding: 3px 6px;
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 3px;
		color: var(--gm-text-muted);
		font-family: 'JetBrains Mono', monospace;
		font-size: 9px;
		cursor: pointer;
		transition: all 0.1s;
	}

	.port-chip:hover {
		border-color: var(--gm-text-secondary);
		color: var(--gm-text-primary);
	}

	.port-chip.has-device {
		border-color: #3b82f6;
		color: #93c5fd;
	}

	.port-chip.is-trunk {
		border-color: #8b5cf6;
		color: #c4b5fd;
	}

	.port-chip.is-shutdown {
		opacity: 0.4;
		border-style: dashed;
	}

	/* ── Legend ──────────────────────────────────────── */

	.physical-legend {
		display: flex;
		align-items: center;
		gap: 14px;
		padding: 8px 16px;
		border-top: 1px solid var(--gm-border);
		background: var(--gm-bg-secondary);
		font-size: 9px;
		letter-spacing: 0.5px;
		flex-shrink: 0;
	}

	.legend-title {
		color: var(--gm-text-muted);
		font-weight: 600;
		letter-spacing: 1.5px;
	}

	.legend-item {
		display: flex;
		align-items: center;
		gap: 4px;
		color: var(--gm-text-secondary);
	}

	.legend-dot {
		width: 8px;
		height: 8px;
		border-radius: 50%;
	}
</style>
