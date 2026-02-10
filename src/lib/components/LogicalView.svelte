<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { topology, selectedAssetId, groupingMode } from '$lib/stores';
	import { addFilteredView, addWatchTab } from '$lib/stores';
	import type { TopologyGraph, TopologyNode, GroupingMode, Asset } from '$lib/types';
	import { assets } from '$lib/stores';
	import {
		DEVICE_COLORS,
		DEVICE_LABELS,
		PROTOCOL_COLORS,
		edgeWidth,
		getGroupId,
		getGroupLabel,
		isOtProtocol
	} from '$lib/utils/graph';

	let graphContainer: HTMLDivElement;
	let cy: any = null;
	let fcoseRegistered = false;

	// ── Context Menu State ──────────────────────────────────
	let ctxMenu = $state<{ x: number; y: number; nodeId: string | null; show: boolean }>({
		x: 0,
		y: 0,
		nodeId: null,
		show: false
	});
	let groupSubmenu = $state(false);

	function hideContextMenu() {
		ctxMenu = { ...ctxMenu, show: false };
		groupSubmenu = false;
	}

	async function initCytoscape() {
		const cytoscape = (await import('cytoscape')).default;

		// Register fcose layout once
		if (!fcoseRegistered) {
			const fcose = (await import('cytoscape-fcose')).default;
			cytoscape.use(fcose);
			fcoseRegistered = true;
		}

		cy = cytoscape({
			container: graphContainer,
			style: [
				// ── Compound (group) nodes ──
				{
					selector: 'node.compound',
					style: {
						'background-color': 'rgba(30, 41, 59, 0.4)',
						'background-opacity': 0.4,
						'border-color': '#334155',
						'border-width': 1,
						'border-style': 'dashed' as any,
						label: 'data(label)',
						color: '#64748b',
						'font-size': '9px',
						'font-family': 'JetBrains Mono, monospace',
						'text-valign': 'top',
						'text-halign': 'center',
						'text-margin-y': -4,
						padding: '16px',
						shape: 'roundrectangle'
					}
				},
				// ── Regular device nodes ──
				{
					selector: 'node.device',
					style: {
						'background-color': '#1e293b',
						'border-color': 'data(color)',
						'border-width': 2,
						label: 'data(label)',
						color: '#e2e8f0',
						'font-size': '10px',
						'font-family': 'JetBrains Mono, monospace',
						'text-valign': 'bottom',
						'text-margin-y': 6,
						'text-wrap': 'wrap' as any,
						'text-max-width': '120px',
						width: 32,
						height: 32
					}
				},
				// ── OT device highlight ──
				{
					selector: 'node.device.ot',
					style: {
						'background-color': '#0f1d2e',
						'border-width': 2.5
					}
				},
				// ── Selected node ──
				{
					selector: 'node.device:selected',
					style: {
						'border-color': '#3b82f6',
						'border-width': 3,
						'background-color': '#1e3a5f'
					}
				},
				// ── Edges ──
				{
					selector: 'edge',
					style: {
						width: 'data(weight)',
						'line-color': 'data(color)',
						'target-arrow-color': 'data(color)',
						'target-arrow-shape': 'triangle',
						'arrow-scale': 0.8,
						'curve-style': 'bezier',
						opacity: 0.7
					}
				},
				// ── Bidirectional edges (arrows on both ends) ──
				{
					selector: 'edge.bidirectional',
					style: {
						'source-arrow-color': 'data(color)',
						'source-arrow-shape': 'triangle',
						'target-arrow-shape': 'triangle'
					}
				},
				// ── Selected edge ──
				{
					selector: 'edge:selected',
					style: {
						'line-color': '#3b82f6',
						'target-arrow-color': '#3b82f6',
						'source-arrow-color': '#3b82f6',
						opacity: 1
					}
				}
			],
			layout: { name: 'grid' },
			minZoom: 0.1,
			maxZoom: 5,
			wheelSensitivity: 0.3
		});

		// ── Node tap → select asset ──
		cy.on('tap', 'node.device', (event: any) => {
			selectedAssetId.set(event.target.id());
		});

		// ── Background tap → deselect ──
		cy.on('tap', (event: any) => {
			if (event.target === cy) {
				selectedAssetId.set(null);
				hideContextMenu();
			}
		});

		// ── Right-click context menu ──
		cy.on('cxttap', 'node.device', (event: any) => {
			const pos = event.renderedPosition || event.position;
			const rect = graphContainer.getBoundingClientRect();
			ctxMenu = {
				x: pos.x + rect.left,
				y: pos.y + rect.top,
				nodeId: event.target.id(),
				show: true
			};
			groupSubmenu = false;
		});

		cy.on('cxttap', (event: any) => {
			if (event.target === cy) {
				const rect = graphContainer.getBoundingClientRect();
				ctxMenu = {
					x: event.renderedPosition.x + rect.left,
					y: event.renderedPosition.y + rect.top,
					nodeId: null,
					show: true
				};
				groupSubmenu = false;
			}
		});
	}

	/** Build a display label for a node, including vendor if available */
	function nodeLabel(node: TopologyNode, assetMap: Map<string, Asset>): string {
		const asset = assetMap.get(node.ip_address);
		const vendor = asset?.vendor ?? node.vendor;
		if (vendor) {
			// Shorten long vendor names for the label
			const shortVendor = vendor.length > 20 ? vendor.substring(0, 18) + '...' : vendor;
			return `${node.ip_address}\n${shortVendor}`;
		}
		return node.ip_address;
	}

	/** Build Cytoscape elements from topology graph with current grouping */
	function buildElements(graph: TopologyGraph, mode: GroupingMode) {
		const elements: any[] = [];

		// Build asset map for enrichment
		let currentAssets: Asset[] = [];
		assets.subscribe((a) => (currentAssets = a))();
		const assetMap = new Map(currentAssets.map((a) => [a.ip_address, a]));

		if (mode !== 'none') {
			// Collect unique groups
			const groups = new Set<string>();
			for (const node of graph.nodes) {
				const gid = getGroupId(node, mode);
				if (gid) groups.add(gid);
			}

			// Add compound parent nodes
			for (const gid of groups) {
				elements.push({
					group: 'nodes',
					data: { id: gid, label: getGroupLabel(gid, mode) },
					classes: 'compound'
				});
			}
		}

		// Add device nodes
		for (const node of graph.nodes) {
			const hasOt = node.protocols.some((p) => isOtProtocol(p));
			const color = DEVICE_COLORS[node.device_type] ?? DEVICE_COLORS.unknown;
			const parentId = mode !== 'none' ? getGroupId(node, mode) : undefined;
			const asset = assetMap.get(node.ip_address);
			const confidence = asset?.confidence ?? 0;

			elements.push({
				group: 'nodes',
				data: {
					id: node.id,
					label: nodeLabel(node, assetMap),
					deviceType: node.device_type,
					vendor: asset?.vendor ?? node.vendor,
					productFamily: asset?.product_family,
					confidence,
					subnet: node.subnet,
					protocols: node.protocols.join(', '),
					packetCount: node.packet_count,
					color,
					...(parentId ? { parent: parentId } : {})
				},
				classes: hasOt ? 'device ot' : 'device'
			});
		}

		// Add edges
		for (const edge of graph.edges) {
			const color = PROTOCOL_COLORS[edge.protocol as string] ?? PROTOCOL_COLORS.unknown;
			const weight = edgeWidth(edge.packet_count);

			elements.push({
				group: 'edges',
				data: {
					id: edge.id,
					source: edge.source,
					target: edge.target,
					protocol: edge.protocol,
					packetCount: edge.packet_count,
					byteCount: edge.byte_count,
					color,
					weight
				},
				classes: edge.bidirectional ? 'bidirectional' : ''
			});
		}

		return elements;
	}

	function runLayout() {
		if (!cy || cy.nodes('.device').length === 0) return;

		cy.layout({
			name: 'fcose',
			animate: true,
			animationDuration: 600,
			quality: 'default',
			// Node repulsion — higher = more spread out
			nodeRepulsion: () => 8000,
			// Ideal edge length
			idealEdgeLength: () => 140,
			// Edge elasticity
			edgeElasticity: () => 0.45,
			// Alignment and nesting for compound nodes
			nestingFactor: 0.1,
			gravity: 0.25,
			gravityRange: 3.8,
			// Packing
			tile: true,
			tilingPaddingVertical: 20,
			tilingPaddingHorizontal: 20,
			padding: 40,
			// Compound node handling
			fit: true,
			randomize: false
		}).run();
	}

	/** Full graph rebuild when topology or grouping changes */
	function updateGraph(graph: TopologyGraph, mode: GroupingMode) {
		if (!cy || graph.nodes.length === 0) return;

		cy.elements().remove();
		const elements = buildElements(graph, mode);
		cy.add(elements);
		runLayout();
	}

	// ── Context menu actions ──

	function handleGroupBy(mode: GroupingMode) {
		groupingMode.set(mode);
		hideContextMenu();
	}

	function handleWatch() {
		if (ctxMenu.nodeId) {
			addWatchTab(ctxMenu.nodeId, 2);
		}
		hideContextMenu();
	}

	function handleCreateFilteredView() {
		addFilteredView([]);
		hideContextMenu();
	}

	// ── Store subscriptions ──

	let currentGraph: TopologyGraph = { nodes: [], edges: [] };
	let currentMode: GroupingMode = 'subnet';

	const unsubTopo = topology.subscribe((g) => {
		currentGraph = g;
		updateGraph(currentGraph, currentMode);
	});

	const unsubMode = groupingMode.subscribe((m) => {
		currentMode = m;
		updateGraph(currentGraph, currentMode);
	});

	// Rebuild graph when assets update (e.g., after signature matching enriches vendor data)
	const unsubAssets = assets.subscribe(() => {
		if (currentGraph.nodes.length > 0) {
			updateGraph(currentGraph, currentMode);
		}
	});

	// Close context menu on any click outside
	function handleWindowClick() {
		if (ctxMenu.show) hideContextMenu();
	}

	onMount(() => {
		initCytoscape();
		window.addEventListener('click', handleWindowClick);
	});

	onDestroy(() => {
		unsubTopo();
		unsubMode();
		unsubAssets();
		window.removeEventListener('click', handleWindowClick);
		cy?.destroy();
	});

	// Grouping mode labels for the toolbar dropdown
	const groupingOptions: { mode: GroupingMode; label: string }[] = [
		{ mode: 'subnet', label: 'Subnet (/24)' },
		{ mode: 'protocol', label: 'Protocol' },
		{ mode: 'device_role', label: 'Device Role' },
		{ mode: 'vendor', label: 'Vendor' },
		{ mode: 'none', label: 'None (Flat)' }
	];
</script>

<div class="topology-container">
	<!-- Toolbar -->
	<div class="topology-toolbar">
		<div class="toolbar-section">
			<h2 class="view-title">Logical View</h2>
			<span class="toolbar-sep"></span>
			<label class="group-label">
				Group:
				<select
					class="group-select"
					value={$groupingMode}
					onchange={(e) => groupingMode.set((e.target as HTMLSelectElement).value as GroupingMode)}
				>
					{#each groupingOptions as opt}
						<option value={opt.mode}>{opt.label}</option>
					{/each}
				</select>
			</label>
		</div>
		<div class="toolbar-section">
			<button class="tool-btn" onclick={() => cy?.fit(undefined, 40)}>Fit</button>
			<button class="tool-btn" onclick={() => cy?.center()}>Center</button>
			<button class="tool-btn" onclick={runLayout}>Relayout</button>
		</div>
	</div>

	<!-- Graph Canvas -->
	<div class="graph-area" bind:this={graphContainer}>
		{#if $topology.nodes.length === 0}
			<div class="empty-state">
				<div class="empty-icon">&#x2B21;</div>
				<h3>No Topology Data</h3>
				<p>Import a PCAP file or start a live capture to visualize network topology.</p>
				<p class="hint">Go to <strong>Capture</strong> &rarr; Import PCAP to get started.</p>
			</div>
		{/if}
	</div>

	<!-- Context Menu -->
	{#if ctxMenu.show}
		<!-- svelte-ignore a11y_no_static_element_interactions a11y_click_events_have_key_events -->
		<div
			class="context-menu"
			style="left: {ctxMenu.x}px; top: {ctxMenu.y}px;"
			onclick={(e) => e.stopPropagation()}
			oncontextmenu={(e) => e.preventDefault()}
		>
			{#if ctxMenu.nodeId}
				<button class="ctx-item" onclick={handleWatch}>
					Watch Node
				</button>
				<div class="ctx-sep"></div>
			{/if}
			<button class="ctx-item" onclick={handleCreateFilteredView}>
				Create Filtered View
			</button>
			<div class="ctx-sep"></div>
			<button
				class="ctx-item has-sub"
				onclick={(e) => { e.stopPropagation(); groupSubmenu = !groupSubmenu; }}
			>
				Group By &rsaquo;
			</button>
			{#if groupSubmenu}
				<div class="ctx-submenu">
					{#each groupingOptions as opt}
						<button
							class="ctx-item"
							class:ctx-active={$groupingMode === opt.mode}
							onclick={() => handleGroupBy(opt.mode)}
						>
							{opt.label}
						</button>
					{/each}
				</div>
			{/if}
		</div>
	{/if}

	<!-- Legend -->
	<div class="topology-legend">
		<span class="legend-title">DEVICES</span>
		{#each Object.entries(DEVICE_COLORS) as [type, color]}
			<span class="legend-item">
				<span class="legend-dot" style="background: {color}"></span>
				{DEVICE_LABELS[type] ?? type}
			</span>
		{/each}
	</div>
</div>

<style>
	.topology-container {
		display: flex;
		flex-direction: column;
		height: 100%;
		position: relative;
	}

	.topology-toolbar {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 8px 16px;
		border-bottom: 1px solid var(--gm-border);
		background: var(--gm-bg-secondary);
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

	.group-label {
		font-size: 11px;
		color: var(--gm-text-secondary);
		display: flex;
		align-items: center;
		gap: 6px;
	}

	.group-select {
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 4px;
		color: var(--gm-text-primary);
		font-family: inherit;
		font-size: 11px;
		padding: 3px 8px;
		cursor: pointer;
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
		border-color: var(--gm-border-active);
	}

	.graph-area {
		flex: 1;
		position: relative;
		background: var(--gm-bg-primary);
		background-image: radial-gradient(circle, #1e293b 1px, transparent 1px);
		background-size: 24px 24px;
	}

	/* ── Empty State ─────────────────────────────────── */

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

	.hint {
		margin-top: 12px !important;
		color: var(--gm-text-muted);
	}

	/* ── Context Menu ────────────────────────────────── */

	.context-menu {
		position: fixed;
		z-index: 100;
		min-width: 180px;
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 6px;
		padding: 4px 0;
		box-shadow: 0 8px 24px rgba(0, 0, 0, 0.5);
	}

	.ctx-item {
		display: block;
		width: 100%;
		padding: 7px 14px;
		background: none;
		border: none;
		color: var(--gm-text-secondary);
		font-family: inherit;
		font-size: 11px;
		text-align: left;
		cursor: pointer;
		transition: background 0.1s;
	}

	.ctx-item:hover {
		background: var(--gm-bg-hover);
		color: var(--gm-text-primary);
	}

	.ctx-item.has-sub {
		display: flex;
		justify-content: space-between;
	}

	.ctx-item.ctx-active {
		color: #10b981;
	}

	.ctx-sep {
		height: 1px;
		background: var(--gm-border);
		margin: 4px 0;
	}

	.ctx-submenu {
		border-top: 1px solid var(--gm-border);
		padding: 2px 0;
		margin-top: 2px;
		background: rgba(0, 0, 0, 0.1);
	}

	/* ── Legend ───────────────────────────────────────── */

	.topology-legend {
		display: flex;
		align-items: center;
		gap: 14px;
		padding: 8px 16px;
		border-top: 1px solid var(--gm-border);
		background: var(--gm-bg-secondary);
		font-size: 9px;
		letter-spacing: 0.5px;
		flex-wrap: wrap;
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
