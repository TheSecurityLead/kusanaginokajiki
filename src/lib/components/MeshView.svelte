<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { topology, selectedAssetId } from '$lib/stores';
	import type { TopologyGraph, IcsProtocol } from '$lib/types';
	import { PROTOCOL_COLORS, DEVICE_COLORS, edgeWidth, isOtProtocol } from '$lib/utils/graph';

	let graphContainer: HTMLDivElement;
	let cy: any = null;

	// ── Filters ──
	let filterProtocol = $state<string>('all');
	let filterMinPackets = $state(0);

	// Collect unique protocols from current topology for the filter dropdown
	let availableProtocols = $derived.by(() => {
		const protos = new Set<string>();
		for (const edge of $topology.edges) {
			protos.add(edge.protocol as string);
		}
		return Array.from(protos).sort();
	});

	async function initCytoscape() {
		const cytoscape = (await import('cytoscape')).default;

		cy = cytoscape({
			container: graphContainer,
			style: [
				{
					selector: 'node',
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
						width: 28,
						height: 28
					}
				},
				{
					selector: 'node.ot',
					style: {
						'background-color': '#0f1d2e',
						'border-width': 2.5
					}
				},
				{
					selector: 'node:selected',
					style: {
						'border-color': '#3b82f6',
						'border-width': 3,
						'background-color': '#1e3a5f'
					}
				},
				{
					selector: 'edge',
					style: {
						width: 'data(weight)',
						'line-color': 'data(color)',
						'target-arrow-color': 'data(color)',
						'target-arrow-shape': 'triangle',
						'arrow-scale': 0.7,
						'curve-style': 'bezier',
						opacity: 0.6
					}
				},
				{
					selector: 'edge.bidirectional',
					style: {
						'source-arrow-color': 'data(color)',
						'source-arrow-shape': 'triangle'
					}
				},
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

		cy.on('tap', 'node', (event: any) => {
			selectedAssetId.set(event.target.id());
		});

		cy.on('tap', (event: any) => {
			if (event.target === cy) selectedAssetId.set(null);
		});
	}

	/** Apply filters and rebuild mesh */
	function updateMesh(graph: TopologyGraph) {
		if (!cy || graph.nodes.length === 0) return;

		// Filter edges
		let filteredEdges = graph.edges;
		if (filterProtocol !== 'all') {
			filteredEdges = filteredEdges.filter((e) => (e.protocol as string) === filterProtocol);
		}
		if (filterMinPackets > 0) {
			filteredEdges = filteredEdges.filter((e) => e.packet_count >= filterMinPackets);
		}

		// Only include nodes that have edges after filtering
		const connectedNodes = new Set<string>();
		for (const e of filteredEdges) {
			connectedNodes.add(e.source);
			connectedNodes.add(e.target);
		}
		const filteredNodes = graph.nodes.filter((n) => connectedNodes.has(n.id));

		cy.elements().remove();

		// Add nodes — flat, no compound parents
		for (const node of filteredNodes) {
			const hasOt = node.protocols.some((p) => isOtProtocol(p));
			const color = DEVICE_COLORS[node.device_type] ?? DEVICE_COLORS.unknown;
			cy.add({
				group: 'nodes',
				data: {
					id: node.id,
					label: node.ip_address,
					color
				},
				classes: hasOt ? 'ot' : ''
			});
		}

		// Add edges
		for (const edge of filteredEdges) {
			const color = PROTOCOL_COLORS[edge.protocol as string] ?? PROTOCOL_COLORS.unknown;
			cy.add({
				group: 'edges',
				data: {
					id: edge.id,
					source: edge.source,
					target: edge.target,
					color,
					weight: edgeWidth(edge.packet_count)
				},
				classes: edge.bidirectional ? 'bidirectional' : ''
			});
		}

		// Circle layout for mesh view — shows all-to-all relationships
		cy.layout({
			name: 'circle',
			animate: true,
			animationDuration: 500,
			padding: 40
		}).run();
	}

	// Re-render when topology or filters change
	$effect(() => {
		// Touch reactive dependencies so this effect re-runs on filter changes
		const _proto = filterProtocol;
		const _min = filterMinPackets;
		const _graph = $topology;
		updateMesh(_graph);
	});

	const unsubTopo = topology.subscribe(() => {});

	onMount(() => {
		initCytoscape();
	});

	onDestroy(() => {
		unsubTopo();
		cy?.destroy();
	});
</script>

<div class="mesh-container">
	<!-- Toolbar -->
	<div class="mesh-toolbar">
		<div class="toolbar-section">
			<h2 class="view-title">Mesh View</h2>
			<span class="toolbar-sep"></span>
			<label class="filter-label">
				Protocol:
				<select class="filter-select" bind:value={filterProtocol}>
					<option value="all">All</option>
					{#each availableProtocols as proto}
						<option value={proto}>{proto}</option>
					{/each}
				</select>
			</label>
			<label class="filter-label">
				Min packets:
				<input
					type="number"
					class="filter-input"
					bind:value={filterMinPackets}
					min="0"
					step="10"
				/>
			</label>
		</div>
		<div class="toolbar-section">
			<button class="tool-btn" onclick={() => cy?.fit(undefined, 40)}>Fit</button>
			<button
				class="tool-btn"
				onclick={() =>
					cy?.layout({ name: 'circle', animate: true, animationDuration: 500, padding: 40 }).run()}
			>
				Relayout
			</button>
		</div>
	</div>

	<!-- Graph Canvas -->
	<div class="graph-area" bind:this={graphContainer}>
		{#if $topology.nodes.length === 0}
			<div class="empty-state">
				<div class="empty-icon">&#x25CE;</div>
				<h3>No Data</h3>
				<p>Import a PCAP to see the all-to-all mesh view.</p>
			</div>
		{/if}
	</div>
</div>

<style>
	.mesh-container {
		display: flex;
		flex-direction: column;
		height: 100%;
		position: relative;
	}

	.mesh-toolbar {
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

	.filter-label {
		font-size: 11px;
		color: var(--gm-text-secondary);
		display: flex;
		align-items: center;
		gap: 6px;
	}

	.filter-select,
	.filter-input {
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 4px;
		color: var(--gm-text-primary);
		font-family: inherit;
		font-size: 11px;
		padding: 3px 8px;
	}

	.filter-input {
		width: 70px;
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
</style>
