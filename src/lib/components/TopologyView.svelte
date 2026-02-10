<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { topology, selectedAssetId, assets } from '$lib/stores';
	import type { TopologyGraph, TopologyNode } from '$lib/types';

	let graphContainer: HTMLDivElement;
	let cy: any = null;

	// Protocol → color mapping
	const protocolColors: Record<string, string> = {
		modbus: '#f59e0b',
		dnp3: '#10b981',
		ethernet_ip: '#8b5cf6',
		bacnet: '#06b6d4',
		s7comm: '#ef4444',
		opc_ua: '#ec4899',
		unknown: '#64748b'
	};

	// Device type → color mapping
	const deviceColors: Record<string, string> = {
		plc: '#f59e0b',
		rtu: '#10b981',
		hmi: '#3b82f6',
		historian: '#8b5cf6',
		engineering_workstation: '#06b6d4',
		scada_server: '#ec4899',
		it_device: '#475569',
		unknown: '#64748b'
	};

	async function initCytoscape() {
		// Dynamic import — Cytoscape is heavy, load only when needed
		const cytoscape = (await import('cytoscape')).default;

		cy = cytoscape({
			container: graphContainer,
			style: [
				{
					selector: 'node',
					style: {
						'background-color': '#1e293b',
						'border-color': '#475569',
						'border-width': 2,
						label: 'data(label)',
						color: '#e2e8f0',
						'font-size': '10px',
						'font-family': 'JetBrains Mono, monospace',
						'text-valign': 'bottom',
						'text-margin-y': 6,
						width: 32,
						height: 32
					}
				},
				{
					selector: 'node.ot-device',
					style: {
						'border-color': '#10b981',
						'border-width': 2
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
						width: 1.5,
						'line-color': '#334155',
						'target-arrow-color': '#334155',
						'target-arrow-shape': 'triangle',
						'curve-style': 'bezier',
						opacity: 0.7
					}
				},
				{
					selector: 'edge:selected',
					style: {
						'line-color': '#3b82f6',
						'target-arrow-color': '#3b82f6',
						width: 2.5,
						opacity: 1
					}
				}
			],
			layout: {
				name: 'grid' // Will switch to fcose once we have real data
			},
			minZoom: 0.1,
			maxZoom: 5,
			wheelSensitivity: 0.3
		});

		// Handle node selection
		cy.on('tap', 'node', (event: any) => {
			const nodeId = event.target.id();
			selectedAssetId.set(nodeId);
		});

		// Deselect on background click
		cy.on('tap', (event: any) => {
			if (event.target === cy) {
				selectedAssetId.set(null);
			}
		});
	}

	/** Update Cytoscape graph when topology store changes */
	function updateGraph(graph: TopologyGraph) {
		if (!cy || graph.nodes.length === 0) return;

		cy.elements().remove();

		// Add nodes
		graph.nodes.forEach((node) => {
			cy.add({
				group: 'nodes',
				data: {
					id: node.id,
					label: node.ip_address,
					deviceType: node.device_type,
					vendor: node.vendor
				},
				classes: node.device_type !== 'it_device' ? 'ot-device' : ''
			});
		});

		// Add edges
		graph.edges.forEach((edge) => {
			cy.add({
				group: 'edges',
				data: {
					id: edge.id,
					source: edge.source,
					target: edge.target,
					protocol: edge.protocol,
					packetCount: edge.packet_count
				}
			});
		});

		// Apply layout
		cy.layout({
			name: 'cose',
			animate: true,
			animationDuration: 500,
			nodeRepulsion: () => 8000,
			idealEdgeLength: () => 120,
			padding: 40
		}).run();
	}

	// Subscribe to topology changes
	const unsubscribe = topology.subscribe((graph) => {
		updateGraph(graph);
	});

	onMount(() => {
		initCytoscape();
	});

	onDestroy(() => {
		unsubscribe();
		cy?.destroy();
	});
</script>

<div class="topology-container">
	<!-- Toolbar -->
	<div class="topology-toolbar">
		<div class="toolbar-section">
			<h2 class="view-title">Network Topology</h2>
		</div>
		<div class="toolbar-section">
			<button class="tool-btn" onclick={() => cy?.fit(undefined, 40)}>Fit</button>
			<button class="tool-btn" onclick={() => cy?.center()}>Center</button>
			<button
				class="tool-btn"
				onclick={() => {
					cy?.layout({ name: 'cose', animate: true, animationDuration: 500 }).run();
				}}>Relayout</button
			>
		</div>
	</div>

	<!-- Graph Canvas -->
	<div class="graph-area" bind:this={graphContainer}>
		<!-- Cytoscape renders here -->

		<!-- Empty state overlay when no data loaded -->
		{#if $topology.nodes.length === 0}
			<div class="empty-state">
				<div class="empty-icon">⬡</div>
				<h3>No Topology Data</h3>
				<p>Import a PCAP file or start a live capture to visualize network topology.</p>
				<p class="hint">Go to <strong>Capture</strong> → Import PCAP to get started.</p>
			</div>
		{/if}
	</div>

	<!-- Legend -->
	<div class="topology-legend">
		<span class="legend-title">PROTOCOLS</span>
		{#each Object.entries(protocolColors) as [proto, color]}
			<span class="legend-item">
				<span class="legend-dot" style="background: {color}"></span>
				{proto.toUpperCase()}
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
		padding: 10px 16px;
		border-bottom: 1px solid var(--gm-border);
		background: var(--gm-bg-secondary);
	}

	.toolbar-section {
		display: flex;
		align-items: center;
		gap: 8px;
	}

	.view-title {
		font-size: 13px;
		font-weight: 600;
		letter-spacing: 1px;
		text-transform: uppercase;
		color: var(--gm-text-primary);
		margin: 0;
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
		/* Subtle grid pattern */
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
