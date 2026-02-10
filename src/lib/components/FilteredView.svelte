<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { topology, selectedAssetId, topologyTabs, groupingMode } from '$lib/stores';
	import { toggleNodeInFilter } from '$lib/stores';
	import type { TopologyGraph, FilteredViewConfig, GroupingMode } from '$lib/types';
	import {
		DEVICE_COLORS,
		PROTOCOL_COLORS,
		edgeWidth,
		isOtProtocol,
		getGroupId,
		getGroupLabel,
		filterGraph
	} from '$lib/utils/graph';

	/** The tab ID for this filtered view — set by the parent */
	let { tabId }: { tabId: string } = $props();

	let graphContainer: HTMLDivElement;
	let cy: any = null;
	let fcoseRegistered = false;

	// Get the filtered view config from the tabs store
	let config = $derived.by(() => {
		let tabs: any[];
		const unsub = topologyTabs.subscribe((t) => (tabs = t));
		unsub();
		return tabs!.find((t) => t.id === tabId) as FilteredViewConfig | undefined;
	});

	let hiddenSet = $derived(new Set(config?.hiddenNodeIds ?? []));

	async function initCytoscape() {
		const cytoscape = (await import('cytoscape')).default;
		if (!fcoseRegistered) {
			const fcose = (await import('cytoscape-fcose')).default;
			cytoscape.use(fcose);
			fcoseRegistered = true;
		}

		cy = cytoscape({
			container: graphContainer,
			style: [
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
						width: 32,
						height: 32
					}
				},
				{
					selector: 'node.device.ot',
					style: { 'background-color': '#0f1d2e', 'border-width': 2.5 }
				},
				{
					selector: 'node.device:selected',
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
						'arrow-scale': 0.8,
						'curve-style': 'bezier',
						opacity: 0.7
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

		cy.on('tap', 'node.device', (event: any) => {
			selectedAssetId.set(event.target.id());
		});

		cy.on('tap', (event: any) => {
			if (event.target === cy) selectedAssetId.set(null);
		});

		// Right-click to hide a node in this filtered view
		cy.on('cxttap', 'node.device', (event: any) => {
			toggleNodeInFilter(tabId, event.target.id());
		});
	}

	function updateGraph(graph: TopologyGraph, hidden: Set<string>, mode: GroupingMode) {
		if (!cy) return;

		const filtered = filterGraph(graph, hidden);
		cy.elements().remove();

		if (filtered.nodes.length === 0) return;

		if (mode !== 'none') {
			const groups = new Set<string>();
			for (const node of filtered.nodes) {
				const gid = getGroupId(node, mode);
				if (gid) groups.add(gid);
			}
			for (const gid of groups) {
				cy.add({
					group: 'nodes',
					data: { id: gid, label: getGroupLabel(gid, mode) },
					classes: 'compound'
				});
			}
		}

		for (const node of filtered.nodes) {
			const hasOt = node.protocols.some((p) => isOtProtocol(p));
			const color = DEVICE_COLORS[node.device_type] ?? DEVICE_COLORS.unknown;
			const parentId = mode !== 'none' ? getGroupId(node, mode) : undefined;
			cy.add({
				group: 'nodes',
				data: {
					id: node.id,
					label: node.ip_address,
					color,
					...(parentId ? { parent: parentId } : {})
				},
				classes: hasOt ? 'device ot' : 'device'
			});
		}

		for (const edge of filtered.edges) {
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

		cy.layout({
			name: 'fcose',
			animate: true,
			animationDuration: 600,
			quality: 'default',
			nodeRepulsion: () => 8000,
			idealEdgeLength: () => 140,
			nestingFactor: 0.1,
			gravity: 0.25,
			padding: 40,
			fit: true,
			randomize: false
		}).run();
	}

	// React to topology, hidden nodes, and grouping changes
	$effect(() => {
		const _graph = $topology;
		const _hidden = hiddenSet;
		const _mode = $groupingMode;
		updateGraph(_graph, _hidden, _mode);
	});

	onMount(() => {
		initCytoscape();
	});

	onDestroy(() => {
		cy?.destroy();
	});
</script>

<div class="filtered-container">
	<div class="filtered-toolbar">
		<div class="toolbar-section">
			<h2 class="view-title">Filtered View</h2>
			<span class="toolbar-sep"></span>
			<span class="filter-info">
				{hiddenSet.size} node{hiddenSet.size !== 1 ? 's' : ''} hidden
			</span>
			{#if hiddenSet.size > 0}
				<button class="tool-btn" onclick={() => {
					if (config) {
						// Unhide all
						for (const id of config.hiddenNodeIds) {
							toggleNodeInFilter(tabId, id);
						}
					}
				}}>
					Show All
				</button>
			{/if}
		</div>
		<div class="toolbar-section">
			<button class="tool-btn" onclick={() => cy?.fit(undefined, 40)}>Fit</button>
			<button class="tool-btn" onclick={() => cy?.layout({
				name: 'fcose', animate: true, animationDuration: 600, quality: 'default',
				nodeRepulsion: () => 8000, idealEdgeLength: () => 140,
				padding: 40, fit: true, randomize: false
			}).run()}>Relayout</button>
		</div>
	</div>

	<div class="graph-area" bind:this={graphContainer}>
		{#if $topology.nodes.length === 0}
			<div class="empty-state">
				<p>No topology data. Import a PCAP first.</p>
			</div>
		{:else if hiddenSet.size === $topology.nodes.length}
			<div class="empty-state">
				<p>All nodes are hidden. Right-click was used to hide nodes. Click "Show All" to restore.</p>
			</div>
		{/if}
	</div>

	<div class="filter-hint">
		Right-click a node to hide it from this view. Main Logical View is never modified.
	</div>
</div>

<style>
	.filtered-container {
		display: flex;
		flex-direction: column;
		height: 100%;
	}

	.filtered-toolbar {
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

	.filter-info {
		font-size: 11px;
		color: var(--gm-text-muted);
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
		font-size: 12px;
	}

	.filter-hint {
		padding: 6px 16px;
		font-size: 9px;
		color: var(--gm-text-muted);
		border-top: 1px solid var(--gm-border);
		background: var(--gm-bg-secondary);
	}
</style>
