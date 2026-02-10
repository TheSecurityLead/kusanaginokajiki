<script lang="ts">
	import { activeTab } from '$lib/stores';
	import { onMount } from 'svelte';
	import { listInterfaces } from '$lib/utils/tauri';
	import { interfaces, connections, topologyTabs, activeTopologyTabId } from '$lib/stores';
	import { closeTopologyTab } from '$lib/stores';
	import LogicalView from '$lib/components/LogicalView.svelte';
	import MeshView from '$lib/components/MeshView.svelte';
	import FilteredView from '$lib/components/FilteredView.svelte';
	import WatchTab from '$lib/components/WatchTab.svelte';
	import InventoryView from '$lib/components/InventoryView.svelte';
	import CaptureView from '$lib/components/CaptureView.svelte';
	import SettingsView from '$lib/components/SettingsView.svelte';
	import SignatureEditor from '$lib/components/SignatureEditor.svelte';
	import ProtocolStats from '$lib/components/ProtocolStats.svelte';
	import ConnectionTree from '$lib/components/ConnectionTree.svelte';

	let showTree = $state(true);

	onMount(async () => {
		try {
			const ifaces = await listInterfaces();
			interfaces.set(ifaces);
		} catch (err) {
			console.warn('Failed to load interfaces (expected in browser dev mode):', err);
		}
	});

	function selectTab(tabId: string) {
		activeTopologyTabId.set(tabId);
	}

	function handleCloseTab(e: Event, tabId: string) {
		e.stopPropagation();
		closeTopologyTab(tabId);
	}
</script>

{#if $connections.length > 0 && ($activeTab === 'topology' || $activeTab === 'inventory')}
	<div class="split-layout">
		{#if showTree}
			<div class="tree-panel">
				<ConnectionTree />
			</div>
			<button class="tree-toggle collapse" onclick={() => (showTree = false)} title="Hide connection tree">
				&#x2039;
			</button>
		{:else}
			<button class="tree-toggle expand" onclick={() => (showTree = true)} title="Show connection tree">
				&#x203A;
			</button>
		{/if}
		<div class="main-panel">
			{#if $activeTab === 'topology'}
				<!-- Topology sub-tab bar -->
				<div class="topo-tab-bar">
					{#each $topologyTabs as tab}
						<button
							class="topo-tab"
							class:active={$activeTopologyTabId === tab.id}
							onclick={() => selectTab(tab.id)}
						>
							<span class="topo-tab-label">{tab.label}</span>
							{#if tab.closeable}
								<span
									class="topo-tab-close"
									role="button"
									tabindex="0"
									onclick={(e) => handleCloseTab(e, tab.id)}
									onkeydown={(e) => { if (e.key === 'Enter') handleCloseTab(e, tab.id); }}
								>&times;</span>
							{/if}
						</button>
					{/each}
				</div>
				<!-- Active topology view -->
				<div class="topo-content">
					{#each $topologyTabs as tab}
						{#if $activeTopologyTabId === tab.id}
							{#if tab.type === 'logical'}
								<LogicalView />
							{:else if tab.type === 'mesh'}
								<MeshView />
							{:else if tab.type === 'filtered'}
								<FilteredView tabId={tab.id} />
							{:else if tab.type === 'watch'}
								<WatchTab tabId={tab.id} />
							{/if}
						{/if}
					{/each}
				</div>
			{:else if $activeTab === 'inventory'}
				<InventoryView />
			{/if}
		</div>
	</div>
{:else if $activeTab === 'topology'}
	<!-- No connections yet — show topology with tab bar but no tree -->
	<div class="full-layout">
		<div class="topo-tab-bar">
			{#each $topologyTabs as tab}
				<button
					class="topo-tab"
					class:active={$activeTopologyTabId === tab.id}
					onclick={() => selectTab(tab.id)}
				>
					<span class="topo-tab-label">{tab.label}</span>
					{#if tab.closeable}
						<span
							class="topo-tab-close"
							role="button"
							tabindex="0"
							onclick={(e) => handleCloseTab(e, tab.id)}
							onkeydown={(e) => { if (e.key === 'Enter') handleCloseTab(e, tab.id); }}
						>&times;</span>
					{/if}
				</button>
			{/each}
		</div>
		<div class="topo-content">
			{#each $topologyTabs as tab}
				{#if $activeTopologyTabId === tab.id}
					{#if tab.type === 'logical'}
						<LogicalView />
					{:else if tab.type === 'mesh'}
						<MeshView />
					{:else if tab.type === 'filtered'}
						<FilteredView tabId={tab.id} />
					{:else if tab.type === 'watch'}
						<WatchTab tabId={tab.id} />
					{/if}
				{/if}
			{/each}
		</div>
	</div>
{:else if $activeTab === 'inventory'}
	<InventoryView />
{:else if $activeTab === 'protocol_stats'}
	<ProtocolStats />
{:else if $activeTab === 'capture'}
	<CaptureView />
{:else if $activeTab === 'signatures'}
	<SignatureEditor />
{:else if $activeTab === 'settings'}
	<SettingsView />
{/if}

<style>
	.split-layout {
		display: flex;
		height: 100%;
		width: 100%;
		position: relative;
	}

	.tree-panel {
		width: 340px;
		min-width: 260px;
		max-width: 480px;
		flex-shrink: 0;
		overflow: hidden;
	}

	.main-panel {
		flex: 1;
		min-width: 0;
		overflow: hidden;
		display: flex;
		flex-direction: column;
	}

	.full-layout {
		display: flex;
		flex-direction: column;
		height: 100%;
		width: 100%;
	}

	.tree-toggle {
		position: absolute;
		z-index: 10;
		top: 50%;
		transform: translateY(-50%);
		width: 16px;
		height: 48px;
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		color: var(--gm-text-muted);
		font-size: 12px;
		cursor: pointer;
		display: flex;
		align-items: center;
		justify-content: center;
		transition: all 0.15s;
	}

	.tree-toggle:hover {
		background: var(--gm-bg-hover);
		color: var(--gm-text-primary);
	}

	.tree-toggle.collapse {
		left: 340px;
		border-radius: 0 4px 4px 0;
	}

	.tree-toggle.expand {
		left: 0;
		border-radius: 0 4px 4px 0;
	}

	/* ── Topology Sub-Tab Bar ──────────────────────── */

	.topo-tab-bar {
		display: flex;
		align-items: stretch;
		background: var(--gm-bg-secondary);
		border-bottom: 1px solid var(--gm-border);
		overflow-x: auto;
		flex-shrink: 0;
	}

	.topo-tab {
		display: flex;
		align-items: center;
		gap: 6px;
		padding: 7px 14px;
		background: transparent;
		border: none;
		border-bottom: 2px solid transparent;
		color: var(--gm-text-muted);
		font-family: inherit;
		font-size: 11px;
		font-weight: 500;
		cursor: pointer;
		white-space: nowrap;
		transition: all 0.15s;
	}

	.topo-tab:hover {
		color: var(--gm-text-secondary);
		background: rgba(255, 255, 255, 0.02);
	}

	.topo-tab.active {
		color: var(--gm-text-primary);
		border-bottom-color: #10b981;
	}

	.topo-tab-close {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		width: 16px;
		height: 16px;
		border-radius: 3px;
		font-size: 13px;
		line-height: 1;
		color: var(--gm-text-muted);
		transition: all 0.1s;
	}

	.topo-tab-close:hover {
		background: rgba(239, 68, 68, 0.2);
		color: #ef4444;
	}

	.topo-content {
		flex: 1;
		min-height: 0;
		overflow: hidden;
	}
</style>
