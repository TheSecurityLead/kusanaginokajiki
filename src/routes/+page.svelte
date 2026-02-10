<script lang="ts">
	import { activeTab } from '$lib/stores';
	import { onMount } from 'svelte';
	import { listInterfaces } from '$lib/utils/tauri';
	import { interfaces, connections } from '$lib/stores';
	import TopologyView from '$lib/components/TopologyView.svelte';
	import InventoryView from '$lib/components/InventoryView.svelte';
	import CaptureView from '$lib/components/CaptureView.svelte';
	import SettingsView from '$lib/components/SettingsView.svelte';
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
</script>

{#if $connections.length > 0 && ($activeTab === 'topology' || $activeTab === 'inventory')}
	<div class="split-layout">
		{#if showTree}
			<div class="tree-panel">
				<ConnectionTree />
			</div>
			<button class="tree-toggle collapse" onclick={() => (showTree = false)} title="Hide connection tree">
				‹
			</button>
		{:else}
			<button class="tree-toggle expand" onclick={() => (showTree = true)} title="Show connection tree">
				›
			</button>
		{/if}
		<div class="main-panel">
			{#if $activeTab === 'topology'}
				<TopologyView />
			{:else if $activeTab === 'inventory'}
				<InventoryView />
			{/if}
		</div>
	</div>
{:else if $activeTab === 'topology'}
	<TopologyView />
{:else if $activeTab === 'inventory'}
	<InventoryView />
{:else if $activeTab === 'capture'}
	<CaptureView />
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
</style>
