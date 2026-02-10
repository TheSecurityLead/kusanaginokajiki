<script lang="ts">
	import { activeTab } from '$lib/stores';
	import { onMount } from 'svelte';
	import { listInterfaces } from '$lib/utils/tauri';
	import { interfaces } from '$lib/stores';
	import TopologyView from '$lib/components/TopologyView.svelte';
	import InventoryView from '$lib/components/InventoryView.svelte';
	import CaptureView from '$lib/components/CaptureView.svelte';
	import SettingsView from '$lib/components/SettingsView.svelte';

	onMount(async () => {
		try {
			const ifaces = await listInterfaces();
			interfaces.set(ifaces);
		} catch (err) {
			console.warn('Failed to load interfaces (expected in browser dev mode):', err);
		}
	});
</script>

{#if $activeTab === 'topology'}
	<TopologyView />
{:else if $activeTab === 'inventory'}
	<InventoryView />
{:else if $activeTab === 'capture'}
	<CaptureView />
{:else if $activeTab === 'settings'}
	<SettingsView />
{/if}
