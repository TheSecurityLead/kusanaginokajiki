<script lang="ts">
	import '../app.css';
	import { activeTab, themeMode } from '$lib/stores';
	import type { ViewTab } from '$lib/stores';
	import { assetCount, connectionCount, captureStatus } from '$lib/stores';
	import { getSettings, saveSettings } from '$lib/utils/tauri';
	import { onMount } from 'svelte';
	import { get } from 'svelte/store';
	import type { ThemeMode } from '$lib/types';

	let { children } = $props();

	const navItems: { id: ViewTab; label: string; icon: string }[] = [
		{ id: 'topology', label: 'Topology', icon: '\u2B21' },
		{ id: 'physical', label: 'Physical', icon: '\u2B22' },
		{ id: 'inventory', label: 'Inventory', icon: '\u2630' },
		{ id: 'protocol_stats', label: 'Protocols', icon: '\u25A4' },
		{ id: 'capture', label: 'Capture', icon: '\u25C9' },
		{ id: 'analysis', label: 'Analysis', icon: '\u2691' },
		{ id: 'export', label: 'Export', icon: '\u2913' },
		{ id: 'signatures', label: 'Signatures', icon: '\u2318' },
		{ id: 'settings', label: 'Settings', icon: '\u2699' }
	];

	function navigate(tab: ViewTab) {
		activeTab.set(tab);
	}

	// Apply theme to document root
	function applyTheme(mode: ThemeMode) {
		if (mode === 'system') {
			const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
			document.documentElement.setAttribute('data-theme', prefersDark ? 'dark' : 'light');
		} else {
			document.documentElement.setAttribute('data-theme', mode);
		}
	}

	async function toggleTheme() {
		const current = get(themeMode);
		const next: ThemeMode = current === 'dark' ? 'light' : current === 'light' ? 'system' : 'dark';
		themeMode.set(next);
		applyTheme(next);

		try {
			await saveSettings({ theme: next });
		} catch {
			// Settings save may fail in dev mode
		}
	}

	let currentTheme = $state<ThemeMode>('dark');
	themeMode.subscribe(v => currentTheme = v);

	onMount(async () => {
		try {
			const settings = await getSettings();
			const mode = settings.theme as ThemeMode;
			themeMode.set(mode);
			applyTheme(mode);
		} catch {
			// Expected in browser dev mode — default to dark
		}

		// Listen for system theme changes
		window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
			const mode = get(themeMode);
			if (mode === 'system') {
				applyTheme('system');
			}
		});
	});
</script>

<div class="app-shell">
	<!-- Sidebar Navigation -->
	<nav class="sidebar">
		<div class="sidebar-brand">
			<div class="brand-icon">KK</div>
			<div class="brand-text">
				<span class="brand-name">KUSANAGI</span>
				<span class="brand-sub">KAJIKI</span>
			</div>
		</div>

		<div class="nav-items">
			{#each navItems as item}
				<button
					class="nav-item"
					class:active={$activeTab === item.id}
					onclick={() => navigate(item.id)}
				>
					<span class="nav-icon">{item.icon}</span>
					<span class="nav-label">{item.label}</span>
				</button>
			{/each}
		</div>

		<!-- Status bar at bottom of sidebar -->
		<div class="sidebar-status">
			<div class="status-row">
				<span class="status-label">Assets</span>
				<span class="status-value">{$assetCount}</span>
			</div>
			<div class="status-row">
				<span class="status-label">Connections</span>
				<span class="status-value">{$connectionCount}</span>
			</div>
			<div class="status-row">
				<span class="status-label">Status</span>
				<span
					class="status-value"
					class:text-green={$captureStatus === 'capturing'}
					class:text-amber={$captureStatus === 'paused'}
					class:text-slate={$captureStatus === 'idle'}
					class:text-red={$captureStatus === 'error'}
				>
					{$captureStatus.toUpperCase()}
				</span>
			</div>
			<button class="theme-toggle" onclick={toggleTheme} title="Toggle theme ({currentTheme})">
				{#if currentTheme === 'dark'}
					<span class="theme-icon">&#9789;</span>
				{:else if currentTheme === 'light'}
					<span class="theme-icon">&#9788;</span>
				{:else}
					<span class="theme-icon">&#9681;</span>
				{/if}
				<span class="theme-label">{currentTheme.toUpperCase()}</span>
			</button>
		</div>
	</nav>

	<!-- Main Content Area -->
	<main class="main-content">
		{@render children()}
	</main>
</div>

<style>
	.app-shell {
		display: flex;
		height: 100vh;
		width: 100vw;
		overflow: hidden;
	}

	/* ── Sidebar ─────────────────────────────────────── */

	.sidebar {
		width: 200px;
		min-width: 200px;
		background: var(--gm-bg-secondary);
		border-right: 1px solid var(--gm-border);
		display: flex;
		flex-direction: column;
		padding: 0;
	}

	.sidebar-brand {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 16px 14px;
		border-bottom: 1px solid var(--gm-border);
	}

	.brand-icon {
		width: 36px;
		height: 36px;
		background: linear-gradient(135deg, #10b981, #059669);
		border-radius: 6px;
		display: flex;
		align-items: center;
		justify-content: center;
		font-size: 12px;
		font-weight: 700;
		color: #0a0e17;
		letter-spacing: 0.5px;
	}

	.brand-text {
		display: flex;
		flex-direction: column;
		line-height: 1.1;
	}

	.brand-name {
		font-size: 11px;
		font-weight: 700;
		letter-spacing: 2px;
		color: var(--gm-text-primary);
	}

	.brand-sub {
		font-size: 9px;
		font-weight: 500;
		letter-spacing: 3px;
		color: #10b981;
	}

	/* ── Navigation ──────────────────────────────────── */

	.nav-items {
		flex: 1;
		padding: 8px;
		display: flex;
		flex-direction: column;
		gap: 2px;
	}

	.nav-item {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 10px 12px;
		border: none;
		border-radius: 6px;
		background: transparent;
		color: var(--gm-text-secondary);
		font-family: inherit;
		font-size: 12px;
		font-weight: 500;
		cursor: pointer;
		transition: all 0.15s ease;
		text-align: left;
		width: 100%;
	}

	.nav-item:hover {
		background: var(--gm-bg-hover);
		color: var(--gm-text-primary);
	}

	.nav-item.active {
		background: rgba(16, 185, 129, 0.1);
		color: #10b981;
	}

	.nav-icon {
		font-size: 14px;
		width: 20px;
		text-align: center;
	}

	/* ── Status Bar ──────────────────────────────────── */

	.sidebar-status {
		padding: 12px 14px;
		border-top: 1px solid var(--gm-border);
		display: flex;
		flex-direction: column;
		gap: 6px;
	}

	.status-row {
		display: flex;
		justify-content: space-between;
		font-size: 10px;
	}

	.status-label {
		color: var(--gm-text-muted);
		text-transform: uppercase;
		letter-spacing: 1px;
	}

	.status-value {
		color: var(--gm-text-secondary);
		font-weight: 600;
	}

	.text-green { color: #10b981; }
	.text-amber { color: #f59e0b; }
	.text-slate { color: #64748b; }
	.text-red { color: #ef4444; }

	/* ── Theme Toggle ───────────────────────────────── */

	.theme-toggle {
		display: flex;
		align-items: center;
		gap: 8px;
		margin-top: 6px;
		padding: 6px 8px;
		border: 1px solid var(--gm-border);
		border-radius: 4px;
		background: transparent;
		color: var(--gm-text-muted);
		font-family: inherit;
		font-size: 10px;
		cursor: pointer;
		transition: all 0.15s;
	}

	.theme-toggle:hover {
		background: var(--gm-bg-hover);
		color: var(--gm-text-primary);
	}

	.theme-icon {
		font-size: 14px;
	}

	.theme-label {
		letter-spacing: 1px;
		font-weight: 500;
	}

	/* ── Main Content ────────────────────────────────── */

	.main-content {
		flex: 1;
		overflow: hidden;
		display: flex;
		flex-direction: column;
	}
</style>
