<script lang="ts">
	import '../app.css';
	import { activeTab, themeMode, activeProject } from '$lib/stores';
	import type { ViewTab } from '$lib/stores';
	import { clearActiveProject, onLiveAttackAlert } from '$lib/utils/tauri';
	import { assetCount, connectionCount, captureStatus } from '$lib/stores';
	import { getSettings, saveSettings } from '$lib/utils/tauri';
	import { onMount, onDestroy } from 'svelte';
	import { get } from 'svelte/store';
	import type { ThemeMode, LiveAttackAlert } from '$lib/types';

	// ── Live ATT&CK Toast Notifications ──────────────────
	interface Toast {
		id: number;
		alert: LiveAttackAlert;
	}

	let toasts = $state<Toast[]>([]);
	let toastCounter = 0;
	let liveAlertBadge = $state(0);
	let unlisten: (() => void) | null = null;

	function addToast(alert: LiveAttackAlert) {
		const id = ++toastCounter;
		toasts = [...toasts, { id, alert }];
		liveAlertBadge++;
		// Auto-dismiss after 8 seconds
		setTimeout(() => {
			toasts = toasts.filter((t) => t.id !== id);
		}, 8000);
	}

	function dismissToast(id: number) {
		toasts = toasts.filter((t) => t.id !== id);
	}

	function clearAlertBadge() {
		liveAlertBadge = 0;
	}

	let { children } = $props();

	const navItems: { id: ViewTab; label: string; icon: string }[] = [
		{ id: 'projects', label: 'Projects', icon: '\u{1F4C1}' },
		{ id: 'topology', label: 'Topology', icon: '\u2B21' },
		{ id: 'physical', label: 'Physical', icon: '\u2B22' },
		{ id: 'inventory', label: 'Inventory', icon: '\u2630' },
		{ id: 'protocol_stats', label: 'Protocols', icon: '\u25A4' },
		{ id: 'comm_patterns', label: 'Comm Patterns', icon: '\u2306' },
		{ id: 'capture', label: 'Capture', icon: '\u25C9' },
		{ id: 'analysis', label: 'Analysis', icon: '\u2691' },
		{ id: 'segmentation', label: 'Segmentation', icon: '\u25FB' },
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

	async function handleClearProject() {
		try {
			await clearActiveProject();
		} catch {
			// ignore errors in dev mode
		}
		activeProject.set(null);
		activeTab.set('projects');
	}

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

		// Subscribe to live ATT&CK alerts from the backend
		try {
			unlisten = await onLiveAttackAlert(addToast);
		} catch {
			// Not available in browser dev mode
		}
	});

	onDestroy(() => {
		if (unlisten) unlisten();
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

		<!-- Active project strip -->
		{#if $activeProject}
			<div class="active-project-strip">
				<div class="active-project-info">
					<span class="active-project-label">Project</span>
					<span class="active-project-name">{$activeProject.name}</span>
					{#if $activeProject.client_name}
						<span class="active-project-client">{$activeProject.client_name}</span>
					{/if}
				</div>
				<button class="active-project-close" title="Close project"
					onclick={handleClearProject}>&#10005;</button>
			</div>
		{/if}

		<!-- Status bar at bottom of sidebar -->
		<div class="sidebar-status">
			<div class="status-row">
				<span class="status-label">Assets</span>
				<span class="status-value">{$assetCount.toLocaleString()}</span>
			</div>
			<div class="status-row">
				<span class="status-label">Connections</span>
				<span class="status-value">{$connectionCount.toLocaleString()}</span>
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

<!-- Live ATT&CK Alert Toasts -->
{#if toasts.length > 0}
	<div class="toast-container">
		{#each toasts as toast (toast.id)}
			<div class="toast toast-sev-{toast.alert.severity}">
				<div class="toast-header">
					<span class="toast-technique">{toast.alert.technique_id}</span>
					<span class="toast-sev">{toast.alert.severity.toUpperCase()}</span>
					<button class="toast-close" onclick={() => dismissToast(toast.id)}>&#10005;</button>
				</div>
				<div class="toast-title">{toast.alert.title}</div>
				<div class="toast-evidence">{toast.alert.evidence}</div>
			</div>
		{/each}
	</div>
{/if}

<!-- Live alert badge (click to dismiss counter) -->
{#if liveAlertBadge > 0}
	<button class="live-alert-badge" onclick={clearAlertBadge} title="Live ATT&CK alerts detected during capture">
		&#9888; {liveAlertBadge} live alert{liveAlertBadge !== 1 ? 's' : ''}
	</button>
{/if}

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

	/* ── Active Project Strip ────────────────────────── */

	.active-project-strip {
		margin: 0 8px 4px;
		padding: 8px 10px;
		background: rgba(16, 185, 129, 0.08);
		border: 1px solid rgba(16, 185, 129, 0.25);
		border-radius: 6px;
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 6px;
	}

	.active-project-info {
		display: flex;
		flex-direction: column;
		gap: 1px;
		min-width: 0;
	}

	.active-project-label {
		font-size: 9px;
		font-weight: 600;
		color: #10b981;
		text-transform: uppercase;
		letter-spacing: 1px;
	}

	.active-project-name {
		font-size: 11px;
		font-weight: 600;
		color: var(--gm-text-primary);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}

	.active-project-client {
		font-size: 10px;
		color: var(--gm-text-muted);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}

	.active-project-close {
		background: transparent;
		border: none;
		color: var(--gm-text-muted);
		font-size: 10px;
		cursor: pointer;
		padding: 2px 4px;
		border-radius: 3px;
		flex-shrink: 0;
		transition: all 0.1s;
	}

	.active-project-close:hover {
		background: rgba(239, 68, 68, 0.15);
		color: #ef4444;
	}

	/* ── Main Content ────────────────────────────────── */

	.main-content {
		flex: 1;
		overflow: hidden;
		display: flex;
		flex-direction: column;
	}

	/* ── Live ATT&CK Toast Notifications ─────────────── */

	:global(.toast-container) {
		position: fixed;
		bottom: 24px;
		right: 24px;
		display: flex;
		flex-direction: column-reverse;
		gap: 8px;
		z-index: 9999;
		max-width: 380px;
	}

	:global(.toast) {
		background: #1a1f2e;
		border: 1px solid var(--gm-border);
		border-left: 3px solid var(--gm-severity-high);
		border-radius: 8px;
		padding: 12px 14px;
		box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
		display: flex;
		flex-direction: column;
		gap: 4px;
	}

	:global(.toast-sev-critical) { border-left-color: var(--gm-severity-critical); }
	:global(.toast-sev-high)     { border-left-color: var(--gm-severity-high); }
	:global(.toast-sev-medium)   { border-left-color: var(--gm-severity-medium); }
	:global(.toast-sev-low)      { border-left-color: var(--gm-severity-low); }

	:global(.toast-header) {
		display: flex;
		align-items: center;
		gap: 8px;
	}

	:global(.toast-technique) {
		font-size: 10px;
		font-weight: 700;
		font-family: 'JetBrains Mono', monospace;
		color: var(--gm-text-muted);
		background: rgba(255, 255, 255, 0.05);
		padding: 2px 6px;
		border-radius: 3px;
	}

	:global(.toast-sev) {
		font-size: 10px;
		font-weight: 700;
		color: var(--gm-severity-high);
		flex: 1;
	}

	:global(.toast-close) {
		background: none;
		border: none;
		color: var(--gm-text-muted);
		font-size: 10px;
		cursor: pointer;
		padding: 0 2px;
	}

	:global(.toast-close:hover) {
		color: var(--gm-text-primary);
	}

	:global(.toast-title) {
		font-size: 12px;
		font-weight: 600;
		color: var(--gm-text-primary);
	}

	:global(.toast-evidence) {
		font-size: 10px;
		color: var(--gm-text-muted);
		font-family: 'JetBrains Mono', monospace;
	}

	:global(.live-alert-badge) {
		position: fixed;
		bottom: 24px;
		left: 210px;
		background: rgba(239, 68, 68, 0.15);
		border: 1px solid rgba(239, 68, 68, 0.4);
		border-radius: 6px;
		color: #ef4444;
		font-size: 11px;
		font-weight: 600;
		padding: 6px 12px;
		cursor: pointer;
		z-index: 9998;
	}

	:global(.live-alert-badge:hover) {
		background: rgba(239, 68, 68, 0.25);
	}
</style>
