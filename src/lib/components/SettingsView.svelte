<script lang="ts">
	import { getAppInfo, getSettings, saveSettings, listPlugins } from '$lib/utils/tauri';
	import { themeMode } from '$lib/stores';
	import { onMount } from 'svelte';
	import type { ThemeMode, PluginManifest } from '$lib/types';

	let appVersion = $state('—');
	let rustVersion = $state('—');
	let currentTheme = $state<ThemeMode>('dark');
	let plugins = $state<PluginManifest[]>([]);

	themeMode.subscribe(v => currentTheme = v);

	function applyTheme(mode: ThemeMode) {
		if (mode === 'system') {
			const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
			document.documentElement.setAttribute('data-theme', prefersDark ? 'dark' : 'light');
		} else {
			document.documentElement.setAttribute('data-theme', mode);
		}
	}

	async function setTheme(mode: ThemeMode) {
		themeMode.set(mode);
		applyTheme(mode);
		try {
			await saveSettings({ theme: mode });
		} catch {
			// May fail in dev
		}
	}

	onMount(async () => {
		try {
			const info = await getAppInfo();
			appVersion = info.version;
			rustVersion = info.rust_version;
		} catch {
			// Expected in browser dev mode
		}

		try {
			const settings = await getSettings();
			currentTheme = settings.theme as ThemeMode;
		} catch {
			// Expected in browser dev mode
		}

		try {
			plugins = await listPlugins();
		} catch {
			// Expected in browser dev mode
		}
	});
</script>

<div class="settings-container">
	<div class="settings-toolbar">
		<h2 class="view-title">Settings</h2>
	</div>

	<div class="settings-content">
		<section class="settings-section">
			<h3 class="section-title">About</h3>
			<div class="about-grid">
				<div class="about-row">
					<span class="about-label">Application</span>
					<span class="about-value">Kusanagi Kajiki</span>
				</div>
				<div class="about-row">
					<span class="about-label">Version</span>
					<span class="about-value">{appVersion}</span>
				</div>
				<div class="about-row">
					<span class="about-label">Rust Backend</span>
					<span class="about-value">{rustVersion}</span>
				</div>
				<div class="about-row">
					<span class="about-label">License</span>
					<span class="about-value">Apache 2.0</span>
				</div>
			</div>
			<p class="about-desc">
				Kusanagi Kajiki — a modern ICS/SCADA passive network discovery tool.
				Rebuilt with Tauri 2.0 (Rust) and SvelteKit for performance, security, and cross-platform support.
			</p>
		</section>

		<section class="settings-section">
			<h3 class="section-title">Theme</h3>
			<p class="section-desc">Light theme is recommended for control room environments where dark screens cause glare.</p>
			<div class="theme-buttons">
				<button
					class="theme-btn"
					class:active={currentTheme === 'dark'}
					onclick={() => setTheme('dark')}
				>
					<span class="theme-btn-icon">&#9789;</span>
					Dark
				</button>
				<button
					class="theme-btn"
					class:active={currentTheme === 'light'}
					onclick={() => setTheme('light')}
				>
					<span class="theme-btn-icon">&#9788;</span>
					Light
				</button>
				<button
					class="theme-btn"
					class:active={currentTheme === 'system'}
					onclick={() => setTheme('system')}
				>
					<span class="theme-btn-icon">&#9681;</span>
					System
				</button>
			</div>
		</section>

		<section class="settings-section">
			<h3 class="section-title">Capture Defaults</h3>
			<div class="setting-row">
				<label class="setting-label" for="promiscuous">Promiscuous Mode</label>
				<input type="checkbox" id="promiscuous" checked />
			</div>
			<div class="setting-row">
				<label class="setting-label" for="bpf">Default BPF Filter</label>
				<input
					type="text"
					id="bpf"
					class="setting-input"
					placeholder="e.g., port 502 or port 20000 or port 44818"
				/>
			</div>
		</section>

		<section class="settings-section">
			<h3 class="section-title">Database</h3>
			<div class="about-row">
				<span class="about-label">Location</span>
				<span class="about-value mono">~/.kusanaginokajiki/data.db</span>
			</div>
			<button class="action-btn danger" style="margin-top: 12px">
				Reset Database
			</button>
		</section>

		<section class="settings-section">
			<h3 class="section-title">Plugins</h3>
			<div class="about-row">
				<span class="about-label">Directory</span>
				<span class="about-value mono">~/.kusanaginokajiki/plugins/</span>
			</div>
			{#if plugins.length === 0}
				<p class="section-desc">No plugins installed. Place plugin directories with a manifest.json in the plugins directory.</p>
			{:else}
				<div class="plugin-list">
					{#each plugins as plugin}
						<div class="plugin-item">
							<div class="plugin-header">
								<span class="plugin-name">{plugin.name}</span>
								<span class="plugin-version">v{plugin.version}</span>
								<span class="plugin-type">{plugin.plugin_type}</span>
							</div>
							<p class="plugin-desc">{plugin.description}</p>
							{#if plugin.author}
								<span class="plugin-author">by {plugin.author}</span>
							{/if}
						</div>
					{/each}
				</div>
			{/if}
		</section>

		<section class="settings-section">
			<h3 class="section-title">CLI Usage</h3>
			<div class="cli-examples">
				<code>kusanaginokajiki --open capture.pcap</code>
				<code>kusanaginokajiki --import-pcap /path/to/file.pcap</code>
				<code>kusanaginokajiki --open session.kkj</code>
			</div>
		</section>
	</div>
</div>

<style>
	.settings-container {
		display: flex;
		flex-direction: column;
		height: 100%;
	}

	.settings-toolbar {
		padding: 10px 16px;
		border-bottom: 1px solid var(--gm-border);
		background: var(--gm-bg-secondary);
	}

	.view-title {
		font-size: 13px;
		font-weight: 600;
		letter-spacing: 1px;
		text-transform: uppercase;
		color: var(--gm-text-primary);
		margin: 0;
	}

	.settings-content {
		flex: 1;
		overflow-y: auto;
		padding: 20px 24px;
		display: flex;
		flex-direction: column;
		gap: 24px;
		max-width: 640px;
	}

	.settings-section {
		background: var(--gm-bg-secondary);
		border: 1px solid var(--gm-border);
		border-radius: 8px;
		padding: 20px;
	}

	.section-title {
		font-size: 13px;
		font-weight: 600;
		color: var(--gm-text-primary);
		margin: 0 0 14px 0;
		letter-spacing: 0.5px;
	}

	.section-desc {
		font-size: 11px;
		color: var(--gm-text-muted);
		margin: 0 0 12px 0;
		line-height: 1.5;
	}

	.about-grid {
		display: flex;
		flex-direction: column;
		gap: 8px;
	}

	.about-row {
		display: flex;
		justify-content: space-between;
		align-items: center;
		font-size: 11px;
	}

	.about-label {
		color: var(--gm-text-muted);
	}

	.about-value {
		color: var(--gm-text-secondary);
		font-weight: 500;
	}

	.about-value.mono {
		font-size: 10px;
	}

	.about-desc {
		font-size: 11px;
		color: var(--gm-text-muted);
		margin-top: 14px;
		line-height: 1.6;
	}

	.setting-row {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 8px 0;
	}

	.setting-label {
		font-size: 11px;
		color: var(--gm-text-secondary);
	}

	.setting-input {
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 4px;
		padding: 6px 10px;
		color: var(--gm-text-primary);
		font-family: inherit;
		font-size: 11px;
		width: 300px;
		outline: none;
	}

	.setting-input:focus {
		border-color: var(--gm-border-active);
	}

	.action-btn.danger {
		padding: 8px 16px;
		background: rgba(239, 68, 68, 0.1);
		border: 1px solid rgba(239, 68, 68, 0.2);
		border-radius: 6px;
		color: #ef4444;
		font-family: inherit;
		font-size: 11px;
		font-weight: 600;
		cursor: pointer;
	}

	/* ── Theme Buttons ──────────────────────────────── */

	.theme-buttons {
		display: flex;
		gap: 8px;
	}

	.theme-btn {
		display: flex;
		align-items: center;
		gap: 6px;
		padding: 8px 16px;
		border: 1px solid var(--gm-border);
		border-radius: 6px;
		background: transparent;
		color: var(--gm-text-secondary);
		font-family: inherit;
		font-size: 11px;
		cursor: pointer;
		transition: all 0.15s;
	}

	.theme-btn:hover {
		background: var(--gm-bg-hover);
	}

	.theme-btn.active {
		background: rgba(16, 185, 129, 0.1);
		border-color: #10b981;
		color: #10b981;
	}

	.theme-btn-icon {
		font-size: 16px;
	}

	/* ── Plugin List ─────────────────────────────────── */

	.plugin-list {
		display: flex;
		flex-direction: column;
		gap: 8px;
		margin-top: 12px;
	}

	.plugin-item {
		padding: 10px 12px;
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 6px;
	}

	.plugin-header {
		display: flex;
		align-items: center;
		gap: 8px;
		margin-bottom: 4px;
	}

	.plugin-name {
		font-size: 12px;
		font-weight: 600;
		color: var(--gm-text-primary);
	}

	.plugin-version {
		font-size: 10px;
		color: var(--gm-text-muted);
	}

	.plugin-type {
		font-size: 9px;
		padding: 2px 6px;
		background: rgba(16, 185, 129, 0.1);
		color: #10b981;
		border-radius: 3px;
		text-transform: uppercase;
		letter-spacing: 0.5px;
		font-weight: 600;
	}

	.plugin-desc {
		font-size: 10px;
		color: var(--gm-text-muted);
		margin: 0;
		line-height: 1.4;
	}

	.plugin-author {
		font-size: 9px;
		color: var(--gm-text-muted);
	}

	/* ── CLI Examples ────────────────────────────────── */

	.cli-examples {
		display: flex;
		flex-direction: column;
		gap: 6px;
	}

	.cli-examples code {
		display: block;
		padding: 6px 10px;
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 4px;
		font-size: 10px;
		color: var(--gm-text-secondary);
		user-select: text;
		-webkit-user-select: text;
	}
</style>
