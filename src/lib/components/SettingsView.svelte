<script lang="ts">
	import { getAppInfo } from '$lib/utils/tauri';
	import { onMount } from 'svelte';

	let appVersion = $state('—');
	let rustVersion = $state('—');

	onMount(async () => {
		try {
			const info = await getAppInfo();
			appVersion = info.version;
			rustVersion = info.rust_version;
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
</style>
