<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import {
		timelineRange, timelinePosition, timelinePlaying, timelineEnabled, connections
	} from '$lib/stores';
	import type { TimelineRange } from '$lib/types';
	import { getTimelineRange } from '$lib/utils/tauri';

	// ─── Local State ────────────────────────────────────────────

	/** Current slider position (0.0 = earliest, 1.0 = latest/all data) */
	let position = $state(1.0);

	/** Whether the scrubber is enabled (filtering by time) */
	let enabled = $state(false);

	/** Whether playback is active */
	let playing = $state(false);

	/** Playback speed multiplier */
	let speed = $state<1 | 2 | 5>(1);

	/** Whether the scrubber bar is expanded (shows controls) */
	let expanded = $state(false);

	/** Loaded timeline range from backend */
	let range = $state<TimelineRange | null>(null);

	/** Error message if timeline range fetch fails */
	let error = $state<string | null>(null);

	/** Interval ID for playback timer */
	let playbackInterval: ReturnType<typeof setInterval> | null = null;

	// ─── Derived Values ─────────────────────────────────────────

	/** Earliest timestamp as Date, or null if no range */
	let earliestDate = $derived(
		range?.earliest ? new Date(range.earliest) : null
	);

	/** Latest timestamp as Date, or null if no range */
	let latestDate = $derived(
		range?.latest ? new Date(range.latest) : null
	);

	/** Total time span in milliseconds */
	let totalSpanMs = $derived(
		earliestDate && latestDate
			? latestDate.getTime() - earliestDate.getTime()
			: 0
	);

	/** Current position as a Date */
	let currentDate = $derived(
		earliestDate && totalSpanMs > 0
			? new Date(earliestDate.getTime() + totalSpanMs * position)
			: latestDate
	);

	/** ISO timestamp string for display */
	let currentTimestamp = $derived(
		currentDate ? formatTimestamp(currentDate) : '--'
	);

	/** Whether we have valid timeline data to work with */
	let hasData = $derived(
		range !== null && range.earliest !== null && range.latest !== null && range.connection_count > 0
	);

	// ─── Lifecycle ──────────────────────────────────────────────

	onMount(async () => {
		await fetchRange();
	});

	onDestroy(() => {
		stopPlayback();
	});

	// ─── Backend Communication ───────────────────────────────────

	async function fetchRange() {
		try {
			const result = await getTimelineRange();
			range = result;
			error = null;
		} catch (e) {
			error = String(e);
			range = null;
		}
	}

	// ─── Playback Control ───────────────────────────────────────

	function startPlayback() {
		if (!hasData || !enabled) return;
		playing = true;
		timelinePlaying.set(true);

		// Each tick advances by a small fraction of the total span.
		// At 1x, we traverse the full range in ~30 seconds.
		// Tick interval is 50ms for smooth animation.
		const tickMs = 50;
		const baseDurationMs = 30000; // 30 seconds for full playback at 1x

		playbackInterval = setInterval(() => {
			const increment = (tickMs / baseDurationMs) * speed;
			position = Math.min(1.0, position + increment);
			timelinePosition.set(position);

			// Stop at the end
			if (position >= 1.0) {
				stopPlayback();
			}
		}, tickMs);
	}

	function stopPlayback() {
		playing = false;
		timelinePlaying.set(false);
		if (playbackInterval !== null) {
			clearInterval(playbackInterval);
			playbackInterval = null;
		}
	}

	function togglePlayback() {
		if (playing) {
			stopPlayback();
		} else {
			// If at the end, restart from beginning
			if (position >= 1.0) {
				position = 0.0;
				timelinePosition.set(0.0);
			}
			startPlayback();
		}
	}

	// ─── Enable/Disable ─────────────────────────────────────────

	function toggleEnabled() {
		enabled = !enabled;
		timelineEnabled.set(enabled);

		if (!enabled) {
			// When disabling, reset to show all data
			stopPlayback();
			position = 1.0;
			timelinePosition.set(1.0);
		}
	}

	// ─── Speed Control ──────────────────────────────────────────

	function cycleSpeed() {
		if (speed === 1) speed = 2;
		else if (speed === 2) speed = 5;
		else speed = 1;

		// If playing, restart with new speed
		if (playing) {
			stopPlayback();
			startPlayback();
		}
	}

	// ─── Slider Input ───────────────────────────────────────────

	function handleSliderInput(event: Event) {
		const target = event.target as HTMLInputElement;
		position = parseFloat(target.value);
		timelinePosition.set(position);
	}

	// ─── Reset ──────────────────────────────────────────────────

	function resetToEnd() {
		stopPlayback();
		position = 1.0;
		timelinePosition.set(1.0);
	}

	function resetToStart() {
		stopPlayback();
		position = 0.0;
		timelinePosition.set(0.0);
	}

	// ─── Formatting ─────────────────────────────────────────────

	function formatTimestamp(date: Date): string {
		return date.toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, 'Z');
	}

	/** Compact time for the slider labels */
	function formatCompact(date: Date | null): string {
		if (!date) return '--';
		// Show HH:MM:SS for same-day captures, or date + time for multi-day
		const hours = date.getUTCHours().toString().padStart(2, '0');
		const mins = date.getUTCMinutes().toString().padStart(2, '0');
		const secs = date.getUTCSeconds().toString().padStart(2, '0');
		return `${hours}:${mins}:${secs}`;
	}

	/** Percentage for visual progress indicator */
	let progressPercent = $derived(Math.round(position * 100));
</script>

<div class="timeline-scrubber" class:expanded class:enabled>
	<!-- Collapsed bar: always visible -->
	<div class="scrubber-bar">
		<!-- Toggle expand -->
		<button
			class="expand-btn"
			onclick={() => expanded = !expanded}
			title={expanded ? 'Collapse timeline' : 'Expand timeline'}
		>
			{#if expanded}&#9660;{:else}&#9650;{/if}
		</button>

		<!-- Enable/disable toggle -->
		<button
			class="toggle-btn"
			class:active={enabled}
			onclick={toggleEnabled}
			disabled={!hasData}
			title={enabled ? 'Disable timeline filter' : 'Enable timeline filter'}
		>
			{#if enabled}ON{:else}OFF{/if}
		</button>

		{#if hasData && enabled}
			<!-- Play/pause -->
			<button
				class="play-btn"
				onclick={togglePlayback}
				title={playing ? 'Pause playback' : 'Start playback'}
			>
				{#if playing}&#10074;&#10074;{:else}&#9654;{/if}
			</button>

			<!-- Slider -->
			<div class="slider-container">
				<span class="range-label">{formatCompact(earliestDate)}</span>
				<div class="slider-track-wrapper">
					<input
						type="range"
						class="timeline-slider"
						min="0"
						max="1"
						step="0.001"
						value={position}
						oninput={handleSliderInput}
					/>
					<div class="slider-progress" style="width: {progressPercent}%"></div>
				</div>
				<span class="range-label">{formatCompact(latestDate)}</span>
			</div>

			<!-- Current timestamp -->
			<span class="current-time" title={currentTimestamp}>
				{currentTimestamp}
			</span>

			<!-- Speed -->
			<button class="speed-btn" onclick={cycleSpeed} title="Playback speed">
				{speed}x
			</button>
		{:else if !hasData}
			<span class="no-data">No timeline data</span>
		{:else}
			<span class="no-data">Timeline disabled</span>
		{/if}
	</div>

	<!-- Expanded detail: additional controls -->
	{#if expanded && hasData}
		<div class="scrubber-detail">
			<div class="detail-row">
				<span class="detail-label">Range:</span>
				<span class="detail-value">
					{range?.earliest ? formatTimestamp(new Date(range.earliest)) : '--'}
					to
					{range?.latest ? formatTimestamp(new Date(range.latest)) : '--'}
				</span>
			</div>
			<div class="detail-row">
				<span class="detail-label">Connections:</span>
				<span class="detail-value">{range?.connection_count ?? 0}</span>
			</div>
			<div class="detail-row">
				<span class="detail-label">Position:</span>
				<span class="detail-value">{progressPercent}%</span>
			</div>
			<div class="detail-actions">
				<button class="detail-btn" onclick={resetToStart} disabled={!enabled} title="Jump to start">
					|&lt;
				</button>
				<button class="detail-btn" onclick={resetToEnd} disabled={!enabled} title="Jump to end (show all)">
					&gt;|
				</button>
				<button class="detail-btn" onclick={fetchRange} title="Refresh timeline range">
					Refresh
				</button>
			</div>
		</div>
	{/if}
</div>

<style>
	/* ── Container ─────────────────────────────────────── */

	.timeline-scrubber {
		position: absolute;
		bottom: 0;
		left: 0;
		right: 0;
		z-index: 20;
		background: var(--gm-bg-secondary);
		border-top: 1px solid var(--gm-border);
		transition: all 0.2s ease;
		font-size: 11px;
	}

	.timeline-scrubber:not(.expanded) {
		max-height: 40px;
	}

	/* ── Collapsed Bar ─────────────────────────────────── */

	.scrubber-bar {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 6px 12px;
		height: 40px;
		box-sizing: border-box;
	}

	/* ── Expand Button ─────────────────────────────────── */

	.expand-btn {
		background: none;
		border: 1px solid var(--gm-border);
		border-radius: 3px;
		color: var(--gm-text-muted);
		font-size: 8px;
		width: 22px;
		height: 22px;
		display: flex;
		align-items: center;
		justify-content: center;
		cursor: pointer;
		flex-shrink: 0;
		transition: all 0.15s;
		font-family: inherit;
		padding: 0;
	}

	.expand-btn:hover {
		color: var(--gm-text-primary);
		border-color: var(--gm-active);
	}

	/* ── Toggle Button ─────────────────────────────────── */

	.toggle-btn {
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 4px;
		color: var(--gm-text-muted);
		font-family: inherit;
		font-size: 9px;
		font-weight: 700;
		padding: 3px 8px;
		cursor: pointer;
		flex-shrink: 0;
		transition: all 0.15s;
		text-transform: uppercase;
		letter-spacing: 0.5px;
	}

	.toggle-btn:hover:not(:disabled) {
		border-color: var(--gm-active);
		color: var(--gm-text-primary);
	}

	.toggle-btn.active {
		background: rgba(16, 185, 129, 0.15);
		border-color: var(--gm-active);
		color: var(--gm-active);
	}

	.toggle-btn:disabled {
		opacity: 0.4;
		cursor: not-allowed;
	}

	/* ── Play/Pause Button ─────────────────────────────── */

	.play-btn {
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 4px;
		color: var(--gm-active);
		font-size: 10px;
		width: 28px;
		height: 24px;
		display: flex;
		align-items: center;
		justify-content: center;
		cursor: pointer;
		flex-shrink: 0;
		transition: all 0.15s;
		font-family: inherit;
		padding: 0;
	}

	.play-btn:hover {
		border-color: var(--gm-active);
		background: rgba(16, 185, 129, 0.1);
	}

	/* ── Slider ────────────────────────────────────────── */

	.slider-container {
		flex: 1;
		display: flex;
		align-items: center;
		gap: 6px;
		min-width: 0;
	}

	.range-label {
		font-size: 9px;
		color: var(--gm-text-muted);
		font-family: inherit;
		flex-shrink: 0;
		white-space: nowrap;
	}

	.slider-track-wrapper {
		flex: 1;
		position: relative;
		height: 18px;
		display: flex;
		align-items: center;
	}

	.timeline-slider {
		width: 100%;
		height: 4px;
		-webkit-appearance: none;
		appearance: none;
		background: var(--gm-bg-panel);
		border-radius: 2px;
		outline: none;
		cursor: pointer;
		position: relative;
		z-index: 2;
	}

	.timeline-slider::-webkit-slider-thumb {
		-webkit-appearance: none;
		appearance: none;
		width: 12px;
		height: 12px;
		border-radius: 50%;
		background: var(--gm-active);
		border: 2px solid var(--gm-bg-secondary);
		cursor: pointer;
		transition: transform 0.1s;
	}

	.timeline-slider::-webkit-slider-thumb:hover {
		transform: scale(1.3);
	}

	.timeline-slider::-moz-range-thumb {
		width: 12px;
		height: 12px;
		border-radius: 50%;
		background: var(--gm-active);
		border: 2px solid var(--gm-bg-secondary);
		cursor: pointer;
	}

	.slider-progress {
		position: absolute;
		left: 0;
		top: 50%;
		transform: translateY(-50%);
		height: 4px;
		background: var(--gm-active);
		border-radius: 2px;
		pointer-events: none;
		z-index: 1;
		opacity: 0.5;
	}

	/* ── Current Time Display ──────────────────────────── */

	.current-time {
		font-size: 10px;
		color: var(--gm-text-primary);
		font-family: inherit;
		background: var(--gm-bg-panel);
		padding: 3px 8px;
		border-radius: 3px;
		border: 1px solid var(--gm-border);
		white-space: nowrap;
		flex-shrink: 0;
		max-width: 200px;
		overflow: hidden;
		text-overflow: ellipsis;
	}

	/* ── Speed Button ──────────────────────────────────── */

	.speed-btn {
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 4px;
		color: var(--gm-text-secondary);
		font-family: inherit;
		font-size: 10px;
		font-weight: 600;
		padding: 3px 8px;
		cursor: pointer;
		flex-shrink: 0;
		transition: all 0.15s;
	}

	.speed-btn:hover {
		border-color: var(--gm-active);
		color: var(--gm-active);
	}

	/* ── No Data Label ─────────────────────────────────── */

	.no-data {
		font-size: 10px;
		color: var(--gm-text-muted);
		font-style: italic;
	}

	/* ── Expanded Detail Panel ─────────────────────────── */

	.scrubber-detail {
		padding: 8px 12px 10px;
		border-top: 1px solid var(--gm-border);
		display: flex;
		align-items: center;
		gap: 20px;
		flex-wrap: wrap;
		background: var(--gm-bg-panel);
	}

	.detail-row {
		display: flex;
		align-items: center;
		gap: 6px;
	}

	.detail-label {
		font-size: 9px;
		color: var(--gm-text-muted);
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.3px;
	}

	.detail-value {
		font-size: 10px;
		color: var(--gm-text-secondary);
	}

	.detail-actions {
		display: flex;
		align-items: center;
		gap: 6px;
		margin-left: auto;
	}

	.detail-btn {
		background: var(--gm-bg-secondary);
		border: 1px solid var(--gm-border);
		border-radius: 4px;
		color: var(--gm-text-secondary);
		font-family: inherit;
		font-size: 10px;
		padding: 3px 10px;
		cursor: pointer;
		transition: all 0.15s;
	}

	.detail-btn:hover:not(:disabled) {
		border-color: var(--gm-active);
		color: var(--gm-text-primary);
	}

	.detail-btn:disabled {
		opacity: 0.4;
		cursor: not-allowed;
	}
</style>
