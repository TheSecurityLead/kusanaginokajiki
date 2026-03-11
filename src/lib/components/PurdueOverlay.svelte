<script lang="ts">
	import { PURDUE_BANDS } from '$lib/layouts/purdueLayout';
</script>

<!--
	PurdueOverlay — colored horizontal bands behind the Cytoscape canvas.
	Position: absolute, fills graph-area. pointer-events: none so it
	doesn't interfere with graph interaction.
-->
<div class="purdue-overlay" aria-hidden="true">
	{#each PURDUE_BANDS as band, i (i)}
		<div class="band" style="background: {band.color};">
			<span class="band-label">{band.label}</span>
		</div>
	{/each}
</div>

<style>
	.purdue-overlay {
		position: absolute;
		inset: 0;
		display: flex;
		flex-direction: column;
		pointer-events: none;
		z-index: 0;
	}

	.band {
		flex: 1;
		display: flex;
		align-items: center;
		border-bottom: 1px solid rgba(148, 163, 184, 0.08);
	}

	.band:last-child {
		border-bottom: none;
	}

	.band-label {
		font-family: 'JetBrains Mono', monospace;
		font-size: 9px;
		font-weight: 600;
		letter-spacing: 0.8px;
		text-transform: uppercase;
		color: rgba(148, 163, 184, 0.45);
		padding: 0 10px;
		white-space: nowrap;
		user-select: none;
	}
</style>
