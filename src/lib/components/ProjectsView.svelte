<script lang="ts">
	import { activeProject, activeTab } from '$lib/stores';
	import {
		listProjects,
		createProject,
		updateProject,
		deleteProject,
		setActiveProject
	} from '$lib/utils/tauri';
	import type { ProjectSummary, Project } from '$lib/types';

	let projects = $state<ProjectSummary[]>([]);
	let loading = $state(true);
	let error = $state<string | null>(null);

	// Form state
	let showForm = $state(false);
	let editingProject = $state<Project | null>(null);
	let formName = $state('');
	let formClient = $state('');
	let formSite = $state('');
	let formAssessor = $state('');
	let formStart = $state('');
	let formEnd = $state('');
	let formNotes = $state('');
	let formError = $state<string | null>(null);
	let formSaving = $state(false);

	// Delete confirmation
	let confirmDeleteId = $state<number | null>(null);

	async function load() {
		loading = true;
		error = null;
		try {
			projects = await listProjects();
		} catch (e) {
			error = String(e);
		} finally {
			loading = false;
		}
	}

	function openNewForm() {
		editingProject = null;
		formName = '';
		formClient = '';
		formSite = '';
		formAssessor = '';
		formStart = '';
		formEnd = '';
		formNotes = '';
		formError = null;
		showForm = true;
	}

	function openEditForm(summary: ProjectSummary) {
		// Pre-fill from summary (full Project fields are superset of summary)
		editingProject = summary as unknown as Project;
		formName = summary.name;
		formClient = summary.client_name;
		formSite = summary.site_name;
		formAssessor = '';
		formStart = '';
		formEnd = '';
		formNotes = '';
		formError = null;
		showForm = true;
	}

	async function handleSave() {
		if (!formName.trim()) {
			formError = 'Project name is required.';
			return;
		}
		formSaving = true;
		formError = null;
		try {
			if (editingProject) {
				await updateProject(
					editingProject.id, formName,
					formClient, formSite, formAssessor,
					formStart, formEnd, formNotes
				);
			} else {
				await createProject(
					formName, formClient, formSite, formAssessor,
					formStart, formEnd, formNotes
				);
			}
			showForm = false;
			await load();
		} catch (e) {
			formError = String(e);
		} finally {
			formSaving = false;
		}
	}

	async function handleOpen(summary: ProjectSummary) {
		try {
			const project = await setActiveProject(summary.id);
			activeProject.set(project);
			activeTab.set('topology');
		} catch (e) {
			error = String(e);
		}
	}

	async function handleDelete(id: number) {
		try {
			await deleteProject(id);
			confirmDeleteId = null;
			await load();
		} catch (e) {
			error = String(e);
		}
	}

	function formatDate(iso: string): string {
		if (!iso) return '—';
		try {
			return new Date(iso).toLocaleDateString(undefined, {
				year: 'numeric', month: 'short', day: 'numeric'
			});
		} catch {
			return iso;
		}
	}

	// Load on mount
	$effect(() => {
		load();
	});
</script>

<div class="projects-view">
	<!-- Header -->
	<div class="view-header">
		<div class="header-left">
			<h1 class="view-title">Projects</h1>
			<span class="view-subtitle">Select or create an engagement project to get started.</span>
		</div>
		<button class="btn-primary" onclick={openNewForm}>+ New Project</button>
	</div>

	{#if error}
		<div class="error-bar">{error}</div>
	{/if}

	<!-- Project grid -->
	{#if loading}
		<div class="empty-state">Loading projects…</div>
	{:else if projects.length === 0}
		<div class="empty-state">
			<div class="empty-icon">&#128193;</div>
			<div class="empty-title">No projects yet</div>
			<div class="empty-sub">Create a project to organize your capture sessions and findings.</div>
			<button class="btn-primary" onclick={openNewForm}>Create First Project</button>
		</div>
	{:else}
		<div class="project-grid">
			{#each projects as p}
				<div class="project-card" role="button" tabindex="0"
					onclick={() => handleOpen(p)}
					onkeydown={(e) => { if (e.key === 'Enter') handleOpen(p); }}>
					<div class="card-top">
						<div class="card-icon">&#128193;</div>
						<div class="card-actions" role="none" onclick={(e) => e.stopPropagation()} onkeydown={() => {}}>
							<button class="card-btn" title="Edit project"
								onclick={() => openEditForm(p)}>&#9998;</button>
							<button class="card-btn card-btn-danger" title="Delete project"
								onclick={() => { confirmDeleteId = p.id; }}>&#10005;</button>
						</div>
					</div>
					<div class="card-name">{p.name}</div>
					{#if p.client_name}
						<div class="card-meta card-client">{p.client_name}</div>
					{/if}
					{#if p.site_name}
						<div class="card-meta">{p.site_name}</div>
					{/if}
					<div class="card-footer">
						<span class="card-sessions">
							{p.session_count} {p.session_count === 1 ? 'session' : 'sessions'}
						</span>
						<span class="card-date">{formatDate(p.updated_at)}</span>
					</div>
				</div>
			{/each}
		</div>
	{/if}
</div>

<!-- Create / Edit form modal -->
{#if showForm}
	<div class="modal-backdrop" role="dialog" aria-modal="true">
		<div class="modal">
			<div class="modal-header">
				<h2 class="modal-title">{editingProject ? 'Edit Project' : 'New Project'}</h2>
				<button class="modal-close" onclick={() => { showForm = false; }}>&#10005;</button>
			</div>
			<div class="modal-body">
				{#if formError}
					<div class="form-error">{formError}</div>
				{/if}
				<div class="form-field">
					<label class="form-label" for="proj-name">Project Name *</label>
					<input id="proj-name" class="form-input" type="text"
						bind:value={formName} placeholder="e.g. Site Alpha Assessment" />
				</div>
				<div class="form-row">
					<div class="form-field">
						<label class="form-label" for="proj-client">Client Name</label>
						<input id="proj-client" class="form-input" type="text"
							bind:value={formClient} placeholder="e.g. Acme Corporation" />
					</div>
					<div class="form-field">
						<label class="form-label" for="proj-site">Site Name</label>
						<input id="proj-site" class="form-input" type="text"
							bind:value={formSite} placeholder="e.g. Plant 1" />
					</div>
				</div>
				<div class="form-field">
					<label class="form-label" for="proj-assessor">Assessor Name</label>
					<input id="proj-assessor" class="form-input" type="text"
						bind:value={formAssessor} placeholder="Your name" />
				</div>
				<div class="form-row">
					<div class="form-field">
						<label class="form-label" for="proj-start">Start Date</label>
						<input id="proj-start" class="form-input" type="date"
							bind:value={formStart} />
					</div>
					<div class="form-field">
						<label class="form-label" for="proj-end">End Date</label>
						<input id="proj-end" class="form-input" type="date"
							bind:value={formEnd} />
					</div>
				</div>
				<div class="form-field">
					<label class="form-label" for="proj-notes">Notes</label>
					<textarea id="proj-notes" class="form-textarea"
						bind:value={formNotes} rows={3}
						placeholder="Scope, objectives, special considerations…"></textarea>
				</div>
			</div>
			<div class="modal-footer">
				<button class="btn-secondary" onclick={() => { showForm = false; }}>Cancel</button>
				<button class="btn-primary" onclick={handleSave} disabled={formSaving}>
					{formSaving ? 'Saving…' : (editingProject ? 'Save Changes' : 'Create Project')}
				</button>
			</div>
		</div>
	</div>
{/if}

<!-- Delete confirmation -->
{#if confirmDeleteId !== null}
	<div class="modal-backdrop" role="dialog" aria-modal="true">
		<div class="modal modal-sm">
			<div class="modal-header">
				<h2 class="modal-title">Delete Project</h2>
			</div>
			<div class="modal-body">
				<p class="confirm-text">
					This will permanently delete the project and <strong>all its sessions</strong>,
					including captured assets, connections, and findings. This cannot be undone.
				</p>
			</div>
			<div class="modal-footer">
				<button class="btn-secondary" onclick={() => { confirmDeleteId = null; }}>Cancel</button>
				<button class="btn-danger" onclick={() => confirmDeleteId !== null && handleDelete(confirmDeleteId)}>
					Delete
				</button>
			</div>
		</div>
	</div>
{/if}

<style>
	.projects-view {
		padding: 32px 40px;
		height: 100%;
		overflow-y: auto;
		display: flex;
		flex-direction: column;
		gap: 24px;
	}

	/* ── Header ─────────────────────────────────────── */

	.view-header {
		display: flex;
		align-items: flex-start;
		justify-content: space-between;
		gap: 16px;
	}

	.header-left {
		display: flex;
		flex-direction: column;
		gap: 4px;
	}

	.view-title {
		font-size: 22px;
		font-weight: 700;
		color: var(--gm-text-primary);
		margin: 0;
		letter-spacing: 0.5px;
	}

	.view-subtitle {
		font-size: 12px;
		color: var(--gm-text-muted);
	}

	/* ── Buttons ────────────────────────────────────── */

	.btn-primary {
		padding: 8px 16px;
		background: #10b981;
		color: #0a0e17;
		border: none;
		border-radius: 5px;
		font-family: inherit;
		font-size: 12px;
		font-weight: 600;
		cursor: pointer;
		transition: background 0.15s;
		white-space: nowrap;
	}

	.btn-primary:hover:not(:disabled) {
		background: #059669;
	}

	.btn-primary:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.btn-secondary {
		padding: 8px 16px;
		background: transparent;
		color: var(--gm-text-secondary);
		border: 1px solid var(--gm-border);
		border-radius: 5px;
		font-family: inherit;
		font-size: 12px;
		font-weight: 500;
		cursor: pointer;
		transition: all 0.15s;
	}

	.btn-secondary:hover {
		background: var(--gm-bg-hover);
		color: var(--gm-text-primary);
	}

	.btn-danger {
		padding: 8px 16px;
		background: rgba(239, 68, 68, 0.15);
		color: #ef4444;
		border: 1px solid rgba(239, 68, 68, 0.3);
		border-radius: 5px;
		font-family: inherit;
		font-size: 12px;
		font-weight: 600;
		cursor: pointer;
		transition: all 0.15s;
	}

	.btn-danger:hover {
		background: rgba(239, 68, 68, 0.25);
	}

	/* ── Error / Empty ──────────────────────────────── */

	.error-bar {
		padding: 10px 14px;
		background: rgba(239, 68, 68, 0.1);
		border: 1px solid rgba(239, 68, 68, 0.3);
		border-radius: 4px;
		color: #ef4444;
		font-size: 12px;
	}

	.empty-state {
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		gap: 12px;
		padding: 80px 20px;
		color: var(--gm-text-muted);
		font-size: 13px;
		text-align: center;
	}

	.empty-icon {
		font-size: 48px;
		opacity: 0.4;
	}

	.empty-title {
		font-size: 16px;
		font-weight: 600;
		color: var(--gm-text-secondary);
	}

	.empty-sub {
		font-size: 12px;
		max-width: 360px;
	}

	/* ── Project Grid ───────────────────────────────── */

	.project-grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
		gap: 16px;
	}

	.project-card {
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 8px;
		padding: 20px;
		cursor: pointer;
		display: flex;
		flex-direction: column;
		gap: 6px;
		transition: all 0.15s;
		outline: none;
	}

	.project-card:hover,
	.project-card:focus {
		border-color: #10b981;
		background: rgba(16, 185, 129, 0.04);
		box-shadow: 0 0 0 1px #10b981;
	}

	.card-top {
		display: flex;
		align-items: center;
		justify-content: space-between;
		margin-bottom: 4px;
	}

	.card-icon {
		font-size: 24px;
		opacity: 0.7;
	}

	.card-actions {
		display: flex;
		gap: 4px;
		opacity: 0;
		transition: opacity 0.1s;
	}

	.project-card:hover .card-actions,
	.project-card:focus .card-actions {
		opacity: 1;
	}

	.card-btn {
		background: transparent;
		border: 1px solid transparent;
		border-radius: 4px;
		color: var(--gm-text-muted);
		font-size: 12px;
		width: 24px;
		height: 24px;
		display: flex;
		align-items: center;
		justify-content: center;
		cursor: pointer;
		transition: all 0.1s;
	}

	.card-btn:hover {
		background: var(--gm-bg-hover);
		color: var(--gm-text-primary);
		border-color: var(--gm-border);
	}

	.card-btn-danger:hover {
		background: rgba(239, 68, 68, 0.15);
		color: #ef4444;
		border-color: rgba(239, 68, 68, 0.3);
	}

	.card-name {
		font-size: 15px;
		font-weight: 700;
		color: var(--gm-text-primary);
		line-height: 1.2;
	}

	.card-meta {
		font-size: 11px;
		color: var(--gm-text-muted);
	}

	.card-client {
		color: #10b981;
		font-weight: 500;
	}

	.card-footer {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-top: 8px;
		padding-top: 8px;
		border-top: 1px solid var(--gm-border);
	}

	.card-sessions {
		font-size: 10px;
		color: var(--gm-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.5px;
	}

	.card-date {
		font-size: 10px;
		color: var(--gm-text-muted);
	}

	/* ── Modal ──────────────────────────────────────── */

	.modal-backdrop {
		position: fixed;
		inset: 0;
		background: rgba(0, 0, 0, 0.6);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 1000;
	}

	.modal {
		background: var(--gm-bg-panel);
		border: 1px solid var(--gm-border);
		border-radius: 8px;
		width: 540px;
		max-width: 95vw;
		max-height: 90vh;
		display: flex;
		flex-direction: column;
		overflow: hidden;
	}

	.modal-sm {
		width: 400px;
	}

	.modal-header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 18px 20px 14px;
		border-bottom: 1px solid var(--gm-border);
	}

	.modal-title {
		font-size: 14px;
		font-weight: 700;
		color: var(--gm-text-primary);
		margin: 0;
	}

	.modal-close {
		background: transparent;
		border: none;
		color: var(--gm-text-muted);
		font-size: 14px;
		cursor: pointer;
		padding: 4px;
		line-height: 1;
	}

	.modal-close:hover {
		color: var(--gm-text-primary);
	}

	.modal-body {
		padding: 20px;
		overflow-y: auto;
		display: flex;
		flex-direction: column;
		gap: 14px;
	}

	.modal-footer {
		display: flex;
		justify-content: flex-end;
		gap: 8px;
		padding: 14px 20px;
		border-top: 1px solid var(--gm-border);
	}

	/* ── Form ───────────────────────────────────────── */

	.form-error {
		padding: 8px 12px;
		background: rgba(239, 68, 68, 0.1);
		border: 1px solid rgba(239, 68, 68, 0.3);
		border-radius: 4px;
		color: #ef4444;
		font-size: 12px;
	}

	.form-row {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 12px;
	}

	.form-field {
		display: flex;
		flex-direction: column;
		gap: 5px;
	}

	.form-label {
		font-size: 11px;
		font-weight: 600;
		color: var(--gm-text-secondary);
		text-transform: uppercase;
		letter-spacing: 0.5px;
	}

	.form-input,
	.form-textarea {
		background: var(--gm-bg-secondary);
		border: 1px solid var(--gm-border);
		border-radius: 4px;
		color: var(--gm-text-primary);
		font-family: inherit;
		font-size: 12px;
		padding: 8px 10px;
		outline: none;
		transition: border-color 0.15s;
		width: 100%;
		box-sizing: border-box;
	}

	.form-input:focus,
	.form-textarea:focus {
		border-color: #10b981;
	}

	.form-textarea {
		resize: vertical;
	}

	/* ── Delete confirm ─────────────────────────────── */

	.confirm-text {
		font-size: 13px;
		color: var(--gm-text-secondary);
		line-height: 1.6;
		margin: 0;
	}

	.confirm-text strong {
		color: var(--gm-text-primary);
	}
</style>
