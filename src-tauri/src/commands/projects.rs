//! Project management commands: create, list, get, update, delete, set active.

use tauri::State;
use gm_db::{Project, ProjectInput, ProjectSummary};

use super::AppState;

/// Create a new project.
#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn create_project(
    state: State<'_, AppState>,
    name: String,
    client_name: Option<String>,
    site_name: Option<String>,
    assessor_name: Option<String>,
    engagement_start: Option<String>,
    engagement_end: Option<String>,
    notes: Option<String>,
) -> Result<Project, String> {
    let inner = state.inner.lock().map_err(|e| e.to_string())?;
    let db = inner.db.as_ref().ok_or("Database not available")?;
    let input = ProjectInput {
        name,
        client_name: client_name.unwrap_or_default(),
        site_name: site_name.unwrap_or_default(),
        assessor_name: assessor_name.unwrap_or_default(),
        engagement_start: engagement_start.unwrap_or_default(),
        engagement_end: engagement_end.unwrap_or_default(),
        notes: notes.unwrap_or_default(),
    };
    db.create_project(&input).map_err(|e| e.to_string())
}

/// List all projects with session counts.
#[tauri::command]
pub async fn list_projects(
    state: State<'_, AppState>,
) -> Result<Vec<ProjectSummary>, String> {
    let inner = state.inner.lock().map_err(|e| e.to_string())?;
    let db = inner.db.as_ref().ok_or("Database not available")?;
    db.list_projects().map_err(|e| e.to_string())
}

/// Get a single project by ID.
#[tauri::command]
pub async fn get_project(
    state: State<'_, AppState>,
    id: i64,
) -> Result<Project, String> {
    let inner = state.inner.lock().map_err(|e| e.to_string())?;
    let db = inner.db.as_ref().ok_or("Database not available")?;
    db.get_project(id).map_err(|e| e.to_string())
}

/// Update a project's metadata.
#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn update_project(
    state: State<'_, AppState>,
    id: i64,
    name: String,
    client_name: Option<String>,
    site_name: Option<String>,
    assessor_name: Option<String>,
    engagement_start: Option<String>,
    engagement_end: Option<String>,
    notes: Option<String>,
) -> Result<Project, String> {
    let inner = state.inner.lock().map_err(|e| e.to_string())?;
    let db = inner.db.as_ref().ok_or("Database not available")?;
    let input = ProjectInput {
        name,
        client_name: client_name.unwrap_or_default(),
        site_name: site_name.unwrap_or_default(),
        assessor_name: assessor_name.unwrap_or_default(),
        engagement_start: engagement_start.unwrap_or_default(),
        engagement_end: engagement_end.unwrap_or_default(),
        notes: notes.unwrap_or_default(),
    };
    db.update_project(id, &input).map_err(|e| e.to_string())
}

/// Delete a project (and cascade to all its sessions).
#[tauri::command]
pub async fn delete_project(
    state: State<'_, AppState>,
    id: i64,
) -> Result<(), String> {
    let mut inner = state.inner.lock().map_err(|e| e.to_string())?;
    let db = inner.db.as_ref().ok_or("Database not available")?;
    db.delete_project(id).map_err(|e| e.to_string())?;
    // Clear active project if it was the one deleted
    if inner.current_project_id == Some(id) {
        inner.current_project_id = None;
    }
    log::info!("Deleted project {}", id);
    Ok(())
}

/// Set the active project. All subsequent save_session / list_sessions calls
/// will be scoped to this project.
#[tauri::command]
pub async fn set_active_project(
    state: State<'_, AppState>,
    id: i64,
) -> Result<Project, String> {
    let mut inner = state.inner.lock().map_err(|e| e.to_string())?;
    let db = inner.db.as_ref().ok_or("Database not available")?;
    let project = db.get_project(id).map_err(|e| e.to_string())?;
    inner.current_project_id = Some(id);
    log::info!("Active project set to '{}' ({})", project.name, id);
    Ok(project)
}

/// Clear the active project (return to project selection view).
#[tauri::command]
pub async fn clear_active_project(
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut inner = state.inner.lock().map_err(|e| e.to_string())?;
    inner.current_project_id = None;
    Ok(())
}
