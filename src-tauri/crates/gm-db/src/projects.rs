//! Project CRUD operations.
//!
//! A project is the top-level container for an assessment engagement.
//! Sessions are scoped to a project; deleting a project cascades to its sessions.

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

use crate::error::DbError;
use crate::sessions::SessionRow;

/// Input fields for creating or updating a project.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProjectInput {
    pub name: String,
    pub client_name: String,
    pub site_name: String,
    pub assessor_name: String,
    pub engagement_start: String,
    pub engagement_end: String,
    pub notes: String,
}

/// A named engagement project with client metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: i64,
    pub name: String,
    pub client_name: String,
    pub site_name: String,
    pub assessor_name: String,
    pub engagement_start: String,
    pub engagement_end: String,
    pub notes: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Lightweight project summary for the project list view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectSummary {
    pub id: i64,
    pub name: String,
    pub client_name: String,
    pub site_name: String,
    /// Number of sessions associated with this project.
    pub session_count: i64,
    pub created_at: String,
    pub updated_at: String,
}

/// Create a new project.
pub fn create_project(conn: &Connection, input: &ProjectInput) -> Result<Project, DbError> {
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO projects (name, client_name, site_name, assessor_name,
             engagement_start, engagement_end, notes, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            input.name, input.client_name, input.site_name, input.assessor_name,
            input.engagement_start, input.engagement_end, input.notes, now, now
        ],
    )?;
    get_project(conn, conn.last_insert_rowid())
}

/// Get a project by ID.
pub fn get_project(conn: &Connection, id: i64) -> Result<Project, DbError> {
    conn.query_row(
        "SELECT id, name, client_name, site_name, assessor_name,
                engagement_start, engagement_end, notes, created_at, updated_at
         FROM projects WHERE id = ?1",
        params![id],
        |row| {
            Ok(Project {
                id: row.get(0)?,
                name: row.get(1)?,
                client_name: row.get(2)?,
                site_name: row.get(3)?,
                assessor_name: row.get(4)?,
                engagement_start: row.get(5)?,
                engagement_end: row.get(6)?,
                notes: row.get(7)?,
                created_at: row.get(8)?,
                updated_at: row.get(9)?,
            })
        },
    )
    .map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => DbError::NotFound(format!("Project {}", id)),
        other => DbError::Sqlite(other),
    })
}

/// List all projects with session counts, ordered by most recent first.
pub fn list_projects(conn: &Connection) -> Result<Vec<ProjectSummary>, DbError> {
    let mut stmt = conn.prepare(
        "SELECT p.id, p.name, p.client_name, p.site_name,
                COUNT(s.id) AS session_count,
                p.created_at, p.updated_at
         FROM projects p
         LEFT JOIN sessions s ON s.project_id = p.id
         GROUP BY p.id
         ORDER BY p.updated_at DESC",
    )?;

    let rows = stmt
        .query_map([], |row| {
            Ok(ProjectSummary {
                id: row.get(0)?,
                name: row.get(1)?,
                client_name: row.get(2)?,
                site_name: row.get(3)?,
                session_count: row.get(4)?,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
            })
        })?
        .filter_map(|r| r.ok())
        .collect();

    Ok(rows)
}

/// Update a project's metadata fields.
pub fn update_project(conn: &Connection, id: i64, input: &ProjectInput) -> Result<Project, DbError> {
    let now = chrono::Utc::now().to_rfc3339();
    let affected = conn.execute(
        "UPDATE projects SET name = ?1, client_name = ?2, site_name = ?3,
             assessor_name = ?4, engagement_start = ?5, engagement_end = ?6,
             notes = ?7, updated_at = ?8
         WHERE id = ?9",
        params![
            input.name, input.client_name, input.site_name, input.assessor_name,
            input.engagement_start, input.engagement_end, input.notes, now, id
        ],
    )?;
    if affected == 0 {
        return Err(DbError::NotFound(format!("Project {}", id)));
    }
    get_project(conn, id)
}

/// Delete a project (cascades to its sessions, which cascade to assets/connections).
pub fn delete_project(conn: &Connection, id: i64) -> Result<(), DbError> {
    let affected = conn.execute("DELETE FROM projects WHERE id = ?1", params![id])?;
    if affected == 0 {
        return Err(DbError::NotFound(format!("Project {}", id)));
    }
    Ok(())
}

/// Assign a session to a project.
pub fn assign_session_to_project(
    conn: &Connection,
    session_id: &str,
    project_id: i64,
) -> Result<(), DbError> {
    conn.execute(
        "UPDATE sessions SET project_id = ?1 WHERE id = ?2",
        params![project_id, session_id],
    )?;
    Ok(())
}

/// List all sessions belonging to a specific project.
pub fn list_sessions_for_project(
    conn: &Connection,
    project_id: i64,
) -> Result<Vec<SessionRow>, DbError> {
    let mut stmt = conn.prepare(
        "SELECT id, name, description, created_at, updated_at,
                asset_count, connection_count, metadata
         FROM sessions WHERE project_id = ?1 ORDER BY updated_at DESC",
    )?;

    let rows = stmt
        .query_map(params![project_id], |row| {
            Ok(SessionRow {
                id: row.get(0)?,
                name: row.get(1)?,
                description: row.get(2)?,
                created_at: row.get(3)?,
                updated_at: row.get(4)?,
                asset_count: row.get(5)?,
                connection_count: row.get(6)?,
                metadata: row.get(7)?,
            })
        })?
        .filter_map(|r| r.ok())
        .collect();

    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema;

    fn setup() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        schema::initialize(&conn).unwrap();
        conn
    }

    fn make_input(name: &str, client: &str) -> ProjectInput {
        ProjectInput {
            name: name.to_string(),
            client_name: client.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn test_create_project_returns_valid_project() {
        let conn = setup();
        let input = ProjectInput {
            name: "Site Alpha".to_string(),
            client_name: "Acme Corp".to_string(),
            site_name: "Plant 1".to_string(),
            assessor_name: "Jane Doe".to_string(),
            engagement_start: "2025-01-01".to_string(),
            engagement_end: "2025-01-07".to_string(),
            notes: "Initial assessment".to_string(),
        };
        let p = create_project(&conn, &input).unwrap();
        assert!(p.id > 0);
        assert_eq!(p.name, "Site Alpha");
        assert_eq!(p.client_name, "Acme Corp");
        assert_eq!(p.assessor_name, "Jane Doe");
    }

    #[test]
    fn test_list_projects_with_counts() {
        let conn = setup();
        let p = create_project(&conn, &make_input("Alpha", "Client A")).unwrap();
        // Create a session scoped to this project
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO sessions (id, name, description, created_at, updated_at, metadata, project_id)
             VALUES ('s1', 'Session 1', '', ?1, ?1, '{}', ?2)",
            params![now, p.id],
        ).unwrap();
        let list = list_projects(&conn).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].session_count, 1);
    }

    #[test]
    fn test_delete_project_removes_it() {
        let conn = setup();
        let p = create_project(&conn, &make_input("Beta", "")).unwrap();
        assert_eq!(list_projects(&conn).unwrap().len(), 1);
        delete_project(&conn, p.id).unwrap();
        assert_eq!(list_projects(&conn).unwrap().len(), 0);
    }

    #[test]
    fn test_list_sessions_for_project_scopes_correctly() {
        let conn = setup();
        let p1 = create_project(&conn, &make_input("P1", "")).unwrap();
        let p2 = create_project(&conn, &make_input("P2", "")).unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        // Two sessions in p1, one in p2
        conn.execute(
            "INSERT INTO sessions (id, name, description, created_at, updated_at, metadata, project_id)
             VALUES ('s1', 'S1', '', ?1, ?1, '{}', ?2)",
            params![now, p1.id],
        ).unwrap();
        conn.execute(
            "INSERT INTO sessions (id, name, description, created_at, updated_at, metadata, project_id)
             VALUES ('s2', 'S2', '', ?1, ?1, '{}', ?2)",
            params![now, p1.id],
        ).unwrap();
        conn.execute(
            "INSERT INTO sessions (id, name, description, created_at, updated_at, metadata, project_id)
             VALUES ('s3', 'S3', '', ?1, ?1, '{}', ?2)",
            params![now, p2.id],
        ).unwrap();

        let p1_sessions = list_sessions_for_project(&conn, p1.id).unwrap();
        let p2_sessions = list_sessions_for_project(&conn, p2.id).unwrap();
        assert_eq!(p1_sessions.len(), 2);
        assert_eq!(p2_sessions.len(), 1);
    }
}
