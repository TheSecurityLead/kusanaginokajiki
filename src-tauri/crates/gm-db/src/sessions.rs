//! Session CRUD operations.

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

use crate::error::DbError;

/// A saved session record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRow {
    pub id: String,
    pub name: String,
    pub description: String,
    pub created_at: String,
    pub updated_at: String,
    pub asset_count: i64,
    pub connection_count: i64,
    /// Arbitrary JSON metadata (topology, deep_parse_info, imported_files, etc.)
    pub metadata: String,
}

/// Create a new session.
pub fn create_session(
    conn: &Connection,
    id: &str,
    name: &str,
    description: &str,
    metadata: &str,
) -> Result<SessionRow, DbError> {
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO sessions (id, name, description, created_at, updated_at, metadata)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![id, name, description, &now, &now, metadata],
    )?;

    get_session(conn, id)
}

/// Get a session by ID.
pub fn get_session(conn: &Connection, id: &str) -> Result<SessionRow, DbError> {
    conn.query_row(
        "SELECT id, name, description, created_at, updated_at, asset_count, connection_count, metadata
         FROM sessions WHERE id = ?1",
        params![id],
        |row| {
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
        },
    )
    .map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => DbError::NotFound(format!("Session {}", id)),
        other => DbError::Sqlite(other),
    })
}

/// List all sessions, ordered by most recent first.
pub fn list_sessions(conn: &Connection) -> Result<Vec<SessionRow>, DbError> {
    let mut stmt = conn.prepare(
        "SELECT id, name, description, created_at, updated_at, asset_count, connection_count, metadata
         FROM sessions ORDER BY updated_at DESC",
    )?;

    let rows = stmt
        .query_map([], |row| {
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

/// Delete a session (cascades to assets, connections, findings).
pub fn delete_session(conn: &Connection, id: &str) -> Result<(), DbError> {
    let affected = conn.execute("DELETE FROM sessions WHERE id = ?1", params![id])?;
    if affected == 0 {
        return Err(DbError::NotFound(format!("Session {}", id)));
    }
    Ok(())
}

/// Update session counts after inserting assets/connections.
pub fn update_counts(
    conn: &Connection,
    id: &str,
    asset_count: i64,
    connection_count: i64,
) -> Result<(), DbError> {
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "UPDATE sessions SET asset_count = ?1, connection_count = ?2, updated_at = ?3 WHERE id = ?4",
        params![asset_count, connection_count, now, id],
    )?;
    Ok(())
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

    #[test]
    fn test_session_crud() {
        let conn = setup();

        // Create
        let session = create_session(&conn, "s1", "Test Session", "A test", "{}").unwrap();
        assert_eq!(session.name, "Test Session");
        assert_eq!(session.description, "A test");

        // Get
        let fetched = get_session(&conn, "s1").unwrap();
        assert_eq!(fetched.name, "Test Session");

        // List
        let list = list_sessions(&conn).unwrap();
        assert_eq!(list.len(), 1);

        // Delete
        delete_session(&conn, "s1").unwrap();
        let list = list_sessions(&conn).unwrap();
        assert_eq!(list.len(), 0);
    }

    #[test]
    fn test_session_not_found() {
        let conn = setup();
        let result = get_session(&conn, "nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_update_counts() {
        let conn = setup();
        create_session(&conn, "s1", "Test", "", "{}").unwrap();
        update_counts(&conn, "s1", 42, 100).unwrap();

        let session = get_session(&conn, "s1").unwrap();
        assert_eq!(session.asset_count, 42);
        assert_eq!(session.connection_count, 100);
    }
}
