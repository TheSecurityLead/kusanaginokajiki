//! Database schema initialization.

use rusqlite::Connection;
use crate::error::DbError;

/// All CREATE TABLE statements for the Kusanagi Kajiki database.
const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS sessions (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    asset_count     INTEGER NOT NULL DEFAULT 0,
    connection_count INTEGER NOT NULL DEFAULT 0,
    metadata        TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS assets (
    id                TEXT PRIMARY KEY,
    session_id        TEXT NOT NULL,
    ip_address        TEXT NOT NULL,
    mac_address       TEXT,
    hostname          TEXT,
    device_type       TEXT NOT NULL DEFAULT 'unknown',
    vendor            TEXT,
    product_family    TEXT,
    protocols         TEXT NOT NULL DEFAULT '[]',
    confidence        INTEGER NOT NULL DEFAULT 0,
    purdue_level      INTEGER,
    tags              TEXT NOT NULL DEFAULT '[]',
    notes             TEXT NOT NULL DEFAULT '',
    packet_count      INTEGER NOT NULL DEFAULT 0,
    signature_matches TEXT NOT NULL DEFAULT '[]',
    oui_vendor        TEXT,
    country           TEXT,
    is_public_ip      INTEGER NOT NULL DEFAULT 0,
    first_seen        TEXT NOT NULL,
    last_seen         TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_assets_session ON assets(session_id);
CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip_address);

CREATE TABLE IF NOT EXISTS connections (
    id              TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL,
    src_ip          TEXT NOT NULL,
    src_port        INTEGER NOT NULL,
    src_mac         TEXT,
    dst_ip          TEXT NOT NULL,
    dst_port        INTEGER NOT NULL,
    dst_mac         TEXT,
    protocol        TEXT NOT NULL,
    transport       TEXT NOT NULL,
    packet_count    INTEGER NOT NULL DEFAULT 0,
    byte_count      INTEGER NOT NULL DEFAULT 0,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    origin_files    TEXT NOT NULL DEFAULT '[]',
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_connections_session ON connections(session_id);

CREATE TABLE IF NOT EXISTS asset_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id    TEXT NOT NULL,
    field_name  TEXT NOT NULL,
    old_value   TEXT,
    new_value   TEXT,
    changed_at  TEXT NOT NULL,
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_history_asset ON asset_history(asset_id);

CREATE TABLE IF NOT EXISTS findings (
    id                TEXT PRIMARY KEY,
    session_id        TEXT NOT NULL,
    finding_type      TEXT NOT NULL,
    severity          TEXT NOT NULL DEFAULT 'info',
    title             TEXT NOT NULL,
    description       TEXT NOT NULL DEFAULT '',
    affected_asset_id TEXT,
    evidence          TEXT NOT NULL DEFAULT '{}',
    created_at        TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
    FOREIGN KEY (affected_asset_id) REFERENCES assets(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
"#;

/// Initialize the database schema (creates tables if they don't exist).
pub fn initialize(conn: &Connection) -> Result<(), DbError> {
    // Enable WAL mode for better concurrent read performance
    conn.execute_batch("PRAGMA journal_mode=WAL;")?;
    // Enable foreign key enforcement
    conn.execute_batch("PRAGMA foreign_keys=ON;")?;
    // Apply schema
    conn.execute_batch(SCHEMA_SQL)?;
    log::info!("Database schema initialized");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_initialization() {
        let conn = Connection::open_in_memory().unwrap();
        initialize(&conn).unwrap();

        // Verify tables exist by querying sqlite_master
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        assert!(tables.contains(&"sessions".to_string()));
        assert!(tables.contains(&"assets".to_string()));
        assert!(tables.contains(&"connections".to_string()));
        assert!(tables.contains(&"asset_history".to_string()));
        assert!(tables.contains(&"findings".to_string()));
    }

    #[test]
    fn test_schema_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        initialize(&conn).unwrap();
        // Running again should not error
        initialize(&conn).unwrap();
    }
}
