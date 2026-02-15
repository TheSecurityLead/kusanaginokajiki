//! # gm-db
//!
//! SQLite persistence layer for Kusanagi Kajiki.
//!
//! Provides:
//! - Session save/load with full state serialization
//! - Asset CRUD with field-level change history
//! - Connection storage
//! - IEEE OUI vendor lookup
//! - GeoIP country identification

pub mod error;
pub mod schema;
pub mod sessions;
pub mod assets;
pub mod connections;
pub mod oui;
pub mod geoip;

pub use error::DbError;
pub use sessions::SessionRow;
pub use assets::{AssetRow, HistoryRow};
pub use connections::ConnectionRow;
pub use oui::OuiLookup;
pub use geoip::GeoIpLookup;

use std::path::Path;

/// Database connection wrapper.
///
/// Wraps a rusqlite Connection and provides high-level operations.
pub struct Database {
    conn: rusqlite::Connection,
}

impl Database {
    /// Open (or create) a database at the given path and initialize the schema.
    pub fn open(path: &Path) -> Result<Self, DbError> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = rusqlite::Connection::open(path)?;
        schema::initialize(&conn)?;

        log::info!("Database opened at {}", path.display());
        Ok(Self { conn })
    }

    /// Open an in-memory database (for testing).
    pub fn open_in_memory() -> Result<Self, DbError> {
        let conn = rusqlite::Connection::open_in_memory()?;
        schema::initialize(&conn)?;
        Ok(Self { conn })
    }

    // ─── Session Operations ────────────────────────────────────

    pub fn create_session(
        &self,
        id: &str,
        name: &str,
        description: &str,
        metadata: &str,
    ) -> Result<SessionRow, DbError> {
        sessions::create_session(&self.conn, id, name, description, metadata)
    }

    pub fn get_session(&self, id: &str) -> Result<SessionRow, DbError> {
        sessions::get_session(&self.conn, id)
    }

    pub fn list_sessions(&self) -> Result<Vec<SessionRow>, DbError> {
        sessions::list_sessions(&self.conn)
    }

    pub fn delete_session(&self, id: &str) -> Result<(), DbError> {
        sessions::delete_session(&self.conn, id)
    }

    pub fn update_session_counts(
        &self,
        id: &str,
        asset_count: i64,
        connection_count: i64,
    ) -> Result<(), DbError> {
        sessions::update_counts(&self.conn, id, asset_count, connection_count)
    }

    // ─── Asset Operations ──────────────────────────────────────

    pub fn insert_asset(&self, asset: &AssetRow) -> Result<(), DbError> {
        assets::insert_asset(&self.conn, asset)
    }

    pub fn get_asset(&self, id: &str) -> Result<AssetRow, DbError> {
        assets::get_asset(&self.conn, id)
    }

    pub fn list_assets(&self, session_id: &str) -> Result<Vec<AssetRow>, DbError> {
        assets::list_assets(&self.conn, session_id)
    }

    pub fn update_asset_field(
        &self,
        asset_id: &str,
        field_name: &str,
        new_value: &str,
    ) -> Result<(), DbError> {
        assets::update_field(&self.conn, asset_id, field_name, new_value)
    }

    pub fn bulk_update_asset_field(
        &self,
        asset_ids: &[String],
        field_name: &str,
        new_value: &str,
    ) -> Result<usize, DbError> {
        assets::bulk_update_field(&self.conn, asset_ids, field_name, new_value)
    }

    pub fn get_asset_history(&self, asset_id: &str) -> Result<Vec<HistoryRow>, DbError> {
        assets::get_history(&self.conn, asset_id)
    }

    // ─── Connection Operations ─────────────────────────────────

    pub fn insert_connection(&self, row: &ConnectionRow) -> Result<(), DbError> {
        connections::insert_connection(&self.conn, row)
    }

    pub fn list_connections(&self, session_id: &str) -> Result<Vec<ConnectionRow>, DbError> {
        connections::list_connections(&self.conn, session_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_in_memory() {
        let db = Database::open_in_memory().unwrap();

        // Create session
        let session = db.create_session("s1", "Test Session", "description", "{}").unwrap();
        assert_eq!(session.name, "Test Session");

        // List sessions
        let sessions = db.list_sessions().unwrap();
        assert_eq!(sessions.len(), 1);

        // Insert asset
        let asset = AssetRow {
            id: "a1".into(),
            session_id: "s1".into(),
            ip_address: "192.168.1.100".into(),
            mac_address: None,
            hostname: None,
            device_type: "plc".into(),
            vendor: None,
            product_family: None,
            protocols: "[]".into(),
            confidence: 1,
            purdue_level: None,
            tags: "[]".into(),
            notes: "".into(),
            packet_count: 100,
            signature_matches: "[]".into(),
            oui_vendor: None,
            country: None,
            is_public_ip: false,
            first_seen: "2024-01-01T00:00:00Z".into(),
            last_seen: "2024-01-01T01:00:00Z".into(),
        };
        db.insert_asset(&asset).unwrap();

        // Update counts
        db.update_session_counts("s1", 1, 0).unwrap();
        let session = db.get_session("s1").unwrap();
        assert_eq!(session.asset_count, 1);

        // Delete session cascades
        db.delete_session("s1").unwrap();
        assert!(db.list_assets("s1").unwrap().is_empty());
    }
}
