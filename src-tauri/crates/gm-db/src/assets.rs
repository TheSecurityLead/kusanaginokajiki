//! Asset CRUD operations with history tracking.

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

use crate::error::DbError;

/// An asset record stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetRow {
    pub id: String,
    pub session_id: String,
    pub ip_address: String,
    pub mac_address: Option<String>,
    pub hostname: Option<String>,
    pub device_type: String,
    pub vendor: Option<String>,
    pub product_family: Option<String>,
    pub protocols: String,      // JSON array
    pub confidence: i64,
    pub purdue_level: Option<i64>,
    pub tags: String,           // JSON array
    pub notes: String,
    pub packet_count: i64,
    pub signature_matches: String, // JSON array
    pub oui_vendor: Option<String>,
    pub country: Option<String>,
    pub is_public_ip: bool,
    pub first_seen: String,
    pub last_seen: String,
}

/// Change history for an asset field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryRow {
    pub id: i64,
    pub asset_id: String,
    pub field_name: String,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub changed_at: String,
}

/// Insert an asset into the database.
pub fn insert_asset(conn: &Connection, asset: &AssetRow) -> Result<(), DbError> {
    conn.execute(
        "INSERT OR REPLACE INTO assets (
            id, session_id, ip_address, mac_address, hostname, device_type,
            vendor, product_family, protocols, confidence, purdue_level, tags,
            notes, packet_count, signature_matches, oui_vendor, country,
            is_public_ip, first_seen, last_seen
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
        params![
            asset.id, asset.session_id, asset.ip_address, asset.mac_address,
            asset.hostname, asset.device_type, asset.vendor, asset.product_family,
            asset.protocols, asset.confidence, asset.purdue_level, asset.tags,
            asset.notes, asset.packet_count, asset.signature_matches,
            asset.oui_vendor, asset.country, asset.is_public_ip,
            asset.first_seen, asset.last_seen
        ],
    )?;
    Ok(())
}

/// Get an asset by ID.
pub fn get_asset(conn: &Connection, id: &str) -> Result<AssetRow, DbError> {
    conn.query_row(
        "SELECT id, session_id, ip_address, mac_address, hostname, device_type,
                vendor, product_family, protocols, confidence, purdue_level, tags,
                notes, packet_count, signature_matches, oui_vendor, country,
                is_public_ip, first_seen, last_seen
         FROM assets WHERE id = ?1",
        params![id],
        row_to_asset,
    )
    .map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => DbError::NotFound(format!("Asset {}", id)),
        other => DbError::Sqlite(other),
    })
}

/// List all assets for a session.
pub fn list_assets(conn: &Connection, session_id: &str) -> Result<Vec<AssetRow>, DbError> {
    let mut stmt = conn.prepare(
        "SELECT id, session_id, ip_address, mac_address, hostname, device_type,
                vendor, product_family, protocols, confidence, purdue_level, tags,
                notes, packet_count, signature_matches, oui_vendor, country,
                is_public_ip, first_seen, last_seen
         FROM assets WHERE session_id = ?1
         ORDER BY packet_count DESC",
    )?;

    let rows = stmt
        .query_map(params![session_id], row_to_asset)?
        .filter_map(|r| r.ok())
        .collect();

    Ok(rows)
}

/// Update a single field on an asset and record the change in history.
pub fn update_field(
    conn: &Connection,
    asset_id: &str,
    field_name: &str,
    new_value: &str,
) -> Result<(), DbError> {
    // Validate field name to prevent SQL injection
    let column = match field_name {
        "device_type" | "hostname" | "notes" | "tags" | "vendor" | "product_family" => field_name,
        "purdue_level" => "purdue_level",
        _ => return Err(DbError::NotFound(format!("Unknown field: {}", field_name))),
    };

    // Get current value for history
    let old_value: Option<String> = conn
        .query_row(
            &format!("SELECT {} FROM assets WHERE id = ?1", column),
            params![asset_id],
            |row| row.get(0),
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => DbError::NotFound(format!("Asset {}", asset_id)),
            other => DbError::Sqlite(other),
        })?;

    // Update the field
    conn.execute(
        &format!("UPDATE assets SET {} = ?1 WHERE id = ?2", column),
        params![new_value, asset_id],
    )?;

    // Record history
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO asset_history (asset_id, field_name, old_value, new_value, changed_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![asset_id, field_name, old_value, new_value, now],
    )?;

    Ok(())
}

/// Bulk update a single field on multiple assets.
pub fn bulk_update_field(
    conn: &Connection,
    asset_ids: &[String],
    field_name: &str,
    new_value: &str,
) -> Result<usize, DbError> {
    let mut count = 0;
    for id in asset_ids {
        update_field(conn, id, field_name, new_value)?;
        count += 1;
    }
    Ok(count)
}

/// Get change history for an asset.
pub fn get_history(conn: &Connection, asset_id: &str) -> Result<Vec<HistoryRow>, DbError> {
    let mut stmt = conn.prepare(
        "SELECT id, asset_id, field_name, old_value, new_value, changed_at
         FROM asset_history WHERE asset_id = ?1 ORDER BY changed_at DESC",
    )?;

    let rows = stmt
        .query_map(params![asset_id], |row| {
            Ok(HistoryRow {
                id: row.get(0)?,
                asset_id: row.get(1)?,
                field_name: row.get(2)?,
                old_value: row.get(3)?,
                new_value: row.get(4)?,
                changed_at: row.get(5)?,
            })
        })?
        .filter_map(|r| r.ok())
        .collect();

    Ok(rows)
}

/// Map a database row to an AssetRow.
fn row_to_asset(row: &rusqlite::Row) -> rusqlite::Result<AssetRow> {
    Ok(AssetRow {
        id: row.get(0)?,
        session_id: row.get(1)?,
        ip_address: row.get(2)?,
        mac_address: row.get(3)?,
        hostname: row.get(4)?,
        device_type: row.get(5)?,
        vendor: row.get(6)?,
        product_family: row.get(7)?,
        protocols: row.get(8)?,
        confidence: row.get(9)?,
        purdue_level: row.get(10)?,
        tags: row.get(11)?,
        notes: row.get(12)?,
        packet_count: row.get(13)?,
        signature_matches: row.get(14)?,
        oui_vendor: row.get(15)?,
        country: row.get(16)?,
        is_public_ip: row.get(17)?,
        first_seen: row.get(18)?,
        last_seen: row.get(19)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema;

    fn setup() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        schema::initialize(&conn).unwrap();
        // Create a session for testing
        conn.execute(
            "INSERT INTO sessions (id, name, created_at, updated_at) VALUES ('s1', 'Test', '2024-01-01', '2024-01-01')",
            [],
        ).unwrap();
        conn
    }

    fn sample_asset() -> AssetRow {
        AssetRow {
            id: "a1".into(),
            session_id: "s1".into(),
            ip_address: "192.168.1.100".into(),
            mac_address: Some("00:0e:8c:01:02:03".into()),
            hostname: None,
            device_type: "plc".into(),
            vendor: Some("Siemens".into()),
            product_family: Some("S7-300".into()),
            protocols: "[\"modbus\"]".into(),
            confidence: 4,
            purdue_level: Some(1),
            tags: "[]".into(),
            notes: "".into(),
            packet_count: 1000,
            signature_matches: "[]".into(),
            oui_vendor: Some("Siemens AG".into()),
            country: None,
            is_public_ip: false,
            first_seen: "2024-01-01T00:00:00Z".into(),
            last_seen: "2024-01-01T01:00:00Z".into(),
        }
    }

    #[test]
    fn test_asset_insert_and_get() {
        let conn = setup();
        let asset = sample_asset();
        insert_asset(&conn, &asset).unwrap();

        let fetched = get_asset(&conn, "a1").unwrap();
        assert_eq!(fetched.ip_address, "192.168.1.100");
        assert_eq!(fetched.vendor, Some("Siemens".into()));
        assert_eq!(fetched.oui_vendor, Some("Siemens AG".into()));
    }

    #[test]
    fn test_asset_list() {
        let conn = setup();
        insert_asset(&conn, &sample_asset()).unwrap();

        let mut asset2 = sample_asset();
        asset2.id = "a2".into();
        asset2.ip_address = "192.168.1.101".into();
        insert_asset(&conn, &asset2).unwrap();

        let list = list_assets(&conn, "s1").unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_asset_update_with_history() {
        let conn = setup();
        insert_asset(&conn, &sample_asset()).unwrap();

        update_field(&conn, "a1", "notes", "Test note").unwrap();

        let fetched = get_asset(&conn, "a1").unwrap();
        assert_eq!(fetched.notes, "Test note");

        let history = get_history(&conn, "a1").unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].field_name, "notes");
        assert_eq!(history[0].old_value, Some("".into()));
        assert_eq!(history[0].new_value, Some("Test note".into()));
    }

    #[test]
    fn test_bulk_update() {
        let conn = setup();
        insert_asset(&conn, &sample_asset()).unwrap();

        let mut asset2 = sample_asset();
        asset2.id = "a2".into();
        insert_asset(&conn, &asset2).unwrap();

        let ids = vec!["a1".to_string(), "a2".to_string()];
        let count = bulk_update_field(&conn, &ids, "device_type", "rtu").unwrap();
        assert_eq!(count, 2);

        let a1 = get_asset(&conn, "a1").unwrap();
        let a2 = get_asset(&conn, "a2").unwrap();
        assert_eq!(a1.device_type, "rtu");
        assert_eq!(a2.device_type, "rtu");
    }
}
