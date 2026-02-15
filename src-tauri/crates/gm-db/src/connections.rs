//! Connection CRUD operations.

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

use crate::error::DbError;

/// A connection record stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionRow {
    pub id: String,
    pub session_id: String,
    pub src_ip: String,
    pub src_port: i64,
    pub src_mac: Option<String>,
    pub dst_ip: String,
    pub dst_port: i64,
    pub dst_mac: Option<String>,
    pub protocol: String,
    pub transport: String,
    pub packet_count: i64,
    pub byte_count: i64,
    pub first_seen: String,
    pub last_seen: String,
    pub origin_files: String, // JSON array
}

/// Insert a connection into the database.
pub fn insert_connection(conn: &Connection, row: &ConnectionRow) -> Result<(), DbError> {
    conn.execute(
        "INSERT OR REPLACE INTO connections (
            id, session_id, src_ip, src_port, src_mac, dst_ip, dst_port, dst_mac,
            protocol, transport, packet_count, byte_count, first_seen, last_seen, origin_files
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            row.id, row.session_id, row.src_ip, row.src_port, row.src_mac,
            row.dst_ip, row.dst_port, row.dst_mac, row.protocol, row.transport,
            row.packet_count, row.byte_count, row.first_seen, row.last_seen,
            row.origin_files
        ],
    )?;
    Ok(())
}

/// List all connections for a session.
pub fn list_connections(conn: &Connection, session_id: &str) -> Result<Vec<ConnectionRow>, DbError> {
    let mut stmt = conn.prepare(
        "SELECT id, session_id, src_ip, src_port, src_mac, dst_ip, dst_port, dst_mac,
                protocol, transport, packet_count, byte_count, first_seen, last_seen, origin_files
         FROM connections WHERE session_id = ?1
         ORDER BY packet_count DESC",
    )?;

    let rows = stmt
        .query_map(params![session_id], |row| {
            Ok(ConnectionRow {
                id: row.get(0)?,
                session_id: row.get(1)?,
                src_ip: row.get(2)?,
                src_port: row.get(3)?,
                src_mac: row.get(4)?,
                dst_ip: row.get(5)?,
                dst_port: row.get(6)?,
                dst_mac: row.get(7)?,
                protocol: row.get(8)?,
                transport: row.get(9)?,
                packet_count: row.get(10)?,
                byte_count: row.get(11)?,
                first_seen: row.get(12)?,
                last_seen: row.get(13)?,
                origin_files: row.get(14)?,
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

    #[test]
    fn test_connection_insert_and_list() {
        let conn = Connection::open_in_memory().unwrap();
        schema::initialize(&conn).unwrap();
        conn.execute(
            "INSERT INTO sessions (id, name, created_at, updated_at) VALUES ('s1', 'Test', '2024-01-01', '2024-01-01')",
            [],
        ).unwrap();

        let row = ConnectionRow {
            id: "c1".into(),
            session_id: "s1".into(),
            src_ip: "192.168.1.100".into(),
            src_port: 12345,
            src_mac: Some("aa:bb:cc:dd:ee:ff".into()),
            dst_ip: "192.168.1.1".into(),
            dst_port: 502,
            dst_mac: None,
            protocol: "Modbus".into(),
            transport: "tcp".into(),
            packet_count: 100,
            byte_count: 5000,
            first_seen: "2024-01-01T00:00:00Z".into(),
            last_seen: "2024-01-01T01:00:00Z".into(),
            origin_files: "[\"test.pcap\"]".into(),
        };

        insert_connection(&conn, &row).unwrap();

        let list = list_connections(&conn, "s1").unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].src_ip, "192.168.1.100");
        assert_eq!(list[0].dst_port, 502);
    }
}
