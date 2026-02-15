//! Database error types.

#[derive(thiserror::Error, Debug)]
pub enum DbError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Record not found: {0}")]
    NotFound(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("GeoIP error: {0}")]
    GeoIp(String),

    #[error("OUI lookup error: {0}")]
    Oui(String),
}
