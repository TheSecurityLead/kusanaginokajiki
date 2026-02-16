//! Error types for the gm-physical crate.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PhysicalError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Unsupported vendor: {0}")]
    UnsupportedVendor(String),
}
