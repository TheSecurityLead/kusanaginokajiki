//! Error types for the gm-report crate.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReportError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("PDF generation error: {0}")]
    Pdf(String),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("No data available: {0}")]
    NoData(String),
}
