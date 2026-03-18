//! Crate-specific error types for gm-segmentation.

use thiserror::Error;

/// Errors that can occur during segmentation analysis.
#[derive(Debug, Error)]
pub enum SegmentationError {
    /// The segmentation input is empty or insufficient.
    #[error("empty input: {0}")]
    EmptyInput(String),

    /// An invalid configuration was provided.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    /// JSON serialization / deserialization failed.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}
