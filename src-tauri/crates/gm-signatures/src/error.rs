//! Error types for the signature engine.

/// Errors that can occur during signature loading and matching.
#[derive(thiserror::Error, Debug)]
pub enum SignatureError {
    #[error("I/O error: {0}")]
    IoError(String),

    #[error("YAML parse error: {0}")]
    ParseError(String),

    #[error("Signature validation error: {0}")]
    ValidationError(String),
}
