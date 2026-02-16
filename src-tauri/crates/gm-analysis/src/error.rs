//! Error types for the gm-analysis crate.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AnalysisError {
    #[error("Analysis failed: {0}")]
    AnalysisFailed(String),
}
