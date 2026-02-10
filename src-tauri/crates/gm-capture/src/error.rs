use thiserror::Error;

#[derive(Error, Debug)]
pub enum CaptureError {
    #[error("Failed to open PCAP file: {0}")]
    FileOpen(String),

    #[error("Failed to read packet: {0}")]
    PacketRead(String),

    #[error("Network interface not found: {0}")]
    InterfaceNotFound(String),

    #[error("Failed to list interfaces: {0}")]
    InterfaceList(String),

    #[error("Capture error: {0}")]
    Capture(String),

    #[error("Parse error: {0}")]
    Parse(String),
}

// Allow conversion from pcap errors
impl From<pcap::Error> for CaptureError {
    fn from(err: pcap::Error) -> Self {
        CaptureError::Capture(err.to_string())
    }
}
