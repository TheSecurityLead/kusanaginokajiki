//! # gm-parsers
//!
//! ICS/SCADA protocol identification and deep parsing.
//!
//! ## Architecture
//!
//! Protocol identification happens in two passes:
//!
//! 1. **Port-based detection** (fast, works on every packet):
//!    Maps well-known ports to likely protocols. This gives us an initial
//!    classification that's correct ~95% of the time for standard deployments.
//!
//! 2. **Payload-based detection** (Phase 3, deeper analysis):
//!    Inspects application-layer bytes for protocol magic numbers,
//!    function codes, and header structures. This catches non-standard
//!    port usage and confirms port-based guesses.
//!
//! ## Adding a New Protocol
//!
//! 1. Add a variant to `IcsProtocol`
//! 2. Add port mappings in `identify_by_port()`
//! 3. (Phase 3) Add a parser module under `parsers/`

mod protocol;

pub use protocol::{IcsProtocol, identify_protocol, identify_by_port};
