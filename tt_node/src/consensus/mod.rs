//! Consensus module for TT Protocol
//!
//! Mechanizmy konsensusu:
//! - Checkpoint system (long-range attack protection)
//! - [przyszłe] VRF-based leader selection
//! - [przyszłe] Finality gadget

pub mod checkpoint;

// Re-exports
pub use checkpoint::{
    CheckpointStore, CheckpointConfig, Checkpoint, CheckpointError,
    CheckpointProposal, CheckpointStats,
    init_with_hardcoded, get_hardcoded_checkpoints,
};
