//! grantctl: cluster-wide user and access management.
//!
//! The crate is split in two halves that talk JSON over SSH:
//!
//! * the control side (this milestone): configuration, validation, token
//!   editing and the per-node desired state, all pure and unit-tested;
//! * the node side (`grantctl node ...`, later milestones): compares the
//!   desired state with the machine and applies the difference.
//!
//! See `docs/DESIGN.md`.

pub mod config;
pub mod desired;
pub mod edit;
pub mod error;
pub mod validate;

pub use error::{Error, Result};

/// Wire protocol version between the control side and `grantctl node ...`.
/// The control side refuses to talk to a node that reports a different value.
pub const PROTOCOL: u32 = 1;
