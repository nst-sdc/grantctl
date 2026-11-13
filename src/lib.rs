//! grantctl: cluster-wide user and access management.
//!
//! The crate is split in two halves that talk JSON over SSH:
//!
//! * the control side: configuration, validation, token editing and the
//!   per-node desired state (pure and unit-tested), plus the commands that
//!   reach nodes over SSH (`control`);
//! * the node side (`grantctl node ...`): compares the desired state with
//!   the machine and applies the difference (`node`).
//!
//! See `docs/DESIGN.md`.

pub mod config;
pub mod control;
pub mod desired;
pub mod edit;
pub mod error;
pub mod node;
pub mod validate;

pub use error::{Error, Result};

/// Wire protocol version between the control side and `grantctl node ...`.
/// The control side refuses to talk to a node that reports a different value.
pub const PROTOCOL: u32 = 1;
