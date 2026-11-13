//! The node side: `grantctl node <command>`, run as root on every node.
//!
//! Each command reads JSON on stdin and answers with JSON on stdout. The
//! control side reaches it through `ssh <node> sudo -n grantctl node ...`.

pub mod apply;
#[doc(hidden)]
pub mod fake;
pub mod ops;
pub mod system;

use crate::desired::NodeDesired;
use crate::PROTOCOL;
use serde::{Deserialize, Serialize};
use system::System;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Only adds: groups, accounts, memberships, unlocks.
    Widen,
    /// Replaces the sudoers, limits and sshd files; validated, rolled back on failure.
    Switch,
    /// Only removes: memberships, locks. Runs only after a successful switch.
    Narrow,
    /// Slice limits and quotas.
    Limits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "do", rename_all = "snake_case")]
pub enum Action {
    CreateGroup {
        group: String,
        gid: Option<u32>,
    },
    CreateUser {
        user: String,
        home: String,
        uid: Option<u32>,
    },
    AddMember {
        user: String,
        group: String,
    },
    Unlock {
        user: String,
    },
    /// Set the password to the control node's. The hash itself is in the
    /// desired state, never in a report.
    Password {
        user: String,
    },
    Install {
        path: String,
        mode: u32,
        old: Option<String>,
        new: String,
    },
    Remove {
        path: String,
        old: Option<String>,
    },
    RemoveMember {
        user: String,
        group: String,
    },
    Lock {
        user: String,
    },
    Slice {
        user: String,
        settings: Vec<String>,
    },
    Quota {
        user: String,
        size: String,
        base: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Planned,
    Done,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    pub phase: Phase,
    pub action: Action,
    pub status: Status,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// What `node apply` found and did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub protocol: u32,
    /// The machine's own hostname.
    pub host: String,
    pub dry_run: bool,
    /// False when a guard refused the state or a step failed.
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Existing accounts that gain or lose SSH access through this change.
    pub ssh_gain: Vec<String>,
    pub ssh_lose: Vec<String>,
    pub steps: Vec<Step>,
    pub warnings: Vec<String>,
    /// Accounts of people who are not in access.conf. Never modified.
    pub unmanaged: Vec<String>,
    /// Managed users with an account here but no access here, not locked.
    pub stray: Vec<String>,
    /// Accounts created in this run. They have no usable password yet.
    pub created: Vec<String>,
    /// Managed users who already had an account before this run.
    pub had_account: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Version {
    pub protocol: u32,
    pub version: String,
}

fn to_json<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_string(value).map_err(|e| format!("cannot encode the answer: {e}"))
}

fn from_json<'a, T: Deserialize<'a>>(what: &str, text: &'a str) -> Result<T, String> {
    serde_json::from_str(text).map_err(|e| format!("cannot read {what} from stdin: {e}"))
}

/// Entry point of `grantctl node ...`. `args` are the words after `node`.
pub fn handle(sys: &mut dyn System, args: &[String], stdin: &str) -> Result<String, String> {
    let command = args.first().map(String::as_str).unwrap_or("");
    if command == "version" {
        return to_json(&Version {
            protocol: PROTOCOL,
            version: env!("CARGO_PKG_VERSION").to_string(),
        });
    }
    if sys.query(&["id", "-u"]).stdout.trim() != "0" {
        return Err("grantctl node commands must run as root (sudo -n grantctl node ...)".into());
    }
    match command {
        "apply" => {
            let desired: NodeDesired = from_json("the desired state", stdin)?;
            let dry_run = args.iter().any(|a| a == "--dry-run");
            to_json(&apply::apply(sys, &desired, dry_run))
        }
        "facts" => to_json(&ops::facts(sys)),
        "hashes" => {
            let request: ops::HashesRequest = from_json("the user list", stdin)?;
            to_json(&ops::hashes(sys, &request))
        }
        "account" => {
            let request: ops::AccountRequest = from_json("the account request", stdin)?;
            to_json(&ops::account(sys, &request))
        }
        "audit" => {
            let request: ops::AuditRequest = from_json("the audit request", stdin)?;
            to_json(&ops::audit(sys, &request))
        }
        other => Err(format!("unknown node command: {other:?}")),
    }
}
