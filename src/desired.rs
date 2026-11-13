//! The desired state of one node, computed on the control side.
//!
//! `build` turns the configuration into a `NodeDesired`: which accounts and
//! group memberships the node must have, and the exact content of the sshd,
//! sudoers and limits files grantctl owns there. It is pure: no I/O, no SSH.
//! The node side (`grantctl node apply`) receives this as JSON, compares it
//! with the machine and applies the difference.
//!
//! The rendered rules are checked against the bash v1 in `tests/parity.rs`.

use crate::config::{Config, From};
use crate::error::{Error, Result};
use crate::PROTOCOL;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Files grantctl owns on every node.
pub const SSHD_DIR: &str = "/etc/ssh/sshd_config.d";
pub const SUDOERS_DIR: &str = "/etc/sudoers.d";
pub const LIMITS_DIR: &str = "/etc/security/limits.d";
/// Global sshd settings and AllowGroups. sshd uses the first value it reads,
/// so this file must sort before distribution drop-ins such as 50-cloud-init.
pub const SSHD_MAIN_FILE: &str = "10-grantctl.conf";
/// Match blocks. Must be the last file: a Match block extends to the next one.
pub const SSHD_MATCH_FILE: &str = "99-grantctl.conf";
/// sudo uses the LAST matching rule, so this file sorts last and writes its
/// NOPASSWD lines at the end.
pub const SUDOERS_FILE: &str = "99-grantctl";
pub const LIMITS_FILE: &str = "60-grantctl.conf";
/// Drop-in under /etc/systemd/system/user-<uid>.slice.d/.
pub const SLICE_FILE: &str = "50-grantctl.conf";

pub const SSHD_MAIN_HEADER: &str =
    "# managed by grantctl. Edit /etc/grantctl/*, then run: grantctl sync\n";
pub const SSHD_MATCH_HEADER: &str = "# managed by grantctl. Keep LAST and Match-only.\n";
pub const OWNED_HEADER: &str = "# managed by grantctl. Do not edit.\n";

/// Files written by nst-cockpit (the bash v1). grantctl replaces them on the
/// first sync, so moving from v1 to v2 needs no manual cleanup.
const V1_SSHD: [&str; 2] = ["10-nst-cockpit.conf", "99-nst-cockpit.conf"];
const V1_SUDOERS: [&str; 1] = ["10-nst-cockpit"];
const V1_LIMITS: [&str; 1] = ["60-nst-cockpit.conf"];
const V1_SLICE_MARKER: &str = "managed by nst-cockpit";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    pub user: String,
    /// New accounts get their home at `<home_base>/<user>`. Existing homes
    /// are never moved.
    pub home_base: String,
    /// The user's UID on the control node; used for a new account when free.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Group {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
    /// Exact membership: anyone else is removed from the group.
    pub members: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Slice {
    pub user: String,
    /// systemd settings such as `CPUQuota=800%`.
    pub settings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quota {
    pub user: String,
    pub size: String,
    /// Mount point (or a directory on it) the quota applies to.
    pub base: String,
}

/// A password to copy from the control node: the same password everywhere,
/// unless the user changed it on this node themselves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Password {
    pub user: String,
    /// The shadow hash on the control node.
    pub hash: String,
    /// The shadow "last change" field there; `0` forces a change at next login.
    pub last_change: String,
}

/// Files of other tools that grantctl replaces, removed only after its own
/// files have been validated.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Legacy {
    pub sshd: Vec<String>,
    pub sudoers: Vec<String>,
    pub limits: Vec<String>,
    pub slice_markers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeDesired {
    pub protocol: u32,
    pub node: String,
    pub is_control: bool,
    /// The person running grantctl. The node refuses a state that would
    /// remove their sudo.
    pub operator: String,
    pub sudo_group: String,
    /// Everyone in access.conf. Accounts of other users are never modified.
    pub managed_users: Vec<String>,
    /// Users who must have an account on this node.
    pub accounts: Vec<Account>,
    /// Managed users whose account, if present, must be locked.
    pub locked: Vec<String>,
    /// Every role group, including those that must be empty here.
    pub groups: Vec<Group>,
    /// Groups allowed to log in over SSH.
    pub allow_groups: Vec<String>,
    /// Content of `SSHD_MAIN_FILE`.
    pub sshd_main: String,
    /// Content of `SSHD_MATCH_FILE`.
    pub sshd_match: String,
    /// Content of `SUDOERS_FILE`.
    pub sudoers: String,
    /// Content of `LIMITS_FILE`.
    pub limits: String,
    pub slices: Vec<Slice>,
    pub quotas: Vec<Quota>,
    /// Passwords of the control node, for accounts on this node. Empty on
    /// the control node itself. See `node::apply` for when one is applied.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub passwords: Vec<Password>,
    pub legacy: Legacy,
}

/// Facts from outside the configuration that the desired state depends on.
#[derive(Debug, Clone, Default)]
pub struct Hints {
    /// Addresses of the control node, for roles with `from = control`.
    pub control_ips: Vec<String>,
    /// UIDs and GIDs on the control node, reused on other nodes when free.
    pub uids: BTreeMap<String, u32>,
    pub gids: BTreeMap<String, u32>,
    /// Usable password hashes on the control node: user -> (hash, last change).
    pub passwords: BTreeMap<String, (String, String)>,
}

/// What `node` must look like.
pub fn build(cfg: &Config, node: &str, operator: &str, hints: &Hints) -> Result<NodeDesired> {
    if !cfg.has_node(node) {
        return Err(Error::msg(format!("unknown node: {node}")));
    }
    let sudo_group = cfg.site.sudo_group.clone();

    // A role is active on a node when the node is in its default scope, or
    // when a user's token puts it there (`gpu@node3`).
    let mut active: Vec<bool> = cfg.roles.iter().map(|r| r.nodes.contains(node)).collect();
    let mut members: BTreeMap<String, BTreeSet<String>> = cfg
        .managed_groups()
        .into_iter()
        .map(|g| (g, BTreeSet::new()))
        .collect();
    let mut managed = BTreeSet::new();
    let mut accounts = BTreeSet::new();
    let mut home: BTreeMap<String, String> = BTreeMap::new();
    let mut slices: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut quotas: BTreeMap<String, (String, String)> = BTreeMap::new();
    let mut sudoers_users = BTreeSet::new();
    let mut flags: BTreeSet<(String, String)> = BTreeSet::new();

    for entry in cfg.access.entries() {
        let user = &entry.user;
        managed.insert(user.clone());
        for token in &entry.tokens {
            if !cfg.token_on(token, node) {
                continue;
            }
            if token.is_flag() {
                flags.insert((token.name.clone(), user.clone()));
                continue;
            }
            let Some(index) = cfg.roles.iter().position(|r| r.name == token.name) else {
                continue;
            };
            let role = &cfg.roles[index];
            active[index] = true;
            accounts.insert(user.clone());
            // When several roles disagree, the first one on the user's line wins.
            if role.home != "/home" {
                home.entry(user.clone())
                    .or_insert_with(|| role.home.clone());
            }
            if !role.slice.is_empty() {
                slices
                    .entry(user.clone())
                    .or_insert_with(|| role.slice.clone());
            }
            if let Some(size) = &role.quota {
                quotas
                    .entry(user.clone())
                    .or_insert_with(|| (size.clone(), role.home.clone()));
            }
            if role.grants_sudo(&sudo_group) {
                sudoers_users.insert(user.clone());
            }
            for group in &role.groups {
                members
                    .entry(group.clone())
                    .or_default()
                    .insert(user.clone());
            }
        }
    }
    let has_flag = |flag: &str, user: &str| flags.contains(&(flag.to_string(), user.to_string()));

    // What the active roles mean for sshd, sudoers and limits on this node.
    let mut allow = BTreeSet::new();
    let mut password = BTreeSet::new();
    let mut open = BTreeSet::new();
    let mut restricted: BTreeSet<(String, String)> = BTreeSet::new();
    let mut options: BTreeSet<(String, Vec<(String, String)>)> = BTreeSet::new();
    let mut sudo_groups = BTreeSet::new();
    let mut limits: BTreeSet<(String, Vec<(String, String)>)> = BTreeSet::new();
    for (role, _) in cfg.roles.iter().zip(&active).filter(|(_, on)| **on) {
        for group in &role.groups {
            allow.insert(group.clone());
            if role.password {
                password.insert(group.clone());
            }
            match &role.from {
                From::Any => {
                    open.insert(group.clone());
                }
                other => {
                    restricted.insert((group.clone(), other.to_string()));
                }
            }
            if !role.sshd.is_empty() {
                options.insert((group.clone(), role.sshd.clone()));
            }
            if role.sudo {
                sudo_groups.insert(group.clone());
            }
            if !role.limits.is_empty() {
                limits.insert((group.clone(), role.limits.clone()));
            }
        }
    }
    if !allow.contains(&sudo_group) {
        return Err(Error::msg(format!(
            "no role puts group {sudo_group} on {node}: nobody could administer it"
        )));
    }

    // sshd Match blocks. Order matters: sshd applies the first value it sees
    // for each keyword, so per-user blocks come before per-group ones.
    let mut sshd_match = String::from(SSHD_MATCH_HEADER);
    for user in accounts.iter().filter(|u| has_flag("pwonly", u)) {
        sshd_match.push_str(&format!(
            "Match User {user}\n    PubkeyAuthentication no\n    PasswordAuthentication yes\n    AuthenticationMethods password\n"
        ));
    }
    if !password.is_empty() {
        sshd_match.push_str(&format!(
            "Match Group {}\n    PasswordAuthentication yes\n",
            join(&password, ",")
        ));
    }
    for (group, settings) in &options {
        sshd_match.push_str(&format!("Match Group {group}\n"));
        for (key, value) in settings {
            sshd_match.push_str(&format!("    {key} {value}\n"));
        }
    }
    for (group, from) in &restricted {
        let ips: Vec<String> = if from == "control" {
            hints.control_ips.clone()
        } else {
            from.split(',').map(String::from).collect()
        };
        if ips.is_empty() {
            return Err(Error::msg(format!(
                "group {group} uses from = control, but the control node's addresses are unknown"
            )));
        }
        // Members who also hold an unrestricted group are exempt.
        let exempt: String = open
            .iter()
            .filter(|g| *g != group)
            .map(|g| format!(",!{g}"))
            .collect();
        let outside: String = ips.iter().map(|ip| format!(",!{ip}")).collect();
        sshd_match.push_str(&format!(
            "Match Group {group}{exempt} Address *{outside}\n    DenyGroups {group}\n"
        ));
    }

    let mut sshd_main = String::from(SSHD_MAIN_HEADER);
    for line in &cfg.baseline {
        sshd_main.push_str(line);
        sshd_main.push('\n');
    }
    sshd_main.push_str(&format!("AllowGroups {}\n", join(&allow, " ")));

    let mut sudoers = String::from(OWNED_HEADER);
    sudoers.push_str(&format!("%{sudo_group} ALL=(ALL:ALL) ALL\n"));
    for group in &sudo_groups {
        sudoers.push_str(&format!("%{group} ALL=(ALL:ALL) ALL\n"));
    }
    for user in accounts
        .iter()
        .filter(|u| has_flag("nopasswd", u) && sudoers_users.contains(*u))
    {
        sudoers.push_str(&format!("{user} ALL=(ALL:ALL) NOPASSWD: ALL\n"));
    }

    let mut limits_text = String::from(OWNED_HEADER);
    for (group, items) in &limits {
        for (item, value) in items {
            limits_text.push_str(&format!("@{group} hard {item} {value}\n"));
        }
    }

    let site = &cfg.site;
    let with = |builtin: &[&str], extra: &[String]| -> Vec<String> {
        builtin
            .iter()
            .map(|s| s.to_string())
            .chain(extra.iter().cloned())
            .collect()
    };
    Ok(NodeDesired {
        protocol: PROTOCOL,
        node: node.to_string(),
        is_control: node == cfg.control(),
        operator: operator.to_string(),
        sudo_group,
        managed_users: managed.iter().cloned().collect(),
        accounts: accounts
            .iter()
            .map(|user| Account {
                user: user.clone(),
                home_base: home
                    .get(user)
                    .cloned()
                    .unwrap_or_else(|| "/home".to_string()),
                uid: hints.uids.get(user).copied(),
            })
            .collect(),
        locked: managed
            .iter()
            .filter(|u| has_flag("locked", u))
            .cloned()
            .collect(),
        groups: members
            .into_iter()
            .map(|(name, users)| Group {
                gid: hints.gids.get(&name).copied(),
                name,
                members: users.into_iter().collect(),
            })
            .collect(),
        allow_groups: allow.into_iter().collect(),
        sshd_main,
        sshd_match,
        sudoers,
        limits: limits_text,
        slices: slices
            .into_iter()
            .map(|(user, settings)| Slice { user, settings })
            .collect(),
        quotas: quotas
            .into_iter()
            .map(|(user, (size, base))| Quota { user, size, base })
            .collect(),
        passwords: accounts
            .iter()
            .filter(|u| node != cfg.control() && !has_flag("locked", u))
            .filter_map(|u| {
                hints.passwords.get(u).map(|(hash, last_change)| Password {
                    user: u.clone(),
                    hash: hash.clone(),
                    last_change: last_change.clone(),
                })
            })
            .collect(),
        legacy: Legacy {
            sshd: with(&V1_SSHD, &site.legacy_sshd),
            sudoers: with(&V1_SUDOERS, &site.legacy_sudo),
            limits: with(&V1_LIMITS, &site.legacy_limits),
            slice_markers: with(&[V1_SLICE_MARKER], site.legacy_slice_marker.as_slice()),
        },
    })
}

fn join(set: &BTreeSet<String>, sep: &str) -> String {
    set.iter().map(String::as_str).collect::<Vec<_>>().join(sep)
}
