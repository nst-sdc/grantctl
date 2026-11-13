//! Checks that must pass before any node is touched.

use crate::config::{Config, FLAGS};
use std::collections::BTreeSet;

/// Usernames grantctl is willing to manage.
pub fn valid_username(user: &str) -> bool {
    let mut chars = user.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// Problems in the configuration, in file order. Empty means usable.
///
/// `operator` is the person running grantctl. The configuration must never
/// take away their own way in: they need sudo on every node, and passwordless
/// sudo everywhere except the control node (grantctl runs `sudo -n` there).
pub fn validate(cfg: &Config, operator: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let mut seen = BTreeSet::new();
    for entry in cfg.access.entries() {
        let user = &entry.user;
        if !valid_username(user) {
            problems.push(format!("invalid username: {user}"));
        }
        if !seen.insert(user.as_str()) {
            problems.push(format!("duplicate user: {user}"));
        }
        let mut roles = 0;
        let mut locked = false;
        for token in &entry.tokens {
            if token.name == "review" {
                problems.push(format!("{user}: unresolved review"));
                continue;
            }
            let is_flag = FLAGS.contains(&token.name.as_str());
            if !is_flag && cfg.role(&token.name).is_none() {
                problems.push(format!("{user}: unknown role or flag {}", token.name));
                continue;
            }
            if is_flag {
                locked |= token.name == "locked";
            } else {
                roles += 1;
            }
            for node in token.scope.iter().flatten() {
                if !cfg.has_node(node) {
                    problems.push(format!("{user}: unknown node {node}"));
                }
            }
        }
        if roles == 0 && !locked {
            problems.push(format!(
                "{user}: no role (give one, mark the user locked, or delete the account)"
            ));
        }
    }
    problems.extend(operator_problems(cfg, operator));
    problems
}

fn operator_problems(cfg: &Config, operator: &str) -> Vec<String> {
    let Some(entry) = cfg.access.get(operator) else {
        return vec![format!(
            "you ({operator}) are not listed in access.conf; the operator needs sudo on every node"
        )];
    };
    let sudo_group = cfg.site.sudo_group.as_str();
    let control = cfg.control();
    let (mut no_sudo, mut no_nopasswd, mut locked) = (Vec::new(), Vec::new(), Vec::new());
    for node in &cfg.nodes {
        let has = |name: &str| {
            entry
                .tokens
                .iter()
                .any(|t| t.name == name && cfg.token_on(t, node))
        };
        let sudo = entry.tokens.iter().any(|t| {
            cfg.role(&t.name).is_some_and(|r| r.grants_sudo(sudo_group)) && cfg.token_on(t, node)
        });
        if !sudo {
            no_sudo.push(node.as_str());
        } else if node != control && !has("nopasswd") {
            no_nopasswd.push(node.as_str());
        }
        if has("locked") {
            locked.push(node.as_str());
        }
    }
    let mut problems = Vec::new();
    if !no_sudo.is_empty() {
        problems.push(format!(
            "you ({operator}) need sudo on every node; missing on: {}",
            no_sudo.join(", ")
        ));
    }
    if !no_nopasswd.is_empty() {
        problems.push(format!(
            "you ({operator}) need the nopasswd flag on every node except the control node; missing on: {}",
            no_nopasswd.join(", ")
        ));
    }
    if !locked.is_empty() {
        problems.push(format!(
            "you ({operator}) are marked locked on: {}",
            locked.join(", ")
        ));
    }
    problems
}
