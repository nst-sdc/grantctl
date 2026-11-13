//! Drafting access.conf from what the nodes look like today.
//!
//! `init` and `adopt` collect facts from every node and turn them into
//! roster lines. The draft changes nothing by itself: a user gets the roles
//! whose groups they are already in, on the nodes where that is the case.
//! Anything that does not map onto a role is marked `review`, and `sync`
//! refuses to run until every `review` is resolved.

use crate::config::Config;
use crate::node::ops::Facts;
use std::collections::{BTreeMap, BTreeSet};

/// Roster lines for every human account in `facts` (or only for `only`).
/// `facts` holds one entry per reachable node: (node name, facts).
pub fn draft(cfg: &Config, facts: &[(String, Facts)], only: Option<&str>) -> Vec<String> {
    let sudo_group = cfg.site.sudo_group.as_str();
    // Hosts in nodes-file order.
    let hosts: Vec<&str> = cfg
        .nodes
        .iter()
        .map(String::as_str)
        .filter(|n| facts.iter().any(|(h, _)| h == n))
        .collect();
    let of = |host: &str| facts.iter().find(|(h, _)| h == host).map(|(_, f)| f);
    let in_group = |user: &str, group: &str, host: &str| {
        of(host).is_some_and(|f| {
            f.groups
                .iter()
                .any(|g| g.name == group && g.members.iter().any(|m| m == user))
        })
    };
    let csv = |list: &[&str]| list.join(",");
    // `role` when the hosts are all the reachable nodes of its scope, else `role@hosts`.
    let scoped = |name: &str, default: &[&str], list: &[&str]| -> String {
        if default.iter().all(|h| list.contains(h)) && !default.is_empty() {
            name.to_string()
        } else {
            format!("{name}@{}", csv(list))
        }
    };

    let mut users: BTreeSet<&str> = BTreeSet::new();
    for (_, f) in facts {
        users.extend(f.accounts.iter().map(|a| a.user.as_str()));
    }
    // Roles with more groups first, so `admin` is tried before a role that
    // only has a subset of its groups.
    let mut roles: Vec<_> = cfg.roles.iter().collect();
    roles.sort_by_key(|r| std::cmp::Reverse(r.groups.len()));

    let mut lines: Vec<(String, String)> = Vec::new();
    for user in users {
        if only.is_some_and(|o| o != user) {
            continue;
        }
        let has = |pick: &dyn Fn(&Facts) -> bool| -> Vec<&str> {
            hosts
                .iter()
                .copied()
                .filter(|h| of(h).is_some_and(pick))
                .collect()
        };
        let mut tokens: Vec<String> = Vec::new();
        let mut why = String::new();
        let mut held: BTreeSet<(&str, &str)> = BTreeSet::new(); // (host, group)
        let mut covered: BTreeSet<&str> = BTreeSet::new();
        let mut sudo_covered: BTreeSet<&str> = BTreeSet::new();
        let mut evidence: BTreeMap<&str, Vec<String>> = BTreeMap::new();

        for role in &roles {
            let scope: Vec<&str> = hosts
                .iter()
                .copied()
                .filter(|h| role.nodes.contains(h))
                .collect();
            let on: Vec<&str> = scope
                .iter()
                .copied()
                .filter(|h| role.groups.iter().all(|g| in_group(user, g, h)))
                .collect();
            if on.is_empty() {
                continue;
            }
            let redundant = on
                .iter()
                .all(|h| role.groups.iter().all(|g| held.contains(&(*h, g.as_str()))));
            if redundant {
                continue;
            }
            tokens.push(scoped(&role.name, &scope, &on));
            for h in on.iter().copied() {
                covered.insert(h);
                if role.grants_sudo(sudo_group) {
                    sudo_covered.insert(h);
                }
                for g in &role.groups {
                    held.insert((h, g.as_str()));
                    evidence.entry(h).or_default().push(format!("grp:{g}"));
                }
            }
        }

        let sudo_on = has(&|f: &Facts| {
            f.sudo_users.iter().any(|u| u == user)
                || f.groups
                    .iter()
                    .any(|g| g.name == sudo_group && g.members.iter().any(|m| m == user))
        });
        let uncovered: Vec<&str> = sudo_on
            .iter()
            .copied()
            .filter(|h| !sudo_covered.contains(h))
            .collect();
        if !uncovered.is_empty() {
            why.push_str(&format!(
                " sudo on {} is not covered by a role;",
                csv(&uncovered)
            ));
        }
        for h in sudo_on.iter().copied() {
            evidence.entry(h).or_default().push("sudo".into());
        }

        let ssh_on = has(&|f: &Facts| f.allow_users.iter().any(|u| u == user));
        let extra: Vec<&str> = ssh_on
            .iter()
            .copied()
            .filter(|h| !covered.contains(h))
            .collect();
        if !extra.is_empty() {
            if cfg.role(&cfg.site.shell_role).is_some() {
                tokens.push(format!("{}@{}", cfg.site.shell_role, csv(&extra)));
            } else {
                why.push_str(&format!(
                    " ssh on {} is not covered by a role;",
                    csv(&extra)
                ));
            }
        }

        let nopasswd = has(&|f: &Facts| f.nopasswd_users.iter().any(|u| u == user));
        if !nopasswd.is_empty() {
            tokens.push(scoped("nopasswd", &hosts, &nopasswd));
        }
        let pwonly = has(&|f: &Facts| f.pwonly_users.iter().any(|u| u == user));
        if !pwonly.is_empty() {
            tokens.push(scoped("pwonly", &hosts, &pwonly));
        }
        if !has(&|f: &Facts| f.accounts.iter().any(|a| a.user == user && a.locked)).is_empty() {
            tokens.push("locked".into());
        }

        let accounts = has(&|f: &Facts| f.accounts.iter().any(|a| a.user == user));
        if tokens.is_empty() {
            why.push_str(&format!(
                " account only on {}; give a role, lock or delete it;",
                csv(&accounts)
            ));
            tokens.push("review".into());
        } else if !why.is_empty() {
            tokens.push("review".into());
        }
        let seen: Vec<String> = evidence
            .iter()
            .map(|(h, e)| format!("{h}: {}", e.join(" ")))
            .collect();
        let comment = if why.is_empty() {
            seen.join("; ")
        } else {
            format!("review:{why} {}", seen.join("; "))
        };
        let tokens = tokens.join(" ");
        lines.push((
            tokens.clone(),
            format!("{user:<16} {tokens:<34} # {}", comment.trim_end())
                .trim_end()
                .to_string(),
        ));
    }
    // Group similar users together: sort by tokens, then by name.
    lines.sort();
    lines.into_iter().map(|(_, line)| line).collect()
}

pub const DRAFT_HEADER: &str = "\
# grantctl source of truth.   <user> <token> [token..]   [# comment]
#   token: role | role@node,node | flag | flag@node     flags: locked nopasswd pwonly
#   Every account on every node should be listed here. Groups named in roles.ini are made exact.
#   'review' MUST be resolved (adjust the tokens, delete the word) before sync.
#   Drafted from the current state of the nodes. Comments show the evidence per node.
";
