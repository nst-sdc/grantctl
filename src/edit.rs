//! Editing a user's tokens: what `grant`, `revoke`, `lock` and `unlock` do
//! to access.conf.
//!
//! Scopes are handled as node sets. Granting unions them, revoking subtracts
//! them, and the result is written back in canonical form: `role` when the
//! set equals the role's default nodes, `role@a,b` otherwise.

use crate::config::{AccessFile, Config, Entry, Token};
use crate::error::{Error, Result};
use crate::validate::valid_username;

/// One role or flag of a user with the nodes it covers. Tokens grantctl does
/// not know (for example `review`) are kept untouched as `opaque`.
struct Slot {
    name: String,
    nodes: Vec<String>,
    opaque: Option<Token>,
}

fn slots(cfg: &Config, tokens: &[Token]) -> Vec<Slot> {
    let mut out: Vec<Slot> = Vec::new();
    for token in tokens {
        let Some(default) = cfg.default_nodes(&token.name) else {
            out.push(Slot {
                name: token.name.clone(),
                nodes: Vec::new(),
                opaque: Some(token.clone()),
            });
            continue;
        };
        let nodes = token.scope.clone().unwrap_or(default);
        add(&mut out, &token.name, &nodes);
    }
    out
}

fn find<'a>(slots: &'a mut [Slot], name: &str) -> Option<&'a mut Slot> {
    slots
        .iter_mut()
        .find(|s| s.opaque.is_none() && s.name == name)
}

fn add(slots: &mut Vec<Slot>, name: &str, nodes: &[String]) {
    match find(slots, name) {
        Some(slot) => {
            for node in nodes {
                if !slot.nodes.contains(node) {
                    slot.nodes.push(node.clone());
                }
            }
        }
        None => slots.push(Slot {
            name: name.to_string(),
            nodes: nodes.to_vec(),
            opaque: None,
        }),
    }
}

/// Canonical token for a node set, or `None` when the set is empty.
fn canon(cfg: &Config, name: &str, set: &[String]) -> Option<Token> {
    let ordered: Vec<String> = cfg
        .nodes
        .iter()
        .filter(|n| set.contains(n))
        .cloned()
        .collect();
    if ordered.is_empty() {
        return None;
    }
    let default = cfg.default_nodes(name).unwrap_or_default();
    Some(if ordered == default {
        Token::plain(name)
    } else {
        Token {
            name: name.to_string(),
            scope: Some(ordered),
        }
    })
}

fn rebuild(cfg: &Config, slots: &[Slot]) -> Vec<Token> {
    slots
        .iter()
        .filter_map(|s| match &s.opaque {
            Some(token) => Some(token.clone()),
            None => canon(cfg, &s.name, &s.nodes),
        })
        .collect()
}

/// The nodes a requested token names: `--on` wins over the token's own
/// `@scope`; `None` means "no scope given".
fn requested(cfg: &Config, token: &Token, on: Option<&[String]>) -> Result<Option<Vec<String>>> {
    if cfg.default_nodes(&token.name).is_none() {
        return Err(Error::msg(format!(
            "unknown role or flag: {} (see: grantctl roles)",
            token.name
        )));
    }
    let nodes = on.map(<[String]>::to_vec).or_else(|| token.scope.clone());
    for node in nodes.iter().flatten() {
        if !cfg.has_node(node) {
            return Err(Error::msg(format!("unknown node: {node}")));
        }
    }
    Ok(nodes)
}

/// Add roles or flags to a user, creating the line if the user is new.
/// `stamp` goes into the comment of a new line (for example `2026-11-13 by alice`).
pub fn grant(
    cfg: &Config,
    access: &mut AccessFile,
    user: &str,
    tokens: &[Token],
    on: Option<&[String]>,
    stamp: &str,
) -> Result<()> {
    if !valid_username(user) {
        return Err(Error::msg(format!("invalid username: {user}")));
    }
    if tokens.is_empty() {
        return Err(Error::msg(
            "give at least one role or flag (see: grantctl roles)",
        ));
    }
    let existing = access
        .get(user)
        .map(|e| e.tokens.clone())
        .unwrap_or_default();
    let mut all = slots(cfg, &existing);
    for token in tokens {
        let nodes = match requested(cfg, token, on)? {
            Some(nodes) => nodes,
            None => cfg.default_nodes(&token.name).unwrap_or_default(),
        };
        add(&mut all, &token.name, &nodes);
    }
    let tokens = rebuild(cfg, &all);
    match access.get_mut(user) {
        Some(entry) => entry.set_tokens(tokens),
        None => access.push(Entry::new(user, tokens, &format!("# added {stamp}"))),
    }
    Ok(())
}

/// Remove roles or flags from a user.
///
/// * tokens without scope: the token goes entirely;
/// * `--on` or `role@nodes`: only those nodes are subtracted;
/// * no tokens but `--on`: everything the user has on those nodes;
/// * neither: the user's line is removed.
///
/// Returns `true` when the user is no longer in the file.
pub fn revoke(
    cfg: &Config,
    access: &mut AccessFile,
    user: &str,
    tokens: &[Token],
    on: Option<&[String]>,
) -> Result<bool> {
    let Some(existing) = access.get(user).map(|e| e.tokens.clone()) else {
        return Err(Error::msg(format!("{user} is not in access.conf")));
    };
    if tokens.is_empty() && on.is_none() {
        access.remove(user);
        return Ok(true);
    }
    let mut all = slots(cfg, &existing);
    let targets: Vec<Token> = if tokens.is_empty() {
        all.iter()
            .filter(|s| s.opaque.is_none())
            .map(|s| Token::plain(&s.name))
            .collect()
    } else {
        tokens.to_vec()
    };
    for token in &targets {
        let cut = requested(cfg, token, on)?;
        if let Some(slot) = find(&mut all, &token.name) {
            match cut {
                None => slot.nodes.clear(),
                Some(cut) => slot.nodes.retain(|n| !cut.contains(n)),
            }
        }
    }
    let tokens = rebuild(cfg, &all);
    if tokens.is_empty() {
        access.remove(user);
        return Ok(true);
    }
    if let Some(entry) = access.get_mut(user) {
        entry.set_tokens(tokens);
    }
    Ok(false)
}
