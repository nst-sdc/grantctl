//! Configuration on the control node (default directory: `/etc/grantctl`).
//!
//! | file            | content                                              |
//! |-----------------|------------------------------------------------------|
//! | `access.conf`   | one user per line: roles and flags                   |
//! | `roles.ini`     | what each role means                                 |
//! | `nodes`         | node names, control node first                       |
//! | `grantctl.conf` | optional site settings                               |
//! | `sshd-baseline` | optional override of the global sshd settings        |
//!
//! The formats are the ones nst-cockpit (the bash v1) used, so an existing
//! configuration directory can be copied over unchanged.

pub mod access;
pub mod roles;
pub mod site;

use crate::error::{Error, Result};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub use access::{AccessFile, Entry, Line, Token, FLAGS};
pub use roles::{From, Role, Scope};
pub use site::Site;

pub const DEFAULT_DIR: &str = "/etc/grantctl";

/// Global sshd settings written to every node unless `sshd-baseline` overrides them.
pub const DEFAULT_BASELINE: &str = "\
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
PermitUserEnvironment no
MaxAuthTries 4
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 3
";

#[derive(Debug, Clone)]
pub struct Config {
    pub dir: PathBuf,
    pub site: Site,
    /// Node names in file order. The first one is the control node unless
    /// `CONTROL` says otherwise.
    pub nodes: Vec<String>,
    pub roles: Vec<Role>,
    pub access: AccessFile,
    /// Lines of the global sshd settings (comments and blanks removed).
    pub baseline: Vec<String>,
}

impl Config {
    /// Load a complete configuration directory.
    pub fn load(dir: &Path) -> Result<Config> {
        let nodes_path = dir.join("nodes");
        let nodes = read_opt(&nodes_path)?.ok_or_else(|| {
            Error::msg(format!(
                "no nodes configured ({}). Run: grantctl init <control-node> <node>...",
                nodes_path.display()
            ))
        })?;
        let access_path = dir.join("access.conf");
        let access = read_opt(&access_path)?.ok_or_else(|| {
            Error::msg(format!(
                "{} is missing. Run: grantctl init",
                access_path.display()
            ))
        })?;
        let roles = read_opt(&dir.join("roles.ini"))?;
        let site = read_opt(&dir.join("grantctl.conf"))?.unwrap_or_default();
        let mut cfg = Config::from_strs(
            &nodes,
            roles.as_deref().unwrap_or(roles::DEFAULT_ROLES),
            &access,
            &site,
        )?;
        if let Some(text) = read_opt(&dir.join("sshd-baseline"))? {
            cfg.baseline = parse_baseline(&text);
        }
        cfg.dir = dir.to_path_buf();
        Ok(cfg)
    }

    /// Build a configuration from file contents. Used by `load` and by tests.
    pub fn from_strs(nodes: &str, roles: &str, access: &str, site: &str) -> Result<Config> {
        let nodes = parse_nodes(nodes);
        if nodes.is_empty() {
            return Err(Error::msg("the nodes file lists no nodes"));
        }
        let site = Site::parse(site, "grantctl.conf")?;
        if let Some(control) = &site.control {
            if !nodes.contains(control) {
                return Err(Error::msg(format!(
                    "CONTROL={control} is not listed in the nodes file"
                )));
            }
        }
        Ok(Config {
            dir: PathBuf::from(DEFAULT_DIR),
            site,
            nodes,
            roles: roles::parse(roles, "roles.ini")?,
            access: AccessFile::parse(access),
            baseline: parse_baseline(DEFAULT_BASELINE),
        })
    }

    /// Roles only; works before `init` has written anything else.
    pub fn load_roles(dir: &Path) -> Result<Vec<Role>> {
        let text = read_opt(&dir.join("roles.ini"))?;
        roles::parse(text.as_deref().unwrap_or(roles::DEFAULT_ROLES), "roles.ini")
    }

    pub fn control(&self) -> &str {
        self.site.control.as_deref().unwrap_or(&self.nodes[0])
    }

    pub fn role(&self, name: &str) -> Option<&Role> {
        self.roles.iter().find(|r| r.name == name)
    }

    pub fn has_node(&self, name: &str) -> bool {
        self.nodes.iter().any(|n| n == name)
    }

    /// Accept a full node name, or a suffix that matches exactly one node
    /// (`3` or `n3` for `nst-n3`).
    pub fn resolve_node(&self, name: &str) -> Result<String> {
        if self.has_node(name) {
            return Ok(name.to_string());
        }
        let hits: Vec<&String> = self.nodes.iter().filter(|n| n.ends_with(name)).collect();
        match hits.as_slice() {
            [one] => Ok((*one).clone()),
            [] => Err(Error::msg(format!("unknown node: {name}"))),
            many => Err(Error::msg(format!(
                "ambiguous node {name}: matches {}",
                many.iter()
                    .map(|n| n.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))),
        }
    }

    /// Every group named by any role, sorted. grantctl keeps the membership
    /// of these groups exact on every node.
    pub fn managed_groups(&self) -> Vec<String> {
        let set: BTreeSet<&String> = self.roles.iter().flat_map(|r| r.groups.iter()).collect();
        set.into_iter().cloned().collect()
    }

    /// Nodes a role or flag covers when the token has no `@scope`, in
    /// nodes-file order. `None` for a name that is neither a role nor a flag.
    pub fn default_nodes(&self, name: &str) -> Option<Vec<String>> {
        if FLAGS.contains(&name) {
            return Some(self.nodes.clone());
        }
        self.role(name).map(|r| {
            self.nodes
                .iter()
                .filter(|n| r.nodes.contains(n))
                .cloned()
                .collect()
        })
    }

    /// Does this token apply on this node? Unknown names never apply.
    pub fn token_on(&self, token: &Token, node: &str) -> bool {
        match (&token.scope, token.is_flag(), self.role(&token.name)) {
            (Some(scope), true, _) | (Some(scope), false, Some(_)) => {
                scope.iter().any(|n| n == node)
            }
            (None, true, _) => true,
            (None, false, Some(role)) => role.nodes.contains(node),
            (_, false, None) => false,
        }
    }
}

/// Node names: first word of every line that is not blank or a comment.
pub fn parse_nodes(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|w| !w.starts_with('#'))
        .map(String::from)
        .collect()
}

/// sshd baseline: every line that is not blank or a comment.
pub fn parse_baseline(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect()
}

fn read_opt(path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(Error::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}
