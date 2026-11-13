//! Role definitions: `roles.ini`.
//!
//! One `[name]` section per role. Whitespace inside values is ignored, `#`
//! starts a comment. See `DEFAULT_ROLES` for the keys.

use crate::config::access::FLAGS;
use crate::error::{Error, Result};
use std::fmt;

/// Which nodes a role covers when a token has no `@scope`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    All,
    Nodes(Vec<String>),
}

impl Scope {
    pub fn parse(s: &str) -> Scope {
        if s == "all" {
            Scope::All
        } else {
            Scope::Nodes(split_list(s))
        }
    }

    pub fn contains(&self, node: &str) -> bool {
        match self {
            Scope::All => true,
            Scope::Nodes(nodes) => nodes.iter().any(|n| n == node),
        }
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // `pad` honours width and alignment, so tables can use `{:<10}`.
            Scope::All => f.pad("all"),
            Scope::Nodes(nodes) => f.pad(&nodes.join(",")),
        }
    }
}

/// Where SSH connections for a role's groups may come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum From {
    Any,
    /// Only from the control node's addresses (jump-host pattern).
    Control,
    Ips(Vec<String>),
}

impl fmt::Display for From {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            From::Any => f.write_str("any"),
            From::Control => f.write_str("control"),
            From::Ips(ips) => f.write_str(&ips.join(",")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Role {
    pub name: String,
    /// Unix groups the role puts users in.
    pub groups: Vec<String>,
    pub nodes: Scope,
    /// Allow SSH password login for these groups.
    pub password: bool,
    pub from: From,
    /// Extra sshd options for these groups: (keyword, value).
    pub sshd: Vec<(String, String)>,
    /// Write `%group ALL=(ALL:ALL) ALL` for each group.
    pub sudo: bool,
    /// Base directory for accounts created through this role.
    pub home: String,
    /// systemd per-user slice settings, e.g. `CPUQuota=800%`.
    pub slice: Vec<String>,
    /// Block quota per user on the filesystem holding `home`, e.g. `90G`.
    pub quota: Option<String>,
    /// pam_limits for the groups: (item, value).
    pub limits: Vec<(String, String)>,
}

impl Role {
    /// Does holding this role make a user a sudoer?
    pub fn grants_sudo(&self, sudo_group: &str) -> bool {
        self.sudo || self.groups.iter().any(|g| g == sudo_group)
    }
}

/// Written by `init` when no roles.ini exists yet.
pub const DEFAULT_ROLES: &str = "\
# grantctl roles. One [section] per role. Keys (defaults in brackets):
#   groups    unix groups the role puts users in (comma list)            [required]
#   nodes     default nodes: all | node,node  (token role@node overrides)   [all]
#   password  yes = password SSH login allowed for these groups              [no]
#   from      any | control | ip,ip = SSH only from these source IPs        [any]
#             control = the control node's addresses (jump-host pattern)
#   sshd      extra sshd options for these groups: Key=Val,Key=Val          [-]
#   sudo      yes = \"%group ALL=(ALL:ALL) ALL\" for each group                [no]
#   home      base dir for NEW accounts created through this role            [/home]
#   slice     systemd per-user slice limits: Key=Val,..                      [-]
#   quota     block quota per user on the filesystem holding home, e.g. 90G  [-]
#   limits    pam_limits for the group: item=value,..                        [-]

[admin]        # SSH + sudo everywhere
groups   = cluster-admins,sudo

[user]         # plain shell access. Typical: user@node3
groups   = cluster-users

# More examples (uncomment and adapt):
#
# [student]    # password login on the control node only
# groups   = students
# nodes    = node1
# password = yes
#
# [gpu]        # GPU node: reachable only via the control node, with limits
# groups   = gpu-users
# nodes    = gpu1
# from     = control
# sshd     = MaxSessions=4,AllowAgentForwarding=no,X11Forwarding=no
# home     = /srv/gpu-home
# slice    = CPUQuota=800%,MemoryMax=20G,MemoryHigh=16G,TasksMax=1024
# quota    = 90G
# limits   = nproc=1024,maxlogins=4,core=0
";

struct Section {
    name: String,
    line: usize,
    settings: Vec<(String, String, usize)>,
}

pub fn parse(text: &str, file: &str) -> Result<Vec<Role>> {
    let squeeze = |s: &str| -> String { s.chars().filter(|c| !c.is_whitespace()).collect() };
    let mut sections: Vec<Section> = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let n = i + 1;
        let line = match raw.find('#') {
            Some(p) => &raw[..p],
            None => raw,
        }
        .trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            let Some(inner) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) else {
                return Err(Error::parse(file, n, "malformed [role] header"));
            };
            let name = squeeze(inner);
            check_role_name(&name).map_err(|m| Error::parse(file, n, m))?;
            if sections.iter().any(|s| s.name == name) {
                return Err(Error::parse(
                    file,
                    n,
                    format!("role {name} is defined twice"),
                ));
            }
            sections.push(Section {
                name,
                line: n,
                settings: Vec::new(),
            });
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(Error::parse(file, n, "expected key = value"));
        };
        let Some(section) = sections.last_mut() else {
            return Err(Error::parse(file, n, "setting outside a [role] section"));
        };
        section.settings.push((squeeze(key), squeeze(value), n));
    }

    let mut roles = Vec::new();
    for s in sections {
        let mut role = Role {
            name: s.name.clone(),
            groups: Vec::new(),
            nodes: Scope::All,
            password: false,
            from: From::Any,
            sshd: Vec::new(),
            sudo: false,
            home: "/home".to_string(),
            slice: Vec::new(),
            quota: None,
            limits: Vec::new(),
        };
        for (key, value, n) in s.settings {
            let bad = |m: String| Error::parse(file, n, format!("role {}: {m}", s.name));
            match key.as_str() {
                "groups" => role.groups = split_list(&value),
                "nodes" => role.nodes = Scope::parse(&value),
                "password" => role.password = yes_no(&value).map_err(bad)?,
                "sudo" => role.sudo = yes_no(&value).map_err(bad)?,
                "from" => {
                    role.from = match value.as_str() {
                        "any" => From::Any,
                        "control" => From::Control,
                        _ => From::Ips(split_list(&value)),
                    }
                }
                "sshd" => role.sshd = pairs(&value).map_err(bad)?,
                "limits" => role.limits = pairs(&value).map_err(bad)?,
                "home" => {
                    if !value.starts_with('/') {
                        return Err(bad("home must be an absolute path".to_string()));
                    }
                    role.home = value.trim_end_matches('/').to_string();
                }
                "slice" => {
                    role.slice = if value == "-" {
                        Vec::new()
                    } else {
                        split_list(&value)
                    }
                }
                "quota" => role.quota = quota(&value).map_err(bad)?,
                other => return Err(bad(format!("unknown key {other}"))),
            }
        }
        if role.groups.is_empty() {
            return Err(Error::parse(
                file,
                s.line,
                format!("role {}: groups is required", s.name),
            ));
        }
        roles.push(role);
    }
    Ok(roles)
}

fn check_role_name(name: &str) -> std::result::Result<(), String> {
    let ok = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !ok {
        return Err(format!("invalid role name {name:?}"));
    }
    if FLAGS.contains(&name) || name == "review" {
        return Err(format!("{name} is reserved and cannot be a role name"));
    }
    Ok(())
}

fn split_list(s: &str) -> Vec<String> {
    s.split(',')
        .filter(|x| !x.is_empty())
        .map(String::from)
        .collect()
}

fn yes_no(s: &str) -> std::result::Result<bool, String> {
    match s {
        "yes" => Ok(true),
        "no" => Ok(false),
        other => Err(format!("expected yes or no, got {other}")),
    }
}

fn pairs(s: &str) -> std::result::Result<Vec<(String, String)>, String> {
    if s == "-" {
        return Ok(Vec::new());
    }
    s.split(',')
        .filter(|x| !x.is_empty())
        .map(|kv| {
            kv.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .ok_or_else(|| format!("expected Key=Value, got {kv}"))
        })
        .collect()
}

fn quota(s: &str) -> std::result::Result<Option<String>, String> {
    if s == "-" {
        return Ok(None);
    }
    let digits = s.strip_suffix('G').unwrap_or("");
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("quota must look like 90G, got {s}"));
    }
    Ok(Some(s.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_roles_parse() {
        let roles = parse(DEFAULT_ROLES, "roles.ini").unwrap();
        let names: Vec<&str> = roles.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["admin", "user"]);
        assert!(roles[0].grants_sudo("sudo"));
        assert!(!roles[1].grants_sudo("sudo"));
    }

    #[test]
    fn full_role() {
        let text = "[gpu]  # GPU box\ngroups = gpu-users\nnodes = gpu1, gpu2\npassword = yes\n\
                    from = control\nsshd = MaxSessions=4, X11Forwarding=no\nhome = /srv/gpu-home/\n\
                    slice = CPUQuota=800%,MemoryMax=20G\nquota = 90G\nlimits = nproc=1024\n";
        let r = &parse(text, "f").unwrap()[0];
        assert_eq!(r.nodes, Scope::Nodes(vec!["gpu1".into(), "gpu2".into()]));
        assert!(r.password);
        assert_eq!(r.from, From::Control);
        assert_eq!(r.sshd[1], ("X11Forwarding".to_string(), "no".to_string()));
        assert_eq!(r.home, "/srv/gpu-home");
        assert_eq!(r.slice, ["CPUQuota=800%", "MemoryMax=20G"]);
        assert_eq!(r.quota.as_deref(), Some("90G"));
    }

    #[test]
    fn rejects_bad_input() {
        for text in [
            "groups = a\n",                    // outside a section
            "[a]\n",                           // no groups
            "[a]\ngroups=a\ncolour=blue\n",    // unknown key
            "[a]\ngroups=a\npassword=maybe\n", // not yes/no
            "[a]\ngroups=a\nquota=lots\n",     // bad quota
            "[a]\ngroups=a\n[a]\ngroups=b\n",  // duplicate
            "[locked]\ngroups=a\n",            // reserved name
            "[a]\ngroups=a\nsshd=NoEquals\n",  // bad pair
        ] {
            assert!(parse(text, "f").is_err(), "should reject: {text:?}");
        }
    }
}
