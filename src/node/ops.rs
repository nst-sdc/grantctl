//! Node commands other than `apply`: facts, single-account operations, audit.

use super::apply::{slice_dir, SLICE_ROOT, STATE_DIR};
use super::system::{self, Grp, System, User};
use crate::desired::{LIMITS_DIR, LIMITS_FILE, SSHD_DIR, SSHD_MAIN_FILE, SSHD_MATCH_FILE};
use crate::desired::{SUDOERS_DIR, SUDOERS_FILE};
use crate::PROTOCOL;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------- facts

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountFact {
    pub user: String,
    pub uid: u32,
    pub home: String,
    pub locked: bool,
    pub has_password: bool,
    /// The password must be changed at the next login.
    pub must_change: bool,
    /// Number of keys in ~/.ssh/authorized_keys.
    pub keys: usize,
    pub sessions: usize,
    /// Supplementary groups.
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupFact {
    pub name: String,
    pub gid: u32,
    pub members: Vec<String>,
}

/// The current state of a node, as far as access is concerned. `init` and
/// `adopt` draft access.conf from it; `status` prints it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Facts {
    pub protocol: u32,
    pub host: String,
    /// Accounts of people (uid 1000 to 59999).
    pub accounts: Vec<AccountFact>,
    pub groups: Vec<GroupFact>,
    /// Users with their own rule in /etc/sudoers.d.
    pub sudo_users: Vec<String>,
    pub nopasswd_users: Vec<String>,
    /// Users named in AllowUsers.
    pub allow_users: Vec<String>,
    pub allow_groups: Vec<String>,
    /// Users forced to password-only SSH by a Match block.
    pub pwonly_users: Vec<String>,
    pub sshd_files: Vec<String>,
    pub sudoers_files: Vec<String>,
}

fn account_fact(sys: &dyn System, user: &User, groups: &[Grp]) -> AccountFact {
    let (hash, last_change, expire) = system::shadow(sys, &user.name).unwrap_or_default();
    let keys = sys
        .read(&format!("{}/.ssh/authorized_keys", user.home))
        .unwrap_or_default()
        .lines()
        .filter(|l| ["ssh-", "ecdsa-", "sk-"].iter().any(|p| l.starts_with(p)))
        .count();
    let sessions = sys
        .query(&["who"])
        .stdout
        .lines()
        .filter(|l| l.split_whitespace().next() == Some(user.name.as_str()))
        .count();
    AccountFact {
        user: user.name.clone(),
        uid: user.uid,
        home: user.home.clone(),
        locked: expire == "1",
        has_password: hash.trim_start_matches('!').len() > 1,
        must_change: last_change == "0",
        keys,
        sessions,
        groups: groups
            .iter()
            .filter(|g| g.members.contains(&user.name))
            .map(|g| g.name.clone())
            .collect(),
    }
}

/// Lines that are neither blank nor comments.
fn rules(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
}

pub fn facts(sys: &dyn System) -> Facts {
    let users = system::users(sys);
    let groups = system::groups(sys);
    let sudoers_files: Vec<String> = sys
        .list(SUDOERS_DIR)
        .into_iter()
        .filter(|n| n != "README")
        .collect();
    let (mut sudo_users, mut nopasswd_users) = (Vec::new(), Vec::new());
    for file in &sudoers_files {
        let text = sys
            .read(&format!("{SUDOERS_DIR}/{file}"))
            .unwrap_or_default();
        for line in rules(&text) {
            let who = line.split_whitespace().next().unwrap_or("");
            let is_user = !who.starts_with('%')
                && !who.starts_with('@')
                && who != "Defaults"
                && !who.ends_with("_Alias");
            if is_user && !sudo_users.contains(&who.to_string()) {
                sudo_users.push(who.to_string());
            }
            if is_user && line.contains("NOPASSWD") && !nopasswd_users.contains(&who.to_string()) {
                nopasswd_users.push(who.to_string());
            }
        }
    }
    // Match User a,b ... AuthenticationMethods password
    let mut pwonly_users = Vec::new();
    let mut matched: Vec<String> = Vec::new();
    for (_, line) in system::sshd_lines(sys) {
        let words: Vec<&str> = line.split_whitespace().collect();
        match words.as_slice() {
            [k, kind, list, ..] if k.eq_ignore_ascii_case("match") => {
                matched = if kind.eq_ignore_ascii_case("user") {
                    list.split(',').map(String::from).collect()
                } else {
                    Vec::new()
                };
            }
            [k, "password"] if k.eq_ignore_ascii_case("authenticationmethods") => {
                pwonly_users.append(&mut matched);
            }
            _ => {}
        }
    }
    Facts {
        protocol: PROTOCOL,
        host: system::hostname(sys),
        accounts: users
            .iter()
            .filter(|u| u.is_human())
            .map(|u| account_fact(sys, u, &groups))
            .collect(),
        groups: groups
            .iter()
            .map(|g| GroupFact {
                name: g.name.clone(),
                gid: g.gid,
                members: g.members.clone(),
            })
            .collect(),
        sudo_users,
        nopasswd_users,
        allow_users: system::sshd_values(sys, "AllowUsers")
            .iter()
            .map(|e| e.split('@').next().unwrap_or("").to_string())
            .collect(),
        allow_groups: system::sshd_values(sys, "AllowGroups"),
        pwonly_users,
        sshd_files: sys.list(SSHD_DIR),
        sudoers_files,
    }
}

// ---------------------------------------------------------------- one account

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountOp {
    Where,
    /// Set a temporary password and force a change at the next login.
    Passwd,
    Lock,
    Unlock,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountRequest {
    pub op: AccountOp,
    pub user: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// With `Delete`: also remove the home directory, slice limits and quota record.
    #[serde(default)]
    pub purge: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountReply {
    pub host: String,
    pub exists: bool,
    pub ok: bool,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fact: Option<AccountFact>,
}

pub fn account(sys: &mut dyn System, req: &AccountRequest) -> AccountReply {
    let host = system::hostname(sys);
    let users = system::users(sys);
    let Some(user) = users.iter().find(|u| u.name == req.user) else {
        return AccountReply {
            host,
            exists: false,
            ok: true,
            message: "no account".into(),
            fact: None,
        };
    };
    let name = user.name.as_str();
    let result: Result<String, String> = match req.op {
        AccountOp::Where => Ok(String::new()),
        AccountOp::Passwd => match &req.password {
            None => Err("no password given".into()),
            Some(password) => sys
                .run(&["chpasswd"], Some(&format!("{name}:{password}\n")))
                .and_then(|()| sys.run(&["chage", "-d", "0", name], None))
                .map(|()| "password set, change forced at next login".into()),
        },
        AccountOp::Lock => sys
            .run(&["usermod", "-L", "-e", "1", name], None)
            .map(|()| {
                let _ = sys.run(&["pkill", "-KILL", "-u", name], None);
                "locked, sessions ended".into()
            }),
        AccountOp::Unlock => sys.run(&["usermod", "-e", "", name], None).map(|()| {
            let _ = sys.run(&["usermod", "-U", name], None);
            "unlocked".into()
        }),
        AccountOp::Delete => delete(sys, user, req.purge),
    };
    let fact = match req.op {
        AccountOp::Delete => None,
        _ => Some(account_fact(sys, user, &system::groups(sys))),
    };
    AccountReply {
        host,
        exists: true,
        ok: result.is_ok(),
        message: result.unwrap_or_else(|e| e),
        fact,
    }
}

fn delete(sys: &mut dyn System, user: &User, purge: bool) -> Result<String, String> {
    let name = user.name.as_str();
    let _ = sys.run(&["pkill", "-KILL", "-u", name], None);
    let _ = sys.run(&["crontab", "-r", "-u", name], None);
    if !purge {
        sys.run(&["userdel", name], None)?;
        return Ok(format!("deleted (home kept: {})", user.home));
    }
    sys.run(&["userdel", "-r", name], None)
        .or_else(|_| sys.run(&["userdel", name], None))?;
    let _ = sys.run(&["rm", "-rf", &user.home], None);
    let _ = sys.run(&["rm", "-rf", &slice_dir(user.uid)], None);
    let quota = format!("{STATE_DIR}/quota");
    if let Some(state) = sys.read(&quota) {
        let kept: String = state
            .lines()
            .filter(|l| !l.starts_with(&format!("{name} ")))
            .map(|l| format!("{l}\n"))
            .collect();
        let _ = sys.write(&quota, &kept, 0o600);
    }
    Ok("deleted with home, slice limits and quota record".into())
}

// ---------------------------------------------------------------- audit

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRequest {
    /// Everyone in access.conf; empty before `init`.
    pub managed: Vec<String>,
    pub sudo_group: String,
    pub legacy_managers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// `warn` or `info`.
    pub level: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditReply {
    pub host: String,
    pub findings: Vec<Finding>,
    /// (user, uid) of every human account, to spot UIDs that differ between nodes.
    pub uids: Vec<(String, u32)>,
}

/// Files the distribution ships in limits.d.
const DISTRO_LIMITS: [&str; 4] = [
    "10-coredump-debian.conf",
    "20-coredump-debian.conf",
    "25-pw-rlimits.conf",
    "10-gamemode.conf",
];

/// Read-only report of auth-related settings grantctl does not manage.
pub fn audit(sys: &dyn System, req: &AuditRequest) -> AuditReply {
    let mut findings = Vec::new();
    let mut add = |level: &str, text: String| {
        findings.push(Finding {
            level: level.to_string(),
            text,
        })
    };
    let content = |path: &str| -> String {
        rules(&sys.read(path).unwrap_or_default())
            .map(|l| format!("\n      {l}"))
            .collect()
    };

    let os = sys
        .read("/etc/os-release")
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("PRETTY_NAME="))
        .map(|v| v.trim_matches('"').to_string())
        .unwrap_or_default();
    add(
        "info",
        format!("{os}, {}", sys.query(&["ssh", "-V"]).stderr.trim()),
    );

    let effective = sys.query(&["sshd", "-T"]).stdout;
    let keys = [
        "permitrootlogin",
        "passwordauthentication",
        "pubkeyauthentication",
        "maxauthtries",
        "x11forwarding",
        "allowtcpforwarding",
        "allowgroups",
    ];
    let shown: Vec<&str> = effective
        .lines()
        .filter(|l| keys.contains(&l.split(' ').next().unwrap_or("")))
        .collect();
    add("info", format!("sshd effective: {}", shown.join("; ")));
    let allow_users = effective
        .lines()
        .filter(|l| l.starts_with("allowusers "))
        .count();
    if allow_users > 0 {
        add(
            "warn",
            format!("sshd uses per-user AllowUsers ({allow_users} entries)"),
        );
    }
    for file in sys.list(SSHD_DIR) {
        let path = format!("{SSHD_DIR}/{file}");
        if file == SSHD_MAIN_FILE || file == SSHD_MATCH_FILE {
            continue;
        } else if file == "50-cloud-init.conf" {
            add(
                "info",
                format!("cloud-init drop-in {path}:{}", content(&path)),
            );
        } else {
            add(
                "warn",
                format!("foreign sshd file {path}:{}", content(&path)),
            );
        }
    }
    let main = sys.read(system::SSHD_CONFIG).unwrap_or_default();
    let permissive: Vec<&str> = rules(&main)
        .filter(|l| {
            let l = l.to_ascii_lowercase();
            (l.starts_with("permitrootlogin") || l.starts_with("passwordauthentication"))
                && l.ends_with("yes")
        })
        .collect();
    if !permissive.is_empty() {
        add(
            "info",
            format!(
                "main sshd_config has permissive lines (overridden by {SSHD_MAIN_FILE} when it is in place): {}",
                permissive.join("; ")
            ),
        );
    }
    let root_keys = rules(&sys.read("/root/.ssh/authorized_keys").unwrap_or_default()).count();
    if root_keys > 0 {
        add(
            "warn",
            format!("root has {root_keys} authorized_keys lines"),
        );
    }

    for file in sys.list(SUDOERS_DIR) {
        if file != "README" && file != SUDOERS_FILE {
            let path = format!("{SUDOERS_DIR}/{file}");
            add(
                "warn",
                format!("foreign sudoers file {path}:{}", content(&path)),
            );
        }
    }
    let sudo_rule = format!("%{}", req.sudo_group);
    for line in rules(&sys.read("/etc/sudoers").unwrap_or_default()) {
        let who = line.split_whitespace().next().unwrap_or("");
        let standard = ["Defaults", "root", "%admin", "@includedir", "#includedir"];
        if !standard.contains(&who) && who != sudo_rule {
            add("warn", format!("main sudoers extra rule: {line}"));
        }
    }

    for file in sys.list(LIMITS_DIR) {
        if file != LIMITS_FILE && !DISTRO_LIMITS.contains(&file.as_str()) {
            let path = format!("{LIMITS_DIR}/{file}");
            add(
                "warn",
                format!("foreign limits file {path}:{}", content(&path)),
            );
        }
    }
    let limits_conf = content("/etc/security/limits.conf");
    if !limits_conf.is_empty() {
        add("warn", format!("limits.conf has entries:{limits_conf}"));
    }
    for dir in sys.list(SLICE_ROOT) {
        if !(dir.starts_with("user-") && dir.ends_with(".slice.d")) {
            continue;
        }
        for file in sys.list(&format!("{SLICE_ROOT}/{dir}")) {
            let path = format!("{SLICE_ROOT}/{dir}/{file}");
            let ours = sys
                .read(&path)
                .is_some_and(|t| t.contains("managed by grantctl"));
            if !ours {
                add("warn", format!("foreign slice limits {path}"));
            }
        }
    }

    let pam: String = sys
        .list("/etc/pam.d")
        .iter()
        .filter_map(|f| sys.read(&format!("/etc/pam.d/{f}")))
        .collect();
    let common_auth = sys.read("/etc/pam.d/common-auth").unwrap_or_default();
    if rules(&common_auth).any(|l| l.contains("pam_unix.so") && l.contains("nullok")) {
        add(
            "warn",
            "PAM common-auth allows empty passwords (nullok)".into(),
        );
    }
    if !pam.contains("pam_faillock") {
        add(
            "info",
            "no pam_faillock: no lockout after failed logins".into(),
        );
    }
    if !pam.contains("pam_pwquality") {
        add(
            "info",
            "no pam_pwquality: only basic password checks".into(),
        );
    }
    if !sys
        .query(&["systemctl", "is-active", "--quiet", "fail2ban"])
        .ok
    {
        add("info", "fail2ban is not active".into());
    }

    let users = system::users(sys);
    for u in users.iter().filter(|u| u.uid == 0 && u.name != "root") {
        add("warn", format!("uid 0 account: {}", u.name));
    }
    for line in sys.query(&["getent", "shadow"]).stdout.lines() {
        let mut fields = line.split(':');
        if let (Some(name), Some("")) = (fields.next(), fields.next()) {
            add("warn", format!("empty password: {name}"));
        }
    }
    let groups = system::groups(sys);
    let privileged = [
        req.sudo_group.as_str(),
        "adm",
        "wheel",
        "docker",
        "lxd",
        "libvirt",
        "kvm",
        "disk",
        "shadow",
    ];
    for g in groups
        .iter()
        .filter(|g| privileged.contains(&g.name.as_str()))
    {
        if !g.members.is_empty() {
            add("info", format!("group {}: {}", g.name, g.members.join(",")));
        }
    }
    let find = [
        "find",
        "/usr/local/bin",
        "/usr/local/sbin",
        "-maxdepth",
        "1",
        "!",
        "-user",
        "root",
        "-printf",
        "%p (owner %u)\\n",
    ];
    for line in sys.query(&find).stdout.lines() {
        add("warn", format!("not root-owned in root's PATH: {line}"));
    }
    for script in &req.legacy_managers {
        for dir in ["/usr/local/sbin", "/usr/local/bin", "/root"] {
            let path = format!("{dir}/{script}");
            if sys.query(&["test", "-e", &path]).ok {
                add("warn", format!("legacy manager present: {path}"));
            }
        }
    }
    let humans: Vec<&User> = users.iter().filter(|u| u.is_human()).collect();
    if !req.managed.is_empty() {
        for u in humans.iter().filter(|u| !req.managed.contains(&u.name)) {
            add("warn", format!("unmanaged account: {}", u.name));
        }
    }
    AuditReply {
        host: system::hostname(sys),
        uids: humans.iter().map(|u| (u.name.clone(), u.uid)).collect(),
        findings,
    }
}
