//! The control side: commands the operator runs on the control node.

pub mod draft;
pub mod transport;

use crate::config::{Config, Token};
use crate::desired::{self, Hints};
use crate::node::ops::{AccountOp, AccountReply, AccountRequest, AuditReply, AuditRequest, Facts};
use crate::node::ops::{HashesReply, HashesRequest};
use crate::node::{Action, Report, Status, Version};
use crate::{edit, validate, Error, Result, PROTOCOL};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use transport::{CallError, Transport};

pub const PPA: &str = "ppa:nst-sdc/grantctl";

pub struct Ctx<'a> {
    /// Configuration directory.
    pub dir: PathBuf,
    pub transport: &'a dyn Transport,
    /// The person running grantctl.
    pub operator: String,
    pub out: &'a mut dyn Write,
    /// Answer yes to confirmation prompts.
    pub yes: bool,
}

macro_rules! say {
    ($ctx:expr, $($arg:tt)*) => {{
        let _ = writeln!($ctx.out, $($arg)*);
    }};
}

// ---------------------------------------------------------------- helpers

fn load_valid(ctx: &Ctx) -> Result<Config> {
    let cfg = Config::load(&ctx.dir)?;
    let problems = validate::validate(&cfg, &ctx.operator);
    if problems.is_empty() {
        Ok(cfg)
    } else {
        Err(Error::Invalid(problems))
    }
}

/// Nodes to work on, control node first.
fn targets(cfg: &Config, nodes: &[String]) -> Result<Vec<String>> {
    let mut list = if nodes.is_empty() {
        cfg.nodes.clone()
    } else {
        nodes
            .iter()
            .map(|n| cfg.resolve_node(n))
            .collect::<Result<Vec<_>>>()?
    };
    list.sort_by_key(|n| n != cfg.control());
    Ok(list)
}

fn on_nodes(cfg: &Config, on: &Option<String>) -> Result<Option<Vec<String>>> {
    on.as_ref()
        .map(|list| {
            list.split(',')
                .filter(|n| !n.is_empty())
                .map(|n| cfg.resolve_node(n))
                .collect::<Result<Vec<_>>>()
        })
        .transpose()
}

/// Tokens from the command line, with short node names expanded.
fn parse_tokens(cfg: &Config, words: &[String]) -> Result<Vec<Token>> {
    words
        .iter()
        .map(|w| {
            let mut token = Token::parse(w);
            if let Some(scope) = &mut token.scope {
                for node in scope.iter_mut() {
                    *node = cfg.resolve_node(node)?;
                }
            }
            Ok(token)
        })
        .collect()
}

/// Facts about the control node that the desired state depends on.
fn hints(ctx: &Ctx, cfg: &Config) -> Hints {
    let t = ctx.transport;
    let mut hints = Hints::default();
    let route = t
        .local(&["ip", "route", "show", "default"])
        .unwrap_or_default();
    if let Some(dev) = route.split_whitespace().skip_while(|w| *w != "dev").nth(1) {
        let addrs = t
            .local(&["ip", "-o", "addr", "show", "dev", dev, "scope", "global"])
            .unwrap_or_default();
        hints.control_ips = addrs
            .lines()
            .filter_map(|l| l.split_whitespace().nth(3))
            .filter_map(|a| a.split('/').next())
            .map(String::from)
            .collect();
    }
    let ids = |argv: &[&str]| -> BTreeMap<String, u32> {
        t.local(argv)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| {
                let mut f = l.split(':');
                Some((f.next()?.to_string(), f.nth(1)?.parse().ok()?))
            })
            .collect()
    };
    let managed: BTreeSet<&str> = cfg.access.entries().map(|e| e.user.as_str()).collect();
    hints.uids = ids(&["getent", "passwd"]);
    hints.uids.retain(|user, _| managed.contains(user.as_str()));
    let groups = cfg.managed_groups();
    hints.gids = ids(&["getent", "group"]);
    hints.gids.retain(|group, _| groups.contains(group));
    hints
}

/// Call a node command and decode its JSON answer.
fn call<T: DeserializeOwned>(
    ctx: &Ctx,
    node: &str,
    args: &[&str],
    input: &impl Serialize,
) -> std::result::Result<T, CallError> {
    let stdin = serde_json::to_string(input).map_err(|e| CallError::Failed(e.to_string()))?;
    let text = ctx.transport.node(node, args, &stdin)?;
    serde_json::from_str(&text)
        .map_err(|e| CallError::Failed(format!("unexpected answer from the node: {e}")))
}

/// Is grantctl on the node, reachable, and speaking our protocol?
fn ready(ctx: &mut Ctx, node: &str) -> bool {
    match call::<Version>(ctx, node, &["version"], &()) {
        Ok(v) if v.protocol == PROTOCOL => true,
        Ok(v) => {
            say!(ctx, "[{node}] grantctl {} speaks protocol {}, this side speaks {PROTOCOL}. Run: grantctl node install {node}", v.version, v.protocol);
            false
        }
        Err(CallError::Unreachable(_)) => {
            say!(ctx, "[{node}] UNREACHABLE, skipped");
            false
        }
        Err(CallError::NotInstalled) => {
            say!(
                ctx,
                "[{node}] grantctl is not installed there. Run: grantctl node install {node}"
            );
            false
        }
        Err(CallError::Failed(e)) => {
            say!(ctx, "[{node}] FAILED: {e}");
            false
        }
    }
}

fn today(ctx: &Ctx) -> String {
    ctx.transport
        .local(&["date", "+%F"])
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// A temporary password: 14 characters, no look-alikes, from the kernel's RNG.
fn temp_password() -> Result<String> {
    const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let path = Path::new("/dev/urandom");
    let io = |source| Error::Io {
        path: path.to_path_buf(),
        source,
    };
    let mut file = std::fs::File::open(path).map_err(io)?;
    let mut password = String::new();
    let limit = (256 / CHARS.len() * CHARS.len()) as u8;
    while password.len() < 14 {
        let mut buf = [0u8; 32];
        file.read_exact(&mut buf).map_err(io)?;
        for byte in buf.into_iter().filter(|b| *b < limit) {
            if password.len() < 14 {
                password.push(CHARS[byte as usize % CHARS.len()] as char);
            }
        }
    }
    Ok(password)
}

/// Write a configuration file. /etc/grantctl belongs to root, so fall back
/// to `sudo install` when a direct write is refused.
fn write_file(path: &Path, content: &str) -> Result<()> {
    let io = |source| Error::Io {
        path: path.to_path_buf(),
        source,
    };
    let dir = path.parent().unwrap_or(Path::new("/"));
    let direct = std::fs::create_dir_all(dir).and_then(|()| {
        let tmp = path.with_extension("grantctl-tmp");
        std::fs::write(&tmp, content)?;
        std::fs::rename(&tmp, path)
    });
    match direct {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            let tmp = std::env::temp_dir().join(format!("grantctl-{}.tmp", std::process::id()));
            std::fs::write(&tmp, content).map_err(io)?;
            let ok = Command::new("sudo")
                .args(["install", "-D", "-m", "0644"])
                .arg(&tmp)
                .arg(path)
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            let _ = std::fs::remove_file(&tmp);
            if ok {
                Ok(())
            } else {
                Err(Error::msg(format!("cannot write {}", path.display())))
            }
        }
        Err(e) => Err(io(e)),
    }
}

/// Lines to remove (`- `) and to add (`+ `) to get from `old` to `new`.
fn diff(old: &str, new: &str) -> Vec<String> {
    let (a, b): (Vec<&str>, Vec<&str>) = (old.lines().collect(), new.lines().collect());
    let mut lcs = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let (mut i, mut j) = (0, 0);
    let mut out = Vec::new();
    while i < a.len() && j < b.len() {
        if a[i] == b[j] {
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            out.push(format!("- {}", a[i]));
            i += 1;
        } else {
            out.push(format!("+ {}", b[j]));
            j += 1;
        }
    }
    out.extend(a[i..].iter().map(|l| format!("- {l}")));
    out.extend(b[j..].iter().map(|l| format!("+ {l}")));
    out
}

fn describe(action: &Action) -> String {
    let id =
        |label: &str, id: &Option<u32>| id.map(|n| format!(", {label} {n}")).unwrap_or_default();
    match action {
        Action::CreateGroup { group, gid } => format!("create group {group}{}", id("gid", gid)),
        Action::CreateUser { user, home, uid } => {
            format!("create account {user} (home {home}{})", id("uid", uid))
        }
        Action::AddMember { user, group } => format!("add {user} to {group}"),
        Action::Unlock { user } => format!("unlock {user}"),
        Action::Password { user } => {
            format!("set the password of {user} to the one on the control node")
        }
        Action::Install { path, .. } => format!("install {path}"),
        Action::Remove { path, .. } => format!("remove {path}"),
        Action::RemoveMember { user, group } => format!("remove {user} from {group}"),
        Action::Lock { user } => format!("lock {user} (ends their sessions)"),
        Action::Slice { user, settings } => {
            format!("slice limits {user}: {}", settings.join(" "))
        }
        Action::Quota { user, size, base } => format!("quota {user}: {size} on {base}"),
    }
}

fn render(ctx: &mut Ctx, node: &str, r: &Report) {
    if !r.ssh_lose.is_empty() {
        say!(ctx, "[{node}] SSH lose: {}", r.ssh_lose.join(" "));
    }
    if !r.ssh_gain.is_empty() {
        say!(ctx, "[{node}] SSH gain: {}", r.ssh_gain.join(" "));
    }
    for step in &r.steps {
        let what = describe(&step.action);
        match step.status {
            Status::Planned => say!(ctx, "[{node}] would: {what}"),
            Status::Done => say!(ctx, "[{node}] {what}"),
            Status::Skipped => say!(ctx, "[{node}] skipped: {what}"),
            Status::Failed => say!(
                ctx,
                "[{node}] FAILED: {what}{}",
                step.error
                    .as_ref()
                    .map(|e| format!(": {e}"))
                    .unwrap_or_default()
            ),
        }
        if step.status != Status::Planned {
            continue;
        }
        // A dry run shows what would change inside the files.
        let lines = match &step.action {
            Action::Install { old, new, .. } => diff(old.as_deref().unwrap_or(""), new),
            Action::Remove { old: Some(old), .. } => diff(old, ""),
            _ => Vec::new(),
        };
        for line in lines {
            say!(ctx, "[{node}]     {line}");
        }
    }
    for w in &r.warnings {
        say!(ctx, "[{node}] WARN {w}");
    }
    if !r.unmanaged.is_empty() {
        say!(
            ctx,
            "[{node}] UNMANAGED accounts (not in access.conf): {} -> grantctl adopt <user>",
            r.unmanaged.join(" ")
        );
    }
    if !r.stray.is_empty() {
        say!(
            ctx,
            "[{node}] STRAY accounts (no access here, not locked): {} -> grantctl prune",
            r.stray.join(" ")
        );
    }
    if let Some(backup) = &r.backup {
        say!(ctx, "[{node}] backup: {backup}");
    }
    match (&r.error, r.dry_run, r.steps.is_empty()) {
        (Some(e), _, _) => say!(ctx, "[{node}] FAILED: {e}"),
        (None, true, false) => say!(ctx, "[{node}] {} changes pending", r.steps.len()),
        _ => say!(ctx, "[{node}] in sync"),
    }
}

// ---------------------------------------------------------------- sync

/// The usable password hashes on the control node. The other nodes follow
/// them: one password everywhere, unless the user changed it on a node.
fn control_passwords(
    ctx: &mut Ctx,
    control: &str,
    users: &[String],
) -> BTreeMap<String, (String, String)> {
    let request = HashesRequest {
        users: users.to_vec(),
    };
    match call::<HashesReply>(ctx, control, &["hashes"], &request) {
        Ok(reply) => reply
            .passwords
            .into_iter()
            .map(|p| (p.user, (p.hash, p.last_change)))
            .collect(),
        Err(e) => {
            say!(
                ctx,
                "[{control}] WARN cannot read the passwords to copy: {e}"
            );
            BTreeMap::new()
        }
    }
}

fn set_temp_password(ctx: &mut Ctx, node: &str, user: &str, password: &str) -> bool {
    let mut request = AccountRequest::new(AccountOp::Passwd, user);
    request.password = Some(password.to_string());
    request.must_change = true;
    match call::<AccountReply>(ctx, node, &["account"], &request) {
        Ok(reply) if reply.ok => true,
        Ok(reply) => {
            say!(
                ctx,
                "[{node}] FAILED: password for {user}: {}",
                reply.message
            );
            false
        }
        Err(e) => {
            say!(ctx, "[{node}] FAILED: password for {user}: {e}");
            false
        }
    }
}

/// Make nodes match access.conf. Returns `false` when a node was skipped or
/// failed; the others are still synced.
pub fn sync(ctx: &mut Ctx, nodes: &[String], dry_run: bool) -> Result<bool> {
    let cfg = load_valid(ctx)?;
    let mut hints = hints(ctx, &cfg);
    let control = cfg.control().to_string();
    let users: Vec<String> = cfg.access.entries().map(|e| e.user.clone()).collect();
    // Who is entitled to an account on the control node.
    let on_control: BTreeSet<String> = desired::build(&cfg, &control, &ctx.operator, &hints)?
        .accounts
        .into_iter()
        .map(|a| a.user)
        .collect();
    let mut temporary: Vec<(String, String)> = Vec::new();
    // Accounts created on other nodes with no password to copy: user -> nodes.
    let mut without: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut failed: Vec<String> = Vec::new();
    let mut have_passwords = false;

    for node in targets(&cfg, nodes)? {
        say!(ctx, "===== {node}");
        if !ready(ctx, &node) {
            failed.push(node);
            continue;
        }
        if node != control && !have_passwords {
            // Read after the control node was synced, so that accounts
            // created there in this run are included.
            hints.passwords = control_passwords(ctx, &control, &users);
            have_passwords = true;
        }
        let state = desired::build(&cfg, &node, &ctx.operator, &hints)?;
        let args: &[&str] = if dry_run {
            &["apply", "--dry-run"]
        } else {
            &["apply"]
        };
        let report: Report = match call(ctx, &node, args, &state) {
            Ok(report) => report,
            Err(e) => {
                say!(ctx, "[{node}] FAILED: {e}");
                failed.push(node);
                continue;
            }
        };
        render(ctx, &node, &report);
        if !report.ok {
            failed.push(node);
            continue;
        }
        if dry_run {
            continue;
        }
        for user in &report.created {
            if node == control {
                // New on the control node: a temporary password here. The
                // other nodes copy it, so it is the same everywhere.
                let password = temp_password()?;
                if set_temp_password(ctx, &node, user, &password) {
                    temporary.push((user.clone(), password));
                }
            } else if !hints.passwords.contains_key(user) {
                without.entry(user.clone()).or_default().push(node.clone());
            }
        }
    }

    let mut notes: Vec<String> = Vec::new();
    for (user, on) in &without {
        if on_control.contains(user) {
            notes.push(format!(
                "{user}: the new account on {} has no password, because there is none to copy from {control} yet. Sync {control} first, or run: grantctl passwd {user}",
                on.join(", ")
            ));
            continue;
        }
        // No account on the control node to follow: one temporary password
        // for all of the user's new nodes.
        let password = temp_password()?;
        let mut set = false;
        for node in on {
            set |= set_temp_password(ctx, node, user, &password);
        }
        if set {
            temporary.push((user.clone(), password));
        }
    }
    if !temporary.is_empty() {
        say!(ctx, "");
        say!(ctx, "Temporary passwords (the same on every node of the user, change forced at first login; share privately):");
        for (user, password) in &temporary {
            say!(ctx, "  {user:<16} {password}");
        }
    }
    for note in notes {
        say!(ctx, "{note}");
    }
    if !failed.is_empty() {
        say!(ctx, "");
        say!(
            ctx,
            "NOT synced: {}  -> later: grantctl sync {}",
            failed.join(" "),
            failed.join(" ")
        );
    }
    Ok(failed.is_empty())
}

// ---------------------------------------------------------------- editing access.conf

/// Validate the edited roster, then write it. An edit that would break the
/// configuration never reaches the disk.
fn commit(ctx: &mut Ctx, cfg: &Config, user: &str) -> Result<()> {
    let problems = validate::validate(cfg, &ctx.operator);
    if !problems.is_empty() {
        return Err(Error::Invalid(problems));
    }
    write_file(&ctx.dir.join("access.conf"), &cfg.access.render())?;
    match cfg.access.get(user) {
        Some(entry) => say!(ctx, "access.conf: {} {}", entry.user, entry.tokens_text()),
        None => say!(ctx, "access.conf: {user} removed"),
    }
    Ok(())
}

pub fn grant(
    ctx: &mut Ctx,
    user: &str,
    words: &[String],
    on: &Option<String>,
    sync_after: bool,
) -> Result<bool> {
    let mut cfg = Config::load(&ctx.dir)?;
    let tokens = parse_tokens(&cfg, words)?;
    let on = on_nodes(&cfg, on)?;
    let stamp = format!("{} by {}", today(ctx), ctx.operator);
    let mut access = cfg.access.clone();
    edit::grant(&cfg, &mut access, user, &tokens, on.as_deref(), &stamp)?;
    cfg.access = access;
    commit(ctx, &cfg, user)?;
    if sync_after {
        sync(ctx, &[], false)
    } else {
        Ok(true)
    }
}

pub fn revoke(
    ctx: &mut Ctx,
    user: &str,
    words: &[String],
    on: &Option<String>,
    sync_after: bool,
) -> Result<bool> {
    let mut cfg = Config::load(&ctx.dir)?;
    let tokens = parse_tokens(&cfg, words)?;
    let on = on_nodes(&cfg, on)?;
    let mut access = cfg.access.clone();
    edit::revoke(&cfg, &mut access, user, &tokens, on.as_deref())?;
    cfg.access = access;
    commit(ctx, &cfg, user)?;
    if sync_after {
        sync(ctx, &[], false)
    } else {
        Ok(true)
    }
}

/// Lock or unlock. A user in access.conf gets or loses the `locked` flag;
/// any other account is locked directly on the nodes.
pub fn lock(
    ctx: &mut Ctx,
    user: &str,
    locked: bool,
    on: &Option<String>,
    sync_after: bool,
) -> Result<bool> {
    let cfg = Config::load(&ctx.dir)?;
    if cfg.access.get(user).is_some() {
        let flag = ["locked".to_string()];
        return if locked {
            grant(ctx, user, &flag, on, sync_after)
        } else {
            revoke(ctx, user, &flag, on, sync_after)
        };
    }
    if user == ctx.operator {
        return Err(Error::msg("refusing to lock yourself"));
    }
    say!(
        ctx,
        "{user} is not in access.conf: applying directly (adopt the user to make it permanent)"
    );
    let nodes = on_nodes(&cfg, on)?.unwrap_or_default();
    let op = if locked {
        AccountOp::Lock
    } else {
        AccountOp::Unlock
    };
    account_everywhere(ctx, &cfg, &nodes, &AccountRequest::new(op, user))
}

// ---------------------------------------------------------------- single accounts

fn show(reply: &AccountReply) -> String {
    let Some(f) = &reply.fact else {
        return reply.message.clone();
    };
    let state = format!(
        "uid={} {} {}{} keys={} sessions={} home={} groups={}",
        f.uid,
        if f.locked { "LOCKED" } else { "active" },
        if f.has_password {
            "password"
        } else {
            "no-password"
        },
        if f.must_change { "(must-change)" } else { "" },
        f.keys,
        f.sessions,
        f.home,
        f.groups.join(",")
    );
    if reply.message.is_empty() {
        state
    } else {
        format!("{}; {state}", reply.message)
    }
}

/// Run one account operation on the given nodes (all when empty).
/// Returns `false` when a node could not be reached or the operation failed.
fn account_everywhere(
    ctx: &mut Ctx,
    cfg: &Config,
    nodes: &[String],
    request: &AccountRequest,
) -> Result<bool> {
    let mut all_ok = true;
    for node in targets(cfg, nodes)? {
        match call::<AccountReply>(ctx, &node, &["account"], request) {
            Ok(reply) => {
                all_ok &= reply.ok;
                say!(ctx, "[{node}] {}", show(&reply));
            }
            Err(e) => {
                all_ok = false;
                say!(ctx, "[{node}] {e} (rerun later)");
            }
        }
    }
    Ok(all_ok)
}

pub fn where_(ctx: &mut Ctx, user: &str) -> Result<bool> {
    let cfg = Config::load(&ctx.dir)?;
    match cfg.access.get(user) {
        Some(entry) => say!(ctx, "access.conf: {} {}", entry.user, entry.tokens_text()),
        None => say!(ctx, "access.conf: (not listed)"),
    }
    account_everywhere(ctx, &cfg, &[], &AccountRequest::new(AccountOp::Where, user))
}

/// Give a user a new password on all (or the given) nodes.
///
/// Default: one new temporary password, change forced at next login.
/// `from_control`: copy the password the user has on the control node to
/// the other nodes instead, for a user whose passwords have drifted apart.
pub fn passwd(ctx: &mut Ctx, user: &str, on: &Option<String>, from_control: bool) -> Result<bool> {
    let cfg = Config::load(&ctx.dir)?;
    let control = cfg.control().to_string();
    let nodes = on_nodes(&cfg, on)?.unwrap_or_else(|| cfg.nodes.clone());
    let mut request = AccountRequest::new(AccountOp::Passwd, user);
    if from_control {
        let Some((hash, last_change)) =
            control_passwords(ctx, &control, &[user.to_string()]).remove(user)
        else {
            return Err(Error::msg(format!(
                "{user} has no usable password on {control}"
            )));
        };
        request.hash = Some(hash);
        request.must_change = last_change == "0";
        let others: Vec<String> = nodes.into_iter().filter(|n| *n != control).collect();
        if others.is_empty() {
            return Err(Error::msg(
                "nothing to do: --from-control copies to nodes other than the control node",
            ));
        }
        return account_everywhere(ctx, &cfg, &others, &request);
    }
    let password = temp_password()?;
    request.password = Some(password.clone());
    request.must_change = true;
    let ok = account_everywhere(ctx, &cfg, &nodes, &request)?;
    say!(ctx, "");
    say!(
        ctx,
        "Temporary password for {user}: {password}   (change forced at next login)"
    );
    Ok(ok)
}

pub fn delete(ctx: &mut Ctx, user: &str, purge: bool) -> Result<bool> {
    let mut cfg = Config::load(&ctx.dir)?;
    if user == ctx.operator {
        return Err(Error::msg("refusing to delete yourself"));
    }
    if !ctx.yes {
        let extra = if purge {
            " INCLUDING home, slice limits and quota"
        } else {
            ""
        };
        let _ = write!(
            ctx.out,
            "Delete account {user} on ALL nodes{extra}? Type the username: "
        );
        let _ = ctx.out.flush();
        let mut answer = String::new();
        let _ = std::io::stdin().read_line(&mut answer);
        if answer.trim() != user {
            return Err(Error::msg("aborted"));
        }
    }
    if cfg.access.get(user).is_some() {
        cfg.access.remove(user);
        commit(ctx, &cfg, user)?;
    }
    let mut request = AccountRequest::new(AccountOp::Delete, user);
    request.purge = purge;
    account_everywhere(ctx, &cfg, &[], &request)
}

/// Lock accounts that exist on a node where the user has no access.
pub fn prune(ctx: &mut Ctx, dry_run: bool) -> Result<bool> {
    let cfg = load_valid(ctx)?;
    let hints = hints(ctx, &cfg);
    let mut all_ok = true;
    for node in targets(&cfg, &[])? {
        if !ready(ctx, &node) {
            all_ok = false;
            continue;
        }
        let state = desired::build(&cfg, &node, &ctx.operator, &hints)?;
        let facts: Facts = match call(ctx, &node, &["facts"], &()) {
            Ok(facts) => facts,
            Err(e) => {
                say!(ctx, "[{node}] FAILED: {e}");
                all_ok = false;
                continue;
            }
        };
        let wanted: BTreeSet<&str> = state.accounts.iter().map(|a| a.user.as_str()).collect();
        let strays: Vec<String> = facts
            .accounts
            .iter()
            .filter(|a| !a.locked && a.user != ctx.operator)
            .filter(|a| cfg.access.get(&a.user).is_some() && !wanted.contains(a.user.as_str()))
            .map(|a| a.user.clone())
            .collect();
        for user in strays {
            if dry_run {
                say!(ctx, "[{node}] would lock stray {user}");
                continue;
            }
            let request = AccountRequest::new(AccountOp::Lock, &user);
            match call::<AccountReply>(ctx, &node, &["account"], &request) {
                Ok(reply) => say!(ctx, "[{node}] {user}: {}", reply.message),
                Err(e) => {
                    say!(ctx, "[{node}] FAILED: {user}: {e}");
                    all_ok = false;
                }
            }
        }
    }
    Ok(all_ok)
}

// ---------------------------------------------------------------- reports

pub fn status(ctx: &mut Ctx, nodes: &[String]) -> Result<bool> {
    let cfg = Config::load(&ctx.dir)?;
    let mut shown: BTreeSet<String> = cfg.managed_groups().into_iter().collect();
    shown.insert(cfg.site.sudo_group.clone());
    let mut all_ok = true;
    for node in targets(&cfg, nodes)? {
        match call::<Facts>(ctx, &node, &["facts"], &()) {
            Ok(facts) => {
                for g in facts.groups.iter().filter(|g| shown.contains(&g.name)) {
                    say!(ctx, "[{node}] {}: {}", g.name, g.members.join(","));
                }
                say!(
                    ctx,
                    "[{node}] sshd_config.d: {}",
                    facts.sshd_files.join(" ")
                );
                say!(ctx, "[{node}] sudoers.d: {}", facts.sudoers_files.join(" "));
            }
            Err(e) => {
                say!(ctx, "[{node}] {e}");
                all_ok = false;
            }
        }
    }
    Ok(all_ok)
}

pub fn audit(ctx: &mut Ctx, nodes: &[String]) -> Result<bool> {
    let cfg = Config::load(&ctx.dir)?;
    let request = AuditRequest {
        managed: cfg.access.entries().map(|e| e.user.clone()).collect(),
        sudo_group: cfg.site.sudo_group.clone(),
        legacy_managers: cfg.site.legacy_managers.clone(),
    };
    let mut uids: BTreeMap<String, Vec<(String, u32)>> = BTreeMap::new();
    let mut all_ok = true;
    for node in targets(&cfg, nodes)? {
        say!(ctx, "===== {node}");
        match call::<AuditReply>(ctx, &node, &["audit"], &request) {
            Ok(reply) => {
                for f in &reply.findings {
                    let level = if f.level == "warn" { "WARN" } else { "info" };
                    say!(ctx, "[{node}] {level} {}", f.text);
                }
                for (user, uid) in reply.uids {
                    uids.entry(user).or_default().push((node.clone(), uid));
                }
            }
            Err(e) => {
                say!(ctx, "[{node}] {e}");
                all_ok = false;
            }
        }
    }
    say!(ctx, "===== cluster");
    for (user, seen) in &uids {
        if seen.iter().any(|(_, uid)| *uid != seen[0].1) {
            let list: Vec<String> = seen.iter().map(|(n, uid)| format!("{n}={uid}")).collect();
            say!(
                ctx,
                "[cluster] info uid differs for {user}: {}",
                list.join(" ")
            );
        }
    }
    Ok(all_ok)
}

// ---------------------------------------------------------------- init, adopt

/// Facts from every reachable node, in nodes-file order.
fn inventory(ctx: &mut Ctx, cfg: &Config) -> Result<Vec<(String, Facts)>> {
    let mut all = Vec::new();
    for node in targets(cfg, &[])? {
        if !ready(ctx, &node) {
            continue;
        }
        match call::<Facts>(ctx, &node, &["facts"], &()) {
            Ok(facts) => all.push((node, facts)),
            Err(e) => say!(ctx, "[{node}] FAILED: {e}"),
        }
    }
    Ok(all)
}

/// One-time setup. With node names: write the configuration files and draft
/// access.conf from the current state of the nodes. With `from_cockpit`:
/// copy an nst-cockpit (v1) configuration directory instead.
pub fn init(ctx: &mut Ctx, nodes: &[String], from_cockpit: Option<&Path>) -> Result<()> {
    let dir = ctx.dir.clone();
    let access = dir.join("access.conf");
    if access.exists() {
        return Err(Error::msg(format!(
            "{} already exists. Edit it, or adopt single users with: grantctl adopt <user>",
            access.display()
        )));
    }
    if let Some(source) = from_cockpit {
        let files = [
            ("nodes", "nodes"),
            ("roles.ini", "roles.ini"),
            ("access.conf", "access.conf"),
            ("sshd-baseline", "sshd-baseline"),
            ("cockpit.conf", "grantctl.conf"),
        ];
        for (from, to) in files {
            let path = source.join(from);
            if let Ok(text) = std::fs::read_to_string(&path) {
                write_file(&dir.join(to), &text)?;
                say!(
                    ctx,
                    "copied {} -> {}",
                    path.display(),
                    dir.join(to).display()
                );
            }
        }
        Config::load(&dir)?;
        say!(
            ctx,
            "Imported. Next: grantctl check ; grantctl sync --dry-run"
        );
        return Ok(());
    }

    let nodes_file = dir.join("nodes");
    if !nodes_file.exists() {
        if nodes.is_empty() {
            return Err(Error::msg(
                "usage: grantctl init <control-node> [node...]   (control node first; run it there)",
            ));
        }
        write_file(&nodes_file, &format!("{}\n", nodes.join("\n")))?;
    }
    let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap_or_default();
    let node_list = crate::config::parse_nodes(&read("nodes"));
    let control = node_list.first().cloned().unwrap_or_default();
    if !dir.join("grantctl.conf").exists() {
        let text = format!(
            "# grantctl site settings (KEY=VALUE). See: man grantctl\nCONTROL={control}\nSUDO_GROUP=sudo\nSHELL_ROLE=user\n\
             #LEGACY_SSHD=\"00-old-lockdown.conf\"       # sshd_config.d files to replace\n\
             #LEGACY_SUDO=\"90-old-admins\"              # sudoers.d files to replace\n\
             #LEGACY_LIMITS=\"\"\n#LEGACY_SLICE_MARKER=\"managed by old-tool\"\n#LEGACY_MANAGERS=\"old-adduser.sh\"\n"
        );
        write_file(&dir.join("grantctl.conf"), &text)?;
    }
    if !dir.join("roles.ini").exists() {
        write_file(&dir.join("roles.ini"), crate::config::roles::DEFAULT_ROLES)?;
    }
    if !dir.join("sshd-baseline").exists() {
        let text = format!(
            "# global sshd settings written to every node\n{}",
            crate::config::DEFAULT_BASELINE
        );
        write_file(&dir.join("sshd-baseline"), &text)?;
    }
    let cfg = Config::from_strs(
        &read("nodes"),
        &read("roles.ini"),
        "",
        &read("grantctl.conf"),
    )?;
    let facts = inventory(ctx, &cfg)?;
    let lines = draft::draft(&cfg, &facts, None);
    let reviews = lines.iter().filter(|l| l.contains(" review")).count();
    write_file(
        &access,
        &format!("{}{}\n", draft::DRAFT_HEADER, lines.join("\n")),
    )?;
    say!(
        ctx,
        "Draft: {} ({} users, {reviews} need review)",
        access.display(),
        lines.len()
    );
    say!(
        ctx,
        "Roles: {}. If you change them: remove access.conf and run grantctl init again.",
        dir.join("roles.ini").display()
    );
    say!(
        ctx,
        "Next: edit access.conf, then: grantctl check ; grantctl sync --dry-run"
    );
    Ok(())
}

/// Add an existing account to access.conf, drafted from its current state.
pub fn adopt(ctx: &mut Ctx, user: &str) -> Result<bool> {
    let cfg = Config::load(&ctx.dir)?;
    if cfg.access.get(user).is_some() {
        return Err(Error::msg(format!("{user} is already in access.conf")));
    }
    let facts = inventory(ctx, &cfg)?;
    let lines = draft::draft(&cfg, &facts, Some(user));
    let Some(line) = lines.first() else {
        return Err(Error::msg(format!(
            "{user} has no account on any reachable node"
        )));
    };
    say!(ctx, "{line}");
    if !ctx.yes {
        let _ = write!(ctx.out, "Append this line to access.conf? [y/N] ");
        let _ = ctx.out.flush();
        let mut answer = String::new();
        let _ = std::io::stdin().read_line(&mut answer);
        if answer.trim() != "y" {
            return Err(Error::msg("aborted"));
        }
    }
    let text = format!("{}{line}\n", cfg.access.render());
    write_file(&ctx.dir.join("access.conf"), &text)?;
    if line.contains(" review") {
        say!(ctx, "Resolve 'review' in access.conf, then: grantctl sync");
        return Ok(true);
    }
    sync(ctx, &[], false)
}

// ---------------------------------------------------------------- installing grantctl on nodes

/// Install grantctl on hosts over SSH: from the PPA, or by copying this
/// binary (`copy`), for hosts without internet access.
pub fn node_install(ctx: &mut Ctx, hosts: &[String], copy: bool) -> Result<bool> {
    let control = Config::load(&ctx.dir)
        .map(|c| c.control().to_string())
        .or_else(|_| {
            std::fs::read_to_string(ctx.dir.join("nodes")).map(|t| {
                crate::config::parse_nodes(&t)
                    .first()
                    .cloned()
                    .unwrap_or_default()
            })
        })
        .unwrap_or_default();
    let exe =
        std::env::current_exe().map_err(|e| Error::msg(format!("cannot find myself: {e}")))?;
    let mut all_ok = true;
    for host in hosts {
        let local = *host == control;
        let script = if copy {
            "sudo install -m 0755 /tmp/grantctl.upload /usr/local/sbin/grantctl && rm -f /tmp/grantctl.upload".to_string()
        } else {
            format!("sudo add-apt-repository -y {PPA} && sudo apt-get update -qq && sudo apt-get install -y grantctl")
        };
        let run = |cmd: &mut Command| cmd.status().map(|s| s.success()).unwrap_or(false);
        let ok = if local {
            (!copy || run(Command::new("cp").arg(&exe).arg("/tmp/grantctl.upload")))
                && run(Command::new("sh").args(["-c", &script]))
        } else {
            (!copy
                || run(Command::new("scp")
                    .arg("-q")
                    .arg(&exe)
                    .arg(format!("{host}:/tmp/grantctl.upload"))))
                && run(Command::new("ssh").args(["-t", host.as_str(), script.as_str()]))
        };
        if !ok {
            say!(ctx, "[{host}] FAILED: installation did not complete");
            all_ok = false;
            continue;
        }
        match call::<Version>(ctx, host, &["version"], &()) {
            Ok(v) => say!(
                ctx,
                "[{host}] grantctl {} (protocol {})",
                v.version,
                v.protocol
            ),
            Err(e) => {
                say!(ctx, "[{host}] installed, but not answering: {e}");
                all_ok = false;
            }
        }
    }
    Ok(all_ok)
}
