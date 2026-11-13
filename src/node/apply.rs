//! `grantctl node apply`: make this machine match a desired state.
//!
//! The order is fixed: **widen, switch, narrow**.
//!
//! 1. Guards refuse a state that would cut off the operator. Nothing changes.
//! 2. Widen: create groups and accounts, add memberships, unlock. Only adds.
//! 3. Switch: replace the sudoers, limits and sshd files. Everything is
//!    validated (`visudo`, `sshd -t`); any failure restores the backup and
//!    stops the run.
//! 4. Narrow: remove memberships, lock accounts. Only after a good switch.
//! 5. Limits: slice drop-ins and quotas.
//!
//! If the run stops in step 3 the machine has its old files and a superset
//! of its old memberships, so nobody who could log in before is locked out.
//! A dry run performs steps 1 and the planning only and never calls a
//! mutating method of `System`.

use super::system::{self, System};
use super::{Action, Phase, Report, Status, Step};
use crate::desired::{NodeDesired, LIMITS_DIR, LIMITS_FILE, SLICE_FILE, SSHD_DIR};
use crate::desired::{SSHD_MAIN_FILE, SSHD_MATCH_FILE, SUDOERS_DIR, SUDOERS_FILE};
use crate::PROTOCOL;
use std::collections::BTreeSet;

pub const BACKUP_DIR: &str = "/var/backups/grantctl";
pub const STATE_DIR: &str = "/var/lib/grantctl";
pub const SLICE_ROOT: &str = "/etc/systemd/system";
const QUOTA_STATE: &str = "/var/lib/grantctl/quota";
/// Where nst-cockpit (v1) recorded the quotas it had applied.
const V1_QUOTA_STATE: &str = "/var/lib/nst-cockpit/quota";

pub fn apply(sys: &mut dyn System, d: &NodeDesired, dry_run: bool) -> Report {
    let mut report = Report {
        protocol: PROTOCOL,
        host: system::hostname(sys),
        dry_run,
        ok: true,
        error: None,
        ssh_gain: Vec::new(),
        ssh_lose: Vec::new(),
        steps: Vec::new(),
        warnings: Vec::new(),
        unmanaged: Vec::new(),
        stray: Vec::new(),
        created: Vec::new(),
        had_account: Vec::new(),
        backup: None,
    };
    if let Err(e) = plan(sys, d, &mut report) {
        report.ok = false;
        report.error = Some(e);
        return report;
    }
    if !dry_run {
        execute(sys, d, &mut report);
    }
    report
}

pub fn slice_dir(uid: u32) -> String {
    format!("{SLICE_ROOT}/user-{uid}.slice.d")
}

fn slice_content(user: &str, settings: &[String]) -> String {
    let mut text = format!("# managed by grantctl for {user}\n[Slice]\n");
    for s in settings {
        text.push_str(s);
        text.push('\n');
    }
    text
}

/// Slice drop-ins written by a tool grantctl replaces (for example v1).
fn is_legacy_slice(text: &str, d: &NodeDesired) -> bool {
    d.legacy
        .slice_markers
        .iter()
        .any(|m| text.contains(m.as_str()))
}

fn legacy_slice_files(sys: &dyn System, dir: &str, d: &NodeDesired) -> Vec<String> {
    sys.list(dir)
        .into_iter()
        .filter(|f| f != SLICE_FILE)
        .map(|f| format!("{dir}/{f}"))
        .filter(|path| sys.read(path).is_some_and(|t| is_legacy_slice(&t, d)))
        .collect()
}

// ---------------------------------------------------------------- planning (read-only)

fn plan(sys: &dyn System, d: &NodeDesired, r: &mut Report) -> Result<(), String> {
    if d.protocol != PROTOCOL {
        return Err(format!(
            "protocol mismatch: the control node speaks {}, this node speaks {PROTOCOL}. Run: grantctl node install {}",
            d.protocol, d.node
        ));
    }
    let users = system::users(sys);
    let groups = system::groups(sys);
    let user = |name: &str| users.iter().find(|u| u.name == name);
    let group = |name: &str| groups.iter().find(|g| g.name == name);
    let wanted_members = |name: &str| -> &[String] {
        d.groups
            .iter()
            .find(|g| g.name == name)
            .map(|g| g.members.as_slice())
            .unwrap_or(&[])
    };

    // Guards: never cut off sudo or the operator.
    let sudo_group = d.sudo_group.as_str();
    if !d.allow_groups.iter().any(|g| g == sudo_group) {
        return Err(format!(
            "refusing: group {sudo_group} would not be allowed to log in"
        ));
    }
    if !wanted_members(sudo_group).contains(&d.operator) {
        return Err(format!(
            "refusing: operator {} would lose group {sudo_group}",
            d.operator
        ));
    }
    let nopasswd = format!("{} ALL=(ALL:ALL) NOPASSWD: ALL", d.operator);
    if !d.is_control && !d.sudoers.lines().any(|l| l == nopasswd) {
        return Err(format!(
            "refusing: operator {} would lose passwordless sudo on this node",
            d.operator
        ));
    }
    for a in &d.accounts {
        if user(&a.user).is_none() && !sys.query(&["test", "-d", &a.home_base]).ok {
            return Err(format!(
                "refusing: home base {} for new account {} does not exist",
                a.home_base, a.user
            ));
        }
    }

    // Who can log in over SSH now, and who will be able to afterwards.
    let allow_users = system::sshd_values(sys, "AllowUsers");
    let allow_groups = system::sshd_values(sys, "AllowGroups");
    let mut before: BTreeSet<&str> = BTreeSet::new();
    if allow_users.is_empty() && allow_groups.is_empty() {
        // No allow-list yet: every account can log in.
        before.extend(
            users
                .iter()
                .filter(|u| u.is_human())
                .map(|u| u.name.as_str()),
        );
    } else {
        for entry in &allow_users {
            let name = entry.split('@').next().unwrap_or("");
            if let Some(u) = user(name) {
                before.insert(u.name.as_str());
            }
        }
        for g in allow_groups.iter().filter_map(|g| group(g)) {
            before.extend(
                g.members
                    .iter()
                    .filter_map(|m| user(m))
                    .map(|u| u.name.as_str()),
            );
            before.extend(
                users
                    .iter()
                    .filter(|u| u.gid == g.gid)
                    .map(|u| u.name.as_str()),
            );
        }
    }
    let after: BTreeSet<&str> = d
        .allow_groups
        .iter()
        .flat_map(|g| wanted_members(g).iter())
        .map(String::as_str)
        .collect();
    r.ssh_lose = before.difference(&after).map(|s| s.to_string()).collect();
    r.ssh_gain = after.difference(&before).map(|s| s.to_string()).collect();

    let mut steps: Vec<Step> = Vec::new();
    let mut push = |phase: Phase, action: Action| {
        steps.push(Step {
            phase,
            action,
            status: Status::Planned,
            error: None,
        })
    };

    // Widen. Groups and accounts with a preferred id are created first:
    // one created without would be given the next free number, which may
    // be exactly the number a later one prefers.
    let mut used_gids: BTreeSet<u32> = groups.iter().map(|g| g.gid).collect();
    let missing: Vec<_> = d
        .groups
        .iter()
        .filter(|g| group(&g.name).is_none() && !g.members.is_empty())
        .collect();
    for g in missing
        .iter()
        .filter(|g| g.gid.is_some())
        .chain(missing.iter().filter(|g| g.gid.is_none()))
    {
        let gid = g.gid.filter(|id| used_gids.insert(*id));
        push(
            Phase::Widen,
            Action::CreateGroup {
                group: g.name.clone(),
                gid,
            },
        );
    }
    let mut used_uids: BTreeSet<u32> = users.iter().map(|u| u.uid).collect();
    let missing: Vec<_> = d
        .accounts
        .iter()
        .filter(|a| user(&a.user).is_none())
        .collect();
    for a in missing
        .iter()
        .filter(|a| a.uid.is_some())
        .chain(missing.iter().filter(|a| a.uid.is_none()))
    {
        let uid = a.uid.filter(|id| used_uids.insert(*id));
        push(
            Phase::Widen,
            Action::CreateUser {
                user: a.user.clone(),
                home: format!("{}/{}", a.home_base, a.user),
                uid,
            },
        );
    }
    r.created = missing.iter().map(|a| a.user.clone()).collect();
    for g in &d.groups {
        let current: &[String] = group(&g.name).map(|x| x.members.as_slice()).unwrap_or(&[]);
        for member in g.members.iter().filter(|m| !current.contains(m)) {
            push(
                Phase::Widen,
                Action::AddMember {
                    user: member.clone(),
                    group: g.name.clone(),
                },
            );
        }
    }
    let wanted: BTreeSet<&str> = d.accounts.iter().map(|a| a.user.as_str()).collect();
    for name in &d.managed_users {
        let unlock = user(name).is_some()
            && wanted.contains(name.as_str())
            && !d.locked.contains(name)
            && system::is_locked(sys, name);
        if unlock {
            push(Phase::Widen, Action::Unlock { user: name.clone() });
        }
    }

    // Switch: the files grantctl owns, then the files it replaces.
    let owned: [(&str, &str, u32, &str, &[String]); 4] = [
        (
            SUDOERS_DIR,
            SUDOERS_FILE,
            0o440,
            &d.sudoers,
            &d.legacy.sudoers,
        ),
        (LIMITS_DIR, LIMITS_FILE, 0o644, &d.limits, &d.legacy.limits),
        (SSHD_DIR, SSHD_MAIN_FILE, 0o644, &d.sshd_main, &[]),
        (
            SSHD_DIR,
            SSHD_MATCH_FILE,
            0o644,
            &d.sshd_match,
            &d.legacy.sshd,
        ),
    ];
    let own_names = [SUDOERS_FILE, LIMITS_FILE, SSHD_MAIN_FILE, SSHD_MATCH_FILE];
    for (dir, name, mode, new, legacy) in owned {
        let path = format!("{dir}/{name}");
        let old = sys.read(&path);
        if old.as_deref() != Some(new) {
            push(
                Phase::Switch,
                Action::Install {
                    path,
                    mode,
                    old,
                    new: new.to_string(),
                },
            );
        }
        for name in legacy.iter().filter(|n| !own_names.contains(&n.as_str())) {
            let path = format!("{dir}/{name}");
            if let Some(old) = sys.read(&path) {
                push(
                    Phase::Switch,
                    Action::Remove {
                        path,
                        old: Some(old),
                    },
                );
            }
        }
    }

    // Narrow.
    for g in &d.groups {
        let Some(current) = group(&g.name) else {
            continue;
        };
        for member in current.members.iter().filter(|m| !g.members.contains(m)) {
            push(
                Phase::Narrow,
                Action::RemoveMember {
                    user: member.clone(),
                    group: g.name.clone(),
                },
            );
        }
    }
    for name in &d.locked {
        if user(name).is_some() && !system::is_locked(sys, name) {
            push(Phase::Narrow, Action::Lock { user: name.clone() });
        }
    }
    let slice_uids: BTreeSet<u32> = d
        .slices
        .iter()
        .filter_map(|s| user(&s.user).map(|u| u.uid))
        .collect();
    for entry in sys.list(SLICE_ROOT) {
        let uid = entry
            .strip_prefix("user-")
            .and_then(|e| e.strip_suffix(".slice.d"))
            .and_then(|n| n.parse::<u32>().ok());
        let Some(uid) = uid else { continue };
        if slice_uids.contains(&uid) {
            continue;
        }
        let dir = slice_dir(uid);
        let mut stale = legacy_slice_files(sys, &dir, d);
        if sys.read(&format!("{dir}/{SLICE_FILE}")).is_some() {
            stale.push(format!("{dir}/{SLICE_FILE}"));
        }
        for path in stale {
            push(Phase::Narrow, Action::Remove { path, old: None });
        }
    }

    // Limits.
    for s in &d.slices {
        let current = match user(&s.user) {
            None => false,
            Some(u) => {
                let dir = slice_dir(u.uid);
                sys.read(&format!("{dir}/{SLICE_FILE}")).as_deref()
                    == Some(slice_content(&s.user, &s.settings).as_str())
                    && legacy_slice_files(sys, &dir, d).is_empty()
            }
        };
        if !current {
            push(
                Phase::Limits,
                Action::Slice {
                    user: s.user.clone(),
                    settings: s.settings.clone(),
                },
            );
        }
    }
    let recorded = format!(
        "{}{}",
        sys.read(QUOTA_STATE).unwrap_or_default(),
        sys.read(V1_QUOTA_STATE).unwrap_or_default()
    );
    for q in &d.quotas {
        let line = format!("{} {} {}", q.user, q.size, q.base);
        if recorded.lines().any(|l| l == line) {
            continue;
        }
        let possible = sys.query(&["sh", "-c", "command -v setquota"]).ok
            && sys.query(&["mountpoint", "-q", &q.base]).ok;
        if possible {
            push(
                Phase::Limits,
                Action::Quota {
                    user: q.user.clone(),
                    size: q.size.clone(),
                    base: q.base.clone(),
                },
            );
        } else {
            r.warnings.push(format!(
                "quota {} for {} skipped: {} is not a quota-enabled mount",
                q.size, q.user, q.base
            ));
        }
    }

    // Accounts grantctl does not manage, or that have no business here.
    let managed: BTreeSet<&str> = d.managed_users.iter().map(String::as_str).collect();
    r.unmanaged = users
        .iter()
        .filter(|u| u.is_human() && !managed.contains(u.name.as_str()))
        .map(|u| u.name.clone())
        .collect();
    for name in &d.managed_users {
        if user(name).is_none() {
            continue;
        }
        r.had_account.push(name.clone());
        if !wanted.contains(name.as_str()) && !system::is_locked(sys, name) {
            r.stray.push(name.clone());
        }
    }
    r.steps = steps;
    Ok(())
}

// ---------------------------------------------------------------- execution

fn execute(sys: &mut dyn System, d: &NodeDesired, r: &mut Report) {
    let of = |r: &Report, phase: Phase| -> Vec<usize> {
        (0..r.steps.len())
            .filter(|&i| r.steps[i].phase == phase)
            .collect()
    };
    let stop = |r: &mut Report, error: String| {
        r.ok = false;
        r.error = Some(error);
        for step in r.steps.iter_mut().filter(|s| s.status == Status::Planned) {
            step.status = Status::Skipped;
        }
    };

    for i in of(r, Phase::Widen) {
        let action = r.steps[i].action.clone();
        if let Err(e) = act(sys, d, &action) {
            r.steps[i].status = Status::Failed;
            r.steps[i].error = Some(e.clone());
            stop(r, format!("{e}; stopped before changing any access rule"));
            return;
        }
        r.steps[i].status = Status::Done;
    }

    let switching = of(r, Phase::Switch);
    if !switching.is_empty() {
        if let Err(e) = switch(sys, d, r, &switching) {
            for &i in &switching {
                r.steps[i].status = Status::Failed;
            }
            stop(r, e);
            return;
        }
    }

    let mut slices_changed = false;
    for phase in [Phase::Narrow, Phase::Limits] {
        for i in of(r, phase) {
            let action = r.steps[i].action.clone();
            slices_changed |= matches!(&action, Action::Slice { .. })
                || matches!(&action, Action::Remove { path, .. } if path.starts_with(SLICE_ROOT));
            match act(sys, d, &action) {
                Ok(()) => r.steps[i].status = Status::Done,
                Err(e) => {
                    r.steps[i].status = Status::Failed;
                    r.steps[i].error = Some(e.clone());
                    r.ok = false;
                    r.error.get_or_insert(e);
                }
            }
        }
    }
    if slices_changed && sys.query(&["test", "-d", "/run/systemd/system"]).ok {
        if let Err(e) = sys.run(&["systemctl", "daemon-reload"], None) {
            r.warnings.push(format!("slice limits written, but {e}"));
        }
    }
}

/// One step outside the switch phase.
fn act(sys: &mut dyn System, d: &NodeDesired, action: &Action) -> Result<(), String> {
    match action {
        Action::CreateGroup { group, gid } => match gid {
            Some(id) => sys.run(&["groupadd", "-g", &id.to_string(), group], None),
            None => sys.run(&["groupadd", group], None),
        },
        Action::CreateUser { user, home, uid } => {
            let id = uid.map(|u| u.to_string());
            let mut argv = vec!["useradd", "-m", "-s", "/bin/bash", "-d", home.as_str()];
            if let Some(id) = &id {
                argv.extend(["-u", id.as_str()]);
            }
            argv.push(user);
            sys.run(&argv, None)?;
            sys.run(&["chmod", "0750", home], None)
        }
        Action::AddMember { user, group } => sys.run(&["gpasswd", "-a", user, group], None),
        Action::RemoveMember { user, group } => sys.run(&["gpasswd", "-d", user, group], None),
        Action::Unlock { user } => {
            sys.run(&["usermod", "-e", "", user], None)?;
            // Fails for an account that never had a password; that is fine.
            let _ = sys.run(&["usermod", "-U", user], None);
            Ok(())
        }
        Action::Lock { user } => {
            sys.run(&["usermod", "-L", "-e", "1", user], None)?;
            let _ = sys.run(&["pkill", "-KILL", "-u", user], None);
            Ok(())
        }
        Action::Install {
            path, mode, new, ..
        } => sys.write(path, new, *mode),
        Action::Remove { path, .. } => {
            sys.remove(path)?;
            if let Some((dir, _)) = path.rsplit_once('/') {
                if dir.starts_with(&format!("{SLICE_ROOT}/user-")) && sys.list(dir).is_empty() {
                    let _ = sys.run(&["rmdir", dir], None);
                }
            }
            Ok(())
        }
        Action::Slice { user, settings } => {
            let uid = system::users(sys)
                .iter()
                .find(|u| &u.name == user)
                .map(|u| u.uid)
                .ok_or_else(|| format!("slice limits: no account {user}"))?;
            let dir = slice_dir(uid);
            sys.write(
                &format!("{dir}/{SLICE_FILE}"),
                &slice_content(user, settings),
                0o644,
            )?;
            for path in legacy_slice_files(sys, &dir, d) {
                sys.remove(&path)?;
            }
            Ok(())
        }
        Action::Quota { user, size, base } => {
            let gigabytes: u64 = size
                .trim_end_matches('G')
                .parse()
                .map_err(|_| format!("bad quota size {size}"))?;
            let kilobytes = (gigabytes * 1024 * 1024).to_string();
            sys.run(
                &["setquota", "-u", user, "0", &kilobytes, "0", "0", base],
                None,
            )?;
            let mut state: String = sys
                .read(QUOTA_STATE)
                .unwrap_or_default()
                .lines()
                .filter(|l| !l.starts_with(&format!("{user} ")))
                .map(|l| format!("{l}\n"))
                .collect();
            state.push_str(&format!("{user} {size} {base}\n"));
            sys.write(QUOTA_STATE, &state, 0o600)
        }
    }
}

/// Replace the owned files. On any failure the three directories are
/// restored from the backup taken just before.
fn switch(
    sys: &mut dyn System,
    d: &NodeDesired,
    r: &mut Report,
    steps: &[usize],
) -> Result<(), String> {
    let path = |r: &Report, i: usize| match &r.steps[i].action {
        Action::Install { path, .. } | Action::Remove { path, .. } => path.clone(),
        _ => String::new(),
    };
    let within = |r: &Report, dir: &str| -> Vec<usize> {
        steps
            .iter()
            .copied()
            .filter(|&i| path(r, i).starts_with(&format!("{dir}/")))
            .collect()
    };
    let (sudoers, limits, sshd) = (
        within(r, SUDOERS_DIR),
        within(r, LIMITS_DIR),
        within(r, SSHD_DIR),
    );

    // Checks before anything is touched.
    if !sshd.is_empty() {
        let _ = sys.run(&["mkdir", "-p", "/run/sshd"], None);
        let pre = sys.query(&["sshd", "-t"]);
        if !pre.ok {
            return Err(format!(
                "the sshd configuration is already invalid, nothing changed: {}",
                said(&pre)
            ));
        }
    }
    let mut sudoers_was_valid = true;
    if !sudoers.is_empty() {
        sudoers_was_valid = sys.query(&["visudo", "-c"]).ok;
        let candidate = format!("{STATE_DIR}/candidate-sudoers");
        sys.write(&candidate, &d.sudoers, 0o440)?;
        let check = sys.query(&["visudo", "-cf", &candidate]);
        let _ = sys.remove(&candidate);
        if !check.ok {
            return Err(format!(
                "the generated sudoers file is invalid, nothing changed: {}",
                said(&check)
            ));
        }
    }

    let stamp = sys
        .query(&["date", "+%Y%m%d-%H%M%S"])
        .stdout
        .trim()
        .to_string();
    let backup = format!("{BACKUP_DIR}/{stamp}");
    sys.run(&["mkdir", "-p", &backup], None)?;
    let dirs = [SSHD_DIR, SUDOERS_DIR, LIMITS_DIR];
    for dir in dirs {
        sys.run(&["cp", "-a", dir, &backup], None)?;
    }
    r.backup = Some(backup.clone());

    if let Err(e) = switch_files(sys, r, &sudoers, &limits, &sshd, sudoers_was_valid) {
        for dir in dirs {
            let name = dir.rsplit('/').next().unwrap_or("");
            let _ = sys.run(&["rm", "-rf", dir], None);
            let _ = sys.run(&["cp", "-a", &format!("{backup}/{name}"), dir], None);
        }
        return Err(format!(
            "{e}; restored the previous files from {backup}; no access was removed"
        ));
    }
    Ok(())
}

/// What a failed check printed.
fn said(out: &system::Output) -> String {
    format!("{}{}", out.stderr, out.stdout).trim().to_string()
}

fn install(sys: &mut dyn System, r: &mut Report, which: &[usize]) -> Result<(), String> {
    for &i in which {
        match r.steps[i].action.clone() {
            Action::Install {
                path, mode, new, ..
            } => sys.write(&path, &new, mode)?,
            Action::Remove { path, .. } => sys.remove(&path)?,
            _ => {}
        }
        r.steps[i].status = Status::Done;
    }
    Ok(())
}

/// sudoers first (it takes effect at once and is checked at once), then
/// limits, then sshd with `sshd -t` and a reload.
fn switch_files(
    sys: &mut dyn System,
    r: &mut Report,
    sudoers: &[usize],
    limits: &[usize],
    sshd: &[usize],
    sudoers_was_valid: bool,
) -> Result<(), String> {
    install(sys, r, sudoers)?;
    if !sudoers.is_empty() {
        let post = sys.query(&["visudo", "-c"]);
        if !post.ok && sudoers_was_valid {
            return Err(format!(
                "sudoers is invalid after the change: {}",
                said(&post)
            ));
        }
        if !post.ok {
            r.warnings.push(format!(
                "sudoers was already invalid before grantctl and still is: {}",
                said(&post)
            ));
        }
    }
    install(sys, r, limits)?;
    install(sys, r, sshd)?;
    if !sshd.is_empty() {
        let test = sys.query(&["sshd", "-t"]);
        if !test.ok {
            return Err(format!(
                "sshd -t rejects the new configuration: {}",
                said(&test)
            ));
        }
        reload_sshd(sys, r)?;
    }
    Ok(())
}

fn reload_sshd(sys: &mut dyn System, r: &mut Report) -> Result<(), String> {
    if sys.query(&["test", "-d", "/run/systemd/system"]).ok {
        // The service is called ssh on Debian and Ubuntu, sshd elsewhere.
        if sys
            .run(&["systemctl", "reload-or-restart", "ssh"], None)
            .is_ok()
        {
            return Ok(());
        }
        return sys
            .run(&["systemctl", "reload-or-restart", "sshd"], None)
            .map_err(|e| format!("the sshd configuration is valid but the reload failed: {e}"));
    }
    match sys.read("/run/sshd.pid") {
        Some(pid) => sys
            .run(&["kill", "-HUP", pid.trim()], None)
            .map_err(|e| format!("the sshd configuration is valid but the reload failed: {e}")),
        None => {
            r.warnings.push(
                "sshd is not managed by systemd and has no pid file: reload it yourself".into(),
            );
            Ok(())
        }
    }
}
