//! `grantctl node apply` against simulated machines.
//!
//! These tests pin down the guarantee v2 exists for: a run that fails half
//! way leaves the old files in place and has removed nobody's access.

use grantctl::config::Config;
use grantctl::desired::{self, Hints, NodeDesired};
use grantctl::node::apply::apply;
use grantctl::node::fake::FakeSystem;
use grantctl::node::{Phase, Report, Status};

const NODES: &str = "node1\nnode2\ngpu1\n";

const ROLES: &str = "\
[admin]
groups   = staff,sudo
password = yes
[user]
groups   = shell-users
[student]
groups   = students
nodes    = node1
password = yes
[gpu]
groups   = gpu-users
nodes    = gpu1
password = yes
from     = control
home     = /srv/gpu-home
slice    = CPUQuota=800%,MemoryMax=20G
quota    = 90G
limits   = nproc=1024
";

const ACCESS: &str = "\
alice admin nopasswd
bob   admin
carol student
dave  student gpu
frank locked
";

const SUDOERS: &str = "/etc/sudoers.d/99-grantctl";
const SSHD_MAIN: &str = "/etc/ssh/sshd_config.d/10-grantctl.conf";
const SSHD_MATCH: &str = "/etc/ssh/sshd_config.d/99-grantctl.conf";
const LOCKDOWN: &str = "/etc/ssh/sshd_config.d/00-lockdown.conf";

fn config(access: &str, site: &str) -> Config {
    Config::from_strs(NODES, ROLES, access, site).unwrap()
}

fn state_of(cfg: &Config, node: &str) -> NodeDesired {
    let hints = Hints {
        control_ips: vec!["10.0.0.1".into()],
        ..Hints::default()
    };
    desired::build(cfg, node, "alice", &hints).unwrap()
}

fn state(node: &str) -> NodeDesired {
    state_of(&config(ACCESS, ""), node)
}

/// A machine set up by hand: the operator exists and has sudo.
fn machine(host: &str) -> FakeSystem {
    let mut sys = FakeSystem::new(host);
    sys.add_user("alice", 1001);
    sys.add_group("sudo", 27, &["alice"]);
    sys.dirs.insert("/srv/gpu-home".into());
    sys
}

/// Position of the first log line containing `needle`.
fn at(sys: &FakeSystem, needle: &str) -> usize {
    sys.log
        .iter()
        .position(|l| l.contains(needle))
        .unwrap_or_else(|| panic!("no log line with {needle:?} in {:#?}", sys.log))
}

fn statuses(r: &Report, phase: Phase) -> Vec<Status> {
    r.steps
        .iter()
        .filter(|s| s.phase == phase)
        .map(|s| s.status)
        .collect()
}

// ---------------------------------------------------------------- the normal path

#[test]
fn a_fresh_node_converges_and_stays_converged() {
    let mut sys = machine("node1");
    let d = state("node1");
    let r = apply(&mut sys, &d, false);
    assert!(r.ok, "{:?}", r.error);
    assert_eq!(r.created, ["bob", "carol", "dave"]);
    assert_eq!(r.had_account, ["alice"]);
    assert_eq!(sys.members("sudo"), ["alice", "bob"]);
    assert_eq!(sys.members("staff"), ["alice", "bob"]);
    assert_eq!(sys.members("students"), ["carol", "dave"]);
    assert_eq!(sys.file(SUDOERS), Some(d.sudoers.as_str()));
    assert_eq!(sys.files[SUDOERS].1, 0o440);
    assert_eq!(sys.file(SSHD_MAIN), Some(d.sshd_main.as_str()));
    assert_eq!(sys.file(SSHD_MATCH), Some(d.sshd_match.as_str()));
    assert!(sys
        .log
        .iter()
        .any(|l| l == "systemctl reload-or-restart ssh"));
    assert_eq!(
        r.backup.as_deref(),
        Some("/var/backups/grantctl/20261113-120000")
    );

    let changes = sys.log.len();
    let again = apply(&mut sys, &d, false);
    assert!(again.ok);
    assert!(
        again.steps.is_empty(),
        "second run planned {:?}",
        again.steps
    );
    assert_eq!(
        sys.log.len(),
        changes,
        "an in-sync node must not be touched"
    );
}

#[test]
fn a_dry_run_plans_everything_and_changes_nothing() {
    let mut sys = machine("node1");
    let r = apply(&mut sys, &state("node1"), true);
    assert!(r.ok && r.dry_run);
    assert!(sys.log.is_empty(), "dry run mutated: {:?}", sys.log);
    assert!(!r.steps.is_empty());
    assert!(r.steps.iter().all(|s| s.status == Status::Planned));
    assert_eq!(r.created, ["bob", "carol", "dave"]);
    assert!(r.backup.is_none());
}

#[test]
fn accounts_use_the_control_nodes_uid_when_it_is_free() {
    let cfg = config(ACCESS, "");
    let mut hints = Hints::default();
    hints.uids.insert("bob".into(), 1500);
    hints.uids.insert("carol".into(), 1001); // taken by alice on this machine
    let d = desired::build(&cfg, "node1", "alice", &hints).unwrap();
    let mut sys = machine("node1");
    assert!(apply(&mut sys, &d, false).ok);
    assert_eq!(sys.users["bob"].uid, 1500);
    assert_ne!(sys.users["carol"].uid, 1001);
}

#[test]
fn preferred_ids_are_allocated_before_automatic_ones() {
    // `staff` has no preferred gid and would be given 1002, the next free
    // number, which is exactly what `students` prefers.
    let cfg = config(ACCESS, "");
    let mut hints = Hints::default();
    hints.gids.insert("students".into(), 1002);
    let d = desired::build(&cfg, "node1", "alice", &hints).unwrap();
    let mut sys = machine("node1");
    let r = apply(&mut sys, &d, false);
    assert!(r.ok, "{:?}", r.error);
    assert_eq!(sys.groups["students"].0, 1002);
    assert!(at(&sys, "groupadd -g 1002 students") < at(&sys, "groupadd staff"));
}

// ---------------------------------------------------------------- widen, switch, narrow

/// A node as v1 or an admin left it: an allow-list by user name, and a
/// student who is no longer in the roster.
fn legacy_machine() -> (FakeSystem, Config) {
    let mut sys = machine("node1");
    sys.add_user("erin", 1002);
    sys.add_group("students", 1108, &["erin"]);
    sys.set_file(LOCKDOWN, "AllowUsers alice erin\n", 0o644);
    (sys, config(ACCESS, "LEGACY_SSHD=00-lockdown.conf\n"))
}

#[test]
fn memberships_are_removed_only_after_the_new_rules_are_live() {
    let (mut sys, cfg) = legacy_machine();
    let r = apply(&mut sys, &state_of(&cfg, "node1"), false);
    assert!(r.ok, "{:?}", r.error);
    assert_eq!(r.ssh_lose, ["erin"]);
    assert_eq!(r.ssh_gain, ["bob", "carol", "dave"]);

    let added = at(&sys, "gpasswd -a carol students");
    let sudoers = at(&sys, &format!("write {SUDOERS}"));
    let sshd = at(&sys, &format!("write {SSHD_MAIN}"));
    let reloaded = at(&sys, "systemctl reload-or-restart ssh");
    let removed = at(&sys, "gpasswd -d erin students");
    assert!(added < sudoers, "widen before switch");
    assert!(
        sudoers < sshd && sshd < reloaded,
        "sudoers, then sshd, then reload"
    );
    assert!(reloaded < removed, "narrow only after the switch");
    assert!(
        sys.file(LOCKDOWN).is_none(),
        "the legacy allow-list is replaced"
    );
}

#[test]
fn a_failed_sshd_check_restores_the_files_and_removes_no_access() {
    let (mut sys, mut cfg) = legacy_machine();
    cfg.baseline.push("BROKEN yes".into()); // sshd -t will reject the new file
    let r = apply(&mut sys, &state_of(&cfg, "node1"), false);

    assert!(!r.ok);
    let error = r.error.clone().unwrap();
    assert!(error.contains("sshd -t rejects"), "{error}");
    assert!(
        error.contains("restored") && error.contains("no access was removed"),
        "{error}"
    );
    // Old files are back, new ones are gone: sshd, and sudoers too.
    assert_eq!(sys.file(LOCKDOWN), Some("AllowUsers alice erin\n"));
    assert!(sys.file(SSHD_MAIN).is_none() && sys.file(SSHD_MATCH).is_none());
    assert!(sys.file(SUDOERS).is_none());
    // The run stopped before narrowing: erin keeps her group and her login.
    assert_eq!(sys.members("students"), ["carol", "dave", "erin"]);
    assert!(!sys.log.iter().any(|l| l.contains("gpasswd -d")));
    assert!(!sys.log.iter().any(|l| l.contains("reload-or-restart")));
    assert!(statuses(&r, Phase::Widen)
        .iter()
        .all(|s| *s == Status::Done));
    assert!(statuses(&r, Phase::Switch)
        .iter()
        .all(|s| *s == Status::Failed));
    assert!(statuses(&r, Phase::Narrow)
        .iter()
        .all(|s| *s == Status::Skipped));

    // Fixing the configuration and running again converges.
    cfg.baseline.pop();
    let r = apply(&mut sys, &state_of(&cfg, "node1"), false);
    assert!(r.ok, "{:?}", r.error);
    assert_eq!(sys.members("students"), ["carol", "dave"]);
}

#[test]
fn a_failed_reload_also_stops_before_narrowing() {
    let (mut sys, cfg) = legacy_machine();
    sys.fail_on = vec!["systemctl reload-or-restart".into()];
    let r = apply(&mut sys, &state_of(&cfg, "node1"), false);
    assert!(!r.ok);
    assert!(r.error.unwrap().contains("reload failed"));
    assert_eq!(sys.file(LOCKDOWN), Some("AllowUsers alice erin\n"));
    assert_eq!(sys.members("students"), ["carol", "dave", "erin"]);
}

#[test]
fn a_failure_while_widening_touches_no_access_rule() {
    let (mut sys, cfg) = legacy_machine();
    sys.fail_on = vec!["useradd".into()];
    let r = apply(&mut sys, &state_of(&cfg, "node1"), false);
    assert!(!r.ok);
    assert!(r
        .error
        .unwrap()
        .contains("stopped before changing any access rule"));
    assert!(!sys
        .log
        .iter()
        .any(|l| l.starts_with("write ") || l.contains("gpasswd -d")));
    assert_eq!(sys.file(LOCKDOWN), Some("AllowUsers alice erin\n"));
    assert!(r.backup.is_none());
}

#[test]
fn an_invalid_generated_sudoers_file_is_never_installed() {
    let mut sys = machine("node1");
    let mut d = state("node1");
    d.sudoers.push_str("SYNTAX ERROR\n");
    let r = apply(&mut sys, &d, false);
    assert!(!r.ok);
    assert!(r
        .error
        .unwrap()
        .contains("generated sudoers file is invalid, nothing changed"));
    assert!(!sys.log.iter().any(|l| l.contains("/etc/sudoers.d")));
    assert!(sys.file(SSHD_MAIN).is_none());
    assert!(
        r.backup.is_none(),
        "no backup is needed when nothing was replaced"
    );
}

#[test]
fn an_sshd_configuration_that_is_already_broken_is_left_alone() {
    let mut sys = machine("node1");
    sys.set_file("/etc/ssh/sshd_config", "BROKEN yes\n", 0o644);
    let r = apply(&mut sys, &state("node1"), false);
    assert!(!r.ok);
    assert!(r
        .error
        .unwrap()
        .contains("already invalid, nothing changed"));
    assert!(!sys.log.iter().any(|l| l.starts_with("write /etc/")));
}

/// What locked the NST control node out with v1: a foreign sudoers file with
/// mode 0644 makes `visudo -c` fail for the whole tree.
#[test]
fn a_foreign_sudoers_file_with_a_bad_mode_does_not_abort_the_run() {
    let foreign = "/etc/sudoers.d/11-nst-root";
    let mut sys = machine("node1");
    sys.set_file(foreign, "%nst-root ALL=(ALL:ALL) ALL\n", 0o644);
    let r = apply(&mut sys, &state("node1"), false);
    assert!(r.ok, "{:?}", r.error);
    assert!(r
        .warnings
        .iter()
        .any(|w| w.contains("already invalid before grantctl")));
    assert!(sys.file(SUDOERS).is_some() && sys.file(SSHD_MAIN).is_some());
    assert!(
        sys.file(foreign).is_some(),
        "files grantctl does not own are left alone"
    );

    // Listed as legacy, the file is replaced and the tree is valid again.
    let mut sys = machine("node1");
    sys.set_file(foreign, "%nst-root ALL=(ALL:ALL) ALL\n", 0o644);
    let cfg = config(ACCESS, "LEGACY_SUDO=11-nst-root\n");
    let r = apply(&mut sys, &state_of(&cfg, "node1"), false);
    assert!(
        r.ok && r.warnings.is_empty(),
        "{:?} {:?}",
        r.error,
        r.warnings
    );
    assert!(sys.file(foreign).is_none());
}

#[test]
fn a_sudoers_tree_broken_by_the_change_is_rolled_back() {
    // A site file that is valid on its own but not next to grantctl's file.
    // The candidate check cannot see this; the whole-tree check after the
    // change does.
    let site = "/etc/sudoers.d/50-site";
    let (mut sys, cfg) = legacy_machine();
    sys.set_file(site, "#!conflicts 99-grantctl\n", 0o440);
    let r = apply(&mut sys, &state_of(&cfg, "node1"), false);
    assert!(!r.ok);
    let error = r.error.unwrap();
    assert!(
        error.contains("sudoers is invalid after the change"),
        "{error}"
    );
    assert!(error.contains("restored"), "{error}");
    assert!(
        sys.file(SUDOERS).is_none(),
        "grantctl's file is taken out again"
    );
    assert_eq!(sys.file(site), Some("#!conflicts 99-grantctl\n"));
    assert!(
        sys.file(SSHD_MAIN).is_none(),
        "sshd is not touched after a sudoers failure"
    );
    assert_eq!(sys.members("students"), ["carol", "dave", "erin"]);
}

// ---------------------------------------------------------------- guards

#[test]
fn a_state_that_removes_the_operators_sudo_is_refused() {
    let cfg = config("alice user\nbob admin nopasswd\n", "");
    let mut sys = machine("node1");
    let r = apply(&mut sys, &state_of(&cfg, "node1"), false);
    assert!(!r.ok);
    assert!(r
        .error
        .unwrap()
        .contains("operator alice would lose group sudo"));
    assert!(sys.log.is_empty() && r.steps.is_empty());
}

#[test]
fn a_node_must_keep_the_operators_passwordless_sudo() {
    let cfg = config("alice admin\n", "");
    // Fine on the control node, where sudo may ask for a password.
    assert!(apply(&mut machine("node1"), &state_of(&cfg, "node1"), false).ok);
    let mut sys = machine("node2");
    let r = apply(&mut sys, &state_of(&cfg, "node2"), false);
    assert!(r.error.unwrap().contains("would lose passwordless sudo"));
    assert!(sys.log.is_empty());
}

#[test]
fn a_missing_home_base_is_refused_before_anything_changes() {
    let mut sys = machine("gpu1");
    sys.dirs.remove("/srv/gpu-home");
    let r = apply(&mut sys, &state("gpu1"), false);
    assert!(r.error.unwrap().contains("home base /srv/gpu-home"));
    assert!(sys.log.is_empty());
}

#[test]
fn another_protocol_version_is_refused() {
    let mut d = state("node1");
    d.protocol += 1;
    let mut sys = machine("node1");
    let r = apply(&mut sys, &d, false);
    assert!(r.error.unwrap().contains("protocol mismatch"));
    assert!(sys.log.is_empty());
}

// ---------------------------------------------------------------- locks, limits, reporting

#[test]
fn locking_and_unlocking() {
    let mut sys = machine("node1");
    sys.add_user("frank", 1005);
    let r = apply(&mut sys, &state("node1"), false);
    assert!(r.ok);
    assert!(sys.locked("frank"));
    assert!(at(&sys, "usermod -L -e 1 frank") > at(&sys, "systemctl reload-or-restart ssh"));
    assert!(sys.log.iter().any(|l| l == "pkill -KILL -u frank"));

    // frank returns as a student: unlocked while widening.
    let cfg = config(&ACCESS.replace("frank locked", "frank student"), "");
    let r = apply(&mut sys, &state_of(&cfg, "node1"), false);
    assert!(r.ok, "{:?}", r.error);
    assert!(!sys.locked("frank"));
    assert_eq!(sys.members("students"), ["carol", "dave", "frank"]);
}

#[test]
fn gpu_node_gets_homes_slices_limits_and_quotas() {
    let mut sys = machine("gpu1");
    sys.quota_mounts.insert("/srv/gpu-home".into());
    let d = state("gpu1");
    let r = apply(&mut sys, &d, false);
    assert!(r.ok, "{:?}", r.error);
    let dave = &sys.users["dave"];
    assert_eq!(dave.home, "/srv/gpu-home/dave");
    let slice = format!(
        "/etc/systemd/system/user-{}.slice.d/50-grantctl.conf",
        dave.uid
    );
    assert_eq!(
        sys.file(&slice),
        Some("# managed by grantctl for dave\n[Slice]\nCPUQuota=800%\nMemoryMax=20G\n")
    );
    assert!(sys
        .log
        .iter()
        .any(|l| l == "setquota -u dave 0 94371840 0 0 /srv/gpu-home"));
    assert_eq!(
        sys.file("/var/lib/grantctl/quota"),
        Some("dave 90G /srv/gpu-home\n")
    );
    assert!(sys
        .file("/etc/security/limits.d/60-grantctl.conf")
        .unwrap()
        .contains("@gpu-users hard nproc 1024"));
    assert!(sys.log.iter().any(|l| l == "systemctl daemon-reload"));
    assert!(sys
        .file(SSHD_MATCH)
        .unwrap()
        .contains("Address *,!10.0.0.1"));

    let changes = sys.log.len();
    assert!(apply(&mut sys, &d, false).steps.is_empty());
    assert_eq!(sys.log.len(), changes);
}

#[test]
fn a_quota_without_a_quota_mount_is_a_warning() {
    let mut sys = machine("gpu1");
    let r = apply(&mut sys, &state("gpu1"), false);
    assert!(r.ok);
    assert!(r
        .warnings
        .iter()
        .any(|w| w.contains("quota 90G for dave skipped")));
    assert!(!sys.log.iter().any(|l| l.starts_with("setquota")));
}

#[test]
fn slice_limits_follow_the_role() {
    let mut sys = machine("gpu1");
    assert!(apply(&mut sys, &state("gpu1"), false).ok);
    let uid = sys.users["dave"].uid;
    let slice = format!("/etc/systemd/system/user-{uid}.slice.d/50-grantctl.conf");
    assert!(sys.file(&slice).is_some());
    // dave loses the gpu role: the limits go, in the narrow phase.
    let cfg = config(&ACCESS.replace("dave  student gpu", "dave  student"), "");
    let r = apply(&mut sys, &state_of(&cfg, "gpu1"), false);
    assert!(r.ok, "{:?}", r.error);
    assert!(sys.file(&slice).is_none());
    assert!(sys.members("gpu-users").is_empty());
}

#[test]
fn a_v1_node_moves_to_v2_without_manual_cleanup() {
    let mut sys = machine("gpu1");
    sys.add_user("dave", 1004);
    sys.users.get_mut("dave").unwrap().home = "/srv/gpu-home/dave".into();
    sys.add_group("gpu-users", 1018, &["dave"]);
    sys.quota_mounts.insert("/srv/gpu-home".into());
    let v1_slice = "/etc/systemd/system/user-1004.slice.d/50-nst-limits.conf";
    let v1_files = [
        (
            "/etc/ssh/sshd_config.d/10-nst-cockpit.conf",
            "AllowGroups staff sudo gpu-users\n",
            0o644,
        ),
        (
            "/etc/ssh/sshd_config.d/99-nst-cockpit.conf",
            "Match Group gpu-users\n    PasswordAuthentication yes\n",
            0o644,
        ),
        (
            "/etc/sudoers.d/10-nst-cockpit",
            "%sudo ALL=(ALL:ALL) ALL\nalice ALL=(ALL:ALL) NOPASSWD: ALL\n",
            0o440,
        ),
        (
            "/etc/security/limits.d/60-nst-cockpit.conf",
            "@gpu-users hard nproc 1024\n",
            0o644,
        ),
        (
            v1_slice,
            "# managed by nst-cockpit for dave\n[Slice]\nCPUQuota=800%\n",
            0o644,
        ),
        (
            "/var/lib/nst-cockpit/quota",
            "dave 90G /srv/gpu-home\n",
            0o600,
        ),
    ];
    for (path, content, mode) in v1_files {
        sys.set_file(path, content, mode);
    }
    let r = apply(&mut sys, &state("gpu1"), false);
    assert!(r.ok, "{:?}", r.error);
    for (path, _, _) in &v1_files[..5] {
        assert!(sys.file(path).is_none(), "{path} should be replaced");
    }
    assert!(sys.file(SUDOERS).is_some() && sys.file(SSHD_MAIN).is_some());
    assert!(sys
        .file("/etc/systemd/system/user-1004.slice.d/50-grantctl.conf")
        .is_some());
    assert!(
        !sys.log.iter().any(|l| l.starts_with("setquota")),
        "v1 already set this quota"
    );
    assert_eq!(r.ssh_lose, Vec::<String>::new());
    assert!(apply(&mut sys, &state("gpu1"), false).steps.is_empty());
}

#[test]
fn accounts_outside_the_roster_are_reported_never_touched() {
    let mut sys = machine("gpu1");
    sys.add_user("mallory", 1010); // not in access.conf
    sys.add_user("carol", 1003); // in access.conf, but no access on gpu1
    let r = apply(&mut sys, &state("gpu1"), false);
    assert!(r.ok);
    assert_eq!(r.unmanaged, ["mallory"]);
    assert_eq!(r.stray, ["carol"]);
    // No allow-list existed, so everyone could log in before.
    assert_eq!(r.ssh_lose, ["carol", "mallory"]);
    assert!(sys.users.contains_key("mallory") && !sys.locked("mallory"));
    assert!(!sys
        .log
        .iter()
        .any(|l| l.contains("mallory") || l.contains("carol")));
}
