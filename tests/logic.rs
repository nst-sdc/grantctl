//! The unit tests of the bash v1 (nst-cockpit `tests/run.sh`), ported, plus
//! cases for behaviour that is new in v2.

use grantctl::config::{AccessFile, Config, Token};
use grantctl::desired::{self, Hints, NodeDesired};
use grantctl::{edit, validate};

const NODES: &str = "node1\nnode2\nnode3\ngpu1\n";

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
sshd     = MaxSessions=4,X11Forwarding=no
home     = /srv/gpu-home
slice    = CPUQuota=800%,MemoryMax=20G
quota    = 90G
limits   = nproc=1024,maxlogins=4
";

const ACCESS: &str = "\
# roster
alice    admin nopasswd
bob      admin
carol    student
dave     student gpu pwonly@node1
erin     user@node3

frank    locked
";

fn cfg(access: &str) -> Config {
    Config::from_strs(NODES, ROLES, access, "").unwrap()
}

fn tokens(words: &[&str]) -> Vec<Token> {
    words.iter().map(|w| Token::parse(w)).collect()
}

fn on(nodes: &[&str]) -> Vec<String> {
    nodes.iter().map(|n| n.to_string()).collect()
}

/// A user's tokens after editing, as they appear in the file.
fn line(access: &AccessFile, user: &str) -> String {
    access
        .get(user)
        .map(|e| e.tokens_text())
        .unwrap_or_default()
}

fn plan(c: &Config, node: &str) -> NodeDesired {
    let hints = Hints {
        control_ips: vec!["10.0.0.1".into(), "10.0.0.2".into()],
        ..Hints::default()
    };
    desired::build(c, node, "alice", &hints).unwrap()
}

fn group<'a>(d: &'a NodeDesired, name: &str) -> &'a [String] {
    &d.groups.iter().find(|g| g.name == name).unwrap().members
}

// ---------------------------------------------------------------- validation

#[test]
fn roles_keep_file_order() {
    let names: Vec<String> = cfg(ACCESS).roles.iter().map(|r| r.name.clone()).collect();
    assert_eq!(names, ["admin", "user", "student", "gpu"]);
}

#[test]
fn a_good_configuration_validates() {
    assert_eq!(
        validate::validate(&cfg(ACCESS), "alice"),
        Vec::<String>::new()
    );
}

#[test]
fn validation_reports_every_problem() {
    let bad =
        format!("{ACCESS}x1 wizard\nx2 user@node9\nx3 review\nx1 user\nx4 nopasswd\n9lives user\n");
    let problems = validate::validate(&cfg(&bad), "alice").join("\n");
    for expected in [
        "x1: unknown role or flag wizard",
        "x2: unknown node node9",
        "x3: unresolved review",
        "duplicate user: x1",
        "x4: no role",
        "invalid username: 9lives",
    ] {
        assert!(
            problems.contains(expected),
            "missing {expected:?} in:\n{problems}"
        );
    }
}

#[test]
fn a_locked_user_needs_no_role() {
    let problems = validate::validate(&cfg(ACCESS), "alice");
    assert!(!problems.iter().any(|p| p.starts_with("frank")));
}

#[test]
fn the_operator_must_keep_sudo_everywhere() {
    let no_admin = ACCESS.replace("alice    admin nopasswd", "alice    user");
    let p = validate::validate(&cfg(&no_admin), "alice").join("\n");
    assert!(
        p.contains("need sudo on every node; missing on: node1, node2, node3, gpu1"),
        "{p}"
    );

    let scoped = ACCESS.replace(
        "alice    admin nopasswd",
        "alice    admin@node1,node2 nopasswd",
    );
    let p = validate::validate(&cfg(&scoped), "alice").join("\n");
    assert!(p.contains("missing on: node3, gpu1"), "{p}");
}

#[test]
fn the_operator_needs_nopasswd_off_the_control_node() {
    // bob has sudo everywhere but no nopasswd: fine on node1 (control), not elsewhere.
    let p = validate::validate(&cfg(ACCESS), "bob").join("\n");
    assert!(
        p.contains(
            "nopasswd flag on every node except the control node; missing on: node2, node3, gpu1"
        ),
        "{p}"
    );
}

#[test]
fn the_operator_must_not_be_locked_or_unlisted() {
    let locked = ACCESS.replace(
        "alice    admin nopasswd",
        "alice    admin nopasswd locked@gpu1",
    );
    let p = validate::validate(&cfg(&locked), "alice").join("\n");
    assert!(p.contains("are marked locked on: gpu1"), "{p}");
    let p = validate::validate(&cfg(ACCESS), "mallory").join("\n");
    assert!(p.contains("not listed in access.conf"), "{p}");
}

// ---------------------------------------------------------------- editing

#[test]
fn grant_on_merges_scopes() {
    let c = cfg(ACCESS);
    let mut a = c.access.clone();
    edit::grant(
        &c,
        &mut a,
        "erin",
        &tokens(&["user"]),
        Some(&on(&["node2"])),
        "t",
    )
    .unwrap();
    assert_eq!(line(&a, "erin"), "user@node2,node3");
}

#[test]
fn grant_everywhere_collapses_to_the_plain_role() {
    let c = cfg(ACCESS);
    let mut a = c.access.clone();
    edit::grant(&c, &mut a, "erin", &tokens(&["user"]), None, "t").unwrap();
    assert_eq!(line(&a, "erin"), "user");
}

#[test]
fn revoke_on_subtracts_nodes() {
    let c = cfg(&ACCESS.replace("erin     user@node3", "erin     user"));
    let mut a = c.access.clone();
    let gone = edit::revoke(
        &c,
        &mut a,
        "erin",
        &tokens(&["user"]),
        Some(&on(&["node1", "gpu1"])),
    )
    .unwrap();
    assert!(!gone);
    assert_eq!(line(&a, "erin"), "user@node2,node3");
}

#[test]
fn revoke_on_without_tokens_drops_everything_on_those_nodes() {
    let c = cfg(ACCESS);
    let mut a = c.access.clone();
    // dave: student (node1), gpu (gpu1), pwonly@node1. Leaving node1 keeps only gpu.
    edit::revoke(&c, &mut a, "dave", &[], Some(&on(&["node1"]))).unwrap();
    assert_eq!(line(&a, "dave"), "gpu");
}

#[test]
fn flags_can_be_scoped_and_removed() {
    let c = cfg(ACCESS);
    let mut a = c.access.clone();
    edit::grant(
        &c,
        &mut a,
        "dave",
        &tokens(&["locked"]),
        Some(&on(&["gpu1"])),
        "t",
    )
    .unwrap();
    assert_eq!(line(&a, "dave"), "student gpu pwonly@node1 locked@gpu1");
    edit::revoke(&c, &mut a, "dave", &tokens(&["locked"]), None).unwrap();
    assert_eq!(line(&a, "dave"), "student gpu pwonly@node1");
}

#[test]
fn new_users_get_a_line_and_can_be_dropped() {
    let c = cfg(ACCESS);
    let mut a = c.access.clone();
    edit::grant(
        &c,
        &mut a,
        "gina",
        &tokens(&["student"]),
        None,
        "2026-11-13 by alice",
    )
    .unwrap();
    assert_eq!(line(&a, "gina"), "student");
    assert!(a.render().contains("# added 2026-11-13 by alice"));
    assert!(edit::revoke(&c, &mut a, "gina", &[], None).unwrap());
    assert!(a.get("gina").is_none());
}

#[test]
fn revoking_the_last_role_removes_the_line() {
    let c = cfg(ACCESS);
    let mut a = c.access.clone();
    assert!(edit::revoke(&c, &mut a, "carol", &tokens(&["student"]), None).unwrap());
    assert!(a.get("carol").is_none());
}

#[test]
fn edits_reject_unknown_names_and_keep_the_rest_of_the_file() {
    let c = cfg(ACCESS);
    let mut a = c.access.clone();
    assert!(edit::grant(&c, &mut a, "erin", &tokens(&["wizard"]), None, "t").is_err());
    assert!(edit::grant(
        &c,
        &mut a,
        "erin",
        &tokens(&["user"]),
        Some(&on(&["node9"])),
        "t"
    )
    .is_err());
    assert!(edit::grant(&c, &mut a, "9lives", &tokens(&["user"]), None, "t").is_err());
    assert!(edit::revoke(&c, &mut a, "nobody", &[], None).is_err());
    assert_eq!(a.render(), ACCESS, "failed edits must not change the file");

    edit::grant(&c, &mut a, "erin", &tokens(&["user"]), None, "t").unwrap();
    let out = a.render();
    assert!(out.starts_with("# roster\nalice    admin nopasswd\n"));
    assert!(
        out.contains("\n\nfrank    locked\n"),
        "blank lines and untouched users stay as written"
    );
}

#[test]
fn short_node_names_resolve_when_unambiguous() {
    let c = cfg(ACCESS);
    assert_eq!(c.resolve_node("3").unwrap(), "node3");
    assert_eq!(c.resolve_node("gpu1").unwrap(), "gpu1");
    assert!(c.resolve_node("1").is_err(), "node1 and gpu1 both end in 1");
    assert!(c.resolve_node("node9").is_err());
}

// ---------------------------------------------------------------- per-node desired state

#[test]
fn control_node_plan() {
    let d = plan(&cfg(ACCESS), "node1");
    assert!(d.is_control);
    assert_eq!(group(&d, "students"), ["carol", "dave"]);
    assert!(d
        .sshd_match
        .contains("Match User dave\n    PubkeyAuthentication no\n"));
    assert!(d.sudoers.contains("alice ALL=(ALL:ALL) NOPASSWD: ALL\n"));
    assert!(!d.sudoers.contains("bob ALL"), "bob has no nopasswd flag");
    assert_eq!(d.allow_groups, ["shell-users", "staff", "students", "sudo"]);
}

#[test]
fn gpu_node_plan() {
    let d = plan(&cfg(ACCESS), "gpu1");
    assert!(!d.is_control);
    let dave = d.accounts.iter().find(|a| a.user == "dave").unwrap();
    assert_eq!(dave.home_base, "/srv/gpu-home");
    assert_eq!(d.slices[0].user, "dave");
    assert_eq!(d.slices[0].settings, ["CPUQuota=800%", "MemoryMax=20G"]);
    assert_eq!(
        (d.quotas[0].size.as_str(), d.quotas[0].base.as_str()),
        ("90G", "/srv/gpu-home")
    );
    assert!(d.sshd_match.contains(
        "Match Group gpu-users,!shell-users,!staff,!sudo Address *,!10.0.0.1,!10.0.0.2\n    DenyGroups gpu-users\n"
    ));
    assert!(d
        .sshd_match
        .contains("Match Group gpu-users\n    MaxSessions 4\n    X11Forwarding no\n"));
    assert!(
        !d.sshd_match.contains("Match User dave"),
        "pwonly is scoped to node1"
    );
    assert!(d.sudoers.contains("%sudo ALL=(ALL:ALL) ALL\n"));
    assert!(d.limits.contains("@gpu-users hard maxlogins 4\n"));
    assert_eq!(
        d.allow_groups,
        ["gpu-users", "shell-users", "staff", "sudo"]
    );
    assert!(d
        .sshd_main
        .ends_with("AllowGroups gpu-users shell-users staff sudo\n"));
}

#[test]
fn worker_node_plan() {
    let d = plan(&cfg(ACCESS), "node3");
    assert_eq!(group(&d, "shell-users"), ["erin"]);
    assert!(
        group(&d, "students").is_empty(),
        "students exist on node1 only"
    );
    assert!(
        d.locked.contains(&"frank".to_string()),
        "locked applies on every node"
    );
    assert!(!d.accounts.iter().any(|a| a.user == "carol"));
    assert!(
        !d.accounts.iter().any(|a| a.user == "frank"),
        "a locked-only user gets no account"
    );
    assert_eq!(
        d.managed_users,
        ["alice", "bob", "carol", "dave", "erin", "frank"]
    );
}

#[test]
fn from_control_needs_the_control_addresses() {
    let c = cfg(ACCESS);
    let err = desired::build(&c, "gpu1", "alice", &Hints::default()).unwrap_err();
    assert!(err.to_string().contains("from = control"));
    // node1 has no restricted role active, so it needs none.
    assert!(desired::build(&c, "node1", "alice", &Hints::default()).is_ok());
}

#[test]
fn a_node_nobody_can_administer_is_refused() {
    let c = Config::from_strs(NODES, ROLES, "alice admin@node1 nopasswd\n", "").unwrap();
    assert!(plan(&c, "node1").is_control);
    let roles = ROLES.replace(
        "[admin]\ngroups   = staff,sudo",
        "[admin]\nnodes = node1\ngroups   = staff,sudo",
    );
    let c = Config::from_strs(NODES, &roles, "alice admin nopasswd\n", "").unwrap();
    let err = desired::build(&c, "node2", "alice", &Hints::default()).unwrap_err();
    assert!(err.to_string().contains("nobody could administer"));
}

#[test]
fn v1_files_are_always_treated_as_legacy() {
    let site = "LEGACY_SUDO=\"10-admins\"\nLEGACY_SLICE_MARKER='managed by old-tool'\n";
    let c = Config::from_strs(NODES, ROLES, ACCESS, site).unwrap();
    let d = plan(&c, "node1");
    assert_eq!(
        d.legacy.sshd,
        ["10-nst-cockpit.conf", "99-nst-cockpit.conf"]
    );
    assert_eq!(d.legacy.sudoers, ["10-nst-cockpit", "10-admins"]);
    assert_eq!(
        d.legacy.slice_markers,
        ["managed by nst-cockpit", "managed by old-tool"]
    );
}

#[test]
fn uid_and_gid_hints_are_carried() {
    let c = cfg(ACCESS);
    let mut hints = Hints::default();
    hints.uids.insert("alice".into(), 1001);
    hints.gids.insert("staff".into(), 1099);
    let d = desired::build(&c, "node1", "alice", &hints).unwrap();
    assert_eq!(d.accounts[0].uid, Some(1001));
    assert_eq!(d.accounts[1].uid, None);
    assert_eq!(
        d.groups.iter().find(|g| g.name == "staff").unwrap().gid,
        Some(1099)
    );
}

#[test]
fn the_desired_state_survives_the_wire() {
    let d = plan(&cfg(ACCESS), "gpu1");
    let json = serde_json::to_string(&d).unwrap();
    let back: NodeDesired = serde_json::from_str(&json).unwrap();
    assert_eq!(back, d);
    assert_eq!(back.protocol, grantctl::PROTOCOL);
}
