//! Whole commands (`sync`, `grant`, `init`, ...) against a cluster of
//! simulated machines, wired together in this process instead of over SSH.

use grantctl::control::transport::InProcess;
use grantctl::control::{self, Ctx};
use grantctl::Error;
use std::path::PathBuf;

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
slice    = CPUQuota=800%
";

const ACCESS: &str = "\
alice admin nopasswd
bob   admin
carol student
dave  student gpu
";

struct Lab {
    dir: PathBuf,
    cluster: InProcess,
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Lab {
    /// Three machines set up by hand (the operator has sudo everywhere) and
    /// a configuration directory.
    fn new(name: &str, access: Option<&str>) -> Lab {
        let dir = std::env::temp_dir().join(format!("grantctl-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("nodes"), "node1\nnode2\ngpu1\n").unwrap();
        std::fs::write(dir.join("roles.ini"), ROLES).unwrap();
        if let Some(access) = access {
            std::fs::write(dir.join("access.conf"), access).unwrap();
        }
        let cluster = InProcess::new("node1", &["node1", "node2", "gpu1"]);
        for node in ["node1", "node2", "gpu1"] {
            cluster.with(node, |sys| {
                sys.add_user("alice", 1001);
                sys.add_group("sudo", 27, &["alice"]);
                sys.dirs.insert("/srv/gpu-home".into());
            });
        }
        Lab { dir, cluster }
    }

    /// Run a command as alice; returns its result and what it printed.
    fn run<T>(&self, f: impl FnOnce(&mut Ctx) -> T) -> (T, String) {
        let mut out = Vec::new();
        let mut ctx = Ctx {
            dir: self.dir.clone(),
            transport: &self.cluster,
            operator: "alice".into(),
            out: &mut out,
            yes: true,
        };
        let result = f(&mut ctx);
        (result, String::from_utf8(out).unwrap())
    }

    fn sync(&self) -> (bool, String) {
        let (ok, out) = self.run(|c| control::sync(c, &[], false));
        (ok.unwrap(), out)
    }

    fn access(&self) -> String {
        std::fs::read_to_string(self.dir.join("access.conf")).unwrap()
    }

    fn members(&self, node: &str, group: &str) -> Vec<String> {
        self.cluster.with(node, |s| {
            s.members(group).iter().map(|m| m.to_string()).collect()
        })
    }

    fn mutations(&self) -> usize {
        ["node1", "node2", "gpu1"]
            .iter()
            .map(|n| self.cluster.with(n, |s| s.log.len()))
            .sum()
    }
}

fn words(list: &[&str]) -> Vec<String> {
    list.iter().map(|w| w.to_string()).collect()
}

// ---------------------------------------------------------------- sync

#[test]
fn sync_converges_every_node_control_first() {
    let lab = Lab::new("sync", Some(ACCESS));
    let (ok, out) = lab.sync();
    assert!(ok, "{out}");
    let pos = |needle: &str| {
        out.find(needle)
            .unwrap_or_else(|| panic!("no {needle:?} in:\n{out}"))
    };
    assert!(pos("===== node1") < pos("===== node2") && pos("===== node2") < pos("===== gpu1"));
    assert_eq!(lab.members("node1", "students"), ["carol", "dave"]);
    assert_eq!(lab.members("node2", "sudo"), ["alice", "bob"]);
    assert_eq!(lab.members("gpu1", "gpu-users"), ["dave"]);
    assert!(lab.members("node2", "students").is_empty());
    // from = control resolved to the control node's address
    lab.cluster.with("gpu1", |s| {
        let rules = s.file("/etc/ssh/sshd_config.d/99-grantctl.conf").unwrap();
        assert!(rules.contains("Address *,!10.0.0.1"), "{rules}");
    });

    let before = lab.mutations();
    let (ok, out) = lab.sync();
    assert!(ok);
    assert_eq!(out.matches("in sync").count(), 3, "{out}");
    assert_eq!(
        lab.mutations(),
        before,
        "a second sync must not touch anything"
    );
}

#[test]
fn a_dry_run_shows_the_changes_and_makes_none() {
    let lab = Lab::new("dry", Some(ACCESS));
    let (ok, out) = lab.run(|c| control::sync(c, &[], true));
    assert!(ok.unwrap());
    assert_eq!(lab.mutations(), 0);
    for expected in [
        "[node1] would: create account bob (home /home/bob)",
        "[node1] would: add carol to students",
        "[node1] would: install /etc/sudoers.d/99-grantctl",
        "[node1]     + alice ALL=(ALL:ALL) NOPASSWD: ALL",
        "[gpu1]     + AllowGroups gpu-users shell-users staff sudo",
        "changes pending",
    ] {
        assert!(out.contains(expected), "missing {expected:?} in:\n{out}");
    }
    assert!(!out.contains("Temporary passwords"));
}

#[test]
fn a_new_user_gets_one_temporary_password_on_all_their_nodes() {
    let lab = Lab::new("pw", Some(ACCESS));
    let (_, out) = lab.sync();
    assert!(out.contains("Temporary passwords"), "{out}");
    let hash = |node: &str, user: &str| lab.cluster.with(node, |s| s.users[user].hash.clone());
    let on_node1 = hash("node1", "bob");
    assert!(on_node1.starts_with("$fake$"));
    assert_eq!(hash("node2", "bob"), on_node1);
    assert_eq!(hash("gpu1", "bob"), on_node1);
    assert_ne!(
        hash("node1", "carol"),
        on_node1,
        "every user gets their own password"
    );
    lab.cluster
        .with("node2", |s| assert_eq!(s.users["bob"].last_change, "0"));
    // The password that was printed is the one that was set.
    let printed = out
        .lines()
        .find(|l| l.trim_start().starts_with("bob "))
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap();
    assert_eq!(on_node1, format!("$fake${printed}"));
}

#[test]
fn an_existing_user_gaining_a_node_gets_a_hint_not_a_password() {
    let lab = Lab::new("hint", Some(ACCESS));
    lab.sync();
    let before = lab.cluster.with("node1", |s| s.users["carol"].hash.clone());
    let (result, out) =
        lab.run(|c| control::grant(c, "carol", &words(&["user"]), &Some("node2".into()), true));
    assert!(result.unwrap(), "{out}");
    assert!(
        lab.access().contains("student user@node2"),
        "{}",
        lab.access()
    );
    assert!(out.contains("grantctl passwd carol --on node2"), "{out}");
    assert!(!out.contains("Temporary passwords"), "{out}");
    lab.cluster
        .with("node2", |s| assert_eq!(s.users["carol"].hash, "!"));
    lab.cluster
        .with("node1", |s| assert_eq!(s.users["carol"].hash, before));
}

#[test]
fn unreachable_and_bare_nodes_are_skipped_and_reported() {
    let lab = Lab::new("down", Some(ACCESS));
    lab.cluster.down.borrow_mut().insert("gpu1".into());
    lab.cluster
        .not_installed
        .borrow_mut()
        .insert("node2".into());
    let (ok, out) = lab.sync();
    assert!(!ok, "a partial sync must not report success");
    assert!(out.contains("[gpu1] UNREACHABLE, skipped"), "{out}");
    assert!(
        out.contains("[node2] grantctl is not installed there. Run: grantctl node install node2"),
        "{out}"
    );
    assert!(
        out.contains("NOT synced: node2 gpu1  -> later: grantctl sync node2 gpu1"),
        "{out}"
    );
    assert_eq!(lab.members("node1", "students"), ["carol", "dave"]);
    assert_eq!(lab.cluster.with("gpu1", |s| s.log.len()), 0);

    lab.cluster.down.borrow_mut().clear();
    lab.cluster.not_installed.borrow_mut().clear();
    let (ok, out) = lab.run(|c| control::sync(c, &words(&["node2", "gpu1"]), false));
    assert!(ok.unwrap(), "{out}");
    assert!(!out.contains("===== node1"));
    assert_eq!(lab.members("gpu1", "gpu-users"), ["dave"]);
}

#[test]
fn a_node_that_refuses_fails_the_sync_but_not_the_other_nodes() {
    let lab = Lab::new("refuse", Some(ACCESS));
    lab.cluster.with("node2", |s| {
        s.fail_on = vec!["systemctl reload-or-restart".into()]
    });
    let (ok, out) = lab.sync();
    assert!(!ok);
    assert!(
        out.contains("[node2] FAILED:") && out.contains("no access was removed"),
        "{out}"
    );
    assert_eq!(
        lab.members("gpu1", "gpu-users"),
        ["dave"],
        "later nodes are still synced"
    );
}

// ---------------------------------------------------------------- editing

#[test]
fn grant_and_revoke_edit_validate_and_sync() {
    let lab = Lab::new("grant", Some(ACCESS));
    lab.sync();
    let (r, out) = lab.run(|c| control::grant(c, "erin", &words(&["student"]), &None, true));
    assert!(r.unwrap(), "{out}");
    assert!(lab.access().contains("erin"));
    assert_eq!(lab.members("node1", "students"), ["carol", "dave", "erin"]);

    // Short node names are expanded; --on scopes the role.
    lab.run(|c| control::grant(c, "erin", &words(&["user"]), &Some("2,gpu1".into()), true))
        .0
        .unwrap();
    assert!(
        lab.access().contains("student user@node2,gpu1"),
        "{}",
        lab.access()
    );

    let (r, _) = lab.run(|c| control::revoke(c, "erin", &[], &Some("gpu1".into()), true));
    assert!(r.unwrap());
    assert!(
        lab.access().contains("student user@node2\n")
            || lab.access().contains("student user@node2 "),
        "{}",
        lab.access()
    );
    assert!(lab.members("gpu1", "shell-users").is_empty());
    assert_eq!(lab.members("node2", "shell-users"), ["erin"]);

    let (r, _) = lab.run(|c| control::revoke(c, "erin", &[], &None, true));
    assert!(r.unwrap());
    assert!(!lab.access().contains("erin"));
    assert_eq!(lab.members("node1", "students"), ["carol", "dave"]);
}

#[test]
fn an_edit_that_breaks_the_configuration_never_reaches_the_disk() {
    let lab = Lab::new("guard", Some(ACCESS));
    type Command = Box<dyn Fn(&mut Ctx) -> grantctl::Result<bool>>;
    let cases: [(&str, Command); 4] = [
        (
            "unknown role",
            Box::new(|c| control::grant(c, "erin", &words(&["wizard"]), &None, true)),
        ),
        (
            "unknown node",
            Box::new(|c| control::grant(c, "erin", &words(&["user"]), &Some("node9".into()), true)),
        ),
        (
            "own sudo",
            Box::new(|c| control::revoke(c, "alice", &words(&["admin"]), &None, true)),
        ),
        (
            "own lock",
            Box::new(|c| control::lock(c, "alice", true, &None, true)),
        ),
    ];
    for (name, command) in cases {
        let (result, _) = lab.run(|c| command(c));
        assert!(result.is_err(), "{name} should be refused");
        assert_eq!(lab.access(), ACCESS, "{name} changed access.conf");
    }
    assert_eq!(lab.mutations(), 0);
    let (result, _) = lab.run(|c| control::revoke(c, "alice", &words(&["admin"]), &None, true));
    assert!(matches!(result, Err(Error::Invalid(_))));
}

#[test]
fn lock_and_unlock_follow_the_roster() {
    let lab = Lab::new("lock", Some(ACCESS));
    lab.sync();
    lab.run(|c| control::lock(c, "dave", true, &None, true))
        .0
        .unwrap();
    assert!(lab.access().contains("dave  ") || lab.access().contains("dave "));
    assert!(lab.access().contains("locked"));
    assert!(lab.cluster.with("node1", |s| s.locked("dave")));
    assert!(lab.cluster.with("gpu1", |s| s.locked("dave")));
    lab.run(|c| control::lock(c, "dave", false, &None, true))
        .0
        .unwrap();
    assert!(!lab.access().contains("locked"));
    assert!(!lab.cluster.with("gpu1", |s| s.locked("dave")));
}

// ---------------------------------------------------------------- accounts

#[test]
fn passwd_where_delete_and_prune() {
    let lab = Lab::new("ops", Some(ACCESS));
    lab.sync();

    let (ok, out) = lab.run(|c| control::passwd(c, "dave", &None));
    assert!(ok.unwrap(), "{out}");
    let printed = out
        .lines()
        .last()
        .unwrap()
        .split_whitespace()
        .nth(4)
        .unwrap()
        .to_string();
    for node in ["node1", "gpu1"] {
        lab.cluster.with(node, |s| {
            assert_eq!(s.users["dave"].hash, format!("$fake${printed}"))
        });
    }
    assert!(out.contains("[node2] no account"), "{out}");

    let (_, out) = lab.run(|c| control::where_(c, "dave"));
    assert!(out.contains("access.conf: dave student gpu"), "{out}");
    assert!(
        out.contains("[gpu1] uid=")
            && out.contains("(must-change)")
            && out.contains("home=/srv/gpu-home/dave"),
        "{out}"
    );

    // dave loses the GPU role: the account on gpu1 stays behind as a stray.
    lab.run(|c| control::revoke(c, "dave", &words(&["gpu"]), &None, true))
        .0
        .unwrap();
    let (_, out) = lab.sync();
    assert!(
        out.contains("[gpu1] STRAY accounts (no access here, not locked): dave"),
        "{out}"
    );
    let (_, out) = lab.run(|c| control::prune(c, true));
    assert!(out.contains("[gpu1] would lock stray dave"), "{out}");
    assert!(!lab.cluster.with("gpu1", |s| s.locked("dave")));
    lab.run(|c| control::prune(c, false)).0.unwrap();
    assert!(lab.cluster.with("gpu1", |s| s.locked("dave")));
    assert!(
        !lab.cluster.with("node1", |s| s.locked("dave")),
        "only the stray account is locked"
    );

    let (ok, _) = lab.run(|c| control::delete(c, "dave", true));
    assert!(ok.unwrap());
    assert!(!lab.access().contains("dave"));
    for node in ["node1", "gpu1"] {
        lab.cluster
            .with(node, |s| assert!(!s.users.contains_key("dave")));
    }
    assert!(
        lab.run(|c| control::delete(c, "alice", false)).0.is_err(),
        "the operator cannot delete themselves"
    );
}

#[test]
fn status_and_audit_report_without_changing_anything() {
    let lab = Lab::new("report", Some(ACCESS));
    lab.sync();
    lab.cluster.with("node2", |s| {
        s.add_user("mallory", 1010);
        s.set_file(
            "/etc/sudoers.d/50-mallory",
            "mallory ALL=(ALL) NOPASSWD: ALL\n",
            0o440,
        );
        s.users.get_mut("bob").unwrap().uid = 4242;
    });
    let before = lab.mutations();
    let (ok, out) = lab.run(|c| control::status(c, &[]));
    assert!(ok.unwrap());
    assert!(out.contains("[node1] students: carol,dave"), "{out}");
    assert!(out.contains("[gpu1] sudoers.d: 99-grantctl"), "{out}");

    let (ok, out) = lab.run(|c| control::audit(c, &[]));
    assert!(ok.unwrap());
    assert!(
        out.contains("[node2] WARN unmanaged account: mallory"),
        "{out}"
    );
    assert!(
        out.contains("[node2] WARN foreign sudoers file /etc/sudoers.d/50-mallory:"),
        "{out}"
    );
    assert!(out.contains("[cluster] info uid differs for bob:"), "{out}");
    assert_eq!(lab.mutations(), before);
}

// ---------------------------------------------------------------- init, adopt

/// Nodes as they were before grantctl: groups maintained by hand.
fn hand_made(name: &str) -> Lab {
    let lab = Lab::new(name, None);
    for node in ["node1", "node2", "gpu1"] {
        lab.cluster
            .with(node, |s| s.add_group("staff", 1099, &["alice"]));
    }
    lab.cluster.with("node1", |s| {
        s.add_user("carol", 1003);
        s.add_group("students", 1108, &["carol"]);
        s.add_user("ghost", 1009);
        s.add_user("heidi", 1012);
        s.add_group("sudo", 27, &["alice", "heidi"]);
        s.set_file(
            "/etc/sudoers.d/00-alice",
            "alice ALL=(ALL:ALL) NOPASSWD: ALL\n",
            0o440,
        );
    });
    lab.cluster.with("gpu1", |s| {
        s.add_user("dave", 1004);
        s.add_group("gpu-users", 1018, &["dave"]);
        s.add_user("erin", 1005);
        s.set_file(
            "/etc/ssh/sshd_config.d/00-lockdown.conf",
            "AllowUsers alice dave erin\n",
            0o644,
        );
    });
    lab
}

#[test]
fn init_drafts_the_roster_from_the_nodes() {
    let lab = hand_made("init");
    std::fs::remove_file(lab.dir.join("nodes")).unwrap();
    let (result, out) = lab.run(|c| control::init(c, &words(&["node1", "node2", "gpu1"]), None));
    result.unwrap();
    assert!(out.contains("need review"), "{out}");
    let access = lab.access();
    let line = |user: &str| {
        let l = access
            .lines()
            .find(|l| l.starts_with(&format!("{user} ")))
            .unwrap_or_else(|| panic!("no {user} in\n{access}"));
        l.split('#')
            .next()
            .unwrap()
            .split_whitespace()
            .skip(1)
            .collect::<Vec<_>>()
            .join(" ")
    };
    assert_eq!(line("alice"), "admin nopasswd@node1");
    assert_eq!(line("carol"), "student");
    assert_eq!(line("dave"), "gpu");
    assert_eq!(
        line("erin"),
        "user@gpu1",
        "SSH access outside any role becomes the shell role"
    );
    assert_eq!(line("ghost"), "review");
    assert_eq!(
        line("heidi"),
        "review",
        "sudo that no role explains must be reviewed"
    );
    assert!(
        access.contains("sudo on node1 is not covered by a role"),
        "{access}"
    );
    assert_eq!(lab.mutations(), 0, "init only reads");
    assert!(std::fs::read_to_string(lab.dir.join("grantctl.conf"))
        .unwrap()
        .contains("CONTROL=node1"));

    // The draft is refused until every review is resolved.
    let (result, _) = lab.run(|c| control::sync(c, &[], true));
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("unresolved review"));
    assert!(
        lab.run(|c| control::init(c, &[], None)).0.is_err(),
        "init never overwrites a roster"
    );
}

#[test]
fn adopt_adds_one_existing_account() {
    let lab = hand_made("adopt");
    std::fs::write(lab.dir.join("access.conf"), "alice admin nopasswd\n").unwrap();
    let (result, out) = lab.run(|c| control::adopt(c, "dave"));
    assert!(result.unwrap(), "{out}");
    assert!(
        lab.access().contains("dave             gpu"),
        "{}",
        lab.access()
    );
    assert!(lab.run(|c| control::adopt(c, "dave")).0.is_err());
    assert!(lab.run(|c| control::adopt(c, "nobody")).0.is_err());
}

#[test]
fn a_v1_configuration_directory_can_be_imported() {
    let lab = Lab::new("import", None);
    let v1 = lab.dir.join("nst-cockpit");
    std::fs::create_dir_all(&v1).unwrap();
    std::fs::write(v1.join("nodes"), "node1\nnode2\ngpu1\n").unwrap();
    std::fs::write(v1.join("roles.ini"), ROLES).unwrap();
    std::fs::write(v1.join("access.conf"), ACCESS).unwrap();
    std::fs::write(v1.join("cockpit.conf"), "CONTROL=node1\nSUDO_GROUP=sudo\n").unwrap();
    let (result, out) = lab.run(|c| control::init(c, &[], Some(v1.as_path())));
    result.unwrap();
    assert!(out.contains("Imported"), "{out}");
    assert_eq!(lab.access(), ACCESS);
    assert!(lab.dir.join("grantctl.conf").exists());
    assert!(lab.sync().0);
}
