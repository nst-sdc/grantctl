//! Parity with the bash v1 (nst-cockpit 1.0.0).
//!
//! `tests/golden/teaching.golden` was produced by running the published v1
//! against `tests/fixtures/teaching` (see `tests/golden/regen-from-v1.sh`).
//! The Rust planner must produce the same accounts, group memberships and
//! sshd / sudoers / limits rules for every node.

use grantctl::config::Config;
use grantctl::desired::{self, Hints, NodeDesired};
use std::path::Path;

/// The golden text for one node, in the format the v1 generator writes.
fn golden(d: &NodeDesired) -> String {
    // Each owned file starts with a header line that v1 did not have.
    let body = |text: &str| {
        text.split_once('\n')
            .map(|(_, rest)| rest.to_string())
            .unwrap_or_default()
    };
    let mut out = format!("=== {}\n", d.node);
    let accounts: Vec<String> = d
        .accounts
        .iter()
        .map(|a| format!("{}:{}", a.user, a.home_base))
        .collect();
    out += &format!("accounts={}\n", accounts.join(" "));
    out += &format!("managed={}\n", d.managed_users.join(" "));
    out += &format!("locked={}\n", d.locked.join(" "));
    out += &format!("allow={}\n", d.allow_groups.join(" "));
    for g in &d.groups {
        out += &format!("group {}={}\n", g.name, g.members.join(","));
    }
    let slices: Vec<String> = d
        .slices
        .iter()
        .map(|s| format!("{}:{}", s.user, s.settings.join(",")))
        .collect();
    out += &format!("slices={}\n", slices.join(" "));
    let quotas: Vec<String> = d
        .quotas
        .iter()
        .map(|q| format!("{}:{}:{}", q.user, q.size, q.base))
        .collect();
    out += &format!("quotas={}\n", quotas.join(" "));
    out += "--- match\n";
    out += &body(&d.sshd_match);
    out += "--- sudoers\n";
    out += &body(&d.sudoers);
    out += "--- limits\n";
    out += &body(&d.limits);
    out
}

#[test]
fn teaching_cluster_matches_v1() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let cfg = Config::load(&root.join("fixtures/teaching")).unwrap();
    let expected = std::fs::read_to_string(root.join("golden/teaching.golden")).unwrap();
    // The generator ran v1 with these control node addresses.
    let hints = Hints {
        control_ips: vec!["192.0.2.10".into(), "192.0.2.11".into()],
        ..Hints::default()
    };
    let mut actual = String::new();
    for node in &cfg.nodes {
        actual += &golden(&desired::build(&cfg, node, "alice", &hints).unwrap());
    }
    if actual != expected {
        for (i, (a, e)) in actual.lines().zip(expected.lines()).enumerate() {
            assert_eq!(
                a,
                e,
                "first difference at line {} (left: v2, right: v1)",
                i + 1
            );
        }
        assert_eq!(
            actual.lines().count(),
            expected.lines().count(),
            "line count differs"
        );
        panic!("outputs differ only in line endings");
    }
}

#[test]
fn the_fixture_is_a_valid_configuration() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/teaching");
    let cfg = Config::load(&root).unwrap();
    assert_eq!(
        grantctl::validate::validate(&cfg, "alice"),
        Vec::<String>::new()
    );
}
