//! How the control side reaches `grantctl node ...` on a node.

use crate::node::fake::FakeSystem;
use crate::node::system::System;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::process::{Command, Stdio};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallError {
    /// SSH could not connect.
    Unreachable(String),
    /// The node has no grantctl binary.
    NotInstalled,
    /// The node command ran and failed.
    Failed(String),
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Unreachable(why) => write!(f, "unreachable: {why}"),
            CallError::NotInstalled => f.write_str("grantctl is not installed there"),
            CallError::Failed(why) => f.write_str(why),
        }
    }
}

pub trait Transport {
    /// Run `grantctl node <args>` as root on `node` with `stdin`; returns its stdout.
    fn node(&self, node: &str, args: &[&str], stdin: &str) -> Result<String, CallError>;
    /// Run a read-only command on the control node as the operator.
    /// `None` when it fails.
    fn local(&self, argv: &[&str]) -> Option<String>;
}

/// The real transport: `sudo` on the control node, `ssh ... sudo -n` elsewhere.
pub struct Ssh {
    /// Name of the control node; it is never reached over SSH.
    pub control: String,
    /// The grantctl binary on the nodes. A bare name is looked up in sudo's
    /// secure path.
    pub node_bin: String,
}

impl Transport for Ssh {
    fn node(&self, node: &str, args: &[&str], stdin: &str) -> Result<String, CallError> {
        let local = node == self.control;
        let mut cmd = if local {
            let mut c = Command::new("sudo");
            c.arg(&self.node_bin);
            c
        } else {
            let mut c = Command::new("ssh");
            c.args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=5", node, "--"]);
            c.args(["sudo", "-n", self.node_bin.as_str()]);
            c
        };
        cmd.arg("node")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd
            .spawn()
            .map_err(|e| CallError::Failed(format!("cannot start {:?}: {e}", cmd.get_program())))?;
        if let Some(mut pipe) = child.stdin.take() {
            let _ = pipe.write_all(stdin.as_bytes());
        }
        let out = child
            .wait_with_output()
            .map_err(|e| CallError::Failed(e.to_string()))?;
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        if out.status.success() {
            return Ok(stdout);
        }
        let missing = stderr.contains("command not found") || stderr.contains("No such file");
        Err(match out.status.code() {
            Some(255) if !local => CallError::Unreachable(stderr),
            _ if missing => CallError::NotInstalled,
            _ => CallError::Failed(if stderr.is_empty() { stdout } else { stderr }),
        })
    }

    fn local(&self, argv: &[&str]) -> Option<String> {
        let out = Command::new(argv[0]).args(&argv[1..]).output().ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

/// A cluster of simulated machines in this process. Used by the tests to run
/// whole commands (`sync`, `grant`, `init`, ...) without SSH or root.
#[doc(hidden)]
#[derive(Default)]
pub struct InProcess {
    pub control: String,
    pub systems: RefCell<BTreeMap<String, FakeSystem>>,
    /// Nodes that do not answer.
    pub down: RefCell<BTreeSet<String>>,
    /// Nodes without grantctl.
    pub not_installed: RefCell<BTreeSet<String>>,
}

impl InProcess {
    pub fn new(control: &str, nodes: &[&str]) -> InProcess {
        let systems = nodes
            .iter()
            .map(|n| (n.to_string(), FakeSystem::new(n)))
            .collect();
        InProcess {
            control: control.to_string(),
            systems: RefCell::new(systems),
            ..InProcess::default()
        }
    }

    /// Look at or change one simulated machine.
    pub fn with<T>(&self, node: &str, f: impl FnOnce(&mut FakeSystem) -> T) -> T {
        f(self
            .systems
            .borrow_mut()
            .get_mut(node)
            .unwrap_or_else(|| panic!("no simulated node {node}")))
    }
}

impl Transport for InProcess {
    fn node(&self, node: &str, args: &[&str], stdin: &str) -> Result<String, CallError> {
        if self.down.borrow().contains(node) {
            return Err(CallError::Unreachable("connection timed out".into()));
        }
        if self.not_installed.borrow().contains(node) {
            return Err(CallError::NotInstalled);
        }
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        let mut systems = self.systems.borrow_mut();
        let sys = systems
            .get_mut(node)
            .ok_or_else(|| CallError::Unreachable("unknown host".into()))?;
        crate::node::handle(sys, &args, stdin).map_err(CallError::Failed)
    }

    fn local(&self, argv: &[&str]) -> Option<String> {
        let systems = self.systems.borrow();
        let out = systems.get(&self.control)?.query(argv);
        out.ok.then_some(out.stdout)
    }
}
