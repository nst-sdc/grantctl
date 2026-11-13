//! The machine as the node side sees it.
//!
//! Everything `grantctl node ...` does to a machine goes through `System`.
//! `RealSystem` runs the usual tools (`useradd`, `gpasswd`, `visudo`, ...);
//! `fake::FakeSystem` simulates them so the apply logic, including failures
//! half way through, can be tested on any OS without root.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

#[derive(Debug, Clone, Default)]
pub struct Output {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
}

pub trait System {
    /// Run a command that only reads or checks (`getent`, `visudo -c`, `sshd -t`).
    fn query(&self, argv: &[&str]) -> Output;
    /// Run a command that changes the machine.
    fn run(&mut self, argv: &[&str], stdin: Option<&str>) -> Result<(), String>;
    fn read(&self, path: &str) -> Option<String>;
    /// File names in a directory, sorted. Empty when it does not exist.
    fn list(&self, dir: &str) -> Vec<String>;
    /// Write a file atomically with the given permission bits.
    fn write(&mut self, path: &str, content: &str, mode: u32) -> Result<(), String>;
    /// Remove a file. Removing a missing file is not an error.
    fn remove(&mut self, path: &str) -> Result<(), String>;
}

pub struct RealSystem;

fn exec(argv: &[&str], stdin: Option<&str>) -> Output {
    let mut cmd = Command::new(argv[0]);
    cmd.args(&argv[1..])
        .env("LC_ALL", "C")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            return Output {
                ok: false,
                stdout: String::new(),
                stderr: format!("{}: {e}", argv[0]),
            }
        }
    };
    if let (Some(text), Some(mut pipe)) = (stdin, child.stdin.take()) {
        let _ = pipe.write_all(text.as_bytes());
    }
    match child.wait_with_output() {
        Ok(out) => Output {
            ok: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        },
        Err(e) => Output {
            ok: false,
            stdout: String::new(),
            stderr: format!("{}: {e}", argv[0]),
        },
    }
}

impl System for RealSystem {
    fn query(&self, argv: &[&str]) -> Output {
        exec(argv, None)
    }

    fn run(&mut self, argv: &[&str], stdin: Option<&str>) -> Result<(), String> {
        let out = exec(argv, stdin);
        if out.ok {
            Ok(())
        } else {
            let detail = out.stderr.trim();
            Err(if detail.is_empty() {
                format!("{} failed", argv.join(" "))
            } else {
                format!("{}: {detail}", argv.join(" "))
            })
        }
    }

    fn read(&self, path: &str) -> Option<String> {
        std::fs::read_to_string(path).ok()
    }

    fn list(&self, dir: &str) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .filter_map(|e| e.file_name().into_string().ok())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    fn write(&mut self, path: &str, content: &str, mode: u32) -> Result<(), String> {
        let target = Path::new(path);
        let fail = |e: std::io::Error| format!("{path}: {e}");
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(fail)?;
        }
        // A name with a second extension is ignored by sshd (*.conf) and by
        // sudo (no dots), so a half-written file is never read.
        let tmp = format!("{path}.grantctl-tmp");
        std::fs::write(&tmp, content).map_err(fail)?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode)).map_err(fail)?;
        std::fs::rename(&tmp, target).map_err(fail)
    }

    fn remove(&mut self, path: &str) -> Result<(), String> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("{path}: {e}")),
        }
    }
}

// ---------------------------------------------------------------- reading the account database

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
}

impl User {
    /// Accounts of people, as opposed to system accounts.
    pub fn is_human(&self) -> bool {
        (1000..60000).contains(&self.uid)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grp {
    pub name: String,
    pub gid: u32,
    pub members: Vec<String>,
}

pub fn users(sys: &dyn System) -> Vec<User> {
    sys.query(&["getent", "passwd"])
        .stdout
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split(':').collect();
            Some(User {
                name: f.first()?.to_string(),
                uid: f.get(2)?.parse().ok()?,
                gid: f.get(3)?.parse().ok()?,
                home: f.get(5)?.to_string(),
                shell: f.get(6).unwrap_or(&"").to_string(),
            })
        })
        .collect()
}

pub fn groups(sys: &dyn System) -> Vec<Grp> {
    sys.query(&["getent", "group"])
        .stdout
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split(':').collect();
            Some(Grp {
                name: f.first()?.to_string(),
                gid: f.get(2)?.parse().ok()?,
                members: f
                    .get(3)
                    .unwrap_or(&"")
                    .split(',')
                    .filter(|m| !m.is_empty())
                    .map(String::from)
                    .collect(),
            })
        })
        .collect()
}

/// Fields of the user's shadow entry: (password hash, last change, expiry).
pub fn shadow(sys: &dyn System, user: &str) -> Option<(String, String, String)> {
    let out = sys.query(&["getent", "shadow", user]);
    let line = out.stdout.lines().next()?;
    let f: Vec<&str> = line.split(':').collect();
    Some((
        f.get(1)?.to_string(),
        f.get(2).unwrap_or(&"").to_string(),
        f.get(7).unwrap_or(&"").to_string(),
    ))
}

/// grantctl locks an account by locking the password and setting the expiry
/// date to day 1, which also blocks SSH keys. Expiry day 1 is the marker.
pub fn is_locked(sys: &dyn System, user: &str) -> bool {
    shadow(sys, user).is_some_and(|(_, _, expire)| expire == "1")
}

pub fn hostname(sys: &dyn System) -> String {
    sys.query(&["hostname"]).stdout.trim().to_string()
}

pub const SSHD_CONFIG: &str = "/etc/ssh/sshd_config";

/// Lines of the main sshd_config and every drop-in, in the order sshd reads
/// the drop-ins: (file path, line).
pub fn sshd_lines(sys: &dyn System) -> Vec<(String, String)> {
    let dir = crate::desired::SSHD_DIR;
    let mut files: Vec<String> = sys
        .list(dir)
        .into_iter()
        .filter(|n| n.ends_with(".conf"))
        .map(|n| format!("{dir}/{n}"))
        .collect();
    files.push(SSHD_CONFIG.to_string());
    let mut lines = Vec::new();
    for file in files {
        for line in sys.read(&file).unwrap_or_default().lines() {
            lines.push((file.clone(), line.trim().to_string()));
        }
    }
    lines
}

/// Arguments of every `keyword` line in the sshd configuration files.
pub fn sshd_values(sys: &dyn System, keyword: &str) -> Vec<String> {
    sshd_lines(sys)
        .iter()
        .filter_map(|(_, line)| {
            let mut words = line.split_whitespace();
            words
                .next()
                .filter(|w| w.eq_ignore_ascii_case(keyword))
                .map(|_| words.map(String::from).collect::<Vec<_>>())
        })
        .flatten()
        .collect()
}
