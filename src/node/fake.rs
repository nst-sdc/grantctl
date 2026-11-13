//! An in-memory machine for tests.
//!
//! `FakeSystem` implements just enough of `getent`, `useradd`, `gpasswd`,
//! `usermod`, `visudo`, `sshd -t`, `cp -a` and friends for the node side to
//! run against it. Every mutation is recorded in `log`, and any command can
//! be made to fail, which is how the tests prove what happens when a run
//! breaks half way through.

use super::system::{Output, System};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
pub struct FakeUser {
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    /// Shadow fields: password hash, last change, expiry.
    pub hash: String,
    pub last_change: String,
    pub expire: String,
}

#[derive(Debug, Clone, Default)]
pub struct FakeSystem {
    pub host: String,
    pub users: BTreeMap<String, FakeUser>,
    pub groups: BTreeMap<String, (u32, BTreeSet<String>)>,
    /// path -> (content, mode)
    pub files: BTreeMap<String, (String, u32)>,
    pub dirs: BTreeSet<String>,
    /// Directories that are quota-enabled mount points.
    pub quota_mounts: BTreeSet<String>,
    /// Every mutation, in order.
    pub log: Vec<String>,
    /// A mutation whose log line contains one of these fails.
    pub fail_on: Vec<String>,
    /// The effective uid `id -u` reports.
    pub euid: u32,
}

fn ok(stdout: impl Into<String>) -> Output {
    Output {
        ok: true,
        stdout: stdout.into(),
        stderr: String::new(),
    }
}

fn bad(stderr: impl Into<String>) -> Output {
    Output {
        ok: false,
        stdout: String::new(),
        stderr: stderr.into(),
    }
}

impl FakeSystem {
    /// A freshly installed machine: root, a sudo group, the usual directories.
    pub fn new(host: &str) -> FakeSystem {
        let mut sys = FakeSystem {
            host: host.to_string(),
            ..FakeSystem::default()
        };
        sys.users.insert(
            "root".into(),
            FakeUser {
                uid: 0,
                gid: 0,
                home: "/root".into(),
                hash: "*".into(),
                last_change: "19000".into(),
                expire: String::new(),
            },
        );
        sys.groups.insert("root".into(), (0, BTreeSet::new()));
        sys.groups.insert("sudo".into(), (27, BTreeSet::new()));
        for dir in [
            "/home",
            "/run/systemd/system",
            "/etc/ssh/sshd_config.d",
            "/etc/sudoers.d",
            "/etc/security/limits.d",
        ] {
            sys.dirs.insert(dir.into());
        }
        sys.set_file(
            "/etc/ssh/sshd_config",
            "Include /etc/ssh/sshd_config.d/*.conf\n",
            0o644,
        );
        sys
    }

    pub fn add_user(&mut self, name: &str, uid: u32) {
        self.users.insert(
            name.into(),
            FakeUser {
                uid,
                gid: uid,
                home: format!("/home/{name}"),
                hash: "$y$fake".into(),
                last_change: "19000".into(),
                expire: String::new(),
            },
        );
        self.groups
            .entry(name.into())
            .or_insert((uid, BTreeSet::new()));
    }

    pub fn add_group(&mut self, name: &str, gid: u32, members: &[&str]) {
        self.groups.insert(
            name.into(),
            (gid, members.iter().map(|m| m.to_string()).collect()),
        );
    }

    pub fn set_file(&mut self, path: &str, content: &str, mode: u32) {
        self.files.insert(path.into(), (content.into(), mode));
    }

    pub fn file(&self, path: &str) -> Option<&str> {
        self.files.get(path).map(|(c, _)| c.as_str())
    }

    pub fn members(&self, group: &str) -> Vec<&str> {
        self.groups
            .get(group)
            .map(|(_, m)| m.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    pub fn locked(&self, user: &str) -> bool {
        self.users.get(user).is_some_and(|u| u.expire == "1")
    }

    fn is_dir(&self, path: &str) -> bool {
        let prefix = format!("{path}/");
        self.dirs.contains(path) || self.files.keys().any(|f| f.starts_with(&prefix))
    }

    fn files_under(&self, dir: &str) -> Vec<String> {
        let prefix = format!("{dir}/");
        self.files
            .keys()
            .filter(|f| f.starts_with(&prefix))
            .cloned()
            .collect()
    }

    fn record(&mut self, line: String) -> Result<(), String> {
        let failing = self.fail_on.iter().any(|p| line.contains(p.as_str()));
        self.log.push(line.clone());
        if failing {
            Err(format!("{line}: injected failure"))
        } else {
            Ok(())
        }
    }

    fn user_mut(&mut self, name: &str) -> Result<&mut FakeUser, String> {
        self.users
            .get_mut(name)
            .ok_or_else(|| format!("user '{name}' does not exist"))
    }
}

impl System for FakeSystem {
    fn query(&self, argv: &[&str]) -> Output {
        match argv {
            ["id", "-u"] => ok(format!("{}\n", self.euid)),
            ["hostname"] => ok(format!("{}\n", self.host)),
            ["date", ..] => ok("20261113-120000\n"),
            ["ip", "route", "show", "default"] => ok("default via 10.0.0.254 dev eth0\n"),
            ["ip", "-o", "addr", "show", "dev", "eth0", ..] => {
                ok("2: eth0    inet 10.0.0.1/24 brd 10.0.0.255 scope global eth0\n")
            }
            ["getent", "passwd"] => ok(self
                .users
                .iter()
                .map(|(n, u)| format!("{n}:x:{}:{}::{}:/bin/bash\n", u.uid, u.gid, u.home))
                .collect::<String>()),
            ["getent", "group"] => ok(self
                .groups
                .iter()
                .map(|(n, (gid, m))| {
                    format!(
                        "{n}:x:{gid}:{}\n",
                        m.iter().cloned().collect::<Vec<_>>().join(",")
                    )
                })
                .collect::<String>()),
            ["getent", "shadow"] => ok(self
                .users
                .iter()
                .map(|(n, u)| {
                    format!(
                        "{n}:{}:{}:0:99999:7::{}:\n",
                        u.hash, u.last_change, u.expire
                    )
                })
                .collect::<String>()),
            ["getent", "shadow", name] => match self.users.get(*name) {
                Some(u) => ok(format!(
                    "{name}:{}:{}:0:99999:7::{}:\n",
                    u.hash, u.last_change, u.expire
                )),
                None => bad(""),
            },
            ["test", "-d", path] if self.is_dir(path) => ok(""),
            ["test", "-e", path] if self.is_dir(path) || self.files.contains_key(*path) => ok(""),
            ["mountpoint", "-q", path] if self.quota_mounts.contains(*path) => ok(""),
            ["sh", "-c", "command -v setquota"] if !self.quota_mounts.is_empty() => ok(""),
            // Like the real one: a syntax error or a wrong mode fails the check.
            ["visudo", "-cf", path] => match self.file(path) {
                Some(text) if !text.contains("SYNTAX ERROR") => ok(""),
                _ => bad(format!("{path}: syntax error")),
            },
            ["visudo", "-c"] => {
                for path in self.files_under("/etc/sudoers.d") {
                    let (text, mode) = &self.files[&path];
                    if path.rsplit('/').next().is_some_and(|n| n.contains('.')) {
                        continue;
                    }
                    if text.contains("SYNTAX ERROR") {
                        return bad(format!("{path}: syntax error"));
                    }
                    if *mode != 0o440 {
                        return bad(format!("{path}: bad permissions, should be mode 0440"));
                    }
                    // Test hook: a file can declare that it is only valid
                    // while another file is absent.
                    let clash = text
                        .lines()
                        .filter_map(|l| l.strip_prefix("#!conflicts "))
                        .any(|other| self.files.contains_key(&format!("/etc/sudoers.d/{other}")));
                    if clash {
                        return bad(format!("{path}: conflicting rule"));
                    }
                }
                ok("")
            }
            // A line saying BROKEN stands for any directive sshd rejects.
            ["sshd", "-t"] => {
                let mut files = self.files_under("/etc/ssh/sshd_config.d");
                files.retain(|f| f.ends_with(".conf"));
                files.push("/etc/ssh/sshd_config".into());
                match files
                    .iter()
                    .find(|f| self.file(f).is_some_and(|t| t.contains("BROKEN")))
                {
                    Some(f) => bad(format!("{f}: Bad configuration option: BROKEN")),
                    None => ok(""),
                }
            }
            _ => bad(""),
        }
    }

    fn run(&mut self, argv: &[&str], stdin: Option<&str>) -> Result<(), String> {
        self.record(argv.join(" "))?;
        match argv {
            ["groupadd", rest @ ..] => {
                let (gid, name) = match rest {
                    ["-g", gid, name] => (gid.parse().map_err(|_| "bad gid")?, *name),
                    [name] => {
                        let next = self.groups.values().map(|(g, _)| *g).max().unwrap_or(999) + 1;
                        (next.max(1000), *name)
                    }
                    _ => return Err("groupadd: bad arguments".into()),
                };
                if self.groups.contains_key(name) || self.groups.values().any(|(g, _)| *g == gid) {
                    return Err(format!(
                        "groupadd: group '{name}' or gid {gid} already exists"
                    ));
                }
                self.groups.insert(name.into(), (gid, BTreeSet::new()));
            }
            ["useradd", "-m", "-s", _, "-d", home, rest @ ..] => {
                let (uid, name) = match rest {
                    ["-u", uid, name] => (uid.parse().map_err(|_| "bad uid")?, *name),
                    [name] => {
                        let next = self.users.values().map(|u| u.uid).max().unwrap_or(999) + 1;
                        (next.max(1000), *name)
                    }
                    _ => return Err("useradd: bad arguments".into()),
                };
                if self.users.contains_key(name) || self.users.values().any(|u| u.uid == uid) {
                    return Err(format!(
                        "useradd: user '{name}' or uid {uid} already exists"
                    ));
                }
                let mut gid = uid;
                while self.groups.values().any(|(g, _)| *g == gid) {
                    gid += 1;
                }
                self.groups.insert(name.into(), (gid, BTreeSet::new()));
                self.users.insert(
                    name.into(),
                    FakeUser {
                        uid,
                        gid,
                        home: home.to_string(),
                        hash: "!".into(),
                        last_change: "19000".into(),
                        expire: String::new(),
                    },
                );
                self.dirs.insert(home.to_string());
            }
            ["gpasswd", flag @ ("-a" | "-d"), user, group] => {
                if !self.users.contains_key(*user) {
                    return Err(format!("gpasswd: user '{user}' does not exist"));
                }
                let Some((_, members)) = self.groups.get_mut(*group) else {
                    return Err(format!("gpasswd: group '{group}' does not exist"));
                };
                if *flag == "-a" {
                    members.insert(user.to_string());
                } else if !members.remove(*user) {
                    return Err(format!(
                        "gpasswd: user '{user}' is not a member of '{group}'"
                    ));
                }
            }
            ["usermod", "-L", "-e", "1", name] => {
                let user = self.user_mut(name)?;
                if !user.hash.starts_with('!') {
                    user.hash.insert(0, '!');
                }
                user.expire = "1".into();
            }
            ["usermod", "-e", "", name] => self.user_mut(name)?.expire.clear(),
            ["usermod", "-U", name] => {
                let user = self.user_mut(name)?;
                if user.hash.len() < 2 || !user.hash.starts_with('!') {
                    return Err(
                        "usermod: unlocking would leave the account without a password".into(),
                    );
                }
                user.hash.remove(0);
            }
            ["chpasswd", "-e"] => {
                let (name, hash) = stdin
                    .and_then(|s| s.trim().split_once(':'))
                    .ok_or("chpasswd: bad input")?;
                let user = self.user_mut(name)?;
                user.hash = hash.to_string();
                user.last_change = "20000".into();
            }
            ["chpasswd"] => {
                let (name, password) = stdin
                    .and_then(|s| s.trim().split_once(':'))
                    .ok_or("chpasswd: bad input")?;
                let user = self.user_mut(name)?;
                user.hash = format!("$fake${password}");
                user.last_change = "20000".into();
            }
            ["chage", "-d", "0", name] => self.user_mut(name)?.last_change = "0".into(),
            ["userdel", rest @ ..] => {
                let name = rest.last().copied().unwrap_or("");
                let user = self
                    .users
                    .remove(name)
                    .ok_or_else(|| format!("userdel: user '{name}' does not exist"))?;
                self.groups.remove(name);
                for (_, members) in self.groups.values_mut() {
                    members.remove(name);
                }
                if rest.first() == Some(&"-r") {
                    self.dirs.remove(&user.home);
                }
            }
            ["mkdir", "-p", dir] => {
                self.dirs.insert(dir.to_string());
            }
            ["rm", "-rf", dir] => {
                for path in self.files_under(dir) {
                    self.files.remove(&path);
                }
                self.dirs
                    .retain(|d| *d != *dir && !d.starts_with(&format!("{dir}/")));
            }
            ["cp", "-a", from, to] => {
                // Into an existing directory: to/<name of from>/...; otherwise to/...
                let target = if self.is_dir(to) {
                    format!("{to}/{}", from.rsplit('/').next().unwrap_or(""))
                } else {
                    to.to_string()
                };
                if !self.is_dir(from) {
                    return Err(format!("cp: cannot stat '{from}'"));
                }
                self.dirs.insert(target.clone());
                for path in self.files_under(from) {
                    let entry = self.files[&path].clone();
                    self.files
                        .insert(format!("{target}{}", &path[from.len()..]), entry);
                }
            }
            // Accepted without an effect worth modelling.
            ["chmod", ..]
            | ["pkill", ..]
            | ["crontab", ..]
            | ["systemctl", ..]
            | ["rmdir", ..]
            | ["kill", ..]
            | ["setquota", ..] => {}
            _ => return Err(format!("fake system: unknown command {}", argv.join(" "))),
        }
        Ok(())
    }

    fn read(&self, path: &str) -> Option<String> {
        self.file(path).map(String::from)
    }

    fn list(&self, dir: &str) -> Vec<String> {
        let prefix = format!("{dir}/");
        let names: BTreeSet<String> = self
            .files
            .keys()
            .chain(self.dirs.iter())
            .filter_map(|p| p.strip_prefix(&prefix))
            .map(|rest| rest.split('/').next().unwrap_or("").to_string())
            .collect();
        names.into_iter().collect()
    }

    fn write(&mut self, path: &str, content: &str, mode: u32) -> Result<(), String> {
        self.record(format!("write {path}"))?;
        self.files.insert(path.into(), (content.into(), mode));
        Ok(())
    }

    fn remove(&mut self, path: &str) -> Result<(), String> {
        self.record(format!("remove {path}"))?;
        self.files.remove(path);
        Ok(())
    }
}
