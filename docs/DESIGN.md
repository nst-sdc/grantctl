# grantctl design

Status: implemented in grantctl 1.0.0.
Maintainers: Krushn Dayshmookh, Raghav.

## 1. Background

grantctl manages accounts, SSH access, sudo rights and resource limits on every node of a small
cluster from one file on a control node. It is written in Rust and built for the NST teaching
cluster.

Design choices that follow from how such tools usually fail:

- A tool that sends generated shell to each node cannot unit-test that half of itself. grantctl
  sends a typed desired state to the same binary on the node instead (section 3).
- Changing group membership before switching sshd can lock people out: when the sudoers step fails
  in between, the old sshd rules are still active but the old groups are already empty, and new
  logins are refused. grantctl orders its changes so that this cannot happen (section 6).

## 2. Requirements

Functional:

- Model: `access.conf` lists users with roles and flags, optionally scoped per node; `roles.ini`
  defines roles.
- Commands: `grant`, `revoke`, `lock`, `unlock`, `where`, `passwd`, `delete`, `adopt`, `prune`,
  `init`, `sync`, `audit`, `status`, `list`, `roles`, `check` (validate offline), `plan <node>`
  (show the desired state offline), `node install <host>...` (install grantctl on a node over SSH).
- A cluster with hand-made sshd, sudoers and limits files moves to grantctl by listing those files
  as `LEGACY_*` and running `sync`. No manual cleanup.

Non-functional:

- A failed or interrupted sync must never leave a node where someone who had access before, and
  should have it after, cannot log in.
- No daemon and no listening port. Everything runs over the operator's SSH session.
- Supported platform: Ubuntu 26.04 LTS and later. 26.04 ships rustc 1.93.1.
- Few dependencies: `clap`, `serde`, `serde_json`. All three are packaged in Ubuntu 26.04
  (clap 4.5.53, serde 1.0.228, serde_json 1.0.145).

Out of scope for 1.0: LDAP/SSSD, SSH key distribution, password synchronisation between nodes,
non-Debian distributions, a web UI.

## 3. Architecture

One binary, installed on the control node and on every managed node.

```
 control node                                   every node (including the control node)
 +--------------------------------------+       +------------------------------------------+
 | /etc/grantctl/                       |       | grantctl node facts   -> JSON            |
 |   access.conf roles.ini nodes ...    |       | grantctl node apply   <- desired state   |
 |                                      |  SSH  |                       -> report (JSON)   |
 | grantctl sync                        | ----> | (run as root through `sudo -n`)          |
 |   load + validate config             |       |                                          |
 |   build desired state per node       |       | uses: useradd, gpasswd, usermod, chage,  |
 |   send it, print the node's report   |       |       visudo, sshd -t, systemctl,        |
 +--------------------------------------+       |       setquota                           |
                                                +------------------------------------------+
```

- **Control side**: reads the configuration, validates it, and computes a `NodeDesired` for each
  node. Pure functions, no I/O beyond reading the configuration.
- **Node side**: `grantctl node apply` reads a `NodeDesired` as JSON on stdin, compares it with the
  machine, and applies the difference in a fixed order (section 6). With `--dry-run` it only reports.
  It answers with a JSON report: every action taken or needed, warnings, and whether it stopped.
- **Transport**: the system `ssh` binary (`BatchMode=yes`), then `sudo -n grantctl node ...`.
  On the control node itself: `sudo grantctl node ...` without SSH.

Decision: the node computes the difference, not the control node. The alternative was to collect
facts first and send a list of steps. Diffing on the node needs one round trip instead of two and
cannot act on stale facts. The rules that matter (who is in which group, what the sshd and sudoers
files contain) are still decided centrally, in tested code.

### Protocol

Every message carries `protocol` (currently 1). Before anything else the control side runs
`grantctl node version --json` on the node. A different protocol number stops the sync for that node
with the instruction to run `grantctl node install <host>`. grantctl never sends a desired state to
a node that speaks another protocol.

## 4. Configuration

Directory: `/etc/grantctl` (override: `--config-dir`, `GRANTCTL_CONF`).

| File | Content |
|---|---|
| `access.conf` | `<user> <token>...` per line; token = `role`, `role@node,node`, or a flag (`locked`, `nopasswd`, `pwonly`), flags can be scoped too |
| `roles.ini` | one `[role]` section: `groups`, `nodes`, `password`, `from`, `sshd`, `sudo`, `home`, `slice`, `quota`, `limits`; unknown keys are an error |
| `nodes` | node names, control node first |
| `grantctl.conf` | `KEY=VALUE`: `CONTROL`, `SUDO_GROUP`, `SHELL_ROLE`, `LEGACY_*`; parsed, never executed as shell |
| `sshd-baseline` | global sshd settings |

Strict on purpose:

- The operator must have sudo on every node and the `nopasswd` flag on every node except the control
  node.
- Role names cannot be flag names. `quota` must look like `90G`.
- A short node name must match exactly one node (`3` for `node3`); ambiguous names are an error.

## 5. Desired state

`desired::build(config, node, operator, hints)` returns a `NodeDesired`:

- `accounts`: users who must have an account on the node, with the home base for new accounts and
  the UID to prefer (the user's UID on the control node).
- `groups`: every group named in `roles.ini` with its exact membership on this node. Groups that
  must be empty here are listed with no members.
- `locked`: managed users whose account must be locked.
- `sshd_main`, `sshd_match`, `sudoers`, `limits`: the full content of the four files grantctl owns.
- `slices`, `quotas`: per-user systemd slice settings and block quotas.
- `legacy`: files of other tools to remove once grantctl's files are validated, as listed in
  `LEGACY_*` in `grantctl.conf`.

Owned files on a node:

| File | Why this name |
|---|---|
| `/etc/ssh/sshd_config.d/10-grantctl.conf` | sshd keeps the first value it reads; must sort before `50-cloud-init.conf` |
| `/etc/ssh/sshd_config.d/99-grantctl.conf` | Match blocks; must be the last file |
| `/etc/sudoers.d/99-grantctl` | sudo applies the last matching rule; sorts last, NOPASSWD lines at the end |
| `/etc/security/limits.d/60-grantctl.conf` | group pam_limits |
| `/etc/systemd/system/user-<uid>.slice.d/50-grantctl.conf` | per-user cgroup limits |

The planner's output is pinned by a snapshot: `tests/golden.rs` compares it for a four-node
fixture with `tests/golden/teaching.golden`. Accounts, groups, locks, AllowGroups, Match blocks,
sudoers rules, limits, slices and quotas are covered.

When a user holds several roles that define `home`, `slice` or `quota`, the first role on the
user's line wins.

## 6. Applying a desired state (node side)

Order of operations in `grantctl node apply`. The rule: **widen, switch, narrow**.

1. **Guards.** Refuse without changing anything if the state would remove the operator from the
   sudo group, drop the operator's NOPASSWD on a non-control node, leave the sudo group empty, or
   leave the sudo group out of `AllowGroups`. Validate the new sudoers file with `visudo -cf` before
   it is installed.
2. **Widen.** Create groups and accounts, add group memberships, unlock accounts. Nothing is
   removed. After this step everyone who had access still has it under the old rules, and everyone
   who should gain access is already in the right groups.
3. **Switch.** Back up `sshd_config.d`, `sudoers.d` and `limits.d`. Install the sudoers file, remove
   legacy sudoers files, check the whole tree with `visudo -c`. Install limits. Install the sshd
   files, remove legacy sshd files, run `sshd -t`, reload sshd. Any failure restores the backup and
   **stops the run**.
4. **Narrow.** Only after the switch succeeded: remove group memberships, lock accounts, remove
   slice limits that no longer apply.
5. **Limits.** Write slice drop-ins and set quotas.

If the run stops in step 3, the node has its old files and a superset of its old memberships.
Nobody is locked out: memberships are only removed after the new sshd rules are live.

The report lists every action with a phase and a result. `--dry-run` produces the same list without
acting, including who gains and who loses SSH access.

Backups go to `/var/backups/grantctl/<timestamp>/`. State (applied quotas) lives in
`/var/lib/grantctl/`.

## 7. Installing on nodes

`grantctl node install <host>...` from the control node:

- default: adds `ppa:nst-sdc/grantctl` on the host and installs the package (`ssh -t`, so a sudo
  password prompt works the first time);
- `--copy`: copies the control node's own binary to `/usr/local/sbin/grantctl` on the host, for
  hosts without internet access and for testing before a release exists. All nodes run the same
  Ubuntu release and architecture, so the binary is compatible.

`sync` reports nodes where grantctl is missing or speaks another protocol, with the exact
`node install` command. `grantctl node upgrade` upgrades the package everywhere.

## 8. Passwords

Rule: a user has the same password on every node, unless they change it on a node themselves.

- The control node is the source. `sync` asks it for the usable password hashes of the managed
  users (`grantctl node hashes`) after the control node itself has been synced.
- A new account on another node gets that hash, and the "must change at next login" state with it.
- Each node records the hash grantctl last set (`/var/lib/grantctl/passwords`, root only). On a
  later sync, a newer hash from the control node is applied only where the account still has the
  recorded hash, that is, where the user has not changed the password on that node.
- A user who is new everywhere gets one temporary password on the control node, printed once; the
  other nodes copy it in the same run. A user without an account on the control node gets one
  temporary password on all their nodes.
- Accounts that existed before grantctl have no recorded hash and are never overwritten.
  `grantctl passwd <user>` (new temporary password everywhere) or
  `grantctl passwd <user> --from-control` (copy the control node's) brings them under the rule.
- Hashes travel inside the desired state over SSH, are set with `chpasswd -e` on stdin, and never
  appear in a report, a dry-run or a process list.

Limit: a password changed on the control node reaches the other nodes at the next `sync`, not
immediately.

## 9. Testing

| Level | What | Where it runs |
|---|---|---|
| Unit | parsers, validation, token editing, desired state | `cargo test`, any OS |
| Snapshot | planner output for the fixture cluster equals the reviewed golden file | `tests/golden.rs` |
| Apply, simulated | `node apply` against an in-memory machine: ordering, guards, failure injection at every phase, replacing legacy files | `tests/apply.rs` |
| Commands, simulated | `sync`, `grant`, `revoke`, `lock`, `passwd`, `prune`, `delete`, `init`, `adopt`, `audit` against a simulated 3-node cluster | `tests/control.rs` |
| Apply, real | the node side as root with real `useradd`, `gpasswd`, `visudo`, `sshd -t`, `chpasswd`: converge, idempotence, failed switch restores byte-identical files, guards, passwords | `tests/system/node.sh`, CI in `ubuntu:26.04` |
| End to end | control container and two node containers over real SSH: init, `node install --copy`, sync, password login with the printed password, day-to-day commands, an unreachable node | `tests/e2e/run.sh`, CI |
| Package | `dpkg-buildpackage` offline in `ubuntu:26.04`, install, run | CI |

Two defects were found by these levels and not by review: group IDs carried over from the control
node could collide with automatically assigned ones (simulated commands), and two runs within one
second shared a backup directory, so a restore could bring back an older file (real apply).

Rehearsal on the NST cluster (2026-11-13, 1.0.0 built by CI, read-only): `sync --dry-run` on the
five reachable nodes. grantctl planned no account, group, lock or password change, and on every
node the sshd, sudoers and limits rules it would write were line for line the rules already in
place.

## 10. Packaging

- `debian/` in this repository, native package, built for 26.04 (`resolute`) in
  `ppa:nst-sdc/grantctl`.
- Launchpad builders have no network. The build uses the Rust crates packaged in the archive
  (`librust-clap-4.5+derive-dev`, `librust-serde-1+derive-dev`, `librust-serde-json-dev`) through a
  cargo directory source, so nothing is vendored and nothing is downloaded. `Cargo.lock` pins the
  crates.io versions used in development and is set aside during the package build.
- The package installs `/usr/bin/grantctl`, the man page and example configuration.
- n1 of the NST cluster runs Ubuntu 25.10, which is end of life. It must be upgraded to 26.04
  before it can install the package; until then `grantctl node install --copy` works.

## 11. Milestones

| | Scope | State |
|---|---|---|
| M1 | Configuration model, validation, token editing, desired state, snapshot tests | done |
| M2 | Node side: `node facts`, `node apply` with widen/switch/narrow, backups and rollback, account operations | done |
| M3 | Control side: SSH transport, `sync`, `grant`/`revoke`/`lock`, `init`/`adopt`/`prune`, `audit`, `status`, `where`, `passwd`, `delete`, `node install` | done |
| M4 | Packaging, man page, CI for real-system, end-to-end and package builds | done |
| Release | PPA upload of 1.0.0, rehearsal and cutover on NST | maintainers |

## 12. Risks and what to revisit

- **First real sync on production.** The apply logic is tested against simulated machines, a
  real Ubuntu system and containers over SSH, and the dry run on NST matched the rules in place. A
  real sync has not run on NST yet: do it one node at a time, with a root shell open.
- **Version skew** between control node and nodes is possible. The protocol check stops it, at the
  cost of an install step per node.
- **Serial sync.** 1.0 syncs nodes one after another, control node first. Parallel sync is easy to
  add once the report format has settled; it is not needed for seven nodes.
- **PAM** (faillock, `nullok`) is reported by `audit` but not managed.
- **`where`** does not show the last login or quota usage.
