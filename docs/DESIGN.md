# grantctl v2 design

Status: draft for review. Milestone 1 is implemented; sections marked **open** need a decision.
Maintainers: Krushn Dayshmookh, Raghav.

## 1. Background

grantctl manages accounts, SSH access, sudo rights and resource limits on every node of a small
cluster from one file on a control node. Version 1 was a 750-line bash script (`nst-cockpit`, on the
`main` branch) that is in production on the NST cluster. Version 2 is a rewrite in Rust.

Why rewrite:

- Most defects found while building and rolling out v1 were shell and awk defects: an awk builtin
  name collision (`RS`), `pipefail` aborts inside subshells, zsh/bash word-splitting differences,
  quoting of generated scripts.
- v1 sends generated shell to each node. That half of the tool cannot be unit-tested.
- One defect was a design flaw, not a language flaw: v1 changed group membership before it switched
  sshd. When the sudoers step failed in between, the old sshd rules were still active but the old
  groups were already empty, and new logins to the control node were refused. v2 fixes the ordering
  (section 6).

## 2. Requirements

Functional:

- Same model as v1: `access.conf` lists users with roles and flags, optionally scoped per node;
  `roles.ini` defines roles. Existing v1 configuration directories work unchanged.
- Same commands as v1: `grant`, `revoke`, `lock`, `unlock`, `where`, `passwd`, `delete`, `adopt`,
  `prune`, `init`, `sync`, `audit`, `status`, `list`, `roles`.
- New: `check` (validate offline), `plan <node>` (show the desired state offline),
  `node install <host>...` (install grantctl on a node over SSH).
- A v1 cluster moves to v2 by installing v2 and running `sync`. No manual cleanup.

Non-functional:

- A failed or interrupted sync must never leave a node where someone who had access before, and
  should have it after, cannot log in.
- No daemon and no listening port. Everything runs over the operator's SSH session.
- Supported platform: Ubuntu 26.04 LTS and later. 26.04 ships rustc 1.93.1.
- Few dependencies: `clap`, `serde`, `serde_json`. All three are packaged in Ubuntu 26.04
  (clap 4.5.53, serde 1.0.228, serde_json 1.0.145).

Out of scope for 2.0: LDAP/SSSD, SSH key distribution, password synchronisation between nodes,
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
  node. Pure functions, no I/O beyond reading the configuration. Implemented and tested (M1).
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

| File | Content | Change from v1 |
|---|---|---|
| `access.conf` | `<user> <token>...` per line; token = `role`, `role@node,node`, or a flag (`locked`, `nopasswd`, `pwonly`), flags can be scoped too | none |
| `roles.ini` | one `[role]` section: `groups`, `nodes`, `password`, `from`, `sshd`, `sudo`, `home`, `slice`, `quota`, `limits` | unknown keys are now an error |
| `nodes` | node names, control node first | none |
| `grantctl.conf` | `KEY=VALUE`: `CONTROL`, `SUDO_GROUP`, `SHELL_ROLE`, `LEGACY_*` | was `cockpit.conf`; parsed, never executed as shell |
| `sshd-baseline` | global sshd settings | none |

Stricter than v1, on purpose:

- The operator must have sudo on every node and the `nopasswd` flag on every node except the control
  node. v1 only required a role literally named `admin`.
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
- `legacy`: files of other tools to remove once grantctl's files are validated. The v1 file names
  are always included, which is what makes the v1 to v2 move automatic.

Owned files on a node:

| File | Why this name |
|---|---|
| `/etc/ssh/sshd_config.d/10-grantctl.conf` | sshd keeps the first value it reads; must sort before `50-cloud-init.conf` |
| `/etc/ssh/sshd_config.d/99-grantctl.conf` | Match blocks; must be the last file |
| `/etc/sudoers.d/99-grantctl` | sudo applies the last matching rule; sorts last, NOPASSWD lines at the end (v1 used `10-`) |
| `/etc/security/limits.d/60-grantctl.conf` | group pam_limits |
| `/etc/systemd/system/user-<uid>.slice.d/50-grantctl.conf` | per-user cgroup limits |

Parity with v1 is tested: `tests/parity.rs` compares the planner's output for a four-node fixture
with the output of the published v1 for the same configuration (`tests/golden/`). Accounts, groups,
locks, AllowGroups, Match blocks, sudoers rules, limits, slices and quotas are identical.

One intended difference: when a user holds several roles that define `home`, `slice` or `quota`,
the first role on the user's line wins. v1 applied whichever sorted last.

## 6. Applying a desired state (node side, M2)

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

If the run stops in step 3, the node has its old files and a superset of its old memberships. The
v1 lockout cannot happen: memberships are only removed after the new sshd rules are live.

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

## 8. Passwords (**open**)

v1 generated new temporary passwords on every run, so syncing nodes one at a time gave a user a
different password on each node. Proposal for 2.0:

- A brand-new user (no account anywhere) gets one temporary password, set on every node where the
  account is created in that run, with a forced change.
- A user who already exists somewhere and gains a node gets an account with a locked password there.
  The sync report lists these with the command `grantctl passwd <user> --on <nodes>`.
- **Open:** should a new account instead inherit the user's password hash from the control node?
  It gives "same password as on the jump host" with no temporary password, at the cost of copying
  hashes between nodes. Passwords would still diverge after the next change.

## 9. Testing

| Level | What | Status |
|---|---|---|
| Unit | parsers, validation, token editing, desired state (the 36 v1 tests ported, plus new cases) | done |
| Parity | planner output equals v1 output for the fixture cluster | done |
| Node integration | `node apply` inside an Ubuntu 26.04 container: real `useradd`, `visudo`, `sshd -t`; failure injection for the widen/switch/narrow guarantees | M2 |
| End to end | control container plus node containers over SSH | M3 |
| Production rehearsal | v1 and v2 dry runs side by side on the NST cluster; switch when they agree | M4 |

CI: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test` on stable, and `cargo test` in an
`ubuntu:26.04` container with the distribution's rustc.

## 10. Packaging (M4)

- `debian/` in this repository, built for 26.04 (`resolute`) in `ppa:nst-sdc/grantctl`.
- Launchpad builders have no network. Two ways to provide the crates; decide in M4:
  build against the archive's `librust-*-dev` packages with dh-cargo (no vendoring, tied to the
  archive's versions), or ship a vendored tarball (self-contained, larger source package).
- The package installs `/usr/bin/grantctl`, the man page and example configuration.
- n1 of the NST cluster runs Ubuntu 25.10, which is end of life. It must be upgraded to 26.04 before
  the cutover.

## 11. Milestones

| | Scope | State |
|---|---|---|
| M1 | Configuration model, validation, token editing, desired state, parity tests, offline CLI (`roles`, `list`, `check`, `plan`) | done |
| M2 | Node side: `node facts`, `node apply` with widen/switch/narrow, backups and rollback, account operations, container tests | next |
| M3 | Control side: SSH transport, `sync`, `grant`/`revoke`/`lock`, `init`/`adopt`/`prune`, `audit`, `status`, `where`, `passwd`, `delete`, `node install` | |
| M4 | Packaging, man page, PPA release 2.0.0, side-by-side rehearsal and cutover on NST | |

## 12. Risks and what to revisit

- **Parity on the node side.** The planner is proven against v1; the apply logic is new code. The
  container tests in M2 and the side-by-side dry run in M4 are the safety net.
- **Version skew** between control node and nodes is new in v2. The protocol check stops it, at the
  cost of an install step per node.
- **Serial sync.** 2.0 syncs nodes one after another, control node first. Parallel sync is easy to
  add once the report format is stable; it is not needed for seven nodes.
- **PAM** (faillock, `nullok`) is reported by `audit` but not managed. Revisit after 2.0.
