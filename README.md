# nst-cockpit

One file to manage who can log in where, with what rights, across a small Linux cluster.

`nst-cockpit` is a single bash script that runs on a **control node**. It keeps every node's accounts, SSH access, sudo rights and resource limits in step with one source of truth, `/etc/nst-cockpit/access.conf`:

```
alice      admin nopasswd
bob        admin
carol      student
dave       student gpu
erin       user@node3,node4
frank      locked
```

Run `nst-cockpit sync`. Every node then has exactly those accounts, group memberships, sshd rules, sudoers entries, limits and locks. Built at [NST](https://github.com/nst-sdc) for a teaching cluster with a jump host, k3s workers and a shared GPU box.

## Features

- **Roles, scoped per node.** Tokens look like `admin`, `user@node3` or `gpu`. Roles live in `roles.ini`, and adding one is a few lines, not code.
- **Whole auth picture per node:**
  - accounts, with UIDs matched to the control node where they are free;
  - exact group membership;
  - sshd `AllowGroups` and password-login policy;
  - source-IP restrictions, including a jump-host pattern;
  - sudoers rules and NOPASSWD;
  - pam_limits, systemd per-user slice limits, disk quotas;
  - account locks.
- **Account operations across all nodes:** `where`, `passwd`, `lock`, `unlock`, `delete --purge`, `adopt`, `prune`.
- **Safe by default:**
  - `--dry-run` shows every change, including SSH gains and losses, and the content of every file it would remove;
  - `visudo` and `sshd -t` checks with automatic rollback;
  - backups before each change;
  - refuses any change that would lock out the operator or empty the sudo group.
- **`audit`:** a read-only report of every auth-related setting it does not own, PAM gaps, foreign sudoers files, UID drift and more.
- **Adopts existing clusters.** `init` inventories the nodes and drafts `access.conf` from what it finds. Old hand-made files are absorbed through `LEGACY_*` settings.
- **No agent and no daemon.** It needs only bash, SSH and sudo, and the nodes need nothing installed.

## Requirements

- Debian or Ubuntu nodes with systemd: Ubuntu 20.04+ or Debian 11+, so that `sshd_config.d` is supported.
- On the control node: bash 4.4+, awk (mawk or gawk), openssl, iproute2.
- Your account needs an SSH key that reaches every node, and passwordless sudo on every node except the control node.
- Optional: the `quota` package on nodes that use the `quota` role key.

## Install

On the control node:

```bash
git clone https://github.com/nst-sdc/nst-cockpit.git
cd nst-cockpit
sudo ./install.sh          # or: sudo make install   (PREFIX=/usr/local)
man nst-cockpit
```

`sudo ./install.sh --uninstall` removes the script and the man page. It leaves your configuration and the files on the nodes untouched.

## Quick start (new or existing cluster)

```bash
# 1. snapshot auth state on every node first (rollback point)
for h in node1 node2 node3 gpu1; do
  ssh -t "$h" 'sudo tar czf /root/pre-cockpit.tgz -C / etc/passwd etc/shadow etc/group etc/gshadow etc/ssh etc/sudoers etc/sudoers.d etc/security'
done

# 2. initialise (control node first). Writes /etc/nst-cockpit/* and drafts access.conf. Changes nothing on the nodes.
nst-cockpit init node1 node2 node3 gpu1
nst-cockpit audit                      # read every WARN line

# 3. adapt roles to the groups you already use, then redraft if you changed them
sudoedit /etc/nst-cockpit/roles.ini    # see examples/roles.ini
sudo rm /etc/nst-cockpit/access.conf && nst-cockpit init

# 4. resolve every 'review' in the draft
sudoedit /etc/nst-cockpit/access.conf

# 5. preview, then apply one node at a time, control node last, with a root shell open as a safety net
nst-cockpit sync --dry-run
nst-cockpit sync node2 && nst-cockpit sync node3 && nst-cockpit sync gpu1 && nst-cockpit sync node1
```

## Day to day

```bash
nst-cockpit grant rahul student            # new student
nst-cockpit grant priya admin nopasswd     # new admin
nst-cockpit grant rahul user --on node3    # shell on one node
nst-cockpit revoke rahul --on node3        # remove everything rahul has on node3
nst-cockpit lock rahul                     # suspend (blocks keys too, kills sessions)
nst-cockpit passwd rahul                   # temporary password, forced change at next login
nst-cockpit where rahul                    # account state on every node
nst-cockpit sync --dry-run                 # drift check
```

## How it works

| File (control node) | Purpose |
|---|---|
| `/etc/nst-cockpit/access.conf` | users and their tokens (the roster: never commit it) |
| `/etc/nst-cockpit/roles.ini` | what each role means |
| `/etc/nst-cockpit/nodes` | node list, control node first |
| `/etc/nst-cockpit/cockpit.conf` | site settings: `CONTROL`, `SUDO_GROUP`, `LEGACY_*` |
| `/etc/nst-cockpit/sshd-baseline` | global sshd settings |

On every node, `sync` owns exactly these:

| File | Content |
|---|---|
| `/etc/ssh/sshd_config.d/10-nst-cockpit.conf` | baseline + `AllowGroups` |
| `/etc/ssh/sshd_config.d/99-nst-cockpit.conf` | `Match` blocks: password login, per-group options, source IPs |
| `/etc/sudoers.d/10-nst-cockpit` | `%sudo`, role group rules, NOPASSWD lines (written last) |
| `/etc/security/limits.d/60-nst-cockpit.conf` | group pam_limits |
| `/etc/systemd/system/user-<uid>.slice.d/50-nst-limits.conf` | per-user cgroup limits |

It also manages the membership of every group named in `roles.ini`, account locks and quotas. Accounts not listed in `access.conf` are reported, never modified.

### Role keys

```ini
[gpu]
groups   = gpu-users                    # required
nodes    = gpu1                         # default nodes (all | list)
password = yes                          # allow SSH password login
from     = control                      # only via the control node (or: any | ip,ip)
sshd     = MaxSessions=4,X11Forwarding=no
sudo     = no                           # yes: %group ALL=(ALL:ALL) ALL
home     = /srv/gpu-home                # base dir for accounts it creates
slice    = CPUQuota=800%,MemoryMax=20G  # systemd per-user slice
quota    = 90G                          # block quota on home's filesystem
limits   = nproc=1024,maxlogins=4       # pam_limits for the group
```

## Gotchas (learned the hard way)

- **sudo uses the last matching rule.** A `%group ALL` line read after your NOPASSWD line silently overrides it. nst-cockpit writes NOPASSWD last. List old group-rule files in `LEGACY_SUDO`.
- **`visudo -c` fails on any sudoers file that is not mode 0440**, including unrelated old ones. nst-cockpit validates its own file first, then the whole tree after the legacy files are removed.
- **Open sessions keep their old groups.** After a sync, test from a new login.
- **A forced password change needs a TTY.** First logins must use a terminal. Editor remote extensions fail until the password has been changed once.
- **Never remove a group from `AllowGroups` while people still depend on it.** Use `--dry-run` and read every `SSH lose` line.

## Development

```bash
make check     # bash -n, shellcheck, man page lint, unit tests (tests/run.sh, no root needed)
```

CI runs the tests under both mawk and gawk. The pure logic is covered by unit tests: token editing, validation, per-node plans, rendered sshd/sudoers/limits, and the init draft. Changes to node-side behaviour should be tried with `sync --dry-run` on a real cluster before release.

## License

MIT. See [LICENSE](LICENSE).
