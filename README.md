# grantctl

One file to manage who can log in where, with what rights, across a small Linux cluster.

Each user is one line in `/etc/grantctl/access.conf`:

```
alice    admin nopasswd          # sudo everywhere
maya     student gpu@gpu1        # shell on the jump host, GPU box as well
ravi     user@node3 locked       # account kept, login blocked
```

Roles (`admin`, `student`, `gpu`, ...) are defined in `roles.ini`: which Unix groups they mean, on
which nodes, whether password login is allowed, from where, with which resource limits.
`grantctl sync` then makes every node match: accounts, exact group membership, sshd and sudoers
rules, pam limits, systemd slice limits, quotas and locks.

- Runs from one **control node** over SSH. No daemon, no open port.
- **Safe ordering**: access is added first, then the sudoers and sshd files are replaced
  (validated with `visudo` and `sshd -t`, rolled back on failure), and only then is access removed.
  A failed run cannot lock anyone out.
- `--dry-run` shows every change first, including who gains and who loses SSH access.
- **One password everywhere**: new accounts copy the user's password from the control node.
- Accounts that are not in the file are reported, never touched.

Target platform: Ubuntu 26.04 LTS and later.

## Install

On the control node and on every node:

```bash
sudo add-apt-repository ppa:nst-sdc/grantctl
sudo apt install grantctl
```

Or install it on the control node only and let it install itself on the others:

```bash
grantctl node install node2 node3 gpu1          # from the PPA
grantctl node install --copy node2 node3 gpu1   # copy the binary, for nodes without internet
```

You need SSH access and sudo on every node. After the first sync you need the `nopasswd` flag on
every node except the control node.

## First run

```bash
grantctl init node1 node2 node3 gpu1    # control node first; drafts access.conf from the nodes
sudoedit /etc/grantctl/roles.ini        # define your roles (see examples/)
sudoedit /etc/grantctl/access.conf      # resolve every `review`
grantctl check
grantctl sync --dry-run                 # read this before the real thing
grantctl sync
```

`init` changes nothing on the nodes. Files of earlier tooling that grantctl should replace go into
`LEGACY_SSHD` / `LEGACY_SUDO` in `/etc/grantctl/grantctl.conf`.

## Every day

```bash
grantctl grant maya student             # new user: account, groups, one temporary password
grantctl grant maya gpu --on gpu1
grantctl where maya                     # state on every node
grantctl revoke maya gpu
grantctl lock maya                      # keys and password blocked, sessions ended
grantctl passwd maya                    # new temporary password on all nodes
grantctl delete maya --purge
grantctl audit                          # what else on the nodes affects access
```

Full reference: `man grantctl`. Design and guarantees: [docs/DESIGN.md](docs/DESIGN.md).

## Development

```bash
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

| Test | What it proves | Needs |
|---|---|---|
| `cargo test` | parsers, planner (pinned by a golden snapshot), apply ordering and failure handling against a simulated machine, whole commands against a simulated cluster | nothing |
| `tests/system/node.sh` | the node side with real `useradd`, `visudo`, `sshd -t` | root in a **disposable** container |
| `tests/e2e/run.sh` | control node and two nodes over real SSH | docker |

CI runs all of them, and builds the Debian package offline the way Launchpad does.

Minimum supported Rust: 1.91 (Ubuntu 26.04 ships 1.93). Dependencies are limited to `clap`,
`serde` and `serde_json`, all packaged in Ubuntu, because the PPA build has no network access.

## License

MIT
