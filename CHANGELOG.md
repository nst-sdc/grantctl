# Changelog

## 1.0.0

First release of grantctl, the Rust successor of nst-cockpit (bash, on the `main` branch).

Same model and configuration formats as nst-cockpit; an existing `/etc/nst-cockpit` can be imported
with `grantctl init --from-cockpit`, and the first sync replaces nst-cockpit's files on every node.

Changed compared to nst-cockpit:

- One binary on the control node and on every node. The control side sends a typed desired state
  to `grantctl node apply` over SSH instead of a generated shell script.
  `grantctl node install` installs it on nodes (from the PPA, or `--copy`).
- Apply order is widen, switch, narrow. Memberships are removed and accounts locked only after the
  new sudoers and sshd files are validated and live. A failure restores the previous files and
  removes nobody's access. nst-cockpit changed groups first, which could lock people out when a
  later step failed.
- The generated sudoers file is checked before it is installed. A sudoers tree that was already
  invalid before the run (for example a foreign file with the wrong mode) is reported and no
  longer aborts the run.
- The sudoers file is now `99-grantctl` so that its NOPASSWD lines are the last match.
- Passwords follow the control node: a new account on another node gets the same password, and a
  password changed on the control node is copied at the next sync to nodes where the user has not
  changed it. nst-cockpit generated a different temporary password per node and run.
- An edit (`grant`, `revoke`, `lock`) is validated before access.conf is written.
- Validation is stricter: the operator needs sudo on every node and `nopasswd` on every node except
  the control node; unknown keys in roles.ini are errors; ambiguous short node names are errors.
- The dry run also reports accounts that lose SSH access when a node had no allow-list before.
- New commands: `check`, `plan`, `node install`, `passwd --from-control`.
- `where` no longer shows the last login and quota usage.

Requires Ubuntu 26.04 or later on every node.
