# Changelog

## 1.0.1

- Removed the import option of `init`. `init` only drafts a configuration from the nodes.
- No file is treated as legacy by default any more. grantctl replaces only the files listed in
  `LEGACY_SSHD`, `LEGACY_SUDO`, `LEGACY_LIMITS` and `LEGACY_SLICE_MARKER`.

## 1.0.0

First release.

- One binary on the control node and on every node. The control side sends a typed desired state
  to `grantctl node apply` over SSH instead of a generated shell script.
  `grantctl node install` installs it on nodes (from the PPA, or `--copy`).
- Apply order is widen, switch, narrow. Memberships are removed and accounts locked only after the
  new sudoers and sshd files are validated and live. A failure restores the previous files and
  removes nobody's access.
- The generated sudoers file is checked before it is installed. A sudoers tree that was already
  invalid before the run (for example a foreign file with the wrong mode) is reported and no
  longer aborts the run.
- The sudoers file is `99-grantctl` so that its NOPASSWD lines are the last match.
- Passwords follow the control node: a new account on another node gets the same password, and a
  password changed on the control node is copied at the next sync to nodes where the user has not
  changed it.
- An edit (`grant`, `revoke`, `lock`) is validated before access.conf is written.
- Validation is strict: the operator needs sudo on every node and `nopasswd` on every node except
  the control node; unknown keys in roles.ini are errors; ambiguous short node names are errors.
- The dry run also reports accounts that lose SSH access when a node had no allow-list before.
- Commands beyond the day-to-day ones: `check`, `plan`, `node install`, `passwd --from-control`.

Requires Ubuntu 26.04 or later on every node.
