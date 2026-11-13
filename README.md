# grantctl

One file to manage who can log in where, with what rights, across a small Linux cluster.

This branch (`rust`) is the Rust implementation, version 2, **in development**. The production
version is the bash implementation on the [`main`](https://github.com/nst-sdc/grantctl/tree/main)
branch (published as nst-cockpit 1.0.0).

- Design and milestones: [docs/DESIGN.md](docs/DESIGN.md)
- Target platform: Ubuntu 26.04 LTS and later
- Distribution: `ppa:nst-sdc/grantctl` (first release will be 2.0.0)

## Status

| Milestone | Scope | State |
|---|---|---|
| M1 | Configuration model, validation, token editing, per-node desired state, parity tests against v1, offline commands | done |
| M2 | Node side: `grantctl node facts` / `node apply` (widen, switch, narrow), backups, rollback | next |
| M3 | Control side: SSH transport, `sync`, `grant`, `revoke`, `init`, `audit`, `node install`, ... | |
| M4 | Packaging, PPA release, cutover of the NST cluster | |

What works today, without contacting any node:

```bash
cargo build
G="target/debug/grantctl --config-dir tests/fixtures/teaching"
$G roles                                         # effective role table
$G check --operator alice                        # validate the configuration
$G plan gpu1 --operator alice --control-ip 192.0.2.10          # what gpu1 should look like
$G plan gpu1 --operator alice --control-ip 192.0.2.10 --json   # the same, as sent to a node
```

The configuration formats (`access.conf`, `roles.ini`, `nodes`) are the ones v1 uses. See
`tests/fixtures/teaching/` for a complete example.

## Development

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

- `tests/logic.rs`: the unit tests of v1, ported, plus cases for behaviour new in v2.
- `tests/parity.rs`: the planner must reproduce the output of the published bash v1 for the fixture
  cluster. The expected output is `tests/golden/teaching.golden`; regenerate it on Linux with
  `tests/golden/regen-from-v1.sh` and `git show main:bin/nst-cockpit`.

Minimum supported Rust: 1.91 (Ubuntu 26.04 ships 1.93). Dependencies are limited to `clap`,
`serde` and `serde_json`, because the PPA build has no network access.

## License

MIT
