use clap::{Args, Parser, Subcommand};
use grantctl::config::{self, Config};
use grantctl::control::transport::Ssh;
use grantctl::control::{self, Ctx};
use grantctl::desired::{self, Hints, NodeDesired};
use grantctl::node::system::RealSystem;
use grantctl::{validate, Error, Result};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Manage accounts, SSH, sudo and resource limits across a small cluster
/// from one file. Run it on the control node as yourself.
#[derive(Parser)]
#[command(name = "grantctl", version, propagate_version = true)]
struct Cli {
    /// Configuration directory
    #[arg(long, global = true, env = "GRANTCTL_CONF", default_value = config::DEFAULT_DIR)]
    config_dir: PathBuf,
    /// Act as this operator instead of the current user
    #[arg(long, global = true, hide = true)]
    operator: Option<String>,
    /// The grantctl binary on the nodes
    #[arg(
        long,
        global = true,
        env = "GRANTCTL_NODE_BIN",
        default_value = "grantctl",
        hide = true
    )]
    node_bin: String,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Args)]
struct On {
    /// Only these nodes (comma separated; short names work when unambiguous)
    #[arg(long, value_name = "NODES")]
    on: Option<String>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Add roles or flags to a user, then sync
    Grant {
        user: String,
        /// role, role@node,node, or a flag: locked, nopasswd, pwonly
        #[arg(required = true)]
        tokens: Vec<String>,
        #[command(flatten)]
        on: On,
        /// Only edit access.conf
        #[arg(long)]
        no_sync: bool,
    },
    /// Remove roles or flags; with none, drop the user from access.conf
    Revoke {
        user: String,
        tokens: Vec<String>,
        #[command(flatten)]
        on: On,
        #[arg(long)]
        no_sync: bool,
    },
    /// Lock an account: blocks passwords and keys, ends sessions
    Lock {
        user: String,
        #[command(flatten)]
        on: On,
        #[arg(long)]
        no_sync: bool,
    },
    /// Unlock an account
    Unlock {
        user: String,
        #[command(flatten)]
        on: On,
        #[arg(long)]
        no_sync: bool,
    },
    /// Show the state of an account on every node
    Where { user: String },
    /// Set a temporary password and force a change at next login
    Passwd {
        user: String,
        #[command(flatten)]
        on: On,
    },
    /// Delete an account on every node
    Delete {
        user: String,
        /// Also remove the home directory, slice limits and quota record
        #[arg(long)]
        purge: bool,
        /// Do not ask for confirmation
        #[arg(long)]
        yes: bool,
    },
    /// Add an existing account to access.conf from its current state
    Adopt {
        user: String,
        #[arg(long)]
        yes: bool,
    },
    /// Lock accounts that exist on nodes where the user has no access
    Prune {
        #[arg(long)]
        dry_run: bool,
    },
    /// Write the configuration and draft access.conf from the nodes
    Init {
        /// Control node first, then the other nodes
        nodes: Vec<String>,
        /// Copy an nst-cockpit (v1) configuration directory instead
        #[arg(long, value_name = "DIR", num_args = 0..=1, default_missing_value = "/etc/nst-cockpit")]
        from_cockpit: Option<PathBuf>,
    },
    /// Make nodes match access.conf
    Sync {
        /// Show what would change; change nothing
        #[arg(long)]
        dry_run: bool,
        /// Nodes to sync (default: all)
        nodes: Vec<String>,
    },
    /// Read-only report of auth settings grantctl does not manage
    Audit { nodes: Vec<String> },
    /// Role group members and owned files per node
    Status { nodes: Vec<String> },
    /// Print the effective role table
    Roles,
    /// Print access.conf
    List,
    /// Validate the configuration without contacting any node
    Check,
    /// Show what a node should look like (offline; nothing is contacted)
    Plan {
        /// Node name, or an unambiguous suffix of it
        node: String,
        /// Print the desired state as JSON, as sent to the node
        #[arg(long)]
        json: bool,
        /// Address of the control node, for roles with `from = control` (repeatable)
        #[arg(long = "control-ip", value_name = "IP")]
        control_ips: Vec<String>,
    },
    /// Print version and protocol
    Version,
    /// Install grantctl on nodes
    Node {
        #[command(subcommand)]
        command: NodeCmd,
    },
}

#[derive(Subcommand)]
enum NodeCmd {
    /// Install grantctl on hosts over SSH (from the PPA, or --copy this binary)
    Install {
        #[arg(required = true)]
        hosts: Vec<String>,
        /// Copy this binary to /usr/local/sbin instead of using the PPA
        #[arg(long)]
        copy: bool,
    },
    // The commands below run as root on a node. The control side calls them
    // over SSH; they read JSON on stdin and answer with JSON.
    #[command(hide = true)]
    Version,
    #[command(hide = true)]
    Facts,
    #[command(hide = true)]
    Apply {
        #[arg(long)]
        dry_run: bool,
    },
    #[command(hide = true)]
    Account,
    #[command(hide = true)]
    Audit,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(err) => {
            eprintln!("grantctl: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<bool> {
    let dir = cli.config_dir.as_path();
    let operator = cli
        .operator
        .clone()
        .or_else(|| std::env::var("SUDO_USER").ok())
        .or_else(|| std::env::var("USER").ok())
        .unwrap_or_default();

    // Offline commands.
    match &cli.command {
        Cmd::Roles => return roles(dir).map(|()| true),
        Cmd::List => {
            print!("{}", Config::load(dir)?.access.render());
            return Ok(true);
        }
        Cmd::Check => {
            let cfg = checked(dir, &operator)?;
            println!(
                "ok: {} users, {} roles, {} nodes (control: {})",
                cfg.access.entries().count(),
                cfg.roles.len(),
                cfg.nodes.len(),
                cfg.control()
            );
            return Ok(true);
        }
        Cmd::Plan {
            node,
            json,
            control_ips,
        } => {
            let cfg = checked(dir, &operator)?;
            let hints = Hints {
                control_ips: control_ips.clone(),
                ..Hints::default()
            };
            let state = desired::build(&cfg, &cfg.resolve_node(node)?, &operator, &hints)?;
            if *json {
                let text = serde_json::to_string_pretty(&state)
                    .map_err(|e| Error::msg(format!("cannot encode the plan: {e}")))?;
                println!("{text}");
            } else {
                print_plan(&state);
            }
            return Ok(true);
        }
        Cmd::Version => {
            println!(
                "grantctl {} (protocol {})",
                env!("CARGO_PKG_VERSION"),
                grantctl::PROTOCOL
            );
            return Ok(true);
        }
        Cmd::Node { command } => {
            if let Some(args) = node_args(command) {
                return node_side(&args);
            }
        }
        _ => {}
    }

    // Everything else talks to nodes from the control node.
    let control = match &cli.command {
        Cmd::Init { nodes, .. } if !dir.join("nodes").exists() => {
            nodes.first().cloned().unwrap_or_default()
        }
        _ => std::fs::read_to_string(dir.join("nodes"))
            .ok()
            .and_then(|text| {
                let site = std::fs::read_to_string(dir.join("grantctl.conf")).unwrap_or_default();
                Config::from_strs(&text, config::roles::DEFAULT_ROLES, "", &site).ok()
            })
            .map(|cfg| cfg.control().to_string())
            .unwrap_or_default(),
    };
    here_is(&control)?;
    let transport = Ssh {
        control,
        node_bin: cli.node_bin.clone(),
    };
    let mut stdout = std::io::stdout();
    let mut ctx = Ctx {
        dir: dir.to_path_buf(),
        transport: &transport,
        operator,
        out: &mut stdout,
        yes: false,
    };
    match &cli.command {
        Cmd::Grant {
            user,
            tokens,
            on,
            no_sync,
        } => control::grant(&mut ctx, user, tokens, &on.on, !no_sync),
        Cmd::Revoke {
            user,
            tokens,
            on,
            no_sync,
        } => control::revoke(&mut ctx, user, tokens, &on.on, !no_sync),
        Cmd::Lock { user, on, no_sync } => control::lock(&mut ctx, user, true, &on.on, !no_sync),
        Cmd::Unlock { user, on, no_sync } => control::lock(&mut ctx, user, false, &on.on, !no_sync),
        Cmd::Where { user } => control::where_(&mut ctx, user),
        Cmd::Passwd { user, on } => control::passwd(&mut ctx, user, &on.on),
        Cmd::Delete { user, purge, yes } => {
            ctx.yes = *yes;
            control::delete(&mut ctx, user, *purge)
        }
        Cmd::Adopt { user, yes } => {
            ctx.yes = *yes;
            control::adopt(&mut ctx, user)
        }
        Cmd::Prune { dry_run } => control::prune(&mut ctx, *dry_run),
        Cmd::Init {
            nodes,
            from_cockpit,
        } => control::init(&mut ctx, nodes, from_cockpit.as_deref()).map(|()| true),
        Cmd::Sync { dry_run, nodes } => control::sync(&mut ctx, nodes, *dry_run),
        Cmd::Audit { nodes } => control::audit(&mut ctx, nodes),
        Cmd::Status { nodes } => control::status(&mut ctx, nodes),
        Cmd::Node {
            command: NodeCmd::Install { hosts, copy },
        } => control::node_install(&mut ctx, hosts, *copy),
        _ => unreachable!("offline commands returned above"),
    }
}

/// The node-side command line as `node::handle` expects it.
fn node_args(command: &NodeCmd) -> Option<Vec<String>> {
    let words: &[&str] = match command {
        NodeCmd::Install { .. } => return None,
        NodeCmd::Version => &["version"],
        NodeCmd::Facts => &["facts"],
        NodeCmd::Apply { dry_run: true } => &["apply", "--dry-run"],
        NodeCmd::Apply { dry_run: false } => &["apply"],
        NodeCmd::Account => &["account"],
        NodeCmd::Audit => &["audit"],
    };
    Some(words.iter().map(|w| w.to_string()).collect())
}

fn node_side(args: &[String]) -> Result<bool> {
    let mut stdin = String::new();
    if !matches!(args[0].as_str(), "version" | "facts") {
        std::io::stdin()
            .read_to_string(&mut stdin)
            .map_err(|e| Error::msg(format!("cannot read stdin: {e}")))?;
    }
    let answer = grantctl::node::handle(&mut RealSystem, args, &stdin).map_err(Error::Msg)?;
    println!("{answer}");
    Ok(true)
}

/// grantctl treats the control node as "here": it uses sudo instead of SSH
/// for it. Running anywhere else would apply the control node's state to
/// the wrong machine.
fn here_is(control: &str) -> Result<()> {
    if control.is_empty() || std::env::var_os("GRANTCTL_CONTROL_HERE").is_some() {
        return Ok(());
    }
    let out = std::process::Command::new("hostname").output();
    let host = out
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let short = host.split('.').next().unwrap_or("");
    if host == control || short == control {
        Ok(())
    } else {
        Err(Error::msg(format!(
            "run grantctl on the control node ({control}); this is {host}. If this machine is the control node under another name, set GRANTCTL_CONTROL_HERE=1"
        )))
    }
}

fn checked(dir: &Path, operator: &str) -> Result<Config> {
    let cfg = Config::load(dir)?;
    let problems = validate::validate(&cfg, operator);
    if problems.is_empty() {
        Ok(cfg)
    } else {
        Err(Error::Invalid(problems))
    }
}

fn roles(dir: &Path) -> Result<()> {
    let pairs = |kv: &[(String, String)]| -> String {
        if kv.is_empty() {
            return "-".to_string();
        }
        kv.iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(",")
    };
    let yes_no = |b: bool| if b { "yes" } else { "no" };
    println!(
        "{:<11} {:<22} {:<10} {:<4} {:<5} from | sshd | home | slice | quota | limits",
        "role", "groups", "nodes", "pw", "sudo"
    );
    for r in Config::load_roles(dir)? {
        let slice = if r.slice.is_empty() {
            "-".to_string()
        } else {
            r.slice.join(",")
        };
        println!(
            "{:<11} {:<22} {:<10} {:<4} {:<5} {} | {} | {} | {} | {} | {}",
            r.name,
            r.groups.join(","),
            r.nodes,
            yes_no(r.password),
            yes_no(r.sudo),
            r.from,
            pairs(&r.sshd),
            r.home,
            slice,
            r.quota.as_deref().unwrap_or("-"),
            pairs(&r.limits),
        );
    }
    Ok(())
}

fn print_plan(d: &NodeDesired) {
    println!(
        "node {}{}",
        d.node,
        if d.is_control { " (control)" } else { "" }
    );
    let accounts: Vec<String> = d
        .accounts
        .iter()
        .map(|a| {
            if a.home_base == "/home" {
                a.user.clone()
            } else {
                format!("{} (home under {})", a.user, a.home_base)
            }
        })
        .collect();
    println!("accounts ({}): {}", accounts.len(), accounts.join(", "));
    if !d.locked.is_empty() {
        println!("locked: {}", d.locked.join(", "));
    }
    println!("groups (exact membership):");
    for g in &d.groups {
        println!("  {}: {}", g.name, g.members.join(", "));
    }
    for s in &d.slices {
        println!("slice limits {}: {}", s.user, s.settings.join(" "));
    }
    for q in &d.quotas {
        println!("quota {}: {} on {}", q.user, q.size, q.base);
    }
    let file = |dir: &str, name: &str, content: &str| {
        println!("--- {dir}/{name}");
        print!("{content}");
    };
    file(desired::SSHD_DIR, desired::SSHD_MAIN_FILE, &d.sshd_main);
    file(desired::SSHD_DIR, desired::SSHD_MATCH_FILE, &d.sshd_match);
    file(desired::SUDOERS_DIR, desired::SUDOERS_FILE, &d.sudoers);
    file(desired::LIMITS_DIR, desired::LIMITS_FILE, &d.limits);
}
