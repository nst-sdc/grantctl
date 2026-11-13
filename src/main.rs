use clap::{Parser, Subcommand};
use grantctl::config::{self, Config};
use grantctl::desired::{self, Hints, NodeDesired};
use grantctl::{validate, Error, Result};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Manage accounts, SSH, sudo and resource limits across a small cluster
/// from one file.
#[derive(Parser)]
#[command(name = "grantctl", version, propagate_version = true)]
struct Cli {
    /// Configuration directory
    #[arg(long, global = true, env = "GRANTCTL_CONF", default_value = config::DEFAULT_DIR)]
    config_dir: PathBuf,
    #[command(subcommand)]
    command: Command,
}

// Milestone 1 ships the offline commands only. grant, revoke, sync and the
// other commands that reach nodes arrive with the node side (docs/DESIGN.md).
#[derive(Subcommand)]
enum Command {
    /// Print the effective role table
    Roles,
    /// Print access.conf
    List,
    /// Validate the configuration without contacting any node
    Check {
        /// Check as this operator instead of the current user
        #[arg(long)]
        operator: Option<String>,
    },
    /// Show what a node should look like (offline; nothing is contacted)
    Plan {
        /// Node name, or an unambiguous suffix of it
        node: String,
        /// Print the desired state as JSON, as sent to `grantctl node apply`
        #[arg(long)]
        json: bool,
        /// Address of the control node, for roles with `from = control` (repeatable)
        #[arg(long = "control-ip", value_name = "IP")]
        control_ips: Vec<String>,
        /// Plan as this operator instead of the current user
        #[arg(long)]
        operator: Option<String>,
    },
    /// Print version and protocol
    Version,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("grantctl: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<()> {
    let dir = cli.config_dir.as_path();
    match &cli.command {
        Command::Roles => roles(dir),
        Command::List => {
            print!("{}", Config::load(dir)?.access.render());
            Ok(())
        }
        Command::Check { operator } => {
            let cfg = Config::load(dir)?;
            checked(&cfg, &operator_name(operator))?;
            println!(
                "ok: {} users, {} roles, {} nodes (control: {})",
                cfg.access.entries().count(),
                cfg.roles.len(),
                cfg.nodes.len(),
                cfg.control()
            );
            Ok(())
        }
        Command::Plan {
            node,
            json,
            control_ips,
            operator,
        } => {
            let cfg = Config::load(dir)?;
            let operator = operator_name(operator);
            checked(&cfg, &operator)?;
            let node = cfg.resolve_node(node)?;
            let hints = Hints {
                control_ips: control_ips.clone(),
                ..Hints::default()
            };
            let state = desired::build(&cfg, &node, &operator, &hints)?;
            if *json {
                let text = serde_json::to_string_pretty(&state)
                    .map_err(|e| Error::msg(format!("cannot encode the plan: {e}")))?;
                println!("{text}");
            } else {
                print_plan(&state);
            }
            Ok(())
        }
        Command::Version => {
            println!(
                "grantctl {} (protocol {})",
                env!("CARGO_PKG_VERSION"),
                grantctl::PROTOCOL
            );
            Ok(())
        }
    }
}

/// The person running grantctl: `--operator`, else the user behind sudo,
/// else the current user.
fn operator_name(flag: &Option<String>) -> String {
    flag.clone()
        .or_else(|| std::env::var("SUDO_USER").ok())
        .or_else(|| std::env::var("USER").ok())
        .unwrap_or_default()
}

fn checked(cfg: &Config, operator: &str) -> Result<()> {
    let problems = validate::validate(cfg, operator);
    if problems.is_empty() {
        Ok(())
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
