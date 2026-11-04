//! Iron Vault service binary: HTTP and admin interfaces, CLI client, config loading, deployment adapters, response
//! scrubbing, logging, and notifications.

mod cli;
#[cfg(target_os = "linux")]
mod serve;

use std::process::ExitCode;

use cli::{Cli, Command};
use iron_vault::deployment::{Accounts, DeploymentProfile, ProfileEnv};
use iron_vault::hardening;
use iron_vault::trusted_path_report::ServicePaths;

fn main() -> anyhow::Result<ExitCode> {
    let cli = Cli::parse_args();
    match cli.command {
        Command::Serve => run_service().map(|()| ExitCode::SUCCESS),
        // Client commands log nothing: what they report is their output.
        Command::Ping => Ok(run_client(|| cli::ping(cli.admin_socket.as_deref()))),
        Command::Status => Ok(run_client(|| cli::status(cli.admin_socket.as_deref()))),
        Command::Unlock => Ok(run_client(|| cli::unlock(cli.admin_socket.as_deref()))),
        Command::Lock => Ok(run_client(|| cli::lock(cli.admin_socket.as_deref()))),
        Command::Add { name, kind, origins } => Ok(run_client(|| cli::add(cli.admin_socket.as_deref(), name, kind.into(), &origins))),
    }
}

/// Runs a client command after disabling core dumps, because the CLI may hold what the owner types for a prompt.
fn run_client(command: impl FnOnce() -> ExitCode) -> ExitCode {
    if let hardening::CoreDumps::Failed(reason) = hardening::disable_core_dumps() {
        eprintln!("iron-vault: warning: core dumps are not disabled ({reason}); a crash could write typed values to disk");
    }
    command()
}

/// `iron-vault serve`: logging and process hardening first, then the deployment's paths, then the service.
fn run_service() -> anyhow::Result<()> {
    init_logging()?;
    // Hardening comes before anything that could hold a secret, so no secret is ever dumpable or swappable.
    let report = hardening::harden_process();
    hardening::log_report(&report);
    let accounts = Accounts::read()?;
    let env = ProfileEnv::from_process(&accounts)?;
    #[cfg(feature = "dev-mode")]
    warn_development(&env, &accounts)?;
    let paths = ServicePaths::for_profile(DeploymentProfile::current(), &env)?;
    serve(&paths, accounts, report)
}

#[cfg(target_os = "linux")]
fn serve(paths: &ServicePaths, accounts: Accounts, report: hardening::HardeningReport) -> anyhow::Result<()> {
    serve::run(paths, accounts, report)
}

/// The admin socket needs a peer-credential adapter, which only Linux has so far.
#[cfg(not(target_os = "linux"))]
fn serve(_paths: &ServicePaths, _accounts: Accounts, _report: hardening::HardeningReport) -> anyhow::Result<()> {
    anyhow::bail!("`iron-vault serve` is not supported on this platform yet")
}

/// Refuses a development build run as root, and otherwise warns that it gives no isolation from the user's malware.
#[cfg(feature = "dev-mode")]
fn warn_development(env: &ProfileEnv, accounts: &Accounts) -> anyhow::Result<()> {
    let uid = env.invoking_uid;
    let user = accounts.name(uid).map_or_else(|| format!("uid {uid}"), str::to_string);
    tracing::warn!("{}", iron_vault::deployment::development_banner(uid, &user)?);
    Ok(())
}

/// Installs the service's log subscriber with the HTTP and TLS dependency caps. EP-26 replaces the global level with the
/// configurable audit and logging design.
fn init_logging() -> anyhow::Result<()> {
    iron_vault::logging::init().map_err(|e| anyhow::anyhow!("could not install the log subscriber: {e}"))
}
