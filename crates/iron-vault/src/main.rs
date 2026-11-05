//! Iron Vault service binary: HTTP and admin interfaces, CLI client, config loading, deployment adapters, response
//! scrubbing, logging, and notifications.

mod cli;
#[cfg(target_os = "linux")]
mod serve;

use std::process::ExitCode;

#[cfg(target_os = "linux")]
use anyhow::Context;
use cli::{Cli, Command, ConfigCommand};
#[cfg(target_os = "linux")]
use iron_vault::deployment::{Accounts, DeploymentProfile, ProfileEnv};
use iron_vault::hardening;
#[cfg(target_os = "linux")]
use iron_vault::logging::{self, LogDestination, LogFailure};
#[cfg(target_os = "linux")]
use iron_vault::trusted_path_report::ServicePaths;

fn main() -> anyhow::Result<ExitCode> {
    let cli = Cli::parse_args();
    match cli.command {
        Command::Serve { log_to_stdout } => run_service(log_to_stdout).map(|()| ExitCode::SUCCESS),
        // Client commands log nothing: what they report is their output.
        Command::Ping => Ok(run_client(|| cli::ping(cli.admin_socket.as_deref()))),
        Command::Status => Ok(run_client(|| cli::status(cli.admin_socket.as_deref()))),
        Command::List => Ok(run_client(|| cli::list(cli.admin_socket.as_deref()))),
        Command::Unlock => Ok(run_client(|| cli::unlock(cli.admin_socket.as_deref()))),
        Command::Lock => Ok(run_client(|| cli::lock(cli.admin_socket.as_deref()))),
        Command::Init => Ok(run_client(|| cli::init(cli.admin_socket.as_deref()))),
        Command::CallerToken => Ok(run_client(|| cli::caller_token(cli.admin_socket.as_deref()))),
        Command::Add { name, kind, origins } => Ok(run_client(|| cli::add(cli.admin_socket.as_deref(), name, kind.into(), &origins))),
        Command::Rm { name } => Ok(run_client(|| cli::rm(cli.admin_socket.as_deref(), name))),
        Command::Config(ConfigCommand::Approve { file }) => Ok(run_client(|| cli::config_approve(cli.admin_socket.as_deref(), &file))),
    }
}

/// Runs a client command after disabling core dumps, because the CLI may hold what the owner types for a prompt.
fn run_client(command: impl FnOnce() -> ExitCode) -> ExitCode {
    if let hardening::CoreDumps::Failed(reason) = hardening::disable_core_dumps() {
        eprintln!("iron-vault: warning: core dumps are not disabled ({reason}); a crash could write typed values to disk");
    }
    command()
}

/// `iron-vault serve`: process hardening, then the log destination and subscriber, then the deployment's paths, then the
/// service. An error before the subscriber is installed goes to stderr, as the exit status of `main`.
#[cfg(target_os = "linux")]
fn run_service(log_to_stdout: bool) -> anyhow::Result<()> {
    // Hardening comes before anything that could hold a secret, so no secret is ever dumpable or swappable.
    let report = hardening::harden_process();
    let accounts = Accounts::read()?;
    let env = ProfileEnv::from_process(&accounts)?;
    let failure = init_logging(&env, log_to_stdout)?;
    hardening::log_report(&report);
    #[cfg(feature = "dev-mode")]
    warn_development(&env, &accounts)?;
    let paths = ServicePaths::for_profile(DeploymentProfile::current(), &env)?;
    serve::run(&paths, accounts, report, failure)
}

/// The admin socket needs a peer-credential adapter, which only Linux has so far.
#[cfg(not(target_os = "linux"))]
fn run_service(_log_to_stdout: bool) -> anyhow::Result<()> {
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

/// Opens the bootstrap log destination and installs the log subscriber on it, returning the latch its first failed write
/// trips. A destination that cannot be used stops the service here, before any socket is bound.
#[cfg(target_os = "linux")]
fn init_logging(env: &ProfileEnv, log_to_stdout: bool) -> anyhow::Result<LogFailure> {
    let profile = DeploymentProfile::current();
    let destination = LogDestination::bootstrap(profile, env, log_to_stdout)?;
    let journal_stream = std::env::var_os(logging::JOURNAL_STREAM);
    let failure = LogFailure::default();
    logging::install(&destination, profile, env, journal_stream.as_deref(), failure.clone())
        .with_context(|| format!("cannot use the log destination {destination}"))?;
    Ok(failure)
}
