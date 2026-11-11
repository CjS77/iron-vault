//! Iron Vault service binary: HTTP and admin interfaces, CLI client, config loading, deployment adapters, response
//! scrubbing, logging, and notifications.

mod cli;
#[cfg(target_os = "linux")]
mod serve;

use std::process::ExitCode;

#[cfg(target_os = "linux")]
use anyhow::Context;
use cli::{ApproverCommand, Cli, Command, ConfigCommand, RecipientCommand, RecoveryCommand};
#[cfg(target_os = "linux")]
use iron_vault::audit::{AuditEvent, HardeningIncomplete, ServiceStarted};
#[cfg(target_os = "linux")]
use iron_vault::deployment::{Accounts, DeploymentProfile, ProfileEnv, require_service_account};
use iron_vault::hardening;
#[cfg(target_os = "linux")]
use iron_vault::logging::{self, LogDestination, LogSwitch};
#[cfg(target_os = "linux")]
use iron_vault::trusted_path_report::ServicePaths;

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        // One line, not anyhow's `Error:` plus `Caused by:` block, so a collector reading stderr sees one event.
        Err(e) => {
            eprintln!("iron-vault: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> anyhow::Result<ExitCode> {
    let cli = Cli::parse_args();
    match cli.command {
        Command::Serve { log_to_stdout } => run_service(log_to_stdout).map(|()| ExitCode::SUCCESS),
        // Client commands log nothing: what they report is their output.
        Command::Ping => Ok(run_client(|| cli::ping(cli.admin_socket.as_deref()))),
        Command::Status => Ok(run_client(|| cli::status(cli.admin_socket.as_deref()))),
        Command::List => Ok(run_client(|| cli::list(cli.admin_socket.as_deref()))),
        Command::Unlock => Ok(run_client(|| cli::unlock(cli.admin_socket.as_deref()))),
        Command::Lock => Ok(run_client(|| cli::lock(cli.admin_socket.as_deref()))),
        Command::Reset => Ok(run_client(|| cli::reset(cli.admin_socket.as_deref()))),
        Command::Export { bundle } => Ok(run_client(|| cli::export(cli.admin_socket.as_deref(), &bundle))),
        Command::Import { bundle, host_unlock } => Ok(run_client(|| cli::import(cli.admin_socket.as_deref(), &bundle, host_unlock))),
        Command::Init { host_unlock } => Ok(run_client(|| cli::init(cli.admin_socket.as_deref(), host_unlock))),
        Command::CallerToken => Ok(run_client(|| cli::caller_token(cli.admin_socket.as_deref()))),
        Command::Add { name, kind, origins } => Ok(run_client(|| cli::add(cli.admin_socket.as_deref(), name, kind.into(), &origins))),
        Command::Replace { name, kind, origins } => Ok(run_client(|| {
            cli::replace(cli.admin_socket.as_deref(), name, kind.into(), &origins)
        })),
        Command::Rm { name } => Ok(run_client(|| cli::rm(cli.admin_socket.as_deref(), name))),
        // Not a client command: it reads nothing from the service, so it skips the admin socket and core-dump handling.
        Command::Completions { shell } => cli::completions(shell).map(|()| ExitCode::SUCCESS).map_err(Into::into),
        Command::Approver(ApproverCommand::List) => Ok(run_client(|| cli::approver_list(cli.admin_socket.as_deref()))),
        Command::Recipient(RecipientCommand::List) => Ok(run_client(|| cli::recipient_list(cli.admin_socket.as_deref()))),
        Command::Recipient(RecipientCommand::Add {
            recipient,
            label,
            host_unlock,
            ..
        }) => Ok(run_client(|| match recipient {
            Some(recipient) => cli::recipient_add(cli.admin_socket.as_deref(), recipient, label, host_unlock),
            None => cli::recipient_add_recovery(cli.admin_socket.as_deref(), label),
        })),
        Command::Recipient(RecipientCommand::Remove { recipient }) => {
            Ok(run_client(|| cli::recipient_remove(cli.admin_socket.as_deref(), recipient)))
        }
        Command::ForgetMachine { recipient } => Ok(run_client(|| cli::forget_machine(cli.admin_socket.as_deref(), recipient))),
        Command::Approver(ApproverCommand::Add { label, kind }) => {
            Ok(run_client(|| cli::approver_add(cli.admin_socket.as_deref(), kind.into(), label)))
        }
        Command::Approver(ApproverCommand::Remove { approver }) => {
            Ok(run_client(|| cli::approver_remove(cli.admin_socket.as_deref(), approver)))
        }
        Command::Recovery(RecoveryCommand::Check) => Ok(run_client(|| cli::recovery_check(cli.admin_socket.as_deref()))),
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
    // Before the log destination opens, so a wrong account never creates the log file as itself.
    require_service_account(DeploymentProfile::current(), &env)?;
    let destination = LogDestination::bootstrap(DeploymentProfile::current(), &env, log_to_stdout)?;
    let log = init_logging(&env, &destination)?;
    log_startup(&destination, &report);
    #[cfg(feature = "dev-mode")]
    warn_development(&env, &accounts)?;
    let paths = ServicePaths::for_profile(DeploymentProfile::current(), &env)?;
    serve::run(&paths, accounts, report, log)
}

/// The admin socket needs a peer-credential adapter, which only Linux has so far.
#[cfg(not(target_os = "linux"))]
fn run_service(_log_to_stdout: bool) -> anyhow::Result<()> {
    anyhow::bail!("`iron-vault serve` is not supported on this platform yet")
}

/// Refuses a development build run as root, and otherwise warns that it gives no isolation from the user's malware.
#[cfg(all(feature = "dev-mode", target_os = "linux"))]
fn warn_development(env: &ProfileEnv, accounts: &Accounts) -> anyhow::Result<()> {
    let uid = env.invoking_uid;
    let user = accounts.name(uid).map_or_else(|| format!("uid {uid}"), str::to_string);
    tracing::warn!("{}", iron_vault::deployment::development_banner(uid, &user)?);
    Ok(())
}

/// Records the startup event, then the hardening that is missing, if any, as the record to alert on.
#[cfg(target_os = "linux")]
fn log_startup(destination: &LogDestination, report: &hardening::HardeningReport) {
    ServiceStarted {
        destination,
        hardening: report,
    }
    .emit();
    if let Some(incomplete) = HardeningIncomplete::of(report) {
        incomplete.emit();
    }
}

/// Opens the bootstrap log destination and installs the log subscriber on it, returning the switch that holds it. A
/// destination that cannot be used stops the service here, before any socket is bound.
#[cfg(target_os = "linux")]
fn init_logging(env: &ProfileEnv, destination: &LogDestination) -> anyhow::Result<LogSwitch> {
    let journal_stream = std::env::var_os(logging::JOURNAL_STREAM);
    logging::install(destination, DeploymentProfile::current(), env, journal_stream.as_deref())
        .with_context(|| format!("cannot use the log destination {destination}"))
}
