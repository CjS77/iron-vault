//! Iron Vault service binary: HTTP and admin interfaces, CLI client, config loading, deployment adapters, response
//! scrubbing, logging, and notifications.

mod hardening;
#[cfg(target_os = "linux")]
mod serve;

use iron_vault::deployment::{self, Accounts, DeploymentProfile, ProfileEnv};
use iron_vault::trusted_path_report::ServicePaths;

fn main() -> anyhow::Result<()> {
    // The CLI's argument parser replaces this check of the first argument.
    let command = std::env::args_os().nth(1);
    // `--version` needs no install path, so a release check can run it on a machine with no installation.
    if command.as_ref().is_some_and(|arg| arg == "--version") {
        println!("{}", deployment::version_line());
        return Ok(());
    }
    init_logging()?;
    // Hardening comes before anything that could hold a secret, so no secret is ever dumpable or swappable.
    let report = hardening::harden_process();
    hardening::log_report(&report);
    let accounts = Accounts::read()?;
    let env = ProfileEnv::from_process(&accounts)?;
    #[cfg(feature = "dev-mode")]
    warn_development(&env, &accounts)?;
    let paths = ServicePaths::for_profile(DeploymentProfile::current(), &env)?;
    match command {
        Some(arg) if arg == "serve" => serve(&paths),
        _ => Ok(()),
    }
}

#[cfg(target_os = "linux")]
fn serve(paths: &ServicePaths) -> anyhow::Result<()> {
    serve::run(paths)
}

/// The admin socket needs a peer-credential adapter, which only Linux has so far.
#[cfg(not(target_os = "linux"))]
fn serve(_paths: &ServicePaths) -> anyhow::Result<()> {
    anyhow::bail!("`iron-vault serve` is not supported on this platform yet")
}

/// Refuses a development build run as root, and otherwise warns that it gives no isolation from the user's malware.
#[cfg(feature = "dev-mode")]
fn warn_development(env: &ProfileEnv, accounts: &Accounts) -> anyhow::Result<()> {
    let uid = env.invoking_uid;
    let user = accounts.name(uid).map_or_else(|| format!("uid {uid}"), str::to_string);
    tracing::warn!("{}", deployment::development_banner(uid, &user)?);
    Ok(())
}

/// Installs a human-readable subscriber on stderr at INFO and above, without colour codes, because systemd and Docker
/// capture stderr. EP-26 replaces this with the configurable audit and logging design.
fn init_logging() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .try_init()
        .map_err(|e| anyhow::anyhow!("could not install the log subscriber: {e}"))
}
