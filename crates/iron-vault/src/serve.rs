//! `iron-vault serve`: checks the trusted paths, binds the admin socket and serves it until SIGTERM or SIGINT.

use std::fs::DirBuilder;
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

use anyhow::Context;
use iron_vault::admin::dispatch::Handlers;
use iron_vault::admin::principal::AdminPrincipals;
use iron_vault::admin::server::{AdminServer, Limits};
use iron_vault::admin::socket::AdminSocket;
use iron_vault::trusted_path::TrustedPathRule;
use iron_vault::trusted_path_report::{self, ServicePaths, TrustedPathReport};
use tokio::signal::unix::{SignalKind, signal};

/// Serves the admin socket of the installation at `paths` until the service is told to stop.
pub fn run(paths: &ServicePaths) -> anyhow::Result<()> {
    let runtime_dir = paths
        .runtime_dir
        .as_deref()
        .context("this deployment names no runtime directory for the admin socket")?;
    create_runtime_dir(runtime_dir)?;
    check_trusted_paths(paths)?;
    // Everything that can fail or be interrupted comes before binding, so once the socket file exists the server owns
    // it and removes it on every exit.
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let stop = {
        let _context = runtime.enter();
        stop_signal()?
    };
    let principals = AdminPrincipals::new(paths.profile, paths.owner.uid);
    let server = AdminServer::new(principals, Handlers::standard(paths.profile), Limits::default());
    let socket = AdminSocket::bind(runtime_dir, paths.owner)?;
    tracing::info!("admin socket listening at {}", socket.path().display());
    runtime.block_on(server.serve(socket, stop))?;
    tracing::info!("stopped");
    Ok(())
}

/// Creates the runtime directory at mode `0700` when it is missing. In a packaged install the service manager has
/// already created it; a development install has nothing else to make it.
fn create_runtime_dir(dir: &Path) -> anyhow::Result<()> {
    match DirBuilder::new().mode(0o700).create(dir) {
        Err(e) if e.kind() != io::ErrorKind::AlreadyExists => {
            Err(e).with_context(|| format!("cannot create the runtime directory {}", dir.display()))
        }
        _ => Ok(()),
    }
}

/// Logs every untrusted path and refuses to start when one the service relies on now is untrusted: its own binary and
/// the runtime directory holding the admin socket. The config and state paths are reported only, until the service
/// reads them.
fn check_trusted_paths(paths: &ServicePaths) -> anyhow::Result<()> {
    let report = TrustedPathReport::check(paths);
    trusted_path_report::log_cautions(&report);
    let failures: Vec<_> = report
        .entries
        .iter()
        .filter_map(|entry| entry.outcome.as_ref().err().map(|failure| (entry, failure)))
        .collect();
    failures
        .iter()
        .for_each(|(entry, failure)| tracing::warn!("untrusted path {}: {failure}", entry.path.display()));
    match failures
        .iter()
        .find(|(entry, _)| matches!(entry.rule, TrustedPathRule::Binary | TrustedPathRule::RuntimeDir))
    {
        Some((entry, failure)) => Err(anyhow::anyhow!(
            "refusing to start: {} is not trusted: {failure}",
            entry.path.display()
        )),
        None => Ok(()),
    }
}

/// Completes on the first SIGTERM or SIGINT. The handlers are installed before serving starts, so a stop request is
/// never missed.
fn stop_signal() -> io::Result<impl Future<Output = ()>> {
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    Ok(async move {
        tokio::select! {
            _ = terminate.recv() => tracing::info!("stopping on SIGTERM"),
            _ = interrupt.recv() => tracing::info!("stopping on SIGINT"),
        }
    })
}
