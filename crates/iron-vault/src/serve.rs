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
use iron_vault::deployment::DeploymentProfile;
use iron_vault::trusted_path_report::{self, ServicePaths, TrustedPathReport};
use tokio::signal::unix::{SignalKind, signal};

/// Serves the admin socket of the installation at `paths` until the service is told to stop.
pub fn run(paths: &ServicePaths) -> anyhow::Result<()> {
    let runtime_dir = paths
        .runtime_dir
        .as_deref()
        .context("this deployment names no runtime directory for the admin socket")?;
    create_dir(runtime_dir, 0o711, "runtime")?;
    create_config_dir(paths)?;
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

/// Creates `dir` at `mode` when it is missing, naming it by `purpose` in the error.
///
/// The runtime directory is `0711`. In a packaged install the service manager has already created it; a development
/// install has nothing else to make it. Other accounts may search the directory, so they can reach a request socket
/// inside it, but never list or write it, so none can put its own socket there (§3.4). The admin socket in it stays
/// `0600` and peer-checked. In development the directory sits in the user's `0700` `$XDG_RUNTIME_DIR`, so other
/// accounts still cannot reach it; development gives no isolation from other accounts' callers anyway.
fn create_dir(dir: &Path, mode: u32, purpose: &str) -> anyhow::Result<()> {
    match DirBuilder::new().mode(mode).create(dir) {
        Err(e) if e.kind() != io::ErrorKind::AlreadyExists => {
            Err(e).with_context(|| format!("cannot create the {purpose} directory {}", dir.display()))
        }
        _ => Ok(()),
    }
}

/// Creates a development install's config directory at `0700` when it is missing. A packaged install's directory
/// belongs to the package, which creates it with that mode for the service account, so the service never does.
fn create_config_dir(paths: &ServicePaths) -> anyhow::Result<()> {
    match (paths.profile, paths.config.parent()) {
        (DeploymentProfile::Development, Some(dir)) => create_dir(dir, 0o700, "config"),
        _ => Ok(()),
    }
}

/// Refuses to start when a path the service reads before it unlocks anything is untrusted (§3.1: "refuse an unsafe
/// installation and explain which path failed"), and logs each path caution.
fn check_trusted_paths(paths: &ServicePaths) -> anyhow::Result<()> {
    let report = TrustedPathReport::check(paths);
    trusted_path_report::log_cautions(&report);
    match report.refusal() {
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
