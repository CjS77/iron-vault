//! `iron-vault serve`: checks the trusted paths, takes the directory locks and sweeps their stale temp files, starts
//! the service context Locked with its provisional request listeners, and serves the admin socket until SIGTERM or
//! SIGINT, then stops the service.

use std::collections::BTreeMap;
use std::fs::DirBuilder;
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use iron_vault::admin::dispatch::Handlers;
use iron_vault::admin::principal::AdminPrincipals;
use iron_vault::admin::server::{AdminServer, Limits};
use iron_vault::admin::socket::AdminSocket;
use iron_vault::config_check::UpstreamSettings;
use iron_vault::deployment::{Accounts, DeploymentProfile, OVERFLOW_UID_FILE, PasswdDirectory};
use iron_vault::hardening::HardeningReport;
use iron_vault::service_context::{ServiceContext, ServiceLocks, ServiceSetup};
use iron_vault::socket_activation::{ActivationEnv, AdoptedSocket, adopt};
use iron_vault::trusted_path_report::{self, ServicePaths, TrustedPathReport};
use iron_vault::upstream::client::TransportLimits;
use iron_vault_policy::{Capabilities, ListenerConfig, ListenerName};
use iron_vault_store::OsFs;
use tokio::signal::unix::{SignalKind, signal};

/// Runs the service of the installation at `paths` until it is told to stop.
pub fn run(paths: &ServicePaths, accounts: Accounts, hardening: HardeningReport) -> anyhow::Result<()> {
    let runtime_dir = paths
        .runtime_dir
        .as_deref()
        .context("this deployment names no runtime directory for the admin socket")?;
    // In a packaged install the service manager has already created the runtime directory; a development install has
    // nothing else to make it. At `0711` other accounts may search it, so they can reach a request socket inside it, but
    // never list or write it, so none can put its own socket there (§3.4). The admin socket in it stays `0600` and
    // peer-checked. In development it sits in the user's `0700` `$XDG_RUNTIME_DIR`, so other accounts still cannot
    // reach it; development gives no isolation from other accounts' callers anyway.
    create_dir(runtime_dir, 0o711, "runtime")?;
    create_config_dir(paths)?;
    create_state_dir(paths)?;
    check_trusted_paths(paths)?;
    let locks = ServiceLocks::acquire(paths)?;
    locks.sweep_stale_temps(&OsFs);
    let provisional = locks.unverified_listeners(&OsFs);
    // `listenfd` edits the environment as it takes the sockets, so adoption runs before the runtime starts a thread.
    let activated = adopt_sockets(paths, &provisional);
    let setup = ServiceSetup {
        paths: paths.clone(),
        fs: OsFs,
        accounts: PasswdDirectory::new(accounts, paths, Path::new(OVERFLOW_UID_FILE))?,
        capabilities: Capabilities::default(),
        upstream: UpstreamSettings::new(paths.profile, paths.owner, TransportLimits::default()),
        hardening,
    };
    // Everything that can fail or be interrupted comes before binding the admin socket, so once its file exists the
    // server owns it and removes it on every exit.
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let stop = {
        let _context = runtime.enter();
        stop_signal()?
    };
    runtime.block_on(async {
        let service = Arc::new(ServiceContext::start(locks, setup, &provisional, activated)?);
        let principals = AdminPrincipals::new(paths.profile, paths.owner.uid);
        let server = AdminServer::new(principals, Handlers::for_service(&service), Limits::default());
        let socket = AdminSocket::bind(runtime_dir, paths.owner)?;
        tracing::info!("admin socket listening at {}", socket.path().display());
        let served = server.serve(socket, stop).await;
        service.stop().await;
        served.map_err(anyhow::Error::from)
    })?;
    tracing::info!("stopped");
    Ok(())
}

/// The sockets systemd passed for the provisional listeners. Sockets that do not match the unverified config are
/// logged at WARN and none is adopted, so a swapped `config.toml` cannot keep the service from starting; the listeners
/// it names are then bound where the profile allows it, or stay closed.
fn adopt_sockets(paths: &ServicePaths, listeners: &BTreeMap<ListenerName, ListenerConfig>) -> BTreeMap<ListenerName, AdoptedSocket> {
    adopt(&ActivationEnv::from_process(), std::process::id(), listeners, paths.owner).unwrap_or_else(|error| {
        tracing::warn!("no socket adopted from systemd: {error}");
        BTreeMap::new()
    })
}

/// Creates `dir` at `mode` when it is missing, naming it by `purpose` in the error.
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

/// Creates a development install's state directory, and any missing parents, at `0700`. `$XDG_STATE_HOME` may not exist
/// yet and the XDG specification allows `0700` for what is created. An existing directory is left as it is, so a wrong
/// mode is refused by the trusted-path check rather than repaired. A packaged install's directory belongs to the
/// package (§3.1), so the protected profile never creates it.
fn create_state_dir(paths: &ServicePaths) -> anyhow::Result<()> {
    if paths.profile != DeploymentProfile::Development {
        return Ok(());
    }
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&paths.state_dir)
        .with_context(|| format!("cannot create the state directory {}", paths.state_dir.display()))
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use std::sync::atomic::{AtomicU32, Ordering};

    use iron_vault::trusted_path::{ExpectedOwner, TrustedPathRule};

    use std::path::PathBuf;

    use super::*;

    fn paths(profile: DeploymentProfile, state_dir: &Path) -> ServicePaths {
        ServicePaths {
            profile,
            owner: ExpectedOwner {
                uid: rustix::process::getuid().as_raw(),
            },
            config: state_dir.join("config/config.toml"),
            state_dir: state_dir.to_path_buf(),
            runtime_dir: None,
        }
    }

    /// A fresh empty directory under the system temp directory, unique within this process.
    fn scratch() -> PathBuf {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!("iv-serve-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir_all(&dir).expect("scratch");
        dir
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).expect("stat").permissions().mode() & 0o777
    }

    #[test]
    fn development_creates_the_state_directory_and_its_parents_at_0700() {
        let root = scratch();
        let state = root.join("state-home/iron-vault");
        create_state_dir(&paths(DeploymentProfile::Development, &state)).expect("create");
        assert_eq!(mode(&state), 0o700);
        assert_eq!(mode(state.parent().expect("parent")), 0o700);
    }

    #[test]
    fn protected_never_creates_the_state_directory_and_the_check_names_it() {
        let root = scratch();
        let state = root.join("iron-vault");
        let paths = paths(DeploymentProfile::Protected, &state);
        create_state_dir(&paths).expect("no-op");
        assert!(!state.exists());
        let report = TrustedPathReport::check(&paths);
        let entry = report
            .entries
            .iter()
            .find(|e| e.rule == TrustedPathRule::StateDir)
            .expect("state entry");
        assert_eq!(entry.path, state);
        assert!(entry.outcome.is_err());
    }

    #[test]
    fn an_existing_state_directory_keeps_its_mode() {
        let root = scratch();
        let state = root.join("iron-vault");
        DirBuilder::new().mode(0o755).create(&state).expect("mkdir");
        fs::set_permissions(&state, fs::Permissions::from_mode(0o755)).expect("chmod");
        create_state_dir(&paths(DeploymentProfile::Development, &state)).expect("create");
        assert_eq!(mode(&state), 0o755);
        let report = TrustedPathReport::check(&paths(DeploymentProfile::Development, &state));
        let entry = report
            .entries
            .iter()
            .find(|e| e.rule == TrustedPathRule::StateDir)
            .expect("state entry");
        assert!(entry.outcome.is_err());
    }
}
