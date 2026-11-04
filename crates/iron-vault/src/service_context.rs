//! The service context (specification §3.1, §3.11, §3.12): the one owned value the running service is. It drives the
//! service state model, holds the open vault through the serving snapshot, and binds the request interface.
//!
//! Every change takes one async mutex and goes through [`next`], so no two changes interleave and none makes a
//! transition the §3.12 diagram lacks. Requests never take that mutex: each loads its admission from the snapshot
//! holder, which every transition stores into.
//!
//! Outside Ready the request listeners come from the unverified `config.toml` and answer only `503` with the holder's
//! reason, before any caller is identified (glossary: *Listener provenance*). Entering Ready rebuilds them from the
//! verified config before the snapshot is served, so a socket the verified config does not name is closed before the
//! snapshot could serve through it.

mod serving;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use iron_vault_policy::{Capabilities, Limits, ListenerConfig, ListenerName, ParsedConfig};
use iron_vault_store::{
    ApprovalState, ConfigDirLock, ConfigFileName, LockError, OsFs, StateDirLock, StoreFs, VaultIdentity, read_config_file,
};
use tokio::sync::Mutex;

use crate::config_check::{UpstreamSettings, open_and_check, parse_detail};
use crate::deployment::PasswdDirectory;
use crate::hardening::HardeningReport;
use crate::request_listeners::RequestListeners;
use crate::service_state::{IllegalTransition, RequestInterface, ServiceEvent, ServiceState, UnavailableReason, next};
use crate::serving_snapshot::{ServingSnapshot, SnapshotHolder};
use crate::socket_activation::AdoptedSocket;
use crate::trusted_path_report::ServicePaths;
use serving::Serving;

/// The state-directory lock and the config-directory lock, held for the service's lifetime: a second instance on
/// either directory fails to start (§3.1).
#[derive(Debug)]
pub struct ServiceLocks {
    state: StateDirLock,
    config: ConfigDirLock,
}

/// Why the service did not start.
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    /// Another instance holds the state directory, or its lock file is unusable.
    #[error("cannot take the state-directory lock: {0}")]
    StateLock(LockError),
    /// The config path has no parent, so there is no config directory to lock.
    #[error("the config path {} names no config directory", .0.display())]
    NoConfigDir(PathBuf),
    /// Another instance holds the config directory, or its lock file is unusable.
    #[error("cannot take the config-directory lock: {0}")]
    ConfigLock(LockError),
}

impl ServiceLocks {
    /// Takes the state-directory lock, then the config-directory lock, failing at once if another instance holds either.
    pub fn acquire(paths: &ServicePaths) -> Result<Self, StartError> {
        let state = StateDirLock::acquire(&paths.state_dir).map_err(StartError::StateLock)?;
        let config_dir = paths.config.parent().ok_or_else(|| StartError::NoConfigDir(paths.config.clone()))?;
        let config = ConfigDirLock::acquire(config_dir).map_err(StartError::ConfigLock)?;
        Ok(Self { state, config })
    }

    /// The listeners the unverified `config.toml` names, for the provisional listener set and for adopting the sockets
    /// systemd passed, which must happen before the async runtime starts. Nothing else of the unverified config is used.
    ///
    /// An unreadable or unparsable config names none: the service still starts, Locked, with its admin socket up. The
    /// failure is logged at WARN by position only, since a parse error may quote the file.
    pub fn unverified_listeners(&self, fs: &impl StoreFs) -> BTreeMap<ListenerName, ListenerConfig> {
        let parsed = read_config_file(&self.config, fs, ConfigFileName::Active)
            .map_err(|error| error.to_string())
            .and_then(|bytes| ParsedConfig::from_toml(&bytes).map_err(|error| parse_detail(&error)));
        match parsed {
            Ok(config) => config.listeners().clone(),
            Err(detail) => {
                tracing::warn!("no provisional request listeners: {detail}");
                BTreeMap::new()
            }
        }
    }
}

/// What the service runs with besides its locks.
#[derive(Debug)]
pub struct ServiceSetup<F = OsFs> {
    /// The deployment's trusted paths, profile and service account.
    pub paths: ServicePaths,
    /// The filesystem every vault and config file goes through.
    pub fs: F,
    /// The accounts peer callers resolve against.
    pub accounts: PasswdDirectory,
    /// What this installation can do, for activation.
    pub capabilities: Capabilities,
    /// How the config check builds upstream clients.
    pub upstream: UpstreamSettings,
    /// What process hardening achieved before anything secret existed.
    pub hardening: HardeningReport,
}

/// The running service. Shared by the admin handlers and the request side; see the module documentation.
#[derive(Debug)]
pub struct ServiceContext<F = OsFs> {
    setup: ServiceSetup<F>,
    locks: ServiceLocks,
    holder: Arc<SnapshotHolder>,
    inner: Mutex<Inner>,
}

/// What changes, behind the one mutex.
#[derive(Debug)]
struct Inner {
    state: ServiceState,
    /// The approval state of the open vault; the vault itself is in the served snapshot.
    approval: Option<ApprovalState>,
    /// The request listeners and the task serving them; `None` only while they are being rebuilt or once stopped.
    serving: Option<Serving>,
}

impl<F: StoreFs> ServiceContext<F> {
    /// Starts the service on `locks`: Starting, then Locked, with the provisional listener set open on `provisional` and
    /// the sockets in `activated`. Call it inside the async runtime.
    ///
    /// v0 stores the vault identity behind a passphrase only, so startup always needs an interactive unlock; a TPM or
    /// host unlock (EP-32) would move to Checking instead. A provisional listener that cannot be opened is logged at
    /// WARN and left out.
    pub fn start(
        locks: ServiceLocks,
        setup: ServiceSetup<F>,
        provisional: &BTreeMap<ListenerName, ListenerConfig>,
        activated: BTreeMap<ListenerName, AdoptedSocket>,
    ) -> Result<Self, IllegalTransition> {
        let (listeners, failures) = RequestListeners::open_each(provisional, &setup.paths, activated);
        failures
            .iter()
            .for_each(|error| tracing::warn!("provisional request listener not open: {error}"));
        // Starting refuses as Locked does, before any listener accepts. The default limits bound the provisional set:
        // nothing of the unverified config but its listeners is used.
        let holder = Arc::new(SnapshotHolder::refusing(UnavailableReason::Locked));
        let mut service = Self {
            inner: Mutex::new(Inner {
                state: ServiceState::Starting,
                approval: None,
                serving: Some(Serving::start(listeners, Limits::default(), Arc::clone(&holder))),
            }),
            setup,
            locks,
            holder,
        };
        let inner = service.inner.get_mut();
        let state = next(inner.state, ServiceEvent::InteractiveUnlockRequired)?;
        inner.state = state;
        service.store_refusal(state);
        Ok(service)
    }

    /// Unlocks with `identity` and runs the config check: Locked to Checking, then Ready or Unavailable.
    ///
    /// When the check passes, the listener set is rebuilt from the verified config, and only then is the snapshot
    /// served and the set approved. When it fails, the provisional listeners keep answering `503` with the failure's
    /// reason, the check has logged the detail at WARN, and the vault and its identity are dropped.
    pub async fn enter_checking(&self, identity: VaultIdentity) -> Result<ServiceState, IllegalTransition> {
        let mut inner = self.inner.lock().await;
        self.check_and_settle(&mut inner, ServiceEvent::UnlockSucceeded, identity).await
    }

    /// Stops the service on SIGTERM or SIGINT: Ready to Stopped, then drops the snapshot, the vault in it and the
    /// approval state, so their secret buffers clear (§3.11), and closes the request listeners, removing their socket
    /// files.
    ///
    /// §3.12 draws a stop only from Ready. From any other state there is no transition to make: the process ends all
    /// the same, after the same teardown.
    pub async fn stop(&self) {
        let mut inner = self.inner.lock().await;
        if let Err(refused) = self.apply(&mut inner, ServiceEvent::Stop) {
            tracing::info!("stopping from {:?}", refused.state);
        }
        // Stopped has no request interface; storing a refusal withdraws the snapshot and drops the holder's reference.
        self.holder.refuse(UnavailableReason::Locked);
        inner.approval = None;
        if let Some(serving) = inner.serving.take() {
            drop(serving.stop().await);
        }
    }

    /// The current service state.
    pub async fn state(&self) -> ServiceState {
        self.inner.lock().await.state
    }

    /// The names of the open request listeners, in name order.
    pub async fn listener_names(&self) -> Vec<ListenerName> {
        self.inner.lock().await.serving.as_ref().map(Serving::names).unwrap_or_default()
    }

    /// The holder every request's admission is loaded from.
    pub fn holder(&self) -> &Arc<SnapshotHolder> {
        &self.holder
    }

    /// The deployment's paths, profile and service account.
    pub fn paths(&self) -> &ServicePaths {
        &self.setup.paths
    }

    /// What process hardening achieved at startup.
    pub fn hardening(&self) -> &HardeningReport {
        &self.setup.hardening
    }

    /// Moves into Checking on `event` (an unlock; later a reload, an approval's commit or a repair), runs the config check
    /// with `identity` ([`open_and_check`]), and settles in Ready or Unavailable.
    async fn check_and_settle(
        &self,
        inner: &mut Inner,
        event: ServiceEvent,
        identity: VaultIdentity,
    ) -> Result<ServiceState, IllegalTransition> {
        self.apply(inner, event)?;
        let ServiceSetup {
            fs,
            accounts,
            capabilities,
            upstream,
            ..
        } = &self.setup;
        match open_and_check(
            &self.locks.state,
            &self.locks.config,
            fs,
            identity,
            capabilities,
            accounts,
            upstream,
        ) {
            Ok((snapshot, approval)) => self.enter_ready(inner, snapshot, approval).await,
            Err(failure) => self.apply(inner, ServiceEvent::CheckFailed(failure.failure())),
        }
    }

    /// Checking to Ready: the listener rebuild, then the snapshot, then the state.
    async fn enter_ready(
        &self,
        inner: &mut Inner,
        snapshot: ServingSnapshot,
        approval: ApprovalState,
    ) -> Result<ServiceState, IllegalTransition> {
        let ready = next(inner.state, ServiceEvent::CheckPassed)?;
        let config = snapshot.policy().config();
        let current = match inner.serving.take() {
            Some(serving) => serving.stop().await,
            None => RequestListeners::empty(),
        };
        let (listeners, failures) = current.rebuild(config.listeners(), &self.setup.paths);
        failures
            .iter()
            .for_each(|error| tracing::warn!("approved request listener missing until restart: {error}"));
        inner.serving = Some(Serving::start(listeners, *config.limits(), Arc::clone(&self.holder)));
        self.holder.serve(snapshot);
        inner.approval = Some(approval);
        inner.state = ready;
        Ok(ready)
    }

    /// Moves to the state `event` leads to, storing that state's refusal in the holder.
    fn apply(&self, inner: &mut Inner, event: ServiceEvent) -> Result<ServiceState, IllegalTransition> {
        let state = next(inner.state, event)?;
        inner.state = state;
        self.store_refusal(state);
        Ok(state)
    }

    /// Stores the refusal `state`'s request interface gives, so a `503`'s reason has one source. Ready serves, which
    /// [`enter_ready`](Self::enter_ready) stores itself, after the listener rebuild.
    fn store_refusal(&self, state: ServiceState) {
        if let RequestInterface::Refuse(reason) = state.request_interface() {
            self.holder.refuse(reason);
        }
    }
}
