//! The service context (specification §3.1, §3.11, §3.12): the one owned value the running service is. It drives the
//! service state model, keeps the vault identity from unlock until lock or stop, holds the open vault through the
//! serving snapshot, and binds the request interface.
//!
//! Every config check opens a new vault from the kept identity, so a reload, a repair or an approval re-enters Checking
//! without a new unlock, and an Unavailable service holds the one key and none of the decrypted credential records.
//!
//! Every change takes one async mutex and goes through [`next`], so no two changes interleave and none makes a
//! transition the §3.12 diagram lacks. Scrypt and the config check run on the blocking pool with the mutex held, so the
//! runtime thread stays free to answer requests with `503`, serve other admin commands and handle signals (§3.12). Requests never take that mutex: each loads its admission from the snapshot
//! holder, which every transition stores into.
//!
//! Outside Ready the request listeners come from the unverified `config.toml` and answer only `503` with the holder's
//! reason, before any caller is identified (glossary: *Listener provenance*). Entering Ready rebuilds them from the
//! verified config before the snapshot is served, so a socket the verified config does not name is closed before the
//! snapshot could serve through it.

mod approval;
mod serving;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Weak};
use std::time::Duration;

use iron_vault_policy::{Capabilities, Limits, ListenerConfig, ListenerName, ParsedConfig};
use iron_vault_store::{
    ApprovalState, ConfigDirLock, ConfigFileName, LockError, OsFs, Passphrase, StateDirLock, StateFileName, StoreFs, UnlockError,
    VaultIdentity, read_config_file, sweep_stale_config_temps, sweep_stale_temps, unlock_with_passphrase,
};
use tokio::sync::Mutex;

use crate::admin::protocol::{MemoryStatus, StatusReport, UnlockedVault, VaultStatus};
use crate::config_check::{CheckFailure, Checked, UpstreamSettings, open_and_check, parse_detail};
use crate::deployment::PasswdDirectory;
use crate::hardening::HardeningReport;
use crate::request_listeners::RequestListeners;
use crate::service_state::{AdminOperation, IllegalTransition, RequestInterface, ServiceEvent, ServiceState, UnavailableReason, next};
use crate::serving_snapshot::{ServingSnapshot, SnapshotHolder, Withdrawn};
use crate::socket_activation::AdoptedSocket;
use crate::standing::{CredentialStanding, RouteFault};
use crate::trusted_path_report::ServicePaths;
use serving::Serving;

pub use approval::{ApprovalEnd, ApprovalReview};

/// The log target of lock transitions (glossary: *Lock transition*), so the audit design (EP-26) can route them as
/// their own events.
pub const LOCK_TRANSITION_TARGET: &str = "iron_vault::lock_transition";

/// The start of the WARN line an unlock refusal logs, whichever layer refuses it.
pub(crate) const UNLOCK_REFUSED: &str = "unlock refused, the service stays Locked";

/// Why an unlock left the service where it was. No variant holds passphrase text.
#[derive(Debug, thiserror::Error)]
pub enum UnlockRefusal {
    /// The service is not Locked, so there is nothing to unlock.
    #[error("unlock is not allowed while the service is {0:?}")]
    WrongState(ServiceState),
    /// The passphrase does not open the passphrase envelope.
    #[error("wrong passphrase")]
    WrongPassphrase,
    /// The envelopes could not be read or opened; the service stays Locked.
    #[error("the vault could not be unlocked: {0}")]
    Failed(UnlockError),
    /// The unlock task ended without a result (it panicked, or the runtime is shutting down); the service stays Locked.
    #[error("the vault could not be unlocked: the unlock did not finish")]
    Interrupted,
}

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

    /// Removes the stale temp files a crash mid-write left in the state directory and the config directory, each under
    /// its own lock, before anything reads either directory. Each removed temp is logged at INFO by file name.
    ///
    /// A failed sweep is logged at WARN and startup goes on: a leftover temp file only makes the next durable replace
    /// of its file refuse, which reports its own error, and the active files are never touched.
    pub fn sweep_stale_temps(&self, fs: &impl StoreFs) {
        log_sweep(
            "state",
            sweep_stale_temps(&self.state, fs).map(|names| names.iter().map(StateFileName::temp_name).collect()),
        );
        log_sweep(
            "config",
            sweep_stale_config_temps(&self.config, fs).map(|names| names.into_iter().map(ConfigFileName::temp_name).collect()),
        );
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

/// Logs the outcome of one directory's stale temp sweep: each removed temp file at INFO, or the failure at WARN.
fn log_sweep(dir: &str, swept: Result<Vec<String>, impl std::fmt::Display>) {
    match swept {
        Ok(temps) => temps
            .iter()
            .for_each(|temp| tracing::info!("removed stale temp file {temp} from the {dir} directory")),
        Err(error) => tracing::warn!("stale temp sweep of the {dir} directory failed, starting anyway: {error}"),
    }
}

/// How a lock ended: whether the secrets are confirmed gone from memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockOutcome {
    /// Every serving snapshot, the vault in it and the vault identity were dropped within the lock drain.
    Cleared,
    /// The lock drain expired while this many snapshots were still held by requests that ignored their cancellation.
    Held {
        /// The snapshots still held.
        snapshots: usize,
    },
    /// Every snapshot the lock withdrew was dropped, but something else still holds the vault identity: the vault of a
    /// snapshot that a failed check withdrew earlier, still held by a request that ignored its cancellation.
    IdentityHeld,
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
    /// Shared with each blocking task, which must own what it reads.
    setup: Arc<ServiceSetup<F>>,
    locks: Arc<ServiceLocks>,
    holder: Arc<SnapshotHolder>,
    /// The service-wide lock (glossary). `config approve` holds it from its request to its response, prompts included,
    /// and fails at once with `busy` while another holds it; a recheck waits for it. Vault writes take it too.
    service_wide: Mutex<()>,
    inner: Mutex<Inner>,
}

/// What the context keeps of an open vault beside the snapshot. They are one value, so a lock, a stop or a failed check
/// drops the approval state and the credential report together, and neither can outlive the other.
#[derive(Debug)]
struct OpenVault {
    approval: ApprovalState,
    /// The standing of each credential, from the report of opening the vault.
    credentials: Vec<CredentialStanding>,
    /// The routes unavailable for a cause of their own, from the check.
    route_faults: Vec<RouteFault>,
}

/// What changes, behind the one mutex.
#[derive(Debug)]
struct Inner {
    state: ServiceState,
    /// The vault identity, from unlock until lock or stop: `Some` in Checking, Ready and Unavailable. Each vault opened
    /// from it shares this one copy, so its key bytes are cleared when the last of them drops it.
    identity: Option<Arc<VaultIdentity>>,
    /// What the context keeps of the open vault, which itself is in the served snapshot. `None` unless the vault is open.
    open: Option<OpenVault>,
    /// The request listeners and the task serving them; `None` only while they are being rebuilt or once stopped.
    serving: Option<Serving>,
}

impl<F: StoreFs + Send + Sync + 'static> ServiceContext<F> {
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
                identity: None,
                open: None,
                serving: Some(Serving::start(listeners, Limits::default(), Arc::clone(&holder))),
            }),
            setup: Arc::new(setup),
            locks: Arc::new(locks),
            holder,
            service_wide: Mutex::new(()),
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
    /// reason, the check has logged the detail at WARN, and the vault is dropped; the context keeps `identity` either
    /// way. Both state changes are logged as lock transitions, so a host unlock (EP-32) entering here is audited like a
    /// passphrase unlock.
    pub async fn enter_checking(&self, identity: VaultIdentity) -> Result<ServiceState, IllegalTransition> {
        let mut inner = self.inner.lock().await;
        self.check_and_settle(&mut inner, ServiceEvent::UnlockSucceeded, Arc::new(identity))
            .await
    }

    /// Re-enters Checking with the kept vault identity on `event`, runs the config check again and settles in Ready or
    /// Unavailable: [`ServiceEvent::Reload`] from Ready, [`ServiceEvent::Repaired`] from Unavailable after an authorized
    /// repair, a committed transaction's recovery, or a `config approve` out of an invalid policy.
    ///
    /// It waits for the service-wide lock, so a recheck that arrives during an approval runs after it. No unlock is
    /// needed: the check opens a new vault from the identity the context kept. An event that does not lead
    /// to Checking from the current state is refused and changes nothing, and so is any event without a kept identity
    /// (Starting, Locked, Stopped), since there is nothing to check with.
    pub async fn recheck(&self, event: ServiceEvent) -> Result<ServiceState, IllegalTransition> {
        let _service_wide = self.service_wide.lock().await;
        let mut inner = self.inner.lock().await;
        let identity = inner.identity.clone().ok_or(IllegalTransition { state: inner.state, event })?;
        self.check_and_settle(&mut inner, event, identity).await
    }

    /// Reloads on SIGHUP (§3.9, Q-5): [`recheck`](Self::recheck) with [`ServiceEvent::Reload`], which only a Ready service
    /// accepts. In Locked, Checking or Unavailable nothing changes and the signal is logged at INFO: a reload is not an
    /// authorized repair, so it never leads out of Unavailable. A failed check leaves the service Unavailable and logs
    /// `config.reload-failed` at WARN.
    pub async fn reload(&self) -> Result<ServiceState, IllegalTransition> {
        self.recheck(ServiceEvent::Reload).await.inspect_err(|refused| {
            tracing::info!(
                "SIGHUP ignored: reload only runs from Ready, and the service is {:?}",
                refused.state
            );
        })
    }

    /// Unlocks with the owner's `passphrase` (§3.11) and runs the config check: Locked to Checking, then Ready or
    /// Unavailable, as [`enter_checking`](Self::enter_checking) does. Each state change is logged as a lock transition.
    ///
    /// The state is checked under the mutex, so two unlocks never both open the vault. A wrong passphrase or an
    /// unreadable envelope leaves the service Locked: no other storage is ever tried (R-22). The operational identity
    /// the passphrase opens is dropped inside [`unlock_with_passphrase`], once it has unwrapped the vault identity.
    pub async fn unlock(&self, passphrase: Passphrase) -> Result<ServiceState, UnlockRefusal> {
        let mut inner = self.inner.lock().await;
        let locked = inner.state;
        if !locked.admin_allows(AdminOperation::Unlock) {
            return Err(UnlockRefusal::WrongState(locked));
        }
        let identity = self.open_identity(passphrase).await.inspect_err(|refusal| {
            tracing::warn!("{UNLOCK_REFUSED}: {refusal}");
        })?;
        self.check_and_settle(&mut inner, ServiceEvent::UnlockSucceeded, Arc::new(identity))
            .await
            .map_err(|illegal| UnlockRefusal::WrongState(illegal.state))
    }

    /// Locks the service on an explicit `lock`: Ready or Unavailable to Locked, clearing the vault identity and every
    /// cached secret (§3.13, §3.11). §3.12 draws a lock only from those two states; from any other the event is refused.
    ///
    /// Under the context's mutex it stops admitting requests, withdraws the serving snapshot (cancelling the requests
    /// running on it) and drops the approval state, the credential report and the context's copy of the vault identity,
    /// so no later change interleaves. Unavailable has no snapshot to withdraw, so there the identity is cleared at once
    /// unless something else still holds it. The mutex is then released and the call waits up to `drain` for the last
    /// holder of the old snapshot, a streaming response body included, to drop it, so a slow request does not stall the
    /// other admin commands. The vault in that snapshot holds the last reference to the identity, so the identity is
    /// cleared with it. If the drain expires, or the identity is still held, it logs a warning and returns an outcome
    /// other than [`LockOutcome::Cleared`], never claiming the secrets are cleared.
    pub async fn lock(&self, drain: Duration) -> Result<LockOutcome, IllegalTransition> {
        let (mut withdrawn, identity) = self.withdraw_for_lock().await?;
        let snapshots = withdrawn.released(drain).await;
        Ok(lock_outcome(snapshots, identity.strong_count()))
    }

    /// The locked half of [`lock`](Self::lock): moves to Locked, withdraws the snapshot and drops what the context keeps
    /// of the vault. Returns the withdrawn snapshots and a weak reference to the dropped identity, to see whether it is
    /// cleared.
    async fn withdraw_for_lock(&self) -> Result<(Withdrawn, Weak<VaultIdentity>), IllegalTransition> {
        let mut inner = self.inner.lock().await;
        let from = inner.state;
        let state = next(from, ServiceEvent::Lock)?;
        // Refusing first closes the gate and cancels the in-flight requests before anything else changes.
        let withdrawn = self.holder.refuse(UnavailableReason::Locked);
        inner.open = None;
        let identity = inner.identity.take().as_ref().map_or_else(Weak::new, Arc::downgrade);
        inner.state = state;
        log_lock_transition(from, state);
        Ok((withdrawn, identity))
    }

    /// Stops the service on SIGTERM or SIGINT: Ready to Stopped, then drops the snapshot, the vault in it, the approval
    /// state and the vault identity, so their secret buffers clear (§3.11), and closes the request listeners, removing
    /// their socket files.
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
        inner.open = None;
        inner.identity = None;
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

    /// The status report: what the context holds right now, which is all `status` may say.
    ///
    /// The vault ID, approval versions and credentials come from the open vault, so they are known only while the
    /// context holds one. A failed check drops the vault, though not the vault identity, so Unavailable reports them
    /// as unknown too.
    pub async fn status(&self) -> StatusReport {
        let inner = self.inner.lock().await;
        StatusReport {
            state: inner.state,
            profile: self.setup.paths.profile,
            vault: inner.open.as_ref().map_or(VaultStatus::Locked, |open| {
                VaultStatus::Unlocked(UnlockedVault {
                    id: open.approval.vault_id(),
                    committed: open.approval.committed().map(|(version, _)| version.get()),
                    highest_reserved: open.approval.highest_reserved(),
                    credentials: open.credentials.clone(),
                    route_faults: open.route_faults.clone(),
                })
            }),
            memory: MemoryStatus::from(&self.setup.hardening.memory),
        }
    }

    /// A weak reference to the kept vault identity, so a test can see when its last holder drops it; `None` when the
    /// context keeps none.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn identity_probe(&self) -> Option<std::sync::Weak<VaultIdentity>> {
        self.inner.lock().await.identity.as_ref().map(Arc::downgrade)
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

    /// Opens the vault identity with `passphrase` on the blocking pool, since scrypt holds a thread for seconds.
    ///
    /// The task owns the passphrase and drops it when it ends. If this future is dropped first, the task still runs to
    /// its end and drops the identity it opened, which clears its key bytes.
    async fn open_identity(&self, passphrase: Passphrase) -> Result<VaultIdentity, UnlockRefusal> {
        let (locks, setup) = (Arc::clone(&self.locks), Arc::clone(&self.setup));
        tokio::task::spawn_blocking(move || unlock_with_passphrase(&locks.state, &setup.fs, &passphrase))
            .await
            .map_err(|_| UnlockRefusal::Interrupted)?
            .map_err(|error| match error {
                UnlockError::WrongPassphrase => UnlockRefusal::WrongPassphrase,
                other => UnlockRefusal::Failed(other),
            })
    }

    /// Runs [`open_and_check`] with `identity` on the blocking pool, since it reads and decrypts every vault file.
    ///
    /// If this future is dropped first, the task still runs to its end and drops what it built, the vault and its
    /// decrypted records included. A task that ends without a result fails the check.
    async fn run_check(&self, identity: Arc<VaultIdentity>) -> Result<Checked, CheckFailure> {
        let (locks, setup) = (Arc::clone(&self.locks), Arc::clone(&self.setup));
        tokio::task::spawn_blocking(move || {
            open_and_check(
                &locks.state,
                &locks.config,
                &setup.fs,
                identity,
                &setup.capabilities,
                &setup.accounts,
                &setup.upstream,
            )
        })
        .await
        .unwrap_or_else(|_| Err(CheckFailure::interrupted()))
    }

    /// Moves into Checking on `event` (an unlock, a reload, an approval's commit or a repair), keeps `identity`, runs the
    /// config check with it ([`open_and_check`]), and settles in Ready or Unavailable. Leaving Locked, both changes are
    /// logged as lock transitions.
    ///
    /// An event that does not lead to Checking is refused before the state, the snapshot or the kept identity changes.
    /// Entering Checking withdraws any served snapshot, so the context drops what it kept of that vault with it.
    async fn check_and_settle(
        &self,
        inner: &mut Inner,
        event: ServiceEvent,
        identity: Arc<VaultIdentity>,
    ) -> Result<ServiceState, IllegalTransition> {
        let from = inner.state;
        if next(from, event) != Ok(ServiceState::Checking) {
            return Err(IllegalTransition { state: from, event });
        }
        let checking = self.apply(inner, event)?;
        let committed = inner
            .open
            .as_ref()
            .and_then(|open| open.approval.committed())
            .map(|(version, _)| version.get());
        inner.open = None;
        inner.identity = Some(Arc::clone(&identity));
        let leaving_locked = from == ServiceState::Locked;
        if leaving_locked {
            log_lock_transition(from, checking);
        }
        let outcome = self.settle(inner, identity, event, committed).await?;
        if leaving_locked {
            log_lock_transition(checking, outcome);
        }
        Ok(outcome)
    }

    /// Runs the config check in Checking with `identity` and settles in Ready or Unavailable. A failure after a reload is
    /// recorded as `config.reload-failed`, with the version committed before the reload (`committed`).
    async fn settle(
        &self,
        inner: &mut Inner,
        identity: Arc<VaultIdentity>,
        event: ServiceEvent,
        committed: Option<u64>,
    ) -> Result<ServiceState, IllegalTransition> {
        match self.run_check(identity).await {
            Ok(Checked {
                snapshot,
                approval,
                credentials,
                route_faults,
            }) => {
                let open = OpenVault {
                    approval,
                    credentials,
                    route_faults,
                };
                self.enter_ready(inner, snapshot, open).await
            }
            Err(failure) => {
                if event == ServiceEvent::Reload {
                    log_reload_failed(committed, &failure);
                }
                self.apply(inner, ServiceEvent::CheckFailed(failure.failure()))
            }
        }
    }

    /// Checking to Ready: the listener rebuild, then the snapshot, then the state.
    async fn enter_ready(&self, inner: &mut Inner, snapshot: ServingSnapshot, open: OpenVault) -> Result<ServiceState, IllegalTransition> {
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
        inner.open = Some(open);
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

/// Warns the owner that a SIGHUP reload failed (design/config-approval.md, audit events). The detail names versions, routes
/// and credentials only; EP-26 picks the event up by its name.
fn log_reload_failed(committed: Option<u64>, failure: &CheckFailure) {
    tracing::warn!(
        event = "config.reload-failed",
        committed_version = ?committed,
        reason = failure.unavailable().as_str(),
        detail = %failure.detail(),
        "the reload failed, the service stops proxying",
    );
}

/// The outcome of a lock whose drain left `snapshots` held and the vault identity with `identity_holders` strong
/// references, logged at INFO when everything is cleared and at WARN otherwise.
fn lock_outcome(snapshots: usize, identity_holders: usize) -> LockOutcome {
    match (snapshots, identity_holders) {
        (0, 0) => {
            tracing::info!("lock complete: every serving snapshot, the vault in it and the vault identity were dropped");
            LockOutcome::Cleared
        }
        (0, _) => {
            tracing::warn!("lock incomplete: the vault identity is still held by a request that ignores cancellation");
            LockOutcome::IdentityHeld
        }
        (snapshots, _) => {
            tracing::warn!("lock drain expired: {snapshots} serving snapshot(s) are still held by requests that ignore cancellation");
            LockOutcome::Held { snapshots }
        }
    }
}

/// Logs one lock transition at INFO. It names the two states only; nothing an unlock was given reaches the log.
fn log_lock_transition(from: ServiceState, to: ServiceState) {
    tracing::info!(target: LOCK_TRANSITION_TARGET, ?from, ?to, "lock transition: {from:?} to {to:?}");
}
