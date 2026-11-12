//! The service context (specification §4, §14, §15): the one owned value the running service is. It drives the
//! service state model, keeps the vault identity from unlock until lock or stop, holds the open vault through the
//! serving snapshot, and binds the request interface.
//!
//! Every config check opens a new vault from the kept identity, so a reload, a repair or an approval re-enters Checking
//! without a new unlock, and an Unavailable service holds the one key and none of the decrypted credential records.
//!
//! Every change takes one async mutex and goes through [`next`], so no two changes interleave and none makes a
//! transition the §15 diagram lacks. Scrypt and the config check run on the blocking pool with the mutex held, so the
//! runtime thread stays free to answer requests with `503`, serve other admin commands and handle signals (§15).
//! Requests never take that mutex: each loads its admission from the snapshot holder, which every transition stores
//! into.
//!
//! Outside Ready the request listeners come from the unverified `config.toml` and answer only `503` with the holder's
//! reason, before any caller is identified (glossary: *Listener provenance*). Entering Ready rebuilds them from the
//! verified config before the snapshot is served, so a socket the verified config does not name is closed, with its
//! connections, before the snapshot could serve through it. The connections of the listeners kept stay open, so
//! re-entering Ready after a reload or an approval lets the requests admitted before it finish on the old snapshot
//! (design/config-approval.md, open question 1).

mod approval;
mod approver_change;
mod approver_list;
mod approver_order;
mod export;
mod forget_machine;
mod host_unlock;
mod import;
mod init;
mod log_destination;
mod migration;
mod owner_lock;
mod presence;
mod recipient_add;
mod recipient_remove;
mod recipients;
mod recovery;
mod reminder;
mod reset;
mod serving;
#[cfg(test)]
mod tests;
mod tpm_helper;
mod tpm_signer;
mod unlock;
mod vault_change;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::Duration;

use iron_vault_policy::{CredentialName, Limits, ListenerConfig, ListenerName, ParsedConfig};
use iron_vault_store::{
    ApprovalState, ApprovalVersion, ConfigDirLock, ConfigFileName, InitializationState, LockError, OsFs, Passphrase, RecordId,
    StateDirLock, StateFileName, StoreFs, UnfinishedKind, UnlockError, VaultIdentity, read_config_file, sweep_stale_config_temps,
    sweep_stale_temps, unlock_with_passphrase,
};
use tokio::sync::{Mutex, OwnedMutexGuard, watch};
use tokio::time::Instant;

use crate::admin::protocol::{MemoryStatus, StatusReport, UnlockedVault, VaultStatus};
use crate::attempt_limit::{AttemptLimiter, AttemptsCoolingDown};
use crate::audit::vault::{LockIncomplete, UnlockRefused};
use crate::audit::{AuditEvent, CheckFailed, LockTransition, ReloadFailed, count_of};
use crate::clock::{SystemClock, WallClock};
use crate::config_check::{CheckFailure, Checked, UpstreamSettings, open_and_check, parse_detail};
use crate::deployment::PasswdDirectory;
use crate::hardening::{HardeningReport, MemoryProtection};
use crate::logging::{LogSwitch, OpenedLog};
use crate::migration_authorization::PendingMigration;
use crate::request_listeners::RequestListeners;
use crate::service_state::{AdminOperation, IllegalTransition, RequestInterface, ServiceEvent, ServiceState, UnavailableReason, next};
use crate::serving_snapshot::{ServingSnapshot, SnapshotHolder, Withdrawn};
use crate::socket_activation::PassedSockets;
use crate::standing::{CredentialStanding, RouteFault};
use crate::trusted_path::ExpectedOwner;
use crate::trusted_path_report::ServicePaths;
use crate::unlock_handoff::HANDOFF_PATH;
use host_unlock::tries_host_unlock;
use reminder::{ReminderSchedule, SharedSchedule, with_schedule};
use serving::Serving;
use unlock::log_foreign_files;
pub(crate) use unlock::unprotected_reason;

pub use approval::{ApprovalEnd, ApprovalReview, NO_ASKABLE_APPROVER};
pub use approver_change::{ApproverChangePlan, ApproverRefusal};
pub use approver_list::ApproverListRefusal;
pub use export::{ExportError, ExportStream};
pub use forget_machine::ForgetCheck;
pub use host_unlock::{HostUnlockOutcome, HostUnlockRefusal};
pub use import::{BundleRefusal, ImportSlot};
pub use init::{HostUnlockUnavailable, InitRefusal, step_names};
pub use migration::MigrationSession;
pub use presence::{ApproverSecret, ApproverSigner, DenialKind, OwnerPresence, PresenceRefusal};
pub use recipient_add::{AddRefusal, Enrolled, PlanRefusal, RecipientAddPlan};
pub use recipient_remove::{RecipientRemoval, RemovalRefusal, RemovedRecipient};
pub use recipients::RecipientRefusal;
pub use recovery::{RecoveryProof, RecoveryRefusal};
pub use reset::{PlannedVault, ResetOutcome, ResetPlan, ResetRefusal, failure_step};
pub use tpm_helper::TpmStatus;
pub use tpm_signer::TpmSigner;
pub use vault_change::{CredentialChanged, CurrentRecord, VaultChangePlan, VaultChangeRefusal};

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
    /// A protected install's memory is not locked against swap, so the vault is not opened (§14). Holds the memory
    /// protection status, which names the `RLIMIT_MEMLOCK` soft limit or the locking error; never `Locked`.
    #[error("memory is not locked against swap ({}), so a protected install does not open the vault", unprotected_reason(.0))]
    MemoryUnprotected(MemoryProtection),
    /// Too many wrong vault passphrases, here or in migration authorization, so no attempt is made until the cooldown
    /// ends. Refused before any prompt, and again under the lock before the passphrase is tested.
    #[error(transparent)]
    RateLimited(AttemptsCoolingDown),
}

/// The state-directory lock and the config-directory lock, held for the service's lifetime: a second instance on
/// either directory fails to start (§4).
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

/// What an explicit `lock` came to: whether the secrets are confirmed gone, and whether the lock outlasts a restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockResult {
    /// Whether the vault identity and the serving snapshots were cleared within the drain.
    pub outcome: LockOutcome,
    /// Whether the owner-lock file was written. When false the service is Locked now, but a restart may host-unlock it
    /// again.
    pub persisted: bool,
}

/// What a passphrase `unlock` came to besides the state it settled in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unlocked {
    /// The state the config check settled the service in: Ready or Unavailable.
    pub state: ServiceState,
    /// Whether the owner-lock file is gone. When false the vault is open now, but the next start stays Locked.
    pub owner_lock_removed: bool,
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
    /// How the config check builds upstream clients.
    pub upstream: UpstreamSettings,
    /// What process hardening achieved before anything secret existed.
    pub hardening: HardeningReport,
    /// The log's writer, which activation points at the destination the approved config chooses. Its latch trips on a
    /// failed log write, and the request server refuses requests once it has.
    pub log: LogSwitch,
}

/// The running service. Shared by the admin handlers and the request side; see the module documentation.
#[derive(Debug)]
pub struct ServiceContext<F = OsFs> {
    /// Shared with each blocking task, which must own what it reads.
    setup: Arc<ServiceSetup<F>>,
    locks: Arc<ServiceLocks>,
    holder: Arc<SnapshotHolder>,
    /// The service-wide lock (glossary). `config approve` holds it from its request until its transaction ends, prompts
    /// included, and fails at once with `busy` while another holds it. A vault write takes it the same way, so an
    /// approval never sees the credential catalog change under it. A config check holds it to its end, so an unlock, a
    /// recheck and a `lock` wait for it; each takes it before the context's mutex. Shared, so a blocking task can own its
    /// guard and keep it until the task ends, even if the future that started the task is dropped.
    service_wide: Arc<Mutex<()>>,
    /// The import slot: held by the one `import` that is past its first step, so a second is refused with `busy` and the
    /// bundle an import keeps in memory is never doubled. Separate from `service_wide`, which an import takes only to
    /// write, after its prompts.
    import_slot: Arc<Mutex<()>>,
    /// How many `lock` calls are waiting for the service-wide lock. An approval at a prompt ends while it is non-zero.
    lock_requests: watch::Sender<usize>,
    /// Shared for the same reason as `service_wide`: the task that settles a check, and init's write task, own their
    /// guards, so a dropped caller can neither strand Checking nor release the lock while the task still writes.
    inner: Arc<Mutex<Inner>>,
    /// The time every record this context writes is stamped with.
    clock: Arc<dyn WallClock>,
    /// The recovery reminder schedule's memory: the interval in force and when it last reminded.
    reminders: SharedSchedule,
    /// Where `init --host-unlock` and `recipient remove` read the unlock handoff.
    handoff: PathBuf,
    /// The TPM signing helper's socket, in a profile that offers the `tpm` approver kind (`Protected`) and `None` in the rest.
    tpm_socket: Option<PathBuf>,
    /// Who must own the unseal-failure file for it to count: root in production.
    unseal_failure_owner: ExpectedOwner,
}

/// What the context keeps of an open vault beside the snapshot. They are one value, so a lock, a stop or a failed check
/// drops the approval state and the credential report together, and neither can outlive the other.
#[derive(Debug)]
struct OpenVault {
    approval: ApprovalState,
    /// The standing of each credential, from the report of opening the vault.
    credentials: Vec<CredentialStanding>,
    /// The record ID of each credential in `credentials`, which a vault change's summary names.
    record_ids: BTreeMap<CredentialName, RecordId>,
    /// The routes unavailable for a cause of their own, from the check.
    route_faults: Vec<RouteFault>,
}

/// What changes, behind the one mutex.
#[derive(Debug)]
struct Inner {
    state: ServiceState,
    /// What the startup host unlock came to; `None` in a profile that does not try one.
    host_unlock_outcome: Option<HostUnlockOutcome>,
    /// The vault identity, from unlock until lock or stop: `Some` in Checking, Ready and Unavailable. Each vault opened
    /// from it shares this one copy, so its key bytes are cleared when the last of them drops it.
    identity: Option<Arc<VaultIdentity>>,
    /// What the context keeps of the open vault, which itself is in the served snapshot. `None` unless the vault is open.
    open: Option<OpenVault>,
    /// The request listeners and the task serving them; `None` only while they are being rebuilt or once stopped.
    serving: Option<Serving>,
    /// The sockets systemd passed that no listener has adopted yet, for a later listener rebuild to adopt.
    passed: PassedSockets,
    /// The check generation: how many config checks the service has run. An approval commits only at the generation it
    /// started at, because each check discards uncommitted pending files.
    checks: u64,
    /// The one pending migration challenge, measured from the clock origin fixed when the service starts. `lock`
    /// retires it, so no challenge outlives the vault identity it was issued under.
    migration: PendingMigration,
    /// The passphrase attempt limit. Unlike the pending slot, `lock` leaves it alone, so locking cannot reset a guesser's count.
    attempts: AttemptLimiter,
}

impl<F: StoreFs + Send + Sync + 'static> ServiceContext<F> {
    /// Starts the service on `locks` in Starting, with the provisional listener set open on `provisional`, adopting from
    /// the sockets systemd `passed`. Call it inside the async runtime.
    ///
    /// A profile with no host unlock needs an interactive unlock, so it moves on to Locked here. The Protected and Container
    /// profiles stay in Starting, refusing requests as Locked does, until [`unlock_at_start`](Self::unlock_at_start) tries the
    /// unlock handoff: that needs the blocking pool and the detached config check, which this synchronous constructor
    /// cannot await. A provisional listener that cannot be opened is logged at WARN and left out.
    pub fn start(
        locks: ServiceLocks,
        setup: ServiceSetup<F>,
        provisional: &BTreeMap<ListenerName, ListenerConfig>,
        mut passed: PassedSockets,
    ) -> Result<Self, IllegalTransition> {
        let setup_profile = setup.paths.profile;
        let (listeners, failures) = RequestListeners::open_each(provisional, &setup.paths, &mut passed);
        failures
            .iter()
            .for_each(|error| tracing::warn!("provisional request listener not open: {error}"));
        // Starting refuses as Locked does, before any listener accepts. The default limits bound the provisional set:
        // nothing of the unverified config but its listeners is used.
        let holder = Arc::new(SnapshotHolder::refusing(UnavailableReason::Locked));
        let state = match tries_host_unlock(setup.paths.profile) {
            true => ServiceState::Starting,
            false => next(ServiceState::Starting, ServiceEvent::InteractiveUnlockRequired)?,
        };
        store_refusal(&holder, state);
        Ok(Self {
            inner: Arc::new(Mutex::new(Inner {
                state,
                host_unlock_outcome: None,
                identity: None,
                open: None,
                checks: 0,
                migration: PendingMigration::new(Instant::now()),
                attempts: AttemptLimiter::new(),
                serving: Some(Serving::start(
                    listeners,
                    Limits::default(),
                    Arc::clone(&holder),
                    setup.log.failure().clone(),
                )),
                passed,
            })),
            setup: Arc::new(setup),
            locks: Arc::new(locks),
            holder,
            service_wide: Arc::new(Mutex::new(())),
            import_slot: Arc::new(Mutex::new(())),
            lock_requests: watch::Sender::new(0),
            clock: Arc::new(SystemClock),
            reminders: Arc::new(StdMutex::new(ReminderSchedule::default())),
            handoff: PathBuf::from(HANDOFF_PATH),
            tpm_socket: tpm_helper::offered_socket(setup_profile),
            unseal_failure_owner: ExpectedOwner { uid: 0 },
        })
    }

    /// The context reading the unlock handoff for `init --host-unlock` and `recipient remove` at `handoff` instead of
    /// [`HANDOFF_PATH`], so a test stages one in a directory the trusted-path rule accepts.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_handoff_path(mut self, handoff: PathBuf) -> Self {
        self.handoff = handoff;
        self
    }

    /// The context offering the `tpm` approver kind with the helper's socket at `socket`, whatever its profile, so a test
    /// points it at a stand-in helper.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_tpm_socket(mut self, socket: PathBuf) -> Self {
        self.tpm_socket = Some(socket);
        self
    }

    /// The TPM signing helper's socket when this install offers the `tpm` approver kind: a `Protected` profile (or a test's
    /// socket) whose helper socket exists. Otherwise `None`.
    pub fn tpm_helper_socket(&self) -> Option<PathBuf> {
        self.tpm_socket.clone().filter(|socket| socket.exists())
    }

    /// The context accepting an unseal-failure file owned by `owner` instead of root, so a test can stage one.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_unseal_failure_owner(mut self, owner: ExpectedOwner) -> Self {
        self.unseal_failure_owner = owner;
        self
    }

    /// The context reading the time from `clock` instead of the system's, so a test sets the time.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_clock(mut self, clock: Arc<dyn WallClock>) -> Self {
        self.clock = clock;
        self
    }

    /// Unlocks with `identity` and runs the config check: Locked to Checking, then Ready or Unavailable.
    ///
    /// When the check passes, the listener set is rebuilt from the verified config, and only then is the snapshot
    /// served and the set approved. When it fails, the provisional listeners keep answering `503` with the failure's
    /// reason, the check has logged the detail at WARN, and the vault is dropped; the context keeps `identity` either
    /// way. Both state changes are logged as lock transitions. The caller has already opened `identity`, so it must
    /// have passed `require_locked_memory`, the memory guard every unlock path takes, before it did.
    ///
    /// It waits for the service-wide lock, as [`recheck`](Self::recheck) does, so it never runs during an approval.
    ///
    /// Cancel-safe: once the service enters Checking, a task of its own finishes the check and the move to Ready or
    /// Unavailable even if this future is dropped, so the service never stays in Checking (§15).
    pub async fn enter_checking(&self, identity: VaultIdentity) -> Result<ServiceState, IllegalTransition> {
        let service_wide = Arc::clone(&self.service_wide).lock_owned().await;
        let inner = Arc::clone(&self.inner).lock_owned().await;
        self.check_and_settle_detached(service_wide, inner, ServiceEvent::UnlockSucceeded, Arc::new(identity))
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
    ///
    /// Cancel-safe as [`enter_checking`](Self::enter_checking) is: a dropped future never leaves the service in Checking.
    pub async fn recheck(&self, event: ServiceEvent) -> Result<ServiceState, IllegalTransition> {
        let service_wide = Arc::clone(&self.service_wide).lock_owned().await;
        let inner = Arc::clone(&self.inner).lock_owned().await;
        let identity = inner.identity.clone().ok_or(IllegalTransition { state: inner.state, event })?;
        self.check_and_settle_detached(service_wide, inner, event, identity).await
    }

    /// Reloads on SIGHUP (§12, Q-5): [`recheck`](Self::recheck) with [`ServiceEvent::Reload`], which only a Ready service
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

    /// Unlocks with the owner's `passphrase` (§14) and runs the config check: Locked to Checking, then Ready or
    /// Unavailable, as [`enter_checking`](Self::enter_checking) does. Each state change is logged as a lock transition.
    ///
    /// It waits for the service-wide lock, as [`recheck`](Self::recheck) does: the owner has already typed the passphrase,
    /// and in Locked the lock is held only for seconds, by a `lock`, an `init` or a config check. Any approval at a prompt
    /// was cancelled by the `lock` that left the service Locked.
    ///
    /// The state is checked under the mutex, so two unlocks never both open the vault, and so is the initialization
    /// state, which `unlock` also read before its prompt: only Initialized goes on. A protected install whose memory is
    /// not locked is refused next, before scrypt runs, so the passphrase is never used. A wrong passphrase or an
    /// unreadable envelope leaves the service Locked: no other storage is ever tried (§15). The operational identity
    /// the passphrase opens is dropped inside [`unlock_with_passphrase`], once it has unwrapped the vault identity.
    ///
    /// Cancel-safe: dropping this future during scrypt leaves the service Locked, and dropping it once the service has
    /// entered Checking leaves a task of its own to finish the check, as [`enter_checking`](Self::enter_checking) does.
    /// A future dropped after the owner-lock file is removed but before the service settles leaves it Locked with the
    /// file gone, so the next start host-unlocks; that is benign, because the passphrase was right.
    pub async fn unlock(&self, passphrase: Passphrase) -> Result<Unlocked, UnlockRefusal> {
        let service_wide = Arc::clone(&self.service_wide).lock_owned().await;
        let mut inner = Arc::clone(&self.inner).lock_owned().await;
        let locked = inner.state;
        if !locked.admin_allows(AdminOperation::Unlock) {
            return Err(refuse_unlock(UnlockRefusal::WrongState(locked)));
        }
        log_foreign_files(&self.require_initialized().await?);
        self.require_locked_memory()?;
        // Under the mutex, so two exchanges that passed the check before the prompt cannot both test a passphrase.
        check_unlock_attempts(&inner.attempts)?;
        let opened = self.open_identity(passphrase).await;
        record_unlock_outcome(&mut inner.attempts, &opened);
        let identity = opened.inspect_err(|refusal| UnlockRefused { refusal }.emit())?;
        // The owner is present, so the explicit lock ends here; a failed removal is reported, never an unlock failure.
        let owner_lock_removed = self.remove_owner_lock().await;
        let settled = self
            .check_and_settle_detached(service_wide, inner, ServiceEvent::UnlockSucceeded, Arc::new(identity))
            .await
            .map_err(|illegal| refuse_unlock(UnlockRefusal::WrongState(illegal.state)))?;
        // The settle task has released the service-wide lock, which a missing record's first write needs.
        self.evaluate_recovery_reminder().await;
        Ok(Unlocked {
            state: settled,
            owner_lock_removed,
        })
    }

    /// Locks the service on an explicit `lock`: Ready or Unavailable to Locked, clearing the vault identity and every
    /// cached secret (§16, §14). §15 draws a lock only from those two states; from any other the event is refused.
    ///
    /// First it cancels an approval waiting at a prompt, which has reserved nothing, and waits for the service-wide lock:
    /// an approval past its prompts, or a config check, holds it for seconds. Then, under the context's mutex, it stops
    /// admitting requests, withdraws the serving snapshot (cancelling the requests running on it), drops the approval
    /// state, the credential report and the context's copy of the vault identity, and retires any pending migration
    /// challenge, so no later change interleaves. Unavailable has no snapshot to withdraw, so there the identity is
    /// cleared at once unless something else still holds it. Both locks are then released and the call waits up to `drain` for the last holder of the old snapshot,
    /// a streaming response body included, to drop it, so a slow request does not stall the other admin commands. The
    /// vault in that snapshot holds the last reference to the identity, so the identity is cleared with it. If the drain
    /// expires, or the identity is still held, it logs a warning and returns an outcome other than
    /// [`LockOutcome::Cleared`], never claiming the secrets are cleared.
    ///
    /// Under the service-wide lock, once the state check allows the lock and before the withdrawal, it writes the
    /// owner-lock file, so that a crash, a restart or a reboot does not undo the lock by host unlock. If the write fails,
    /// the lock still happens: the failure is logged at WARN and the result says the lock will not survive a restart.
    pub async fn lock(&self, drain: Duration) -> Result<LockResult, IllegalTransition> {
        let (mut withdrawn, identity, persisted) = self.withdraw_for_lock().await?;
        let snapshots = withdrawn.released(drain).await;
        Ok(LockResult {
            outcome: lock_outcome(snapshots, identity.strong_count()),
            persisted,
        })
    }

    /// The locked half of [`lock`](Self::lock): moves to Locked, withdraws the snapshot, drops what the context keeps
    /// of the vault and retires the pending migration challenge. Returns the withdrawn snapshots and a weak reference to the dropped identity, to see whether it is
    /// cleared.
    async fn withdraw_for_lock(&self) -> Result<(Withdrawn, Weak<VaultIdentity>, bool), IllegalTransition> {
        let _request = LockRequest::announce(&self.lock_requests);
        let _service_wide = self.service_wide.lock().await;
        let mut inner = self.inner.lock().await;
        let from = inner.state;
        let state = next(from, ServiceEvent::Lock)?;
        // Before the withdrawal, so a crash at any later point still leaves the file; a failed write does not stop the lock.
        let persisted = self.write_owner_lock().await;
        let (withdrawn, identity) = self.withdraw(&mut inner, from, state);
        Ok((withdrawn, identity, persisted))
    }

    /// The withdrawal `lock` and `reset` share, under the context's mutex: closes the request gate and cancels the
    /// in-flight requests before anything else changes, then drops what the context keeps of the vault, retires the
    /// pending migration challenge and moves to `state`. `reset` calls it from Locked too, where nothing changes but the
    /// retired challenge, and no transition is logged.
    fn withdraw(&self, inner: &mut Inner, from: ServiceState, state: ServiceState) -> (Withdrawn, Weak<VaultIdentity>) {
        let withdrawn = self.holder.refuse(UnavailableReason::Locked);
        inner.open = None;
        inner.migration.retire();
        let identity = inner.identity.take().as_ref().map_or_else(Weak::new, Arc::downgrade);
        inner.state = state;
        if from != state {
            log_lock_transition(from, state);
        }
        (withdrawn, identity)
    }

    /// Stops the service on SIGTERM or SIGINT: Ready to Stopped, then drops the snapshot, the vault in it, the approval
    /// state and the vault identity, so their secret buffers clear (§14), and closes the request listeners, removing
    /// their socket files.
    ///
    /// §15 draws a stop only from Ready. From any other state there is no transition to make: the process ends all
    /// the same, after the same teardown.
    pub async fn stop(&self) {
        let mut inner = self.inner.lock().await;
        if let Err(refused) = apply(&self.holder, &mut inner, ServiceEvent::Stop) {
            tracing::info!("stopping from {:?}", refused.state);
        }
        // Stopped has no request interface; storing a refusal withdraws the snapshot and drops the holder's reference.
        self.holder.refuse(UnavailableReason::Locked);
        inner.open = None;
        inner.identity = None;
        if let Some(serving) = inner.serving.take() {
            serving.stop().await;
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
    ///
    /// While no vault is open the directories are read for [`InitializationState`], on the blocking pool under the
    /// service's own locks. Unrecognized files, or a directory that cannot be listed, report as Locked: `status` has no
    /// error to give, and `unlock` and `init` name the offending files when the owner runs them.
    pub async fn status(&self) -> StatusReport {
        let recovery = self.recovery_status().await;
        let inner = self.inner.lock().await;
        let vault = match inner.open.as_ref() {
            Some(open) => VaultStatus::Unlocked(UnlockedVault {
                id: open.approval.vault_id(),
                committed: open.approval.committed().map(|(version, _)| version.get()),
                highest_reserved: open.approval.highest_reserved(),
                credentials: open.credentials.clone(),
                route_faults: open.route_faults.clone(),
            }),
            None => self.closed_vault_status().await,
        };
        StatusReport {
            state: inner.state,
            profile: self.setup.paths.profile,
            vault,
            memory: MemoryStatus::from(&self.setup.hardening.memory),
            recovery,
            host_unlock_outcome: inner.host_unlock_outcome,
        }
    }

    /// Every credential in the open vault's manifest, in name order, with its kind and permitted origins when its record is
    /// healthy; `None` while no vault is open. Read under the mutex, so a completed `add` shows at once.
    pub async fn list(&self) -> Option<Vec<CredentialStanding>> {
        self.inner.lock().await.open.as_ref().map(|open| open.credentials.clone())
    }

    /// What the directories say about a vault that is not open.
    async fn closed_vault_status(&self) -> VaultStatus {
        let (locks, setup) = (Arc::clone(&self.locks), Arc::clone(&self.setup));
        let read = tokio::task::spawn_blocking(move || InitializationState::read(&locks.state, &locks.config, &setup.fs)).await;
        match read {
            Ok(Ok(InitializationState::Uninitialized)) => VaultStatus::NotInitialized,
            Ok(Ok(InitializationState::Unfinished(UnfinishedKind::Initialization))) => VaultStatus::InitializationUnfinished,
            Ok(Ok(InitializationState::Unfinished(UnfinishedKind::Import))) => VaultStatus::ImportUnfinished,
            Ok(Ok(InitializationState::UnfinishedReset)) => VaultStatus::ResetUnfinished,
            _ => VaultStatus::Locked,
        }
    }

    /// A weak reference to the kept vault identity, so a test can see when its last holder drops it; `None` when the
    /// context keeps none.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn identity_probe(&self) -> Option<std::sync::Weak<VaultIdentity>> {
        self.inner.lock().await.identity.as_ref().map(Arc::downgrade)
    }

    /// The passphrase attempt limiter, so a test can see that `lock` leaves its count alone.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn attempt_limiter(&self) -> tokio::sync::MappedMutexGuard<'_, AttemptLimiter> {
        tokio::sync::MutexGuard::map(self.inner.lock().await, |inner| &mut inner.attempts)
    }

    /// The pending migration slot, so a test can issue a challenge before any command does and see `lock` retire it.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn pending_migration(&self) -> tokio::sync::MappedMutexGuard<'_, PendingMigration> {
        tokio::sync::MutexGuard::map(self.inner.lock().await, |inner| &mut inner.migration)
    }

    /// Advances the check generation without running a check. A config check waits for the service-wide lock an
    /// approval holds, so only this lets a test reach the generation half of the commit's backstop.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn advance_check_generation(&self) {
        let mut inner = self.inner.lock().await;
        inner.checks = inner.checks.wrapping_add(1);
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

    /// Completes once a `lock` is waiting for the service-wide lock, at once when one already waits. An approval or a
    /// vault change at a prompt holds that lock, and ends on this rather than make the `lock` wait for the owner.
    async fn lock_requested(&self) {
        let mut requests = self.lock_requests.subscribe();
        // The sender is the service's, which outlives every caller, so the wait ends only on a request.
        let _ = requests.wait_for(|waiting| *waiting > 0).await;
    }

    /// What the settle step needs of the context, owned, so the step can run in a task of its own.
    fn settler(&self) -> Settler<F> {
        Settler {
            setup: Arc::clone(&self.setup),
            locks: Arc::clone(&self.locks),
            holder: Arc::clone(&self.holder),
            reminders: Arc::clone(&self.reminders),
        }
    }

    /// [`Settler::check_and_settle`] in a spawned task that owns `inner` and the service-wide lock, so the move out of
    /// Checking finishes even if this future is dropped (§15 leaves Checking only on a pass or a failure), and the
    /// service-wide lock is held until the check ends. A task that ends without a result has already failed closed
    /// through its [`SettleGuard`], so the caller only reads the state it left.
    async fn check_and_settle_detached(
        &self,
        service_wide: OwnedMutexGuard<()>,
        inner: OwnedMutexGuard<Inner>,
        event: ServiceEvent,
        identity: Arc<VaultIdentity>,
    ) -> Result<ServiceState, IllegalTransition> {
        let mut guard = SettleGuard::new(inner, Arc::clone(&self.holder));
        let settler = self.settler();
        let settling = tokio::spawn(async move {
            let _service_wide = service_wide;
            settler.check_and_settle(&mut guard.inner, event, identity).await
        });
        match settling.await {
            Ok(settled) => settled,
            Err(crashed) => {
                log_task_crash("the config check's settle task", &crashed);
                Ok(self.inner.lock().await.state)
            }
        }
    }
}

/// The vault passphrase attempt limit's answer now, logged at WARN like every other unlock refusal. `unlock` and
/// migration authorization share the one limiter.
fn check_unlock_attempts(attempts: &AttemptLimiter) -> Result<(), UnlockRefusal> {
    attempts
        .check(tokio::time::Instant::now())
        .map_err(UnlockRefusal::RateLimited)
        .inspect_err(|refusal| UnlockRefused { refusal }.emit())
}

/// Counts what the design counts: a wrong passphrase is a failure, and an opened vault clears the count, whatever state
/// the config check then settles in. An unreadable envelope or an interrupted task shows nothing about a guess.
fn record_unlock_outcome(attempts: &mut AttemptLimiter, opened: &Result<VaultIdentity, UnlockRefusal>) {
    match opened {
        Ok(_) => attempts.record_success(),
        Err(UnlockRefusal::WrongPassphrase) => attempts.record_failure(tokio::time::Instant::now()),
        Err(_) => {}
    }
}

/// Records `refusal` as `vault.unlock-refused` and returns it, for a refusal made at a site that has no event of its own.
fn refuse_unlock(refusal: UnlockRefusal) -> UnlockRefusal {
    UnlockRefused { refusal: &refusal }.emit();
    refusal
}

/// Logs that `task`, a spawned settle or approval task, ended without a result, and whether it panicked or was cancelled.
fn log_task_crash(task: &str, crashed: &tokio::task::JoinError) {
    let ended = if crashed.is_panic() { "panicked" } else { "was cancelled" };
    tracing::error!("{task} {ended} before it gave a result");
}

/// A `lock` waiting for the service-wide lock, counted in [`ServiceContext::lock_requests`] until it is dropped, so a
/// `lock` whose future is dropped stops cancelling approvals.
struct LockRequest<'a>(&'a watch::Sender<usize>);

impl<'a> LockRequest<'a> {
    fn announce(requests: &'a watch::Sender<usize>) -> Self {
        requests.send_modify(|waiting| *waiting = waiting.saturating_add(1));
        Self(requests)
    }
}

impl Drop for LockRequest<'_> {
    fn drop(&mut self) {
        self.0.send_modify(|waiting| *waiting = waiting.saturating_sub(1));
    }
}

/// The settle task's hold on `inner`. The task owns it, so a crash fails closed even after the caller is gone: dropping
/// it while the service is still in Checking moves the service to Unavailable needing recovery, drops the vault the
/// check opened and logs `config.check-failed`. A settled task leaves a state §15 allows, which stays.
struct SettleGuard {
    inner: OwnedMutexGuard<Inner>,
    holder: Arc<SnapshotHolder>,
    /// The check started from an unlock, so leaving Checking is a lock transition too.
    unlocking: bool,
}

impl SettleGuard {
    fn new(inner: OwnedMutexGuard<Inner>, holder: Arc<SnapshotHolder>) -> Self {
        let unlocking = is_unlocking_from(inner.state);
        Self { inner, holder, unlocking }
    }
}

impl Drop for SettleGuard {
    fn drop(&mut self) {
        if self.inner.state != ServiceState::Checking {
            return;
        }
        self.inner.open = None;
        let failed = ServiceEvent::CheckFailed(CheckFailure::interrupted().failure());
        // Checking always leads to Unavailable on a failure, so the transition is always made.
        if let Ok(unavailable) = apply(&self.holder, &mut self.inner, failed)
            && self.unlocking
        {
            log_lock_transition(ServiceState::Checking, unavailable);
        }
    }
}

/// The parts of the context the settle step and the approval transaction ([`Settler::run_approval`]) read, each shared,
/// so either can outlive the caller that started it.
struct Settler<F> {
    setup: Arc<ServiceSetup<F>>,
    locks: Arc<ServiceLocks>,
    holder: Arc<SnapshotHolder>,
    reminders: SharedSchedule,
}

impl<F: StoreFs + Send + Sync + 'static> Settler<F> {
    /// Runs [`open_and_check`] with `identity` on the blocking pool, since it reads and decrypts every vault file.
    ///
    /// If this future is dropped first, the task still runs to its end and drops what it built, the vault and its
    /// decrypted records included. A task that ends without a result fails the check.
    async fn run_check(&self, identity: Arc<VaultIdentity>) -> Result<(Checked, Option<OpenedLog>), CheckFailure> {
        let (locks, setup) = (Arc::clone(&self.locks), Arc::clone(&self.setup));
        tokio::task::spawn_blocking(move || {
            let checked = open_and_check(&locks.state, &locks.config, &setup.fs, identity, &setup.accounts, &setup.upstream)?;
            let log = open_chosen_log(&checked, &setup)?;
            Ok((checked, log))
        })
        .await
        .unwrap_or_else(|_| Err(CheckFailure::interrupted()))
    }

    /// Moves into Checking on `event` (an unlock, a host unlock, a reload, an approval's commit or a repair), keeps
    /// `identity`, runs the config check with it ([`open_and_check`]), and settles in Ready or Unavailable. Leaving Locked
    /// or Starting, both changes are logged as lock transitions.
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
        let checking = apply(&self.holder, inner, event)?;
        let committed = inner
            .open
            .as_ref()
            .and_then(|open| open.approval.committed())
            .map(|(version, _)| version);
        inner.open = None;
        inner.identity = Some(Arc::clone(&identity));
        let unlocking = is_unlocking_from(from);
        if unlocking {
            log_lock_transition(from, checking);
        }
        let outcome = self.settle(inner, identity, event, committed).await?;
        if unlocking {
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
        committed: Option<ApprovalVersion>,
    ) -> Result<ServiceState, IllegalTransition> {
        inner.checks = inner.checks.wrapping_add(1);
        match self.run_check(identity).await {
            Ok((
                Checked {
                    snapshot,
                    approval,
                    credentials,
                    record_ids,
                    route_faults,
                },
                log,
            )) => {
                let open = OpenVault {
                    approval,
                    credentials,
                    record_ids,
                    route_faults,
                };
                self.enter_ready(inner, snapshot, open, log).await
            }
            Err(failure) => {
                if event == ServiceEvent::Reload {
                    ReloadFailed {
                        committed,
                        failure: &failure,
                    }
                    .emit();
                }
                apply(&self.holder, inner, ServiceEvent::CheckFailed(failure.failure()))
            }
        }
    }

    /// Checking to Ready: the log switch when the check opened a new destination, the listener rebuild, then the
    /// snapshot, then the state. The switch comes first, so every record of the activation is in the new destination.
    async fn enter_ready(
        &self,
        inner: &mut Inner,
        snapshot: ServingSnapshot,
        open: OpenVault,
        log: Option<OpenedLog>,
    ) -> Result<ServiceState, IllegalTransition> {
        let ready = next(inner.state, ServiceEvent::CheckPassed)?;
        // A passed check verified the committed config, so a committed version is always there.
        if let Some((opened, (version, _))) = log.zip(open.approval.committed()) {
            log_destination::switch(&self.setup.log, opened, version);
        }
        let config = snapshot.policy().config();
        let limits = *config.limits();
        with_schedule(&self.reminders, |schedule| {
            schedule.set_interval(config.effective_recovery_reminder())
        });
        let current = inner.serving.take().unwrap_or_else(|| {
            Serving::start(
                RequestListeners::empty(),
                limits,
                Arc::clone(&self.holder),
                self.setup.log.failure().clone(),
            )
        });
        let (serving, failures) = current
            .rebuild(config.listeners(), limits, &self.setup.paths, &mut inner.passed)
            .await;
        failures
            .iter()
            .for_each(|error| tracing::warn!("approved request listener missing until restart: {error}"));
        inner.serving = Some(serving);
        self.holder.serve(snapshot);
        inner.open = Some(open);
        inner.state = ready;
        Ok(ready)
    }
}

/// The config check's last step: opening the log destination the checked config chooses, when it moves the log. A
/// destination that cannot be used fails the check, logged as every check failure is, and the log stays where it is.
fn open_chosen_log<F>(checked: &Checked, setup: &ServiceSetup<F>) -> Result<Option<OpenedLog>, CheckFailure> {
    log_destination::open_chosen(checked.snapshot.policy().config(), &setup.log, &setup.paths)
        .map_err(CheckFailure::Config)
        .inspect_err(|failure| CheckFailed { failure }.emit())
}

/// Moves to the state `event` leads to, storing that state's refusal in `holder`.
fn apply(holder: &SnapshotHolder, inner: &mut Inner, event: ServiceEvent) -> Result<ServiceState, IllegalTransition> {
    let state = next(inner.state, event)?;
    inner.state = state;
    store_refusal(holder, state);
    Ok(state)
}

/// Stores the refusal `state`'s request interface gives, so a `503`'s reason has one source. Ready serves, which
/// [`Settler::enter_ready`] stores itself, after the listener rebuild.
fn store_refusal(holder: &SnapshotHolder, state: ServiceState) {
    if let RequestInterface::Refuse(reason) = state.request_interface() {
        holder.refuse(reason);
    }
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
            LockIncomplete {
                snapshots_held: 0,
                identity_held: true,
            }
            .emit();
            LockOutcome::IdentityHeld
        }
        (snapshots, holders) => {
            LockIncomplete {
                snapshots_held: count_of(snapshots),
                identity_held: holders > 0,
            }
            .emit();
            LockOutcome::Held { snapshots }
        }
    }
}

/// Whether entering Checking from `from` brings the vault identity into memory: an unlock from Locked, or a host unlock
/// from Starting. Those checks are lock transitions; a reload, an approval or a repair already held the identity.
const fn is_unlocking_from(from: ServiceState) -> bool {
    matches!(from, ServiceState::Locked | ServiceState::Starting)
}

/// Records one lock transition.
fn log_lock_transition(from: ServiceState, to: ServiceState) {
    LockTransition { from, to }.emit();
}
