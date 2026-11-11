//! The vault events whose fields are the service context's own steps, refusals and outcomes. Only the service context
//! emits them, and it is Linux-only, so they are too.

use iron_vault_store::{InitFailure, InitStep, RecipientInventoryWriteError, UnlockError};

use crate::audit::{AUDIT_TARGET, AuditEvent, EventName, NamedApprover, memory_label};
use crate::hardening::MemoryProtection;
use crate::service_context::{DenialKind, HostUnlockOutcome, UnlockRefusal, step_names};

/// `vault.init-failed`: an init step failed, or its task ended without a result. `step` is the step number, or `discard`;
/// it is left out when no step is known.
#[derive(Debug, Clone, Copy)]
pub enum InitFailed<'a> {
    /// A step failed with `cause`, recorded by its variant only.
    Step {
        /// The failed step.
        step: InitStep,
        /// Why it failed.
        cause: &'a InitFailure,
    },
    /// The task ended without a result, so no step is known.
    TaskEnded,
}

impl AuditEvent for InitFailed<'_> {
    const NAME: EventName = EventName("vault.init-failed");

    fn emit(&self) {
        let (step, error_kind) = match self {
            Self::Step { step, cause } => (Some(step_names(*step).0), Some(init_failure_label(cause))),
            Self::TaskEnded => (None, None),
        };
        tracing::warn!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            step = step.as_deref(),
            error_kind,
            "vault initialization failed",
        );
    }
}

/// `vault.unlock-refused`: an unlock left the service where it was.
#[derive(Debug, Clone, Copy)]
pub struct UnlockRefused<'a> {
    /// Why, recorded as a fixed label.
    pub refusal: &'a UnlockRefusal,
}

impl AuditEvent for UnlockRefused<'_> {
    const NAME: EventName = EventName("vault.unlock-refused");

    fn emit(&self) {
        tracing::warn!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            refusal = unlock_refusal_label(self.refusal),
            memory_protection = unprotected_memory(self.refusal).map(memory_label),
            retry_after = retry_after(self.refusal),
            "unlock refused, the service stays Locked",
        );
    }
}

/// `vault.host-unlock`: a Protected or Container service tried the unlock handoff while Starting. It never holds the
/// handoff's bytes or its recipient key. Its outcome is `host_unlock_outcome`, since `outcome` is the request event's.
#[derive(Debug, Clone, Copy)]
pub struct HostUnlock {
    /// What the attempt came to; a refusal names its fixed reason in `refusal`.
    pub outcome: HostUnlockOutcome,
}

impl AuditEvent for HostUnlock {
    const NAME: EventName = EventName("vault.host-unlock");

    fn emit(&self) {
        let host_unlock_outcome = self.outcome.label();
        match self.outcome {
            HostUnlockOutcome::Unlocked => {
                tracing::info!(target: AUDIT_TARGET, event = Self::NAME.as_str(), host_unlock_outcome, "host unlock opened the vault");
            }
            HostUnlockOutcome::Absent => tracing::info!(
                target: AUDIT_TARGET,
                event = Self::NAME.as_str(),
                host_unlock_outcome,
                "no unlock handoff, the service stays Locked",
            ),
            HostUnlockOutcome::UnsealFailed => tracing::warn!(
                target: AUDIT_TARGET,
                event = Self::NAME.as_str(),
                host_unlock_outcome,
                "no unlock handoff and the handoff unit's unseal failed, the service stays Locked",
            ),
            HostUnlockOutcome::OwnerLocked => tracing::info!(
                target: AUDIT_TARGET,
                event = Self::NAME.as_str(),
                host_unlock_outcome,
                "the owner locked the service, the handoff was not opened, the service stays Locked",
            ),
            HostUnlockOutcome::Refused(refusal) => tracing::warn!(
                target: AUDIT_TARGET,
                event = Self::NAME.as_str(),
                host_unlock_outcome,
                refusal = refusal.label(),
                "host unlock refused, the service stays Locked",
            ),
        }
    }
}

/// `vault.presence-refused`: owner presence for a `replace` or `rm` was refused. No config is involved, so no digest.
#[derive(Debug, Clone, Copy)]
pub struct PresenceRefused<'a> {
    /// Which check of the approver key refused.
    pub refusal: DenialKind,
    /// The approver that was asked.
    pub approver: NamedApprover<'a>,
}

impl AuditEvent for PresenceRefused<'_> {
    const NAME: EventName = EventName("vault.presence-refused");

    fn emit(&self) {
        tracing::warn!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            refusal = self.refusal.label(),
            approver_id = self.approver.id_text().as_str(),
            approver_label = self.approver.label_text().as_str(),
            "owner presence refused; nothing was written",
        );
    }
}

/// The failure's variant: none of the text it wraps reaches the record.
const fn init_failure_label(failure: &InitFailure) -> &'static str {
    match failure {
        InitFailure::State(_) => "init_state",
        InitFailure::Recipients(_) => "recipients",
        InitFailure::Envelope(_) => "envelope",
        InitFailure::Write(_) | InitFailure::InventoryWrite(RecipientInventoryWriteError::Write(_)) => "state_write",
        InitFailure::Read(_) => "state_read",
        InitFailure::IdentityMismatch => "identity_mismatch",
        InitFailure::Inventory(_) | InitFailure::InventoryWrite(_) | InitFailure::InventoryRead(_) => "recipient_inventory",
        InitFailure::DefaultLabel(_) => "default_label",
        InitFailure::InventoryMismatch => "recipient_inventory_mismatch",
        InitFailure::Sign(_) => "sign",
        InitFailure::Vault(_) => "vault",
        InitFailure::Approval(_) => "approval",
        InitFailure::UnexpectedVersion(_) => "unexpected_version",
    }
}

/// The memory protection status a `memory_unprotected` refusal records beside its label, as a fixed label: the locking
/// error is an OS error's text, so it is not logged.
const fn unprotected_memory(refusal: &UnlockRefusal) -> Option<&MemoryProtection> {
    match refusal {
        UnlockRefusal::MemoryUnprotected(memory) => Some(memory),
        _ => None,
    }
}

/// Whole seconds until another attempt is allowed, recorded beside a `rate_limited` refusal.
const fn retry_after(refusal: &UnlockRefusal) -> Option<u64> {
    match refusal {
        UnlockRefusal::RateLimited(cooling) => Some(cooling.retry_after),
        _ => None,
    }
}

const fn unlock_refusal_label(refusal: &UnlockRefusal) -> &'static str {
    match refusal {
        UnlockRefusal::WrongState(_) => "wrong_state",
        UnlockRefusal::WrongPassphrase | UnlockRefusal::Failed(UnlockError::WrongPassphrase) => "wrong_passphrase",
        UnlockRefusal::Failed(UnlockError::Read(_)) => "state_read",
        UnlockRefusal::Failed(UnlockError::PassphraseEnvelope(_)) => "passphrase_envelope",
        UnlockRefusal::Failed(UnlockError::IdentityEnvelope(_)) => "identity_envelope",
        UnlockRefusal::Failed(UnlockError::InitializationUnfinished) => "initialization_unfinished",
        UnlockRefusal::Failed(UnlockError::ResetUnfinished) => "reset_unfinished",
        UnlockRefusal::Failed(UnlockError::NotInitialized) => "not_initialized",
        UnlockRefusal::Failed(UnlockError::Unrecognized { .. }) => "unrecognized_files",
        UnlockRefusal::Failed(UnlockError::InitializationState(_) | UnlockError::ListStateDir { .. }) => "state_unreadable",
        UnlockRefusal::Interrupted => "interrupted",
        UnlockRefusal::MemoryUnprotected(_) => "memory_unprotected",
        UnlockRefusal::RateLimited(_) => "rate_limited",
    }
}
