// SPDX-License-Identifier: MPL-2.0
//! What a host unlock attempt came to, as `vault.host-unlock` records it and `status` reports it. The types are here, and
//! not beside the Linux-only service that runs the unlock, because the CLI decodes them on every platform.

/// What one host unlock attempt came to, as `vault.host-unlock` records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostUnlockOutcome {
    /// The handoff unwrapped the vault identity, and the config check followed.
    Unlocked,
    /// Neither the handoff nor the unseal-failure file was there: a machine never provisioned for host unlock.
    Absent,
    /// No handoff was there, but the handoff unit left the unseal-failure file: its unseal failed, as after a `dbx`
    /// or KEK update changes PCR 7. The file is a diagnostic only; the service waits Locked for passphrase `unlock`,
    /// as for `Absent`.
    UnsealFailed,
    /// The owner-lock file is there: an explicit `lock` stands, so the handoff and the memory guard were never reached.
    OwnerLocked,
    /// The handoff was there, or memory was not locked, and the vault stayed shut.
    Refused(HostUnlockRefusal),
}

/// Why a host unlock left the service Locked. No variant carries the handoff's bytes or its recipient key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostUnlockRefusal {
    /// Memory is not locked against swap, so the handoff was never opened
    /// ([specification §14](../../../../design/iron-vault-specification.md#14-recipients-startup-and-memory)).
    MemoryUnprotected,
    /// The handoff or a directory above it broke the `UnlockHandoff` trusted-path rule.
    Untrusted,
    /// The handoff, the state directory or `identity.age` could not be read, or `identity.age` is malformed.
    Unreadable,
    /// The handoff is not one `age` secret key.
    NotAnIdentity,
    /// The vault is not Initialized.
    NotInitialized,
    /// `identity.age` is not wrapped for the handoff's identity.
    NotARecipient,
}

impl HostUnlockOutcome {
    /// Returns the snake_case label that the `host_unlock_outcome` field records, such as `unseal_failed`.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Unlocked => "unlocked",
            Self::Absent => "absent",
            Self::UnsealFailed => "unseal_failed",
            Self::OwnerLocked => "owner_locked",
            Self::Refused(_) => "refused",
        }
    }
}

impl HostUnlockRefusal {
    /// Returns the snake_case label that the `refusal` field records, such as `not_a_recipient`.
    pub const fn label(self) -> &'static str {
        match self {
            Self::MemoryUnprotected => "memory_unprotected",
            Self::Untrusted => "untrusted",
            Self::Unreadable => "unreadable",
            Self::NotAnIdentity => "not_an_identity",
            Self::NotInitialized => "not_initialized",
            Self::NotARecipient => "not_a_recipient",
        }
    }
}
