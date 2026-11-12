//! Decides whether the helper may try a PIN, from the TPM's dictionary-attack state (`design/tpm-approval-signer.md`
//! "Lockout reserve").
//!
//! The TPM keeps one failure counter for every PIN-protected object on the machine. The helper spends at most its
//! share of that counter and leaves the rest, the lockout reserve, for other users, so Iron Vault never brings the TPM
//! into lockout. For a TPM whose maximum is 32 failures:
//!
//! ```text
//! counter  0 ─────────── 15 │ 16 ─────────── 31 │ 32
//!          the helper's share │ the reserve       │ TPM lockout
//!          (min(32 / 2, 16))  │ never spent here  │
//! ```
//!
//! With the counter at or above the share, the helper answers locked out with the wait until the TPM has forgotten
//! enough failures for one more try.

use iron_vault_tpm_protocol::Response;

/// The shortest lockout interval the helper accepts, in seconds.
///
/// The TPM forgets one failure per interval, so once the share is spent a compromised service gets at most one guess
/// every 600 seconds: 144 a day.
pub const INTERVAL_FLOOR_SECONDS: u32 = 600;
/// The most failures the helper spends, however large the TPM's maximum.
pub const MAX_SHARE: u32 = 16;

/// Holds the TPM's dictionary-attack state, read fresh at every request, and decides what it allows the helper.
///
/// The reserve holds only while one helper instance runs at a time (`MaxConnections=1`): the read and the try are two
/// TPM commands, so two instances could each read a counter below the share and both spend a try.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockoutReserve {
    /// `TPM2_PT_LOCKOUT_COUNTER`: failures the TPM still remembers.
    pub counter: u32,
    /// `TPM2_PT_MAX_AUTH_FAIL`: failures that put the TPM into lockout.
    pub max_tries: u32,
    /// `TPM2_PT_LOCKOUT_INTERVAL`: seconds after which the TPM forgets one failure.
    pub interval_seconds: u32,
    /// `TPMA_PERMANENT.inLockout`.
    pub in_lockout: bool,
}

impl LockoutReserve {
    /// Returns the failures the helper may spend: half the maximum, rounded down, and at most [`MAX_SHARE`].
    ///
    /// The rest, at least half, is the reserve, left for every other dictionary-attack-protected object on the
    /// machine.
    pub fn share(&self) -> u32 {
        (self.max_tries / 2).min(MAX_SHARE)
    }

    /// Returns the `06` refusal, [`Response::WeakDaSettings`], when the TPM's settings would not limit guessing: an
    /// interval below [`INTERVAL_FLOOR_SECONDS`] (0 turns protection off) or a share of 0.
    pub fn settings_refusal(&self) -> Option<Response> {
        (self.interval_seconds < INTERVAL_FLOOR_SECONDS || self.share() == 0).then_some(Response::WeakDaSettings)
    }

    /// Returns the refusal to send instead of trying a PIN, or `None` when the helper may try one.
    ///
    /// The [`settings_refusal`](Self::settings_refusal) comes first. Otherwise the helper refuses with `03`,
    /// [`Response::LockedOut`], while the TPM is in lockout or the counter has reached the share. The wait is the time
    /// the TPM takes to forget enough failures for one more try: with a share of 3, a counter of 5 and a 1000-second
    /// interval, it must forget 3 failures, so the wait is 3000 seconds.
    pub fn try_refusal(&self) -> Option<Response> {
        let share = self.share();
        self.settings_refusal().or_else(|| {
            (self.in_lockout || self.counter >= share).then(|| Response::LockedOut {
                wait_seconds: u64::from(self.counter.saturating_sub(share) + 1) * u64::from(self.interval_seconds),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reserve(counter: u32, max_tries: u32, interval_seconds: u32) -> LockoutReserve {
        LockoutReserve {
            counter,
            max_tries,
            interval_seconds,
            in_lockout: false,
        }
    }

    #[test]
    fn the_share_is_half_the_maximum_rounded_down_and_at_most_sixteen() {
        let shares: Vec<u32> = [0, 1, 2, 3, 6, 7, 32, 33, 1000]
            .iter()
            .map(|max| reserve(0, *max, 600).share())
            .collect();
        assert_eq!(shares, [0, 0, 1, 1, 3, 3, 16, 16, 16]);
    }

    #[test]
    fn weak_settings_are_refused() {
        [reserve(0, 1, 600), reserve(0, 0, 7200), reserve(0, 32, 599), reserve(0, 32, 0)]
            .iter()
            .for_each(|weak| assert_eq!(weak.try_refusal(), Some(Response::WeakDaSettings), "{weak:?}"));
        assert_eq!(reserve(0, 2, 600).settings_refusal(), None);
    }

    #[test]
    fn a_try_is_allowed_only_below_the_share() {
        assert_eq!(reserve(2, 6, 600).try_refusal(), None);
        assert_eq!(reserve(3, 6, 600).try_refusal(), Some(Response::LockedOut { wait_seconds: 600 }));
        assert_eq!(reserve(5, 6, 1000).try_refusal(), Some(Response::LockedOut { wait_seconds: 3000 }));
    }

    #[test]
    fn lockout_is_refused_whatever_the_counter() {
        let locked = LockoutReserve {
            in_lockout: true,
            ..reserve(0, 32, 7200)
        };
        assert_eq!(locked.try_refusal(), Some(Response::LockedOut { wait_seconds: 7200 }));
    }
}
