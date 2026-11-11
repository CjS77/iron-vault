//! The lockout reserve: the part of the TPM's shared dictionary-attack counter the helper never spends
//! (`design/tpm-approval-signer.md` "Lockout reserve").

use iron_vault_tpm_protocol::Response;

/// The shortest lockout interval the helper accepts. With the share spent, a compromised service then gets at most 144
/// guesses a day.
pub const INTERVAL_FLOOR_SECONDS: u32 = 600;
/// The most failures the helper spends however large the TPM's maximum.
pub const MAX_SHARE: u32 = 16;

/// The TPM's dictionary-attack state, read fresh at every request, and what it allows the helper.
///
/// The reserve rests on one helper instance at a time: the read and the try are two TPM commands, so two instances
/// could each read a counter below the share and both spend a try.
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
    /// The failures the helper may spend: half the maximum, rounded down, and at most [`MAX_SHARE`]. The rest, at least
    /// half, is the reserve, left for every other DA-protected object on the machine.
    pub fn share(&self) -> u32 {
        (self.max_tries / 2).min(MAX_SHARE)
    }

    /// The `06` refusal when the settings would not limit guessing: an interval below the floor (0 turns protection off)
    /// or a share of 0.
    pub fn settings_refusal(&self) -> Option<Response> {
        (self.interval_seconds < INTERVAL_FLOOR_SECONDS || self.share() == 0).then_some(Response::WeakDaSettings)
    }

    /// The [`settings_refusal`](Self::settings_refusal), else the `03` refusal while the TPM is in lockout or one more
    /// failure would take the counter past the share. The wait is the time the TPM takes to forget enough failures.
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
