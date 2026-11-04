//! The decompression budget: how much a single response may decode to (spec §3.8, §3.12, §9).

use iron_vault_policy::Limits;

/// Decoded bytes below which the ratio is not checked. A tiny body such as `{}` followed by a long run of spaces
/// compresses by a huge factor yet costs nothing to process, so judging the ratio from the first few bytes would refuse
/// harmless responses. At 1 MiB a bomb has done little damage, and the size limit still applies throughout.
const RATIO_FLOOR: u64 = 1024 * 1024;

/// Which limit a response passed, with the counters at that moment. It carries no body byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BudgetExceeded {
    /// The decoded total passed `max_decompressed_response_bytes`.
    #[error("response body is {decoded} bytes after decoding, over the size limit")]
    TooLarge {
        /// Decoded bytes so far.
        decoded: u64,
        /// Compressed bytes so far.
        compressed: u64,
    },
    /// The decoded total grew faster than `max_decompression_ratio` allows.
    #[error("response body decoded to {decoded} bytes from {compressed}, over the ratio limit")]
    RatioExceeded {
        /// Decoded bytes so far.
        decoded: u64,
        /// Compressed bytes so far.
        compressed: u64,
    },
}

/// The per-response count of decoded bytes, checked against the size and ratio limits.
///
/// Call [`record`](Self::record) after every piece the decoder yields, with the compressed bytes consumed since the
/// last call (zero when none were) and the piece's length.
#[derive(Debug, Clone, Copy)]
pub struct DecompressionBudget {
    max_decoded: u64,
    max_ratio: u64,
    /// False for an `identity` body, which has no compressed size to compare against.
    check_ratio: bool,
    compressed: u64,
    decoded: u64,
}

impl DecompressionBudget {
    /// A budget for a content-coded body under `limits`.
    pub fn new(limits: &Limits) -> Self {
        Self {
            max_decoded: limits.max_decompressed_response_bytes(),
            max_ratio: limits.max_decompression_ratio(),
            check_ratio: true,
            compressed: 0,
            decoded: 0,
        }
    }

    /// A budget for an `identity` body: bounded by size alone, because the size limit bounds what the scrubber processes
    /// whether or not anything was decompressed.
    pub fn identity(limits: &Limits) -> Self {
        Self {
            check_ratio: false,
            ..Self::new(limits)
        }
    }

    /// The decoded bytes recorded so far.
    pub fn decoded(&self) -> u64 {
        self.decoded
    }

    /// Adds `compressed_in` input bytes and `decoded_out` output bytes, then checks both limits.
    pub fn record(&mut self, compressed_in: u64, decoded_out: u64) -> Result<(), BudgetExceeded> {
        self.compressed = self.compressed.saturating_add(compressed_in);
        self.decoded = self.decoded.saturating_add(decoded_out);
        let (decoded, compressed) = (self.decoded, self.compressed);
        if decoded > self.max_decoded {
            Err(BudgetExceeded::TooLarge { decoded, compressed })
        } else if self.check_ratio && decoded > RATIO_FLOOR && decoded > compressed.saturating_mul(self.max_ratio) {
            Err(BudgetExceeded::RatioExceeded { decoded, compressed })
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(toml: &str) -> Limits {
        #[derive(serde::Deserialize)]
        struct Config {
            limits: Limits,
        }
        toml::from_str::<Config>(toml).unwrap().limits
    }

    #[test]
    fn size_limit_is_inclusive() {
        let mut budget = DecompressionBudget::identity(&limits("[limits]\nmax_decompressed_response_bytes = 1000"));
        assert_eq!(budget.record(0, 1000), Ok(()));
        assert_eq!(
            budget.record(0, 1),
            Err(BudgetExceeded::TooLarge {
                decoded: 1001,
                compressed: 0
            })
        );
    }

    #[test]
    fn size_accumulates_across_pieces() {
        let mut budget = DecompressionBudget::new(&limits("[limits]\nmax_decompressed_response_bytes = 10"));
        assert_eq!(budget.record(100, 6), Ok(()));
        assert!(matches!(budget.record(0, 5), Err(BudgetExceeded::TooLarge { decoded: 11, .. })));
    }

    #[test]
    fn ratio_over_limit_below_the_floor_passes() {
        let mut budget = DecompressionBudget::new(&Limits::default());
        assert_eq!(budget.record(1, RATIO_FLOOR), Ok(()));
    }

    #[test]
    fn ratio_over_limit_above_the_floor_fails() {
        let mut budget = DecompressionBudget::new(&Limits::default());
        assert_eq!(budget.record(1, RATIO_FLOOR), Ok(()));
        assert_eq!(
            budget.record(0, 1),
            Err(BudgetExceeded::RatioExceeded {
                decoded: RATIO_FLOOR + 1,
                compressed: 1
            })
        );
    }

    #[test]
    fn ratio_at_the_limit_passes() {
        let mut budget = DecompressionBudget::new(&limits("[limits]\nmax_decompression_ratio = 100"));
        let compressed = RATIO_FLOOR / 100 + 1;
        assert_eq!(budget.record(compressed, compressed * 100), Ok(()));
        assert!(budget.record(0, 1).is_err());
    }

    #[test]
    fn identity_body_is_bounded_by_size_alone() {
        let mut budget = DecompressionBudget::identity(&Limits::default());
        assert_eq!(budget.record(0, 32 * 1024 * 1024), Ok(()));
        assert!(matches!(budget.record(0, 33 * 1024 * 1024), Err(BudgetExceeded::TooLarge { .. })));
    }

    #[test]
    fn counters_saturate_rather_than_wrap() {
        let mut budget = DecompressionBudget::identity(&Limits::default());
        assert!(budget.record(0, u64::MAX).is_err());
        assert!(budget.record(0, u64::MAX).is_err());
    }
}
