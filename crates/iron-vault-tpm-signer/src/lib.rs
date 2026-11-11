//! The TPM signing helper's decisions that need no TPM: which messages it signs, the lockout reserve, and the
//! encoding of its signatures (`design/tpm-approval-signer.md`).
//!
//! They are a library so a plain `cargo test` covers them; the `iron-vault-tpm-signer` binary, which drives the TPM,
//! builds only with the `tpm` feature.

mod message;
mod reserve;
mod signature;

pub use message::is_signable;
pub use reserve::{INTERVAL_FLOOR_SECONDS, LockoutReserve, MAX_SHARE};
pub use signature::{low_s_signature, sec1_point};
