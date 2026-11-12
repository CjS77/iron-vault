//! The TPM signing helper's decisions that need no TPM: which messages it signs, the lockout reserve, and the
//! encoding of its signatures (`design/tpm-approval-signer.md`).
//!
//! This crate is the only one that links `tpm2-tss`. The `iron-vault-tpm-signer` binary in it drives the TPM and builds
//! only with the `tpm` feature. These pure rules live in the library so a plain `cargo test`, with no TPM or TSS
//! installed, covers them.

mod message;
mod reserve;
mod signature;

pub use message::is_signable;
pub use reserve::{INTERVAL_FLOOR_SECONDS, LockoutReserve, MAX_SHARE};
pub use signature::{low_s_signature, sec1_point};
