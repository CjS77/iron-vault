//! Credential resolution, token lifecycle, provider signing rules, and constrained token-endpoint adapters.
//!
//! A kind turns a credential's [`CredentialMaterial`] into the one [`SlotValue`](iron_vault_policy::SlotValue) its
//! route's slot needs, and lists the [`ScrubPatterns`] response scrubbing must watch for. Slot formatting and query
//! encoding stay with slot filling in `iron-vault-policy`, so every kind returns bare secret text and a new kind
//! never touches routing.

mod basic_kind;
pub mod material;
pub mod resolve;
pub mod scrub;
#[cfg(test)]
mod secret_types_tests;
mod static_kind;

pub use basic_kind::BasicCredentialError;
pub use material::CredentialMaterial;
pub use resolve::{KindError, Resolution, resolve};
pub use scrub::ScrubPatterns;
