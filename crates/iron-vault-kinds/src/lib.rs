// SPDX-License-Identifier: MPL-2.0
//! Kinds: the code that turns a stored credential into the secret text one request carries.
//!
//! This crate is the kinds bounded context. The store decrypts a credential record into [`CredentialMaterial`] and
//! calls [`resolve()`]. The kind returns a [`Resolution`] holding the bare [`SlotValue`](iron_vault_policy::SlotValue)
//! for the route's slot and the [`ScrubPatterns`] that response scrubbing must remove. v0 has two kinds, `static` and
//! `basic`. OAuth tokens and provider signatures arrive here as later kinds
//! ([future spec §2.2](../../../design/future-specifications.md#22-credential-kinds)).
//!
//! ```text
//! credential record ──store decrypts──▶ CredentialMaterial
//!                                              │
//!            Slot + AuthorizedRequest ───▶ resolve()
//!                                              │
//!                                         Resolution
//!                         ┌────────────────────┴────────────────────┐
//!                     SlotValue                                ScrubPatterns
//!       slot filling in iron-vault-policy             the scrubber in iron-vault
//!       adds the slot's format or encoding            removes them from the response
//! ```
//!
//! A kind returns bare secret text and never formats it. Slot filling owns formats and query encoding, so adding a kind
//! never touches routing.

mod basic_kind;
pub mod material;
pub mod resolve;
pub mod scrub;
#[cfg(test)]
mod secret_types_tests;
pub mod short_secret;
mod static_kind;

pub use basic_kind::BasicCredentialError;
pub use material::CredentialMaterial;
pub use resolve::{KindError, Resolution, resolve};
pub use scrub::ScrubPatterns;
pub use short_secret::{SHORT_SECRET_LEN, SecretField, ShortSecret};
