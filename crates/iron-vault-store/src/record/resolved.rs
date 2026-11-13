// SPDX-License-Identifier: MPL-2.0
//! One record's resolution for one request, kept with that record's permitted origins
//! ([spec §6](../../../../design/iron-vault-specification.md#6-credential-records-and-configuration),
//! [future spec §2.2](../../../../design/future-specifications.md#22-credential-kinds)).

use iron_vault_kinds::{Resolution, ScrubPatterns};
use iron_vault_policy::BoundCredential;

use crate::permitted_origins::PermittedOrigins;

/// The slot value and scrub patterns a credential record's kind produced, with a borrow of the same record's
/// permitted origins.
///
/// Only [`CredentialRecord::resolve`](crate::CredentialRecord::resolve) builds one, from its own material and its own
/// origins, so the value the final check sees and the destinations it compares against cannot come from different
/// records. There is no `Clone`, so the secret is not copied further, and `Debug` shows the resolution's redacted form.
#[derive(Debug)]
pub struct ResolvedCredential<'a> {
    resolution: Resolution,
    origins: &'a PermittedOrigins,
}

impl<'a> ResolvedCredential<'a> {
    pub(super) fn new(resolution: Resolution, origins: &'a PermittedOrigins) -> Self {
        Self { resolution, origins }
    }

    /// Returns the slot value and the record's origins, as the final outgoing-request check takes them.
    pub fn bound(&self) -> BoundCredential<'_> {
        BoundCredential::new(self.resolution.value(), self.origins.as_set())
    }

    /// Returns the forms of the injected secret that response scrubbing must remove.
    pub fn patterns(&self) -> &ScrubPatterns {
        self.resolution.patterns()
    }

    /// Returns the scrub patterns alone, for response scrubbing once the final check has used the value. The value is
    /// dropped and wiped here.
    pub fn into_patterns(self) -> ScrubPatterns {
        self.resolution.into_parts().1
    }
}
