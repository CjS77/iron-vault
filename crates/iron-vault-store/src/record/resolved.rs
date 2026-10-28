//! One record's resolution for one request, kept with that record's permitted origins (spec §3.3, §5.2).

use iron_vault_kinds::{Resolution, ScrubPatterns};
use iron_vault_policy::BoundCredential;

use crate::permitted_origins::PermittedOrigins;

/// The slot value and scrub patterns a credential record's kind produced, with a borrow of the same record's
/// permitted origins.
///
/// Only [`CredentialRecord::resolve`](crate::CredentialRecord::resolve) builds one, from its own material and its own
/// origins, so the value the final check sees and the destinations it compares against cannot come from different
/// records (R-4). There is no `Clone`, so the secret is not copied further; `Debug` shows the resolution's redacted
/// form.
#[derive(Debug)]
pub struct ResolvedCredential<'a> {
    resolution: Resolution,
    origins: &'a PermittedOrigins,
}

impl<'a> ResolvedCredential<'a> {
    pub(super) fn new(resolution: Resolution, origins: &'a PermittedOrigins) -> Self {
        Self { resolution, origins }
    }

    /// The slot value and the record's origins, as the final outgoing-request check takes them.
    pub fn bound(&self) -> BoundCredential<'_> {
        BoundCredential::new(self.resolution.value(), self.origins.as_set())
    }

    /// The forms of the injected secret response scrubbing must remove.
    pub fn patterns(&self) -> &ScrubPatterns {
        self.resolution.patterns()
    }
}
