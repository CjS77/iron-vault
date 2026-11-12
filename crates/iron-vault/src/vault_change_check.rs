//! The vault change check (glossary; design/credential-commands.md, "Vault change check"): the dry run `replace` and
//! `rm` make before any prompt. It activates the active config against the credential catalog as it would be after the
//! change and keeps only the failures the change causes, so every name the active config references stays in the vault
//! manifest (specification §6, §12).
//!
//! It is pure: the service supplies the active config, its catalog and account directory.

use iron_vault_policy::{
    AccountDirectory, ActivationError, CatalogEntry, CredentialCatalog, CredentialKind, CredentialName, RouteName, ValidatedConfig,
    activate,
};
use iron_vault_store::PermittedOrigins;

/// The change a `replace` or `rm` will write, as the vault change check and owner presence see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlannedChange {
    /// `rm`: the name becomes unknown.
    Remove(CredentialName),
    /// `replace`: the name becomes usable with the new kind and permitted origins, even when its record is damaged.
    Replace {
        /// The credential replaced.
        name: CredentialName,
        /// The new record's kind.
        kind: CredentialKind,
        /// The new record's permitted origins.
        origins: PermittedOrigins,
    },
}

impl PlannedChange {
    /// The credential the change is to.
    pub fn name(&self) -> &CredentialName {
        match self {
            Self::Remove(name) | Self::Replace { name, .. } => name,
        }
    }

    /// The catalog entry the name has after the change.
    fn entry(&self) -> CatalogEntry {
        match self {
            Self::Remove(_) => CatalogEntry::Unknown,
            Self::Replace { kind, origins, .. } => CatalogEntry::Usable {
                kind: *kind,
                origins: origins.as_set().clone(),
            },
        }
    }
}

/// A route that uses the changed name and would no longer activate, with the rule it breaks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AffectedRoute {
    /// The route.
    pub route: RouteName,
    /// Why it would not activate: an unknown credential, an origin the new record does not permit, or a slot the new
    /// kind cannot fill.
    pub reason: ActivationError,
}

/// A catalog with one name's entry replaced by the planned change.
struct Changed<'a, C> {
    current: &'a C,
    change: &'a PlannedChange,
}

impl<C: CredentialCatalog> CredentialCatalog for Changed<'_, C> {
    fn entry(&self, name: &CredentialName) -> CatalogEntry {
        if name == self.change.name() {
            self.change.entry()
        } else {
            self.current.entry(name)
        }
    }
}

/// Activates `config` against `current` with `change` applied, and returns every failure the change causes, in route
/// name order; a route that breaks two rules appears once for each.
///
/// A failure on a route that does not use the name, or on a peer account, was not caused by the change, so it is left
/// for the config check after the write to find.
pub fn vault_change_check(
    config: &ValidatedConfig,
    current: &impl CredentialCatalog,
    accounts: &impl AccountDirectory,
    change: &PlannedChange,
) -> Result<(), Vec<AffectedRoute>> {
    let Err(errors) = activate(config, &Changed { current, change }, accounts) else {
        return Ok(());
    };
    let affected: Vec<_> = errors.into_iter().filter_map(|error| caused_by(error, change.name())).collect();
    if affected.is_empty() { Ok(()) } else { Err(affected) }
}

/// The affected route when `error` is about the credential `name`.
fn caused_by(error: ActivationError, name: &CredentialName) -> Option<AffectedRoute> {
    use ActivationError as E;
    let route = match &error {
        E::UnknownCredential { route, credential }
        | E::OriginNotPermitted { route, credential, .. }
        | E::SlotMismatch { route, credential, .. }
            if credential == name =>
        {
            route.clone()
        }
        _ => return None,
    };
    Some(AffectedRoute { route, reason: error })
}

#[cfg(test)]
mod tests;
