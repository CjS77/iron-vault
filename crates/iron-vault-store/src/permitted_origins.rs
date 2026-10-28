//! The exact destinations a credential record's secret may reach (spec §3.3).

use std::collections::BTreeSet;

use iron_vault_policy::{Host, Port};
use thiserror::Error;

/// A credential record's non-empty set of exact host and port pairs.
///
/// There is no scheme field: HTTPS is mandatory (spec §3.3), so an origin with any other scheme cannot be expressed.
/// The set is ordered, so iterating it, and so encoding it, always gives the same sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermittedOrigins(BTreeSet<(Host, Port)>);

/// Why a set of origins cannot be a record's permitted origins.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PermittedOriginsError {
    /// The set is empty, so the secret could reach nowhere and the record would be useless.
    #[error("a credential record must permit at least one origin")]
    Empty,
}

impl PermittedOrigins {
    /// Accepts `origins` if it holds at least one pair.
    pub fn new(origins: BTreeSet<(Host, Port)>) -> Result<Self, PermittedOriginsError> {
        match origins.is_empty() {
            true => Err(PermittedOriginsError::Empty),
            false => Ok(Self(origins)),
        }
    }

    /// The pairs in ascending order, the order a record payload stores them in.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &(Host, Port)> {
        self.0.iter()
    }

    /// The set as activation and the final outgoing-request check consume it.
    pub fn as_set(&self) -> &BTreeSet<(Host, Port)> {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_sets_are_rejected() {
        assert_eq!(PermittedOrigins::new(BTreeSet::new()), Err(PermittedOriginsError::Empty));
    }

    #[test]
    fn origins_iterate_in_ascending_order() {
        let origins = [("b.example", 443), ("a.example", 8443), ("a.example", 443)]
            .into_iter()
            .map(|(host, port)| (host.parse().unwrap(), Port::try_from(port).unwrap()))
            .collect();
        let ordered: Vec<_> = PermittedOrigins::new(origins).unwrap().iter().map(|(h, p)| format!("{h}:{p}")).collect();
        assert_eq!(ordered, ["a.example:443", "a.example:8443", "b.example:443"]);
    }
}
