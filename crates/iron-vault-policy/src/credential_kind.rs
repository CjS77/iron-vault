//! The name of a credential record's kind, as policy needs it to check a route's slot (spec §3.3, §5.2).
//!
//! The kinds themselves live in `iron-vault-kinds`; this crate only names them so activation can refuse a route whose
//! slot its credential's kind cannot fill.

use crate::slot::Slot;

/// The kind a credential record declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CredentialKind {
    /// A stored provider key, sent as is.
    Static,
    /// A username and password, sent as `Authorization: Basic`.
    Basic,
}

impl CredentialKind {
    /// Whether a credential of this kind can fill `slot`: a static key fills a header or query slot, and a Basic
    /// credential only a Basic slot, since anywhere else its token would travel without its scheme.
    pub fn fills(self, slot: &Slot) -> bool {
        matches!(slot, Slot::Basic) == (self == CredentialKind::Basic)
    }

    /// The kind's name as a record declares it.
    pub fn as_str(self) -> &'static str {
        match self {
            CredentialKind::Static => "static",
            CredentialKind::Basic => "basic",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_kind_fills_only_its_slots() {
        let query = Slot::Query("k".parse().unwrap());
        assert!(CredentialKind::Static.fills(&query) && !CredentialKind::Static.fills(&Slot::Basic));
        assert!(CredentialKind::Basic.fills(&Slot::Basic) && !CredentialKind::Basic.fills(&query));
    }
}
