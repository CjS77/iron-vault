//! A host account table for tests that activate configs with peer callers.

use std::collections::BTreeMap;

use crate::account_name::AccountName;
use crate::activation::AccountDirectory;

/// The uid the test service runs as.
pub(crate) const SERVICE_UID: u32 = 990;

/// The kernel's default overflow uid, which the test host reports unless a test configures another.
pub(crate) const DEFAULT_OVERFLOW_UID: u32 = 65534;

/// The accounts every test host has: root, the service account, `nobody`, and the peer accounts the test configs name.
const HOST: &[(&str, u32)] = &[
    ("root", 0),
    ("iron-vault", SERVICE_UID),
    ("nobody", DEFAULT_OVERFLOW_UID),
    ("code", 1000),
    ("fx-mcp", 1001),
    ("fx-other", 1002),
];

/// Accounts held in memory: a name maps to its uid, and any other name is unknown.
pub(crate) struct FakeAccounts {
    uids: BTreeMap<String, u32>,
    overflow_uid: u32,
}

impl FakeAccounts {
    /// The standard test host.
    pub(crate) fn host() -> Self {
        Self::with(&[])
    }

    /// The standard test host with `extra` accounts added or replacing standard ones.
    pub(crate) fn with(extra: &[(&str, u32)]) -> Self {
        Self {
            uids: HOST.iter().chain(extra).map(|(name, uid)| ((*name).to_owned(), *uid)).collect(),
            overflow_uid: DEFAULT_OVERFLOW_UID,
        }
    }

    /// This host with the kernel configured to report `uid` for unmapped peers.
    pub(crate) fn overflowing_to(self, uid: u32) -> Self {
        Self { overflow_uid: uid, ..self }
    }
}

impl AccountDirectory for FakeAccounts {
    fn uid(&self, name: &AccountName) -> Option<u32> {
        self.uids.get(name.as_str()).copied()
    }

    fn service_account_uid(&self) -> u32 {
        SERVICE_UID
    }

    fn overflow_uid(&self) -> u32 {
        self.overflow_uid
    }
}
