//! Bundle order: the fixed entries one after another, then approvers and records strictly ascending, numbering the header's counts
//! ([migration bundle v1, "Entries"](../../../../../design/storage-formats.md#entries)).

use super::BundleError;
use crate::migration_bundle::{BundleHeader, EntryName};

/// The entries admitted so far, and the bundle header once its bytes are in.
#[derive(Default)]
pub(super) struct EntryOrder {
    last: Option<EntryName>,
    header: Option<BundleHeader>,
    approvers: usize,
    records: usize,
}

impl EntryOrder {
    /// Admits the entry `name` if it comes next in bundle order and within the header's counts.
    pub(super) fn admit(&mut self, name: EntryName) -> Result<(), BundleError> {
        self.check_follows(name)?;
        self.count(name)?;
        self.last = Some(name);
        Ok(())
    }

    /// Records the decoded bundle header, which every later entry's count is checked against.
    pub(super) fn set_header(&mut self, header: BundleHeader) {
        self.header = Some(header);
    }

    pub(super) fn header(&self) -> Option<BundleHeader> {
        self.header
    }

    /// Refuses an archive that ends before every entry is in.
    pub(super) fn check_complete(&self) -> Result<(), BundleError> {
        match self.last {
            Some(EntryName::Config | EntryName::Approver(_) | EntryName::Record(_)) => {
                (self.counted() == self.expected()).then_some(()).ok_or(BundleError::EntryCount)
            }
            _ => Err(BundleError::EntryOrder),
        }
    }

    /// Refuses an entry out of bundle order. The fixed entries follow one another in the listed order, an approver or record only
    /// follows a lower one of its kind, and the first record follows the last approver.
    fn check_follows(&self, name: EntryName) -> Result<(), BundleError> {
        use EntryName::{ApprovalState, Approver, BundleHeader, Config, ExportedIdentity, Manifest, Record};
        let follows = match (self.last, name) {
            (None, BundleHeader)
            | (Some(BundleHeader), ExportedIdentity)
            | (Some(ExportedIdentity), Manifest)
            | (Some(Manifest), ApprovalState)
            | (Some(ApprovalState), Config)
            | (Some(Config), Approver(_))
            | (Some(Approver(_)), Record(_)) => true,
            (Some(last @ Approver(_)), Approver(_)) | (Some(last @ Record(_)), Record(_)) => last < name,
            _ => false,
        };
        follows.then_some(()).ok_or(BundleError::EntryOrder)
    }

    /// Counts an approver or record, refusing one beyond the header's count or a record before every approver.
    fn count(&mut self, name: EntryName) -> Result<(), BundleError> {
        let (approvers, records) = self.expected();
        let within = match name {
            EntryName::Approver(_) => {
                self.approvers += 1;
                self.approvers <= approvers
            }
            EntryName::Record(_) => {
                self.records += 1;
                self.approvers == approvers && self.records <= records
            }
            _ => true,
        };
        within.then_some(()).ok_or(BundleError::EntryCount)
    }

    fn counted(&self) -> (usize, usize) {
        (self.approvers, self.records)
    }

    /// Returns the header's approver and record counts. Before the header is in, no approver or record can be admitted,
    /// so none are expected.
    fn expected(&self) -> (usize, usize) {
        self.header
            .map_or((0, 0), |header| (header.approver_count(), header.record_count()))
    }
}
