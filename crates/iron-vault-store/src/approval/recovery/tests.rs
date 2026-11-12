//! Approval recovery against every row of design/config-approval.md's recovery table, built on [`FaultFs`], and after
//! a failure or power loss at every filesystem call of the approval transaction and of recovery itself.

use std::io;
use std::path::{Path, PathBuf};

use super::*;
use crate::approval::transaction::tests::{
    NEW_CONFIG, OLD, OLD_CONFIG, Setup, TestSigner, approve, approve_new, clean_calls, unsynced_renames, version,
};
use crate::fault_fs::{FaultFs, FsCall, FsOp};
use crate::{ApprovalSigner, PendingConfig, write_pending, write_staged};

const ALL_FILES: [ConfigFileName; 4] = [Active, ActiveSignature, Pending, StagedSignature];

fn recover(setup: &Setup, fs: &FaultFs, state: &ApprovalState) -> Result<RecoveredApproval, ApprovalRecoveryError> {
    recover_approval(&setup.config_lock, fs, state)
}

/// The four config files' visible contents, without recording a call.
fn snapshot(setup: &Setup, fs: &FaultFs) -> Vec<Option<Vec<u8>>> {
    ALL_FILES.iter().map(|&name| fs.contents(&setup.config_path(name))).collect()
}

/// An envelope for `payload` from the pinned signer.
fn signed(payload: ApprovalPayload) -> Vec<u8> {
    TestSigner::pinned().sign(&payload).unwrap().encode()
}

/// Version 2 of `NEW_CONFIG` committed beside the published version 1 pair: pending and staged both wait (row 4).
fn committed_unpublished(setup: &Setup) -> (FaultFs, ApprovalState) {
    let (fs, mut state) = setup.seeded();
    let storage = setup.storage(&fs);
    let pending = PendingConfig::write(&storage, NEW_CONFIG.to_vec()).unwrap();
    let (v, digest) = {
        let prepared = pending.prepare(&storage, &mut state, TestSigner::pinned()).unwrap();
        (prepared.version(), prepared.digest())
    };
    state.commit(&setup.state_lock, &fs, &setup.identity, v, digest).unwrap();
    (fs, state)
}

fn remove(setup: &Setup, fs: &FaultFs, name: ConfigFileName) {
    fs.remove_file(&setup.config_path(name)).unwrap();
}

/// The config directory of recovery row `row` with version 2 committed. Row 50 is row 5 with the staged approval
/// replaced by one for the committed config at an uncommitted version, row 60 is row 6 with another pending config,
/// row 70 is row 7 with C's config in place, and row 71 is row 7 with nothing published at all.
fn row(setup: &Setup, row: u8) -> (FaultFs, ApprovalState) {
    let (fs, state) = committed_unpublished(setup);
    let lock = &setup.config_lock;
    match row {
        1 => publish(lock, &fs, PublishSet::Both).unwrap(),
        2 => publish(lock, &fs, PublishSet::ConfigOnly).unwrap(),
        3 => publish(lock, &fs, PublishSet::SignatureOnly).unwrap(),
        4 => {}
        5 => remove(setup, &fs, StagedSignature),
        50 => {
            let payload = ApprovalPayload::new(state.vault_id(), version(3), ConfigDigest::of(NEW_CONFIG));
            write_staged(lock, &fs, &signed(payload)).unwrap();
        }
        60 => write_pending(lock, &fs, b"# another config\n").unwrap(),
        6 => remove(setup, &fs, Pending),
        7 => [Pending, StagedSignature].into_iter().for_each(|n| remove(setup, &fs, n)),
        70 => {
            publish(lock, &fs, PublishSet::ConfigOnly).unwrap();
            remove(setup, &fs, StagedSignature);
        }
        71 => ALL_FILES.into_iter().for_each(|n| remove(setup, &fs, n)),
        8 => {
            publish(lock, &fs, PublishSet::SignatureOnly).unwrap();
            remove(setup, &fs, Pending);
        }
        _ => unreachable!("no row {row}"),
    }
    (fs, state)
}

/// Recovery passed at version 2: the result and the published pair on disk are `NEW_CONFIG` verifying as it, and
/// nothing waits.
fn assert_recovered_new(setup: &Setup, fs: &FaultFs, state: &ApprovalState, recovered: &RecoveredApproval, context: &str) {
    assert_eq!(recovered.published().approval().version(), version(2), "{context}");
    assert_eq!(recovered.published().config(), NEW_CONFIG, "{context}");
    let (config, envelope) = (setup.read(fs, Active).unwrap(), setup.read(fs, ActiveSignature).unwrap());
    assert_eq!(
        verify_approval(state, &config, &envelope).map(|a| a.version()),
        Ok(version(2)),
        "{context}"
    );
    assert_eq!(
        (setup.read(fs, Pending), setup.read(fs, StagedSignature)),
        (None, None),
        "{context}"
    );
}

/// Recovery never touches the state directory, so it never writes the approval state.
fn assert_state_untouched(setup: &Setup, fs: &FaultFs, base: usize) {
    let state_dir = setup.state_path().parent().unwrap().to_path_buf();
    let touched = fs.trace()[base..].iter().any(|c| match c {
        FsCall::Rename { from, to } | FsCall::HardLink { from, to } => from.starts_with(&state_dir) || to.starts_with(&state_dir),
        FsCall::CreatePrivate(p)
        | FsCall::WriteAll(p)
        | FsCall::SyncFile(p)
        | FsCall::RemoveFile(p)
        | FsCall::SyncDir(p)
        | FsCall::ListDir(p)
        | FsCall::ReadBounded(p) => p.starts_with(&state_dir),
    });
    assert!(!touched, "recovery touched the state directory");
}

#[test]
fn rows_1_to_4_serve_or_finish_publishing_the_committed_approval() {
    let setup = Setup::new("rcv-finish");
    let rows = [
        (1, None),
        (2, Some(PublishSet::SignatureOnly)),
        (3, Some(PublishSet::ConfigOnly)),
        (4, Some(PublishSet::Both)),
    ];
    rows.into_iter().for_each(|(n, finished)| {
        let context = format!("row {n}");
        let (fs, state) = row(&setup, n);
        let base = fs.trace().len();
        let recovered = recover(&setup, &fs, &state).unwrap();
        assert_eq!(recovered.finished(), finished, "{context}");
        assert_recovered_new(&setup, &fs, &state, &recovered, &context);
        assert_state_untouched(&setup, &fs, base);
        assert_eq!(setup.load(&fs), state, "{context}");
        // The finish is durable: after power loss the pair is published and recovery has nothing left to do.
        fs.crash();
        let again = recover(&setup, &fs, &state).unwrap();
        assert_eq!((again.finished(), again.discarded()), (None, &[][..]), "{context}, after reboot");
        assert_recovered_new(&setup, &fs, &state, &again, &format!("{context}, after reboot"));
    });
}

#[test]
fn rows_5_to_8_refuse_with_their_failure_and_touch_nothing() {
    let setup = Setup::new("rcv-refuse");
    let superseded = PublishedPairFault::DoesNotVerify(VerifyError::Superseded {
        version: OLD,
        committed: version(2),
    });
    let changed = PublishedPairFault::DoesNotVerify(VerifyError::ConfigChanged);
    let missing = |missing| ApprovalRecoveryError::CommittedFileMissing {
        version: version(2),
        missing,
        published: superseded.clone(),
    };
    let invalid = |published| ApprovalRecoveryError::PublishedPairInvalid {
        version: version(2),
        published,
    };
    let rows = [
        (5, missing(StagedSignature), RecoveryFailure::RecoveryNeeded),
        (50, missing(StagedSignature), RecoveryFailure::RecoveryNeeded),
        (6, missing(Pending), RecoveryFailure::RecoveryNeeded),
        (60, missing(Pending), RecoveryFailure::RecoveryNeeded),
        (7, invalid(superseded.clone()), RecoveryFailure::PolicyInvalid),
        (70, invalid(changed.clone()), RecoveryFailure::PolicyInvalid),
        (71, invalid(PublishedPairFault::Missing(Active)), RecoveryFailure::PolicyInvalid),
        (8, invalid(changed.clone()), RecoveryFailure::PolicyInvalid),
    ];
    rows.into_iter().for_each(|(n, expected, failure)| {
        let context = format!("row {n}");
        let (fs, state) = row(&setup, n);
        let (before, base) = (snapshot(&setup, &fs), fs.trace().len());
        let error = recover(&setup, &fs, &state).unwrap_err();
        assert_eq!((&error, error.failure()), (&expected, failure), "{context}");
        assert_eq!(snapshot(&setup, &fs), before, "{context}");
        let only_reads = fs.trace()[base..].iter().all(|c| c.op() == FsOp::ReadBounded);
        assert!(only_reads, "{context}: recovery changed the config directory");
        assert_state_untouched(&setup, &fs, base);
    });
}

#[test]
fn nothing_committed_is_policy_invalid_and_reads_nothing() {
    let setup = Setup::new("rcv-none");
    let (fs, state) = setup.created();
    let base = fs.trace().len();
    let error = recover(&setup, &fs, &state).unwrap_err();
    assert_eq!(
        (&error, error.failure()),
        (&ApprovalRecoveryError::NothingCommitted, RecoveryFailure::PolicyInvalid)
    );
    assert_eq!(fs.trace().len(), base);
}

/// A leftover case: its name, the pending and staged bytes written, and what recovery reports discarding.
type Leftover<'a> = (&'a str, Option<&'a [u8]>, Option<Vec<u8>>, Vec<DiscardedFile>);

/// Each leftover beside a published pair that verifies (the row 1 sub-table), with what recovery reports discarding.
#[test]
fn every_leftover_beside_a_verified_pair_is_discarded_and_never_promoted() {
    let setup = Setup::new("rcv-leftovers");
    let (seeded, seeded_state) = setup.seeded();
    let old_envelope = setup.read(&seeded, ActiveSignature).unwrap();
    let vault = seeded_state.vault_id();
    let new_digest = ConfigDigest::of(NEW_CONFIG);
    let other_digest = ConfigDigest::of(b"# another config\n");
    let pending = |file| DiscardedFile {
        file,
        signed_for: None,
        conflicting: false,
    };
    let staged = |v: Option<u64>| DiscardedFile {
        file: StagedSignature,
        signed_for: v.map(version),
        conflicting: false,
    };
    let foreign = TestSigner::with_seed(9)
        .sign(&ApprovalPayload::new(vault, version(3), new_digest))
        .unwrap()
        .encode();
    let cases: [Leftover; 8] = [
        ("nothing", None, None, vec![]),
        ("pending only", Some(b"# edited\n"), None, vec![pending(Pending)]),
        (
            "uncommitted",
            Some(NEW_CONFIG),
            Some(signed(ApprovalPayload::new(vault, version(3), new_digest))),
            vec![pending(Pending), staged(Some(3))],
        ),
        ("superseded", None, Some(old_envelope), vec![staged(Some(1))]),
        (
            "duplicate",
            Some(NEW_CONFIG),
            Some(signed(ApprovalPayload::new(vault, version(2), new_digest))),
            vec![pending(Pending), staged(Some(2))],
        ),
        (
            "digest not committed",
            None,
            Some(signed(ApprovalPayload::new(vault, version(2), other_digest))),
            vec![DiscardedFile {
                conflicting: true,
                ..staged(Some(2))
            }],
        ),
        ("malformed", None, Some(b"not an envelope".to_vec()), vec![staged(None)]),
        ("foreign signer", None, Some(foreign), vec![staged(None)]),
    ];
    cases.into_iter().for_each(|(context, pending_bytes, staged_bytes, discarded)| {
        let (fs, state) = row(&setup, 1);
        pending_bytes
            .into_iter()
            .for_each(|b| write_pending(&setup.config_lock, &fs, b).unwrap());
        staged_bytes
            .into_iter()
            .for_each(|b| write_staged(&setup.config_lock, &fs, &b).unwrap());
        let base = fs.trace().len();
        let recovered = recover(&setup, &fs, &state).unwrap();
        assert_eq!((recovered.finished(), recovered.discarded()), (None, &discarded[..]), "{context}");
        assert_recovered_new(&setup, &fs, &state, &recovered, context);
        assert_state_untouched(&setup, &fs, base);
        fs.crash();
        assert_eq!(
            (setup.read(&fs, Pending), setup.read(&fs, StagedSignature)),
            (None, None),
            "{context}: not durable"
        );
    });
}

#[test]
fn a_staged_approval_never_committed_is_discarded_and_its_version_stays_consumed() {
    let setup = Setup::new("rcv-uncommitted");
    let (fs, mut state) = setup.seeded();
    let storage = setup.storage(&fs);
    // A crash between steps 4 and 5: version 2 is reserved, signed and staged, but never committed.
    let reserved = PendingConfig::write(&storage, NEW_CONFIG.to_vec())
        .unwrap()
        .prepare(&storage, &mut state, TestSigner::pinned())
        .unwrap()
        .version();
    assert_eq!(reserved, version(2));
    fs.crash();
    let state = setup.load(&fs);
    let recovered = recover(&setup, &fs, &state).unwrap();
    assert_eq!(recovered.published().approval().version(), OLD);
    assert_eq!(recovered.published().config(), OLD_CONFIG);
    let discarded = [
        DiscardedFile {
            file: Pending,
            signed_for: None,
            conflicting: false,
        },
        DiscardedFile {
            file: StagedSignature,
            signed_for: Some(version(2)),
            conflicting: false,
        },
    ];
    assert_eq!(recovered.discarded(), discarded);
    assert_eq!(setup.read(&fs, Active).as_deref(), Some(OLD_CONFIG));
    let mut state = setup.load(&fs);
    assert_eq!(state.highest_reserved(), 2);
    let next = approve(&setup, &fs, &mut state, NEW_CONFIG, TestSigner::pinned()).unwrap();
    assert_eq!(next.approval().version(), version(3));
}

/// After power loss at any point of an approval, recovery serves the committed approval: the previous one before the
/// commit, the new one after it, and never an uncommitted version.
fn assert_recovers_the_committed_approval(setup: &Setup, fs: &FaultFs, context: &str) {
    let state = setup.load(fs);
    let recovered = recover(setup, fs, &state).unwrap_or_else(|e| panic!("{context}: {e}"));
    match state.committed().map(|(v, _)| v) {
        Some(OLD) => {
            assert_eq!(recovered.published().approval().version(), OLD, "{context}");
            assert_eq!(recovered.published().config(), OLD_CONFIG, "{context}");
            assert_eq!(
                (setup.read(fs, Pending), setup.read(fs, StagedSignature)),
                (None, None),
                "{context}"
            );
        }
        _ => assert_recovered_new(setup, fs, &state, &recovered, context),
    }
    // What recovery did is durable: a second power loss leaves the same committed approval served.
    fs.crash();
    let again = recover(setup, fs, &state).unwrap_or_else(|e| panic!("{context}, after reboot: {e}"));
    assert_eq!(
        again.published().approval(),
        recovered.published().approval(),
        "{context}, after reboot"
    );
}

#[test]
fn power_loss_after_every_call_of_an_approval_recovers_the_committed_approval() {
    let setup = Setup::new("rcv-txn-crash");
    (0..=clean_calls(&setup).len()).for_each(|k| {
        let (probe, _, _) = approve_new(&setup, |fs, base| fs.cut_power_after(base + k));
        let renames = unsynced_renames(&probe, setup.seeded().0.trace().len(), k);
        let keeps: Vec<Vec<PathBuf>> = [Vec::new(), renames.concat()].into_iter().chain(renames).collect();
        keeps.iter().for_each(|keep| {
            let (fs, _, _) = approve_new(&setup, |fs, base| fs.cut_power_after(base + k));
            fs.crash_keeping(&keep.iter().map(PathBuf::as_path).collect::<Vec<&Path>>());
            assert_recovers_the_committed_approval(&setup, &fs, &format!("power cut after {k} calls, keeping {keep:?}"));
        });
    });
}

#[test]
fn a_failure_at_every_call_of_an_approval_recovers_the_committed_approval() {
    let setup = Setup::new("rcv-txn-faults");
    (0..clean_calls(&setup).len()).for_each(|i| {
        let (fs, _, _) = approve_new(&setup, |fs, base| fs.fail_call(base + i, io::ErrorKind::StorageFull));
        assert_recovers_the_committed_approval(&setup, &fs, &format!("fault at call {i}"));
    });
}

/// The number of calls a clean recovery of `n` makes.
fn recovery_calls(setup: &Setup, n: u8) -> usize {
    let (fs, state) = row(setup, n);
    let base = fs.trace().len();
    recover(setup, &fs, &state).unwrap();
    fs.trace().len() - base
}

#[test]
fn a_recovery_that_fails_at_any_call_is_safe_to_run_again() {
    let setup = Setup::new("rcv-retry-fault");
    [2, 3, 4].into_iter().for_each(|n| {
        (0..recovery_calls(&setup, n)).for_each(|i| {
            let context = format!("row {n}, fault at recovery call {i}");
            let (fs, state) = row(&setup, n);
            fs.fail_call(fs.trace().len() + i, io::ErrorKind::StorageFull);
            if let Ok(recovered) = recover(&setup, &fs, &state) {
                assert_eq!(recovered.published().approval().version(), version(2), "{context}");
            }
            let recovered = recover(&setup, &fs, &state).unwrap_or_else(|e| panic!("{context}: {e}"));
            assert_recovered_new(&setup, &fs, &state, &recovered, &context);
        });
    });
}

#[test]
fn power_loss_at_any_call_of_recovery_is_safe_to_run_again() {
    let setup = Setup::new("rcv-retry-crash");
    [2, 3, 4].into_iter().for_each(|n| {
        (0..=recovery_calls(&setup, n)).for_each(|k| {
            let (probe, probe_state) = row(&setup, n);
            let base = probe.trace().len();
            probe.cut_power_after(base + k);
            let _ = recover(&setup, &probe, &probe_state);
            let renames = unsynced_renames(&probe, base, k);
            let keeps: Vec<Vec<PathBuf>> = [Vec::new(), renames.concat()].into_iter().chain(renames).collect();
            keeps.iter().for_each(|keep| {
                let context = format!("row {n}, power cut after recovery call {k}, keeping {keep:?}");
                let (fs, state) = row(&setup, n);
                fs.cut_power_after(fs.trace().len() + k);
                let _ = recover(&setup, &fs, &state);
                fs.crash_keeping(&keep.iter().map(PathBuf::as_path).collect::<Vec<&Path>>());
                let recovered = recover(&setup, &fs, &state).unwrap_or_else(|e| panic!("{context}: {e}"));
                assert_recovered_new(&setup, &fs, &state, &recovered, &context);
            });
        });
    });
}

/// The kind the OS filesystem gives a read that fails with `EIO`.
#[cfg(unix)]
fn eio() -> io::ErrorKind {
    io::Error::from_raw_os_error(libc::EIO).kind()
}

/// Recovery of row `n` with the read of `file` failing with `kind`: it must refuse with `expected` and change nothing.
fn assert_refuses_on_read_fault(setup: &Setup, n: u8, file: ConfigFileName, kind: io::ErrorKind, expected: &ApprovalRecoveryError) {
    let context = format!("row {n}, reading {file} fails with {kind}");
    let (fs, state) = row(setup, n);
    let (before, base) = (snapshot(setup, &fs), fs.trace().len());
    let read_index = ALL_FILES.iter().position(|&f| f == file).unwrap();
    fs.fail_call(base + read_index, kind);
    let error = recover(setup, &fs, &state).unwrap_err();
    assert_eq!((&error, error.failure()), (expected, RecoveryFailure::RecoveryNeeded), "{context}");
    assert_eq!(snapshot(setup, &fs), before, "{context}");
    let only_reads = fs.trace()[base..].iter().all(|c| c.op() == FsOp::ReadBounded);
    assert!(only_reads, "{context}: recovery changed the config directory");
    assert_state_untouched(setup, &fs, base);
    // Once the file reads again, recovery goes on as the table says.
    let recovered = recover(setup, &fs, &state).unwrap_or_else(|e| panic!("{context}, after the fault: {e}"));
    assert_recovered_new(setup, &fs, &state, &recovered, &context);
}

#[cfg(unix)]
#[test]
fn an_unreadable_config_file_refuses_before_the_table_and_touches_nothing() {
    let setup = Setup::new("rcv-unreadable");
    // Row 4 holds all four files, so an unreadable pending config or staged approval is not row 5 or 6; row 1 holds
    // only the published pair, so an unreadable one is not a missing one.
    let cases = [
        (4, Pending),
        (4, StagedSignature),
        (4, Active),
        (4, ActiveSignature),
        (1, Active),
        (1, ActiveSignature),
    ];
    cases.into_iter().for_each(|(n, file)| {
        [io::ErrorKind::PermissionDenied, eio()].into_iter().for_each(|kind| {
            assert_refuses_on_read_fault(&setup, n, file, kind, &ApprovalRecoveryError::Unreadable { file, kind });
        });
    });
}

/// A missing, oversized or non-regular file is absent, never unreadable. The store filesystem reports an oversized
/// file as `FileTooLarge` and a non-regular one as `InvalidInput`, which the config read maps to `TooLarge` and
/// `NotARegularFile`.
#[test]
fn a_missing_oversized_or_non_regular_file_is_absent_as_before() {
    let setup = Setup::new("rcv-absent");
    let superseded = PublishedPairFault::DoesNotVerify(VerifyError::Superseded {
        version: OLD,
        committed: version(2),
    });
    let missing = |missing| ApprovalRecoveryError::CommittedFileMissing {
        version: version(2),
        missing,
        published: superseded.clone(),
    };
    let kinds = [io::ErrorKind::NotFound, io::ErrorKind::FileTooLarge, io::ErrorKind::InvalidInput];
    kinds.into_iter().for_each(|kind| {
        assert_refuses_on_read_fault(&setup, 4, StagedSignature, kind, &missing(StagedSignature));
        assert_refuses_on_read_fault(&setup, 4, Pending, kind, &missing(Pending));
    });
}

/// After the publish renames, an unreadable `config.toml` in the read-back is reported as published but not verified,
/// naming the committed version, never as `Unreadable`, which promises nothing was touched.
#[cfg(unix)]
#[test]
fn an_unreadable_read_back_after_publishing_is_publish_not_verified() {
    let setup = Setup::new("rcv-read-back");
    let (fs, state) = row(&setup, 4);
    let base = fs.trace().len();
    let (probe, probe_state) = row(&setup, 4);
    let probe_base = probe.trace().len();
    recover(&setup, &probe, &probe_state).unwrap();
    let probe_calls = &probe.trace()[probe_base..];
    let last_rename = probe_calls.iter().rposition(|c| c.op() == FsOp::Rename).unwrap();
    let read_back = last_rename + probe_calls[last_rename..].iter().position(|c| c.op() == FsOp::ReadBounded).unwrap();
    assert_eq!(probe_calls[read_back], FsCall::ReadBounded(setup.config_path(Active)));
    fs.fail_call(base + read_back, eio());
    let error = recover(&setup, &fs, &state).unwrap_err();
    let expected = ApprovalRecoveryError::PublishNotVerified {
        version: version(2),
        renames: PublishSet::Both,
        published: PublishedPairFault::Unreadable { file: Active, kind: eio() },
    };
    assert_eq!((&error, error.failure()), (&expected, RecoveryFailure::RecoveryNeeded));
    // The renames ran: the committed pair is published and nothing waits.
    assert_eq!(setup.read(&fs, Active).as_deref(), Some(NEW_CONFIG));
    assert_eq!((setup.read(&fs, Pending), setup.read(&fs, StagedSignature)), (None, None));
    // Once the file reads again, the next recovery serves it as row 1.
    let recovered = recover(&setup, &fs, &state).unwrap();
    assert_eq!(recovered.finished(), None);
    assert_recovered_new(&setup, &fs, &state, &recovered, "after the read-back fault");
}

#[test]
fn the_first_unreadable_file_in_order_is_reported() {
    let setup = Setup::new("rcv-unreadable-first");
    let (fs, state) = row(&setup, 4);
    let base = fs.trace().len();
    // The pending config and the staged approval are both unreadable; the reads after the pending config never run.
    [2, 3]
        .into_iter()
        .for_each(|i| fs.fail_call(base + i, io::ErrorKind::PermissionDenied));
    let expected = ApprovalRecoveryError::Unreadable {
        file: Pending,
        kind: io::ErrorKind::PermissionDenied,
    };
    assert_eq!(recover(&setup, &fs, &state).unwrap_err(), expected);
    assert_eq!(fs.trace().len() - base, 3);
}

/// A discard that fails partway reports, and so logs, each leftover it removed.
#[test]
fn a_partial_discard_still_reports_the_files_it_removed() {
    let setup = Setup::new("rcv-partial-discard");
    let pending = DiscardedFile {
        file: Pending,
        signed_for: None,
        conflicting: false,
    };
    let staged = DiscardedFile {
        file: StagedSignature,
        signed_for: Some(version(3)),
        conflicting: false,
    };
    // For each failing call: what recovery reports discarding, and whether the pending config is left.
    let cases = [
        (FsOp::RemoveFile, vec![staged], true),
        (FsOp::SyncDir, vec![pending, staged], false),
    ];
    cases.into_iter().for_each(|(op, discarded, pending_left)| {
        let (fs, state) = row(&setup, 1);
        let payload = ApprovalPayload::new(state.vault_id(), version(3), ConfigDigest::of(NEW_CONFIG));
        write_pending(&setup.config_lock, &fs, NEW_CONFIG).unwrap();
        write_staged(&setup.config_lock, &fs, &signed(payload)).unwrap();
        fs.fail_first(op, io::ErrorKind::PermissionDenied);
        let recovered = recover(&setup, &fs, &state).unwrap();
        assert_eq!(recovered.discarded(), discarded, "{op:?} fails");
        assert_eq!(setup.read(&fs, Pending).is_some(), pending_left, "{op:?} fails");
        assert_eq!(setup.read(&fs, StagedSignature), None, "{op:?} fails");
    });
}
