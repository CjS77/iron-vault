//! The approval release checks of specification §19, end to end against a running service context:
//!
//! - an old config/signature pair fails after a newer approval, on restart and on SIGHUP;
//! - the version counters survive a restart, a failed approval, a failed signer and a key replacement without reuse;
//! - a power cut before the approval's commit retains the previous committed policy;
//! - a power cut after the commit completes that exact transaction, or leaves the service unavailable, and never
//!   activates an uncommitted version.
//!
//! The power-cut tests run `config approve` on a [`FaultFs`], cut the power after each filesystem call of the
//! transaction, restart a service on whatever survived, and check the outcome against the recovery table of
//! design/config-approval.md. They print a table of call against outcome (`cargo test -- --nocapture`), which the
//! design document reproduces.

#![cfg(target_os = "linux")]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::approval_harness::{
    APPROVAL_PASSPHRASE, Fixture, approval_passphrase, approve, error_code, get, identity, shutdown, the_two_prompts, the_two_prompts_for,
    versions,
};
use common::shared_fs::SharedFs;
use iron_vault::admin::protocol::{AdminResponse, ApprovalResult, ErrorCode};
use iron_vault::service_context::ServiceContext;
use iron_vault::service_state::{FailureReason, ServiceState};
use iron_vault_store::fault_fs::FsCall;
use iron_vault_store::{
    ApprovalEnvelope, ApprovalPayload, ApprovalProgress, ApprovalSigner, ApprovalState, ApprovalStorage, ApproverId, ApproverLabel,
    ApproverPublicKey, ConfigDigest, OsFs, PendingConfig, PinnedApprover, SignError, SignatureAlgorithm, SoftwareSigner, StateDirLock,
    StoreFs, UtcSecond, Vault, VerifyError, verify_approval, write_signer_key,
};

// ---- Helpers shared by the tests below -------------------------------------------------------------------------

/// The approval state on disk, read while no service holds the directory locks.
fn load_state<F: StoreFs>(lock: &StateDirLock, fs: &F) -> ApprovalState {
    let (vault, _) = Vault::open(lock, fs, identity()).unwrap();
    vault.load_approval_state(lock, fs).unwrap()
}

/// The committed version and highest reserved version on disk.
fn counters(fixture: &Fixture) -> (Option<u64>, u64) {
    let lock = common::approval_harness::state_dir_lock(&fixture.path("state"));
    let state = load_state(&lock, &OsFs);
    (state.committed().map(|(version, _)| version.get()), state.highest_reserved())
}

/// Every request is refused with `503` and `reason`, whichever route it names.
async fn assert_refusing(fixture: &Fixture, reason: &str, context: &str) {
    for route in ["fx", "rates"] {
        let response = get(fixture, route).await;
        assert_eq!((response.status, response.body.as_str()), (503, reason), "{context}: {route}");
    }
}

fn approved_version(response: &AdminResponse) -> u64 {
    match response {
        AdminResponse::ConfigApprove(ApprovalResult { version, .. }) => *version,
        other => panic!("expected an approval, got {other:?}"),
    }
}

// ---- Old pairs fail after a newer approval ---------------------------------------------------------------------

/// Version 1 is approved, then version 2 through `config approve`; returns the service running version 2 and the
/// version 1 pair, which the caller then puts back.
async fn approved_twice(fixture: &Fixture) -> (Arc<ServiceContext>, [Vec<u8>; 2]) {
    let first_pair = fixture.published_pair();
    let service = fixture.ready().await;
    let exchanged = approve(&service, &fixture.config("rates"), &["yes", APPROVAL_PASSPHRASE]).await;
    assert_eq!(approved_version(&exchanged.response), 2);
    assert_eq!(get(fixture, "rates").await.status, 200);
    (service, first_pair)
}

#[tokio::test]
async fn a_version_1_pair_put_back_after_version_2_is_refused_on_sighup() {
    let fixture = Fixture::new().await;
    let (service, first_pair) = approved_twice(&fixture).await;
    let second_pair = fixture.published_pair();
    fixture.put_back(&first_pair);

    // SIGHUP runs `reload`, which is `recheck(Reload)` from Ready.
    let reloaded = service.reload().await;

    assert_eq!(reloaded, Ok(ServiceState::Unavailable(FailureReason::PolicyInvalid)));
    assert_refusing(&fixture, "policy invalid", "after the reload").await;
    // A second SIGHUP is no way out of Unavailable, even once the version 2 pair is back.
    fixture.put_back(&second_pair);
    assert!(service.reload().await.is_err());
    assert_eq!(service.state().await, ServiceState::Unavailable(FailureReason::PolicyInvalid));
    assert_refusing(&fixture, "policy invalid", "after a second reload").await;
    shutdown(service).await;
    assert_eq!(counters(&fixture), (Some(2), 2));
}

#[tokio::test]
async fn a_version_1_pair_put_back_after_version_2_is_refused_on_restart() {
    let fixture = Fixture::new().await;
    let (service, first_pair) = approved_twice(&fixture).await;
    shutdown(service).await;
    fixture.put_back(&first_pair);

    let restarted = fixture.start().await;

    assert_eq!(restarted.state().await, ServiceState::Unavailable(FailureReason::PolicyInvalid));
    assert_refusing(&fixture, "policy invalid", "after the restart").await;
    shutdown(restarted).await;
    assert_eq!(counters(&fixture), (Some(2), 2));
    assert_eq!(fixture.published_pair(), first_pair, "recovery touches nothing when it refuses");
}

// ---- Counters ---------------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_next_version_after_a_restart_is_higher() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    approve(&service, &fixture.config("rates"), &["yes", APPROVAL_PASSPHRASE]).await;
    shutdown(service).await;

    let restarted = fixture.ready().await;

    assert_eq!(versions(&restarted).await, (Some(2), 2));
    let next = approve(&restarted, &fixture.config("other"), &["yes", APPROVAL_PASSPHRASE]).await;
    assert_eq!(next.prompts, the_two_prompts(3));
    assert_eq!(approved_version(&next.response), 3);
}

/// A signer that fails after the version is reserved, as a TPM signer does when its PIN is wrong: the software signer
/// the service uses opens its key before anything is reserved, so only the store can show this path.
struct RefusingSigner(PinnedApprover);

impl ApprovalSigner for RefusingSigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Ed25519
    }

    fn public_key(&self) -> ApproverPublicKey {
        *self.0.public_key()
    }

    fn sign(&self, _: &ApprovalPayload) -> Result<ApprovalEnvelope, SignError> {
        Err(SignError::WrongPassphrase)
    }
}

/// Runs an approval of `config` whose signer fails, on the real filesystem, and returns the version it consumed.
fn approve_with_failing_signer(fixture: &Fixture, config: &str) -> u64 {
    let (state_dir, config_dir) = (
        common::approval_harness::state_dir_lock(&fixture.path("state")),
        common::approval_harness::config_dir_lock(&fixture.path("etc")),
    );
    let mut state = load_state(&state_dir, &OsFs);
    let identity = identity();
    let storage = ApprovalStorage {
        state_dir: &state_dir,
        config_dir: &config_dir,
        identity: &identity,
        fs: &OsFs,
    };
    let signer = RefusingSigner(state.approvers()[0].clone());
    let error = PendingConfig::write(&storage, config.as_bytes().to_vec())
        .unwrap()
        .prepare(&storage, &mut state, signer)
        .unwrap_err();
    match error.progress() {
        ApprovalProgress::Reserved(version) => version.get(),
        other => panic!("expected a consumed version, got {other:?}"),
    }
}

#[tokio::test]
async fn a_version_consumed_by_a_failed_stage_or_a_failed_signer_is_never_reused_across_restarts() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    // A leftover temp file makes the durable write of the staged approval (step 4) refuse, after version 2 is reserved.
    let blocker = fixture.path("etc/.config.toml.sig.staged.tmp");
    fs::write(&blocker, b"").unwrap();
    let failed = approve(&service, &fixture.config("rates"), &["yes", APPROVAL_PASSPHRASE]).await;
    assert_eq!(error_code(&failed.response), ErrorCode::ApprovalFailed);
    fs::remove_file(blocker).unwrap();
    shutdown(service).await;
    assert_eq!(counters(&fixture), (Some(1), 2));

    assert_eq!(approve_with_failing_signer(&fixture, &fixture.config("rates")), 3);

    assert_eq!(counters(&fixture), (Some(1), 3), "the failed signer's version is consumed");
    let restarted = fixture.ready().await;
    assert_eq!(versions(&restarted).await, (Some(1), 3));
    assert_eq!(get(&fixture, "fx").await.status, 200, "the failed approvals changed nothing");
    let next = approve(&restarted, &fixture.config("rates"), &["yes", APPROVAL_PASSPHRASE]).await;
    assert_eq!(next.prompts, the_two_prompts(4));
    assert_eq!(approved_version(&next.response), 4);
    shutdown(restarted).await;
    assert_eq!(counters(&fixture), (Some(4), 4));
}

#[tokio::test]
async fn rotating_the_approver_keeps_the_counters_and_the_active_signature_needs_a_new_approval() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    approve(&service, &fixture.config("rates"), &["yes", APPROVAL_PASSPHRASE]).await;
    shutdown(service).await;
    let before = counters(&fixture);
    assert_eq!(before, (Some(2), 2));
    let replaced_pair = fixture.published_pair();
    let (removed, rotated) = rotate_approver(&fixture);
    assert_eq!(counters(&fixture), before, "rotating the approver keeps both counters");
    assert_eq!(
        verify_published(&fixture, &replaced_pair),
        Err(VerifyError::UnknownApprover { approver: removed })
    );

    let restarted = fixture.start().await;

    assert_eq!(restarted.state().await, ServiceState::Unavailable(FailureReason::PolicyInvalid));
    assert_refusing(&fixture, "policy invalid", "under the replaced approver").await;
    let again = approve(&restarted, &fixture.config("rates"), &["yes", APPROVAL_PASSPHRASE]).await;
    assert_eq!(
        again.prompts,
        the_two_prompts_for(3, "rotated"),
        "the next version is above every earlier one"
    );
    assert_eq!(approved_version(&again.response), 3);
    assert_eq!(restarted.state().await, ServiceState::Ready);
    let envelope = ApprovalEnvelope::decode(&fixture.published_pair()[1]).unwrap();
    assert_eq!(
        envelope.approver_id(),
        rotated,
        "the envelope names the approver the prompt asked for"
    );
    assert_eq!(get(&fixture, "rates").await.status, 200);
    shutdown(restarted).await;
    assert_eq!(counters(&fixture), (Some(3), 3));
}

/// Enrolls a newly generated approver, whose key is sealed under the same approval passphrase, and removes the one
/// that signed the published pair, returning that one's ID and the new one's.
fn rotate_approver(fixture: &Fixture) -> (ApproverId, ApproverId) {
    let lock = common::approval_harness::state_dir_lock(&fixture.path("state"));
    let mut state = load_state(&lock, &OsFs);
    let (key, pinned) = SoftwareSigner::generate().unwrap();
    let sealed = iron_vault_store::seal_signer_key_for_tests(&key, &approval_passphrase(APPROVAL_PASSPHRASE)).unwrap();
    let old = state.approvers()[0].id();
    let rotated = ApproverId::generate();
    write_signer_key(&lock, &OsFs, rotated, &sealed).unwrap();
    let approver = PinnedApprover::software_for_tests(rotated, pinned, ApproverLabel::new("rotated").unwrap(), UtcSecond::EPOCH);
    state.enroll_approver(&lock, &OsFs, &identity(), approver).unwrap();
    state.remove_approver(&lock, &OsFs, &identity(), old).unwrap();
    (old, rotated)
}

/// Whether the published pair `pair` still verifies as the committed approval.
fn verify_published(fixture: &Fixture, pair: &[Vec<u8>; 2]) -> Result<(), VerifyError> {
    let lock = common::approval_harness::state_dir_lock(&fixture.path("state"));
    verify_approval(&load_state(&lock, &OsFs), &pair[0], &pair[1]).map(drop)
}

// ---- Power failure around the commit ----------------------------------------------------------------------------

/// How `config approve` ended, as the owner saw it.
fn answered(response: &AdminResponse) -> String {
    match response {
        AdminResponse::ConfigApprove(ApprovalResult { version, .. }) => format!("approved v{version}"),
        AdminResponse::Error { code, .. } => format!("{code:?}"),
        other => format!("{other:?}"),
    }
}

/// One `config approve` of the `rates` config on a fresh copy of the fixture's version 1 vault, with the power cut after
/// the first `cut` of the approval's filesystem calls (never, when `None`). The service is stopped when it returns;
/// the power has not yet been restored.
struct Approval {
    fs: SharedFs,
    /// How many filesystem calls the service had made before the request.
    base: usize,
    answered: String,
}

impl Approval {
    async fn run(fixture: &Fixture, cut: Option<usize>) -> Self {
        let fs = SharedFs::seeded_from(&[fixture.path("state"), fixture.path("etc")]);
        let service = fixture.ready_on(fs.clone()).await;
        let base = fs.with(|fs| fs.trace().len());
        cut.iter().for_each(|k| fs.with(|fs| fs.cut_power_after(base + k)));
        let exchanged = approve(&service, &fixture.config("rates"), &["yes", APPROVAL_PASSPHRASE]).await;
        shutdown(service).await;
        Self {
            fs,
            base,
            answered: answered(&exchanged.response),
        }
    }

    /// The calls the approval made, in order, including those the power cut failed.
    fn calls(&self) -> Vec<FsCall> {
        self.fs.with(|fs| fs.trace().split_off(self.base))
    }
}

/// The renames among the first `cut` calls that no fsync of their directory followed: the ones a crash may keep or
/// lose, each as the pair of paths `crash_keeping` takes.
fn unsynced_renames(calls: &[FsCall], cut: usize) -> Vec<Vec<PathBuf>> {
    let ran = &calls[..cut.min(calls.len())];
    let synced_after = |i: usize, dir: &Path| ran[i + 1..].iter().any(|call| matches!(call, FsCall::SyncDir(d) if d == dir));
    ran.iter()
        .enumerate()
        .filter_map(|(i, call)| match call {
            FsCall::Rename { from, to } if !to.parent().is_some_and(|dir| synced_after(i, dir)) => Some(vec![from.clone(), to.clone()]),
            _ => None,
        })
        .collect()
}

/// The ways a crash can treat the unsynced renames: lose all of them (the pessimistic model), keep all of them, or keep
/// each alone.
fn crash_variants(renames: &[Vec<PathBuf>]) -> Vec<(String, Vec<PathBuf>)> {
    let each = renames
        .iter()
        .enumerate()
        .filter(|_| renames.len() > 1)
        .map(|(i, rename)| (format!("keep #{}", i + 1), rename.clone()));
    let all = (!renames.is_empty()).then(|| ("keep all".to_owned(), renames.concat()));
    std::iter::once(("lose all".to_owned(), Vec::new()))
        .chain(all)
        .chain(each)
        .collect()
}

/// Where C's config and C's approval are among the four files, as the recovery table looks for them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Place {
    InPlace,
    Waiting,
}

/// What survived on disk: the committed approval C, and the recovery row its files fall into
/// (design/config-approval.md, "Recovery table").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Surviving {
    committed: u64,
    highest_reserved: u64,
    /// The highest version of any signature file that decodes, `config.toml.sig` or `config.toml.sig.staged`: a version
    /// that was signed must stay reserved, or the next approval could sign it again.
    highest_signed: u64,
    row: u8,
}

fn surviving(fixture: &Fixture, fs: &SharedFs) -> Surviving {
    let lock = common::approval_harness::state_dir_lock(&fixture.path("state"));
    let state = load_state(&lock, fs);
    let (version, digest) = state.committed().unwrap();
    let file = |name: &str| fs.contents(&fixture.path(&format!("etc/{name}")));
    let config = [("config.toml", Place::InPlace), ("config.toml.pending", Place::Waiting)]
        .into_iter()
        .find(|(name, _)| file(name).is_some_and(|bytes| ConfigDigest::of(&bytes) == digest));
    let holds_approval = |name: &str| {
        let envelope = file(name).and_then(|bytes| ApprovalEnvelope::decode(&bytes).ok());
        envelope.is_some_and(|e| (e.payload().version(), e.payload().digest()) == (version, digest))
    };
    let signatures = ["config.toml.sig", "config.toml.sig.staged"];
    let highest_signed = signatures
        .iter()
        .filter_map(|name| file(name).and_then(|bytes| ApprovalEnvelope::decode(&bytes).ok()))
        .map(|envelope| envelope.payload().version().get())
        .max()
        .unwrap_or(0);
    let approval = signatures
        .into_iter()
        .zip([Place::InPlace, Place::Waiting])
        .find(|(name, _)| holds_approval(name));
    Surviving {
        committed: version.get(),
        highest_reserved: state.highest_reserved(),
        highest_signed,
        row: row_of(config.map(|(_, place)| place), approval.map(|(_, place)| place)),
    }
}

/// The recovery table's row for where C's config and approval are.
fn row_of(config: Option<Place>, approval: Option<Place>) -> u8 {
    match (config, approval) {
        (Some(Place::InPlace), Some(Place::InPlace)) => 1,
        (Some(Place::InPlace), Some(Place::Waiting)) => 2,
        (Some(Place::Waiting), Some(Place::InPlace)) => 3,
        (Some(Place::Waiting), Some(Place::Waiting)) => 4,
        (Some(Place::Waiting), None) => 5,
        (None, Some(Place::Waiting)) => 6,
        (Some(Place::InPlace) | None, None) => 7,
        (None, Some(Place::InPlace)) => 8,
    }
}

/// What a service restarted on the surviving files serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Restarted {
    /// Ready on the policy before the approval: `fx` answers, `rates` does not exist.
    Previous,
    /// Ready on the approved policy: `rates` answers, `fx` does not exist.
    Approved,
    /// Unavailable, every request refused with this failure's reason.
    Unavailable(FailureReason),
}

impl Restarted {
    /// What the recovery table prescribes for committed version `committed` and recovery `row`: the row decides whether
    /// the service serves, and the committed version which policy it serves. A published pair that does not verify as
    /// the committed approval (rows 7 and 8) is refused even when the committed version is the previous one.
    fn expected(committed: u64, row: u8) -> Self {
        match (row, committed) {
            (1..=4, 1) => Self::Previous,
            (1..=4, _) => Self::Approved,
            (5 | 6, _) => Self::Unavailable(FailureReason::RecoveryNeeded),
            _ => Self::Unavailable(FailureReason::PolicyInvalid),
        }
    }

    fn describe(self) -> String {
        match self {
            Self::Previous => "Ready, previous policy (v1)".to_owned(),
            Self::Approved => "Ready, approved policy (v2)".to_owned(),
            Self::Unavailable(reason) => format!("Unavailable, {reason:?}"),
        }
    }
}

/// Starts a service on `fs`, the files that survived, reads what it serves, and stops it. `fx` is the previous
/// policy's route and `rates` the approved one's.
async fn restart(fixture: &Fixture, fs: &SharedFs) -> Restarted {
    let service = fixture.start_on(fs.clone()).await;
    let state = service.state().await;
    let (fx, rates) = (get(fixture, "fx").await, get(fixture, "rates").await);
    shutdown(service).await;
    match (state, fx.status, rates.status) {
        (ServiceState::Ready, 200, 404) => Restarted::Previous,
        (ServiceState::Ready, 404, 200) => Restarted::Approved,
        (ServiceState::Unavailable(reason), 503, 503) => {
            let text = iron_vault::service_state::UnavailableReason::from_failure(reason).as_str();
            assert_eq!((fx.body.as_str(), rates.body.as_str()), (text, text));
            Restarted::Unavailable(reason)
        }
        other => panic!("a restarted service must serve one whole policy or none: {other:?}"),
    }
}

/// Approves again on a service restarted on `fs`, and returns the version it reserved. Only a Ready service can approve
/// here: one in `RecoveryNeeded` takes a repair, and the version counters are what this checks.
async fn next_approval(fixture: &Fixture, fs: &SharedFs, restarted: Restarted) -> Option<u64> {
    if !matches!(restarted, Restarted::Previous | Restarted::Approved) {
        return None;
    }
    let service = fixture.ready_on(fs.clone()).await;
    let exchanged = approve(&service, &fixture.config("again"), &["yes", APPROVAL_PASSPHRASE]).await;
    shutdown(service).await;
    Some(approved_version(&exchanged.response))
}

/// A row of the printed table.
struct Row {
    cut: usize,
    last_call: String,
    crash: String,
    answered: String,
    surviving: Surviving,
    restarted: Restarted,
    /// The version the next `config approve` on the restarted service reserved; none unless the service was Ready.
    next: Option<u64>,
}

impl Row {
    fn render(&self) -> String {
        format!(
            "{:>3} | {:<46} | {:<8} | {:<20} | C=v{} reserved {} row {} | {:<28} | {}",
            self.cut,
            self.last_call,
            self.crash,
            self.answered,
            self.surviving.committed,
            self.surviving.highest_reserved,
            self.surviving.row,
            self.restarted.describe(),
            self.next.map_or("-".to_owned(), |version| format!("next approval v{version}")),
        )
    }
}

/// The file's name, with a record's random id left out so the table is the same on every run.
fn file_name(path: &Path) -> String {
    let name = path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
    if name.starts_with("record-") {
        "record-*.age".to_owned()
    } else {
        name
    }
}

/// The call as the table names it: the operation and the files' names, not their directories.
fn describe(call: &FsCall) -> String {
    match call {
        FsCall::CreatePrivate(path) => format!("create {}", file_name(path)),
        FsCall::WriteAll(path) => format!("write {}", file_name(path)),
        FsCall::SyncFile(path) => format!("fsync {}", file_name(path)),
        FsCall::Rename { from, to } => format!("rename {} -> {}", file_name(from), file_name(to)),
        FsCall::RemoveFile(path) => format!("unlink {}", file_name(path)),
        FsCall::HardLink { from, to } => format!("link {} -> {}", file_name(from), file_name(to)),
        FsCall::SyncDir(dir) => format!("fsync dir {}", file_name(dir)),
        FsCall::ListDir(dir) => format!("list dir {}", file_name(dir)),
        FsCall::ReadBounded(path) => format!("read {}", file_name(path)),
    }
}

/// The index, among the approval's calls, of step 5's rename of `approval.age`: the second rename onto it, after the
/// reservation's.
fn commit_rename_index(calls: &[FsCall]) -> usize {
    let renames_of_state = calls
        .iter()
        .enumerate()
        .filter(|(_, call)| matches!(call, FsCall::Rename { to, .. } if file_name(to) == "approval.age"));
    renames_of_state.map(|(i, _)| i).nth(1).unwrap()
}

/// Cuts the power after each `cut` in `cuts`, once per way a crash can treat the unsynced renames, and restarts a
/// service on what survives. Checks each restart against the recovery table, prints the table and returns its rows.
async fn power_cut_table(fixture: &Fixture, cuts: impl Iterator<Item = usize>) -> Vec<Row> {
    let mut rows = Vec::new();
    for cut in cuts {
        let probe = Approval::run(fixture, Some(cut)).await;
        let calls = probe.calls();
        let variants = crash_variants(&unsynced_renames(&calls, cut));
        let last_call = cut
            .checked_sub(1)
            .and_then(|i| calls.get(i))
            .map_or("(before the first call)".to_owned(), describe);
        for (crash, keep) in variants {
            let run = if crash == "lose all" {
                None
            } else {
                Some(Approval::run(fixture, Some(cut)).await)
            };
            let approval = run.as_ref().unwrap_or(&probe);
            let kept: Vec<&Path> = keep.iter().map(PathBuf::as_path).collect();
            approval.fs.with(|fs| fs.crash_keeping(&kept));
            let surviving = surviving(fixture, &approval.fs);
            let restarted = restart(fixture, &approval.fs).await;
            let context = format!("power cut after {cut} calls ({last_call}), crash {crash}: {surviving:?}");
            assert_eq!(restarted, Restarted::expected(surviving.committed, surviving.row), "{context}");
            assert!(
                surviving.highest_reserved >= surviving.highest_signed,
                "{context}: a signed version is not reserved"
            );
            assert!(
                surviving.highest_reserved >= surviving.committed,
                "{context}: the committed version is not reserved"
            );
            let next = next_approval(fixture, &approval.fs, restarted).await;
            assert!(
                next.is_none_or(|version| version == surviving.highest_reserved + 1),
                "{context}: the next approval got {next:?}"
            );
            rows.push(Row {
                cut,
                last_call: last_call.clone(),
                crash,
                answered: approval.answered.clone(),
                surviving,
                restarted,
                next,
            });
        }
    }
    println!("{}", table(&rows));
    rows
}

fn table(rows: &[Row]) -> String {
    let header = "cut | last call that ran                          | crash    | config approve said  | surviving             | restarted service            | then";
    std::iter::once(header.to_owned())
        .chain(rows.iter().map(Row::render))
        .collect::<Vec<_>>()
        .join("\n")
}

/// A clean approval's calls, and the index of its commit.
async fn clean_approval(fixture: &Fixture) -> (usize, usize) {
    let clean = Approval::run(fixture, None).await;
    assert_eq!(clean.answered, "approved v2");
    let calls = clean.calls();
    (calls.len(), commit_rename_index(&calls))
}

#[tokio::test]
async fn a_power_cut_before_the_commit_keeps_the_previous_committed_policy() {
    let fixture = Fixture::new().await;
    let (_, commit) = clean_approval(&fixture).await;

    // The commit's rename has not run after `commit` calls, so no crash can leave version 2 committed.
    let rows = power_cut_table(&fixture, 0..=commit).await;

    rows.iter().for_each(|row| {
        let context = row.render();
        assert_eq!(row.surviving.committed, 1, "{context}");
        assert_eq!((row.surviving.row, row.restarted), (1, Restarted::Previous), "{context}");
    });
}

#[tokio::test]
async fn a_power_cut_after_the_commit_completes_that_transaction_or_keeps_the_service_unavailable() {
    let fixture = Fixture::new().await;
    let (calls, commit) = clean_approval(&fixture).await;

    // From the commit's rename having run to the whole approval having run, which the last cut covers.
    let rows = power_cut_table(&fixture, commit + 1..=calls).await;

    rows.iter().for_each(|row| {
        let context = row.render();
        match row.surviving.committed {
            // The commit's directory fsync had not run and the crash undid its rename: the previous policy is intact.
            1 => assert_eq!((row.surviving.row, row.restarted), (1, Restarted::Previous), "{context}"),
            // The commit is durable: recovery finishes exactly it, or refuses; it never serves another version.
            _ => assert!(
                matches!(row.restarted, Restarted::Approved | Restarted::Unavailable(_)),
                "{context}"
            ),
        }
    });
    let last = rows.last().unwrap();
    assert_eq!(
        last.restarted,
        Restarted::Approved,
        "an approval that ran to its end survives a power cut: {}",
        last.render()
    );
}
