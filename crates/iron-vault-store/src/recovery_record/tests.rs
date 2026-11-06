use super::*;
use crate::OsFs;
use crate::fault_fs::{FaultFs, FsCall};
use crate::test_dir::TestDir;

use RecoveryCheckRecordError as E;

fn at(text: &str) -> UtcSecond {
    let record = RecoveryCheckRecord::decode(format!("since = {text}\n").as_bytes()).unwrap();
    record.since()
}

fn decode(text: &str) -> Result<RecoveryCheckRecord, E> {
    RecoveryCheckRecord::decode(text.as_bytes())
}

#[test]
fn the_encoding_is_byte_for_byte_stable() {
    let since = UtcSecond::from_unix_seconds(1_793_958_553).unwrap();
    let checked = UtcSecond::from_unix_seconds(1_801_000_000).unwrap();
    let never = RecoveryCheckRecord::new(since, None).unwrap();
    let done = RecoveryCheckRecord::new(since, Some(checked)).unwrap();
    assert_eq!(never.encode(), b"since = 2026-11-06T09:49:13Z\n");
    assert_eq!(
        done.encode(),
        b"since = 2026-11-06T09:49:13Z\nlast_checked = 2027-01-26T21:46:40Z\n"
    );
    assert_eq!(RecoveryCheckRecord::decode(&never.encode()), Ok(never));
    assert_eq!(RecoveryCheckRecord::decode(&done.encode()), Ok(done));
}

#[test]
fn time_text_round_trips_at_the_edges() {
    [
        "1970-01-01T00:00:00Z",
        "2000-02-29T23:59:59Z",
        "2100-03-01T00:00:00Z",
        "9999-12-31T23:59:59Z",
    ]
    .iter()
    .for_each(|text| assert_eq!(at(text).to_string(), *text));
    assert_eq!(at("1970-01-01T00:00:00Z").unix_seconds(), 0);
    assert_eq!(UtcSecond::from_unix_seconds(MAX_UNIX_SECONDS + 1), Err(UtcSecondError));
    assert_eq!(
        UtcSecond::from_system_time(UNIX_EPOCH - std::time::Duration::from_secs(1)),
        Err(UtcSecondError)
    );
}

#[test]
fn toml_whitespace_and_key_order_are_accepted() {
    let record = decode("last_checked =  2027-01-01T00:00:00Z\n\nsince=2026-01-01T00:00:00Z").unwrap();
    assert_eq!(
        record.last_checked().map(|t| t.to_string()).as_deref(),
        Some("2027-01-01T00:00:00Z")
    );
}

#[test]
fn each_refusal_has_its_own_error() {
    let ok = "since = 2026-01-01T00:00:00Z\n";
    assert_eq!(decode(&format!("{ok}extra = 1\n")), Err(E::UnknownKey));
    assert_eq!(decode(&format!("{ok}version = 1\n")), Err(E::UnknownKey));
    assert_eq!(decode("last_checked = 2026-01-01T00:00:00Z\n"), Err(E::MissingSince));
    assert_eq!(decode(""), Err(E::MissingSince));
    assert_eq!(decode("since = [\n"), Err(E::NotToml));
    assert_eq!(RecoveryCheckRecord::decode(b"since = \xff\n"), Err(E::NotUtf8));
    assert_eq!(
        decode(&format!("{ok}last_checked = 2025-12-31T23:59:59Z\n")),
        Err(E::CheckedBeforeSince)
    );
    assert_eq!(RecoveryCheckRecord::decode(&vec![b'#'; 1025]), Err(E::TooLarge));
    assert!(RecoveryCheckRecord::decode(&[b'#'; 1024]).is_err());
}

#[test]
fn only_utc_whole_second_date_times_are_times() {
    [
        "\"2026-01-01T00:00:00Z\"",
        "2026-01-01",
        "00:00:00",
        "2026-01-01T00:00:00",
        "2026-01-01T00:00:00+01:00",
        "2026-01-01T00:00:00.5Z",
        "2026-01-01T00:00Z",
        "2026-01-01T00:00:60Z",
        "1969-12-31T23:59:59Z",
        "7",
    ]
    .iter()
    .for_each(|value| assert_eq!(decode(&format!("since = {value}\n")), Err(E::BadTime), "{value}"));
    assert_eq!(decode("since = 2026-02-30T00:00:00Z\n"), Err(E::NotToml));
}

#[test]
fn error_messages_are_fixed() {
    assert_eq!(E::UnknownKey.to_string(), "recovery check record has an unknown key");
    assert_eq!(
        E::CheckedBeforeSince.to_string(),
        "recovery check record has `last_checked` before `since`"
    );
}

fn setup(label: &str) -> (TestDir, StateDirLock) {
    let dir = TestDir::new(label);
    let lock = StateDirLock::acquire(dir.path()).unwrap();
    (dir, lock)
}

#[test]
fn an_absent_file_reads_as_none_and_a_written_one_reads_back() {
    let (_dir, lock) = setup("recovery-rec-rw");
    assert_eq!(read_recovery_check(&lock, &OsFs), Ok(None));
    let record = RecoveryCheckRecord::new(at("2026-11-06T09:49:13Z"), None).unwrap();
    write_recovery_check(&lock, &OsFs, &record).unwrap();
    assert_eq!(read_recovery_check(&lock, &OsFs), Ok(Some(record)));
    assert_eq!(remove_recovery_check(&lock, &OsFs), Ok(true));
    assert_eq!(remove_recovery_check(&lock, &OsFs), Ok(false));
    assert_eq!(read_recovery_check(&lock, &OsFs), Ok(None));
}

#[test]
fn unusable_files_are_errors_not_absent() {
    let (dir, lock) = setup("recovery-rec-bad");
    let path = dir.path().join("recovery.toml");
    std::fs::write(&path, b"since = nope\n").unwrap();
    assert!(matches!(read_recovery_check(&lock, &OsFs), Err(RecoveryCheckReadError::Decode(_))));
    std::fs::write(&path, vec![b'#'; 2000]).unwrap();
    assert!(matches!(
        read_recovery_check(&lock, &OsFs),
        Err(RecoveryCheckReadError::Read(ReadError::TooLarge { max_len: 1024, .. }))
    ));
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(matches!(
        read_recovery_check(&lock, &OsFs),
        Err(RecoveryCheckReadError::Read(ReadError::NotARegularFile { .. }))
    ));
}

#[test]
fn a_write_renames_then_syncs_the_directory() {
    let (dir, lock) = setup("recovery-rec-trace");
    let fs = FaultFs::new();
    let record = RecoveryCheckRecord::new(at("2026-11-06T09:49:13Z"), None).unwrap();
    write_recovery_check(&lock, &fs, &record).unwrap();
    let trace = fs.trace();
    let rename = trace
        .iter()
        .position(|c| matches!(c, FsCall::Rename { to, .. } if to == &dir.path().join("recovery.toml")));
    let sync = trace.iter().rposition(|c| c == &FsCall::SyncDir(dir.path().to_path_buf()));
    assert!(rename.is_some() && sync > rename, "{trace:?}");
}
