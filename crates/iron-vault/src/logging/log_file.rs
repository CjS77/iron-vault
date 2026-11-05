//! The log directory and `iron-vault.log` in it, written only through a directory descriptor the trust check verified.
//!
//! A walk of the path by name followed by an open by name would leave a gap: a member of a group that can write an
//! ancestor (`syslog` on stock `/var/log`) could rename the directory away between the two and plant their own. So the
//! walk is followed by one open with `O_DIRECTORY | O_NOFOLLOW`, an `fstat` of that descriptor that must match what the
//! walk saw, and the descriptor is kept: the log file is opened relative to it with `openat` and the directory's path is
//! never resolved again.

use std::fs::File;
use std::io::{self, Write};
use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::Mutex;

use rustix::fs::{AtFlags, FileType, Mode as FileMode, OFlags, Stat, fchmod, fstat, open, openat, statat};
use rustix::io::{Errno, pread};
use tracing_subscriber::fmt::MakeWriter;

use super::destination::LogOpenError;
use super::writer::{Append, LogFailure, RecordWriter};
use crate::deployment::DeploymentProfile;
use crate::path_metadata;
use crate::trusted_path::{self, ComponentKind, ExpectedOwner, FileId, Mode, PathComponent, TrustedPathRule, UnsafePath};
use crate::trusted_path_report::PathFailure;

/// The one file the service writes in the log directory.
pub const LOG_FILE_NAME: &str = "iron-vault.log";

/// The mode of a log file the service creates, whatever its umask: the group may read it for a collector, never write.
const LOG_FILE_MODE: u32 = 0o640;

/// Why a log file the service opened is not one it may append to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FileProblem {
    /// Not a regular file.
    #[error("not a regular file")]
    NotRegular,
    /// Owned by an account other than the service account.
    #[error("not owned by the service account")]
    NotOwned,
    /// Writable by its group or by others.
    #[error("writable by its group or others")]
    Writable,
}

/// A log directory that passed [`TrustedPathRule::LogDir`], held by the descriptor that was verified.
#[derive(Debug)]
pub struct LogDir {
    fd: OwnedFd,
}

impl LogDir {
    /// Checks `path` against the log directory rule and opens it, in the order the design requires: walk with `lstat`,
    /// open the leaf once without following a symlink, `fstat` that descriptor and apply the rule to its own metadata.
    pub fn open(path: &Path, profile: DeploymentProfile, owner: ExpectedOwner) -> Result<Self, LogOpenError> {
        Self::open_verified(path, |chain| trusted_path::check(TrustedPathRule::LogDir, profile, owner, chain))
    }

    /// [`Self::open`] with the rule as a parameter, so tests can open a directory under `/tmp`, which no ancestor rule
    /// would pass.
    fn open_verified(path: &Path, verify: impl Fn(&[PathComponent]) -> Result<(), UnsafePath>) -> Result<Self, LogOpenError> {
        let walked = path_metadata::collect(path).map_err(PathFailure::from)?;
        verify(&walked).map_err(PathFailure::from)?;
        let seen = walked.last().map(|leaf| leaf.id);
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let fd = open(path, flags, FileMode::empty()).map_err(|errno| LogOpenError::Directory {
            path: path.to_path_buf(),
            kind: io::Error::from(errno).kind(),
        })?;
        let stat = fstat(&fd).map_err(|errno| LogOpenError::Directory {
            path: path.to_path_buf(),
            kind: io::Error::from(errno).kind(),
        })?;
        let opened = describe(path, &stat);
        if seen != Some(opened.id) {
            return Err(LogOpenError::DirectoryReplaced { path: path.to_path_buf() });
        }
        let rechecked: Vec<PathComponent> = walked.into_iter().rev().skip(1).rev().chain([opened]).collect();
        verify(&rechecked).map_err(PathFailure::from)?;
        Ok(Self { fd })
    }
}

/// An open file or directory as a trusted-path component, from the metadata of its descriptor.
fn describe(path: &Path, stat: &Stat) -> PathComponent {
    PathComponent {
        path: path.to_path_buf(),
        uid: stat.st_uid,
        gid: stat.st_gid,
        owner_name: None,
        group_name: None,
        mode: Mode::new(stat.st_mode),
        kind: match FileType::from_raw_mode(stat.st_mode) {
            FileType::Directory => ComponentKind::Directory,
            FileType::RegularFile => ComponentKind::RegularFile,
            _ => ComponentKind::Other,
        },
        id: file_id(stat),
    }
}

fn file_id(stat: &Stat) -> FileId {
    FileId {
        dev: stat.st_dev,
        ino: stat.st_ino,
    }
}

/// The open log file and the identity it had when opened, to notice `logrotate` renaming it.
#[derive(Debug)]
struct OpenLog {
    file: File,
    id: FileId,
    /// The file ended in a torn record when opened, so the next write starts with `\n`. A JSON Lines reader would
    /// otherwise lose the next valid record along with the torn one.
    pending_newline: bool,
}

/// Appends records to `iron-vault.log` in a verified directory, following a rotation without a signal.
///
/// Before each record it compares the `(dev, inode)` of the name in the directory with its open file. When they differ,
/// or the name is missing, `logrotate` (with `nocreate`) has renamed the file, so the name is opened again, created if
/// missing, and verified like any file it opens. A record written between the rename and the reopen lands in the
/// renamed file, so none is lost.
#[derive(Debug)]
pub struct LogFile {
    dir: LogDir,
    owner: ExpectedOwner,
    open: Mutex<OpenLog>,
    failure: LogFailure,
}

impl LogFile {
    /// Opens `iron-vault.log` in `dir`, creating it at mode `0640` when missing.
    pub fn open(dir: LogDir, owner: ExpectedOwner, failure: LogFailure) -> Result<Self, LogOpenError> {
        let open = open_log(&dir, owner)?;
        Ok(Self {
            dir,
            owner,
            open: Mutex::new(open),
            failure,
        })
    }

    fn try_append(&self, record: &[u8]) -> io::Result<()> {
        let mut open = self.open.lock().map_err(|_| io::Error::other("the log file lock is poisoned"))?;
        if self.renamed(&open)? {
            *open = open_log(&self.dir, self.owner).map_err(io::Error::other)?;
        }
        if !open.pending_newline {
            return open.file.write_all(record);
        }
        let repaired: Vec<u8> = std::iter::once(b'\n').chain(record.iter().copied()).collect();
        open.file.write_all(&repaired)?;
        open.pending_newline = false;
        Ok(())
    }

    /// Whether the name in the directory is no longer the open file. `AT_SYMLINK_NOFOLLOW` makes a planted symlink differ
    /// from the open file too, and the reopen then refuses it.
    fn renamed(&self, open: &OpenLog) -> io::Result<bool> {
        match statat(&self.dir.fd, LOG_FILE_NAME, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => Ok(file_id(&stat) != open.id),
            Err(Errno::NOENT) => Ok(true),
            Err(errno) => Err(errno.into()),
        }
    }
}

/// Opens (creating when missing) and verifies `iron-vault.log`; a file that fails the rule is closed unused.
fn open_log(dir: &LogDir, owner: ExpectedOwner) -> Result<OpenLog, LogOpenError> {
    let file_error = |errno: Errno| LogOpenError::File {
        kind: io::Error::from(errno).kind(),
    };
    let fd = open_or_create(&dir.fd).map_err(file_error)?;
    let stat = fstat(&fd).map_err(file_error)?;
    verify_file(&stat, owner)?;
    let pending_newline = ends_mid_record(&fd, &stat).map_err(file_error)?;
    Ok(OpenLog {
        file: File::from(fd),
        id: file_id(&stat),
        pending_newline,
    })
}

/// Whether a non-empty file's last byte is not `\n`. Uses `pread`, since the descriptor is `O_APPEND` and a seek would
/// not be needed or wanted.
fn ends_mid_record(fd: &OwnedFd, stat: &Stat) -> Result<bool, Errno> {
    let Some(last) = u64::try_from(stat.st_size).ok().and_then(|len| len.checked_sub(1)) else {
        return Ok(false);
    };
    let mut byte = [0u8; 1];
    let read = pread(fd, &mut byte, last)?;
    Ok(read == 1 && byte[0] != b'\n')
}

/// Opens the name for appending without following a symlink. A missing name is created exclusively and given its mode
/// explicitly, since the unit's umask would otherwise narrow it. Losing the creation race to another process falls back
/// to opening what it made, which is then verified.
fn open_or_create(dir: &OwnedFd) -> Result<OwnedFd, Errno> {
    let existing = OFlags::RDWR | OFlags::APPEND | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mode = FileMode::from_raw_mode(LOG_FILE_MODE);
    match openat(dir, LOG_FILE_NAME, existing, FileMode::empty()) {
        Err(Errno::NOENT) => match openat(dir, LOG_FILE_NAME, existing | OFlags::CREATE | OFlags::EXCL, mode) {
            Ok(fd) => fchmod(&fd, mode).map(|()| fd),
            Err(Errno::EXIST) => openat(dir, LOG_FILE_NAME, existing, FileMode::empty()),
            Err(errno) => Err(errno),
        },
        opened => opened,
    }
}

/// The log file rule: a regular file the service account owns, which neither its group nor others can write.
fn verify_file(stat: &Stat, owner: ExpectedOwner) -> Result<(), FileProblem> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(FileProblem::NotRegular);
    }
    match (stat.st_uid == owner.uid, stat.st_mode & 0o022 == 0) {
        (false, _) => Err(FileProblem::NotOwned),
        (true, false) => Err(FileProblem::Writable),
        (true, true) => Ok(()),
    }
}

impl Append for LogFile {
    fn append(&self, record: &[u8]) -> io::Result<()> {
        self.try_append(record)
    }

    fn failure(&self) -> &LogFailure {
        &self.failure
    }
}

impl<'a> MakeWriter<'a> for LogFile {
    type Writer = RecordWriter<'a, Self>;

    fn make_writer(&'a self) -> Self::Writer {
        RecordWriter(self)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl LogDir {
    /// [`Self::open`] with the rule applied to the leaf alone, so an integration test can log to a directory under the build tree.
    pub fn open_leaf_only(path: &Path, owner: ExpectedOwner) -> Result<Self, LogOpenError> {
        Self::open_verified(path, leaf_only(owner))
    }
}

#[cfg(any(test, feature = "test-support"))]
fn root_dir() -> PathComponent {
    PathComponent {
        path: std::path::PathBuf::from("/"),
        uid: 0,
        gid: 0,
        owner_name: None,
        group_name: None,
        mode: Mode::new(0o755),
        kind: ComponentKind::Directory,
        id: FileId { dev: 0, ino: 0 },
    }
}

/// The log directory rule on the leaf alone, for a test tree under `/tmp` or a build directory, whose ancestors no log
/// directory may sit under.
#[cfg(any(test, feature = "test-support"))]
fn leaf_only(owner: ExpectedOwner) -> impl Fn(&[PathComponent]) -> Result<(), UnsafePath> {
    move |chain| {
        let leaf = chain.last().cloned().into_iter();
        let leaf_chain: Vec<PathComponent> = std::iter::once(root_dir()).chain(leaf).collect();
        trusted_path::check(TrustedPathRule::LogDir, DeploymentProfile::Development, owner, &leaf_chain)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    use tracing_subscriber::fmt::MakeWriter;

    use super::*;
    use crate::logging;

    /// A fresh `0750` directory under the system temp directory, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let dir = std::env::temp_dir().join(format!("iv-log-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).expect("scratch");
            set_mode(&dir, 0o750);
            Self(dir)
        }

        fn log(&self) -> PathBuf {
            self.0.join(LOG_FILE_NAME)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn set_mode(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod");
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).expect("stat").permissions().mode() & 0o7777
    }

    fn me() -> ExpectedOwner {
        ExpectedOwner {
            uid: rustix::process::getuid().as_raw(),
        }
    }

    fn open_dir(dir: &Scratch) -> LogDir {
        LogDir::open_verified(&dir.0, leaf_only(me())).expect("open dir")
    }

    fn open_file(dir: &Scratch, failure: &LogFailure) -> LogFile {
        LogFile::open(open_dir(dir), me(), failure.clone()).expect("open file")
    }

    fn write(file: &LogFile, record: &str) -> io::Result<()> {
        file.make_writer().write_all(record.as_bytes())
    }

    fn read(path: &Path) -> String {
        fs::read_to_string(path).expect("read")
    }

    #[test]
    fn records_are_appended_whole_to_a_log_file_created_at_0640() {
        let dir = Scratch::new();
        let file = open_file(&dir, &LogFailure::default());
        write(&file, "one\n").expect("write");
        write(&file, "two\n").expect("write");
        assert_eq!(read(&dir.log()), "one\ntwo\n");
        assert_eq!(mode(&dir.log()), 0o640);
    }

    #[test]
    fn an_existing_log_file_is_appended_to_not_truncated() {
        let dir = Scratch::new();
        fs::write(dir.log(), "old\n").expect("seed");
        set_mode(&dir.log(), 0o640);
        write(&open_file(&dir, &LogFailure::default()), "new\n").expect("write");
        assert_eq!(read(&dir.log()), "old\nnew\n");
    }

    #[test]
    fn the_subscriber_writes_json_lines_that_are_on_disk_when_the_event_returns() {
        let dir = Scratch::new();
        let file = open_file(&dir, &LogFailure::default());
        tracing::subscriber::with_default(logging::subscriber(file, DeploymentProfile::Development), || {
            tracing::info!(event = "service.started", "started");
            tracing::info!(event = "service.stopped", "stopped");
        });
        let lines: Vec<serde_json::Value> = read(&dir.log()).lines().map(|l| serde_json::from_str(l).expect("JSON")).collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["event"], "service.started");
        assert_eq!(lines[1]["event"], "service.stopped");
        assert_eq!(lines[1]["deployment_profile"], "development");
    }

    #[test]
    fn a_renamed_log_file_is_followed_and_the_new_name_is_created_at_0640() {
        let dir = Scratch::new();
        let file = open_file(&dir, &LogFailure::default());
        write(&file, "before\n").expect("write");
        fs::rename(dir.log(), dir.0.join("iron-vault.log.1")).expect("rotate");
        write(&file, "after\n").expect("write");
        assert_eq!(read(&dir.0.join("iron-vault.log.1")), "before\n");
        assert_eq!(read(&dir.log()), "after\n");
        assert_eq!(mode(&dir.log()), 0o640);
    }

    #[test]
    fn a_removed_log_file_is_created_again() {
        let dir = Scratch::new();
        let file = open_file(&dir, &LogFailure::default());
        write(&file, "before\n").expect("write");
        fs::remove_file(dir.log()).expect("remove");
        write(&file, "after\n").expect("write");
        assert_eq!(read(&dir.log()), "after\n");
    }

    #[test]
    fn a_torn_record_gets_a_newline_before_the_next_record_on_every_open() {
        let dir = Scratch::new();
        fs::write(dir.log(), "{\"a\":1}\n{\"torn\"").expect("seed");
        set_mode(&dir.log(), 0o640);
        let file = open_file(&dir, &LogFailure::default());
        write(&file, "{\"b\":2}\n").expect("write");
        write(&file, "{\"c\":3}\n").expect("write");
        let text = read(&dir.log());
        assert_eq!(text, "{\"a\":1}\n{\"torn\"\n{\"b\":2}\n{\"c\":3}\n");
        assert_eq!(
            text.lines()
                .filter(|l| serde_json::from_str::<serde_json::Value>(l).is_ok())
                .count(),
            3
        );
    }

    #[test]
    fn a_torn_record_in_a_file_reopened_after_rotation_is_terminated() {
        let dir = Scratch::new();
        let file = open_file(&dir, &LogFailure::default());
        write(&file, "before\n").expect("write");
        fs::rename(dir.log(), dir.0.join("iron-vault.log.1")).expect("rotate");
        fs::write(dir.log(), "torn").expect("plant");
        set_mode(&dir.log(), 0o640);
        write(&file, "after\n").expect("write");
        assert_eq!(read(&dir.log()), "torn\nafter\n");
    }

    #[test]
    fn a_file_ending_in_a_newline_and_an_empty_file_get_no_extra_newline() {
        let dir = Scratch::new();
        write(&open_file(&dir, &LogFailure::default()), "one\n").expect("write");
        assert_eq!(read(&dir.log()), "one\n");
        write(&open_file(&dir, &LogFailure::default()), "two\n").expect("write");
        assert_eq!(read(&dir.log()), "one\ntwo\n");
    }

    #[test]
    fn a_group_writable_log_file_is_refused_at_open() {
        let dir = Scratch::new();
        fs::write(dir.log(), "").expect("seed");
        set_mode(&dir.log(), 0o660);
        let opened = LogFile::open(open_dir(&dir), me(), LogFailure::default());
        assert!(matches!(opened, Err(LogOpenError::UnsafeFile(FileProblem::Writable))), "{opened:?}");
    }

    #[test]
    fn a_log_file_owned_by_another_account_is_refused_at_open() {
        let dir = Scratch::new();
        fs::write(dir.log(), "").expect("seed");
        set_mode(&dir.log(), 0o640);
        let other = ExpectedOwner { uid: me().uid + 1 };
        let opened = LogFile::open(open_dir(&dir), other, LogFailure::default());
        assert!(matches!(opened, Err(LogOpenError::UnsafeFile(FileProblem::NotOwned))), "{opened:?}");
    }

    #[test]
    fn a_symlink_planted_as_the_log_file_is_refused_not_followed() {
        let dir = Scratch::new();
        let elsewhere = dir.0.join("elsewhere");
        fs::write(&elsewhere, "target\n").expect("seed");
        symlink(&elsewhere, dir.log()).expect("plant");
        let opened = LogFile::open(open_dir(&dir), me(), LogFailure::default());
        assert!(matches!(opened, Err(LogOpenError::File { .. })), "{opened:?}");
        assert_eq!(read(&elsewhere), "target\n");
    }

    #[test]
    fn a_failed_reopen_mid_run_fails_the_write_and_trips_the_latch() {
        let dir = Scratch::new();
        let failure = LogFailure::default();
        let file = open_file(&dir, &failure);
        write(&file, "before\n").expect("write");
        fs::rename(dir.log(), dir.0.join("iron-vault.log.1")).expect("rotate");
        fs::write(dir.log(), "").expect("plant");
        set_mode(&dir.log(), 0o666);
        assert!(write(&file, "after\n").is_err());
        assert!(failure.is_tripped());
        assert_eq!(read(&dir.log()), "");
    }

    #[test]
    fn a_trusted_directory_is_opened() {
        let dir = Scratch::new();
        set_mode(&dir.0, 0o700);
        assert!(LogDir::open_verified(&dir.0, leaf_only(me())).is_ok());
    }

    fn refused_with(dir: &Path, owner: ExpectedOwner) -> Option<crate::trusted_path::Problem> {
        match LogDir::open_verified(dir, leaf_only(owner)) {
            Err(LogOpenError::Untrusted(PathFailure::Unsafe(unsafe_path))) => Some(unsafe_path.problem),
            _ => None,
        }
    }

    #[test]
    fn a_group_writable_or_other_readable_directory_is_refused_before_any_file_is_made() {
        let dir = Scratch::new();
        [0o770, 0o755, 0o751].into_iter().for_each(|bits| {
            set_mode(&dir.0, bits);
            let refused = refused_with(&dir.0, me());
            assert!(
                matches!(refused, Some(crate::trusted_path::Problem::ModeTooOpen { .. })),
                "{bits:o}: {refused:?}"
            );
            assert!(!dir.log().exists());
        });
    }

    #[test]
    fn a_directory_owned_by_another_account_is_refused() {
        let dir = Scratch::new();
        let refused = refused_with(&dir.0, ExpectedOwner { uid: me().uid + 1 });
        assert!(
            matches!(refused, Some(crate::trusted_path::Problem::WrongOwner { .. })),
            "{refused:?}"
        );
    }

    #[test]
    fn a_symlinked_leaf_and_a_plain_file_are_refused() {
        let dir = Scratch::new();
        let link = dir.0.join("link");
        symlink(&dir.0, &link).expect("link");
        let plain = dir.0.join("plain");
        fs::write(&plain, "").expect("file");
        [link, plain].iter().for_each(|path| {
            assert_eq!(
                refused_with(path, me()),
                Some(crate::trusted_path::Problem::NotADirectory),
                "{path:?}"
            )
        });
    }

    #[test]
    fn a_missing_directory_is_not_created_and_is_refused() {
        let dir = Scratch::new();
        let missing = dir.0.join("missing");
        assert!(matches!(
            LogDir::open_verified(&missing, leaf_only(me())),
            Err(LogOpenError::Untrusted(PathFailure::Uncollected(_)))
        ));
        assert!(!missing.exists());
    }

    #[test]
    fn a_directory_swapped_between_the_walk_and_the_open_is_refused() {
        let dir = Scratch::new();
        let victim = dir.0.join("logs");
        fs::create_dir(&victim).expect("mkdir");
        set_mode(&victim, 0o750);
        let swapped = Cell::new(false);
        let verify = |chain: &[PathComponent]| {
            if !swapped.replace(true) {
                fs::rename(&victim, dir.0.join("logs.moved")).expect("move away");
                fs::create_dir(&victim).expect("plant");
                set_mode(&victim, 0o750);
            }
            leaf_only(me())(chain)
        };
        assert!(matches!(
            LogDir::open_verified(&victim, verify),
            Err(LogOpenError::DirectoryReplaced { .. })
        ));
    }

    #[test]
    fn the_file_is_written_through_the_held_descriptor_after_the_directory_is_renamed() {
        let dir = Scratch::new();
        let logs = dir.0.join("logs");
        fs::create_dir(&logs).expect("mkdir");
        set_mode(&logs, 0o750);
        let held = LogDir::open_verified(&logs, leaf_only(me())).expect("open");
        let file = LogFile::open(held, me(), LogFailure::default()).expect("file");
        fs::rename(&logs, dir.0.join("renamed")).expect("rename");
        fs::create_dir(&logs).expect("plant");
        write(&file, "kept\n").expect("write");
        assert_eq!(read(&dir.0.join("renamed").join(LOG_FILE_NAME)), "kept\n");
        assert!(!logs.join(LOG_FILE_NAME).exists());
    }
}
