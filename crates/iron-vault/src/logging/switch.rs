//! The writer the subscriber holds, which activation can point at another log destination (`design/audit-logging.md`,
//! "Switching at activation").
//!
//! The subscriber is installed once, at startup, so it cannot be given a new writer. It holds a [`LogSwitch`] instead,
//! and each record takes the writer that is current when the record begins: a record being written while the switch
//! happens finishes in the old destination, and none is split between two.

use std::ffi::OsString;
use std::io;
use std::path::Path;
use std::sync::{Arc, PoisonError, RwLock};

use tracing_subscriber::fmt::MakeWriter;

use super::destination::{LogDestination, LogOpenError};
use super::log_file::{LogDir, LogFile};
use super::log_stdout::LogStdout;
use super::writer::{Append, LogFailure, RecordWriter};
use crate::deployment::{DeploymentProfile, ProfileError};
use crate::trusted_path::ExpectedOwner;

/// An open log destination's writer.
#[derive(Debug)]
pub enum LogWriter {
    /// `iron-vault.log` in a verified log directory.
    File(LogFile),
    /// Standard output.
    Stdout(LogStdout),
}

impl Append for LogWriter {
    fn append(&self, record: &[u8]) -> io::Result<()> {
        match self {
            Self::File(file) => file.append(record),
            Self::Stdout(stdout) => stdout.append(record),
        }
    }

    fn failure(&self) -> &LogFailure {
        match self {
            Self::File(file) => file.failure(),
            Self::Stdout(stdout) => stdout.failure(),
        }
    }
}

/// What opening a log destination needs, kept so a config check opens a configured destination exactly as startup opened
/// the bootstrap one, and with the same latch.
#[derive(Debug, Clone)]
pub struct LogOpener {
    profile: DeploymentProfile,
    /// The service account a log directory must belong to; a stdout destination needs none, so a missing account fails
    /// only a directory.
    owner: Result<ExpectedOwner, ProfileError>,
    /// The value of [`JOURNAL_STREAM`](super::JOURNAL_STREAM) at startup, read only to refuse stdout.
    journal_stream: Option<OsString>,
    failure: LogFailure,
    /// Apply the log directory rule to the leaf alone, for a test directory whose ancestors no log directory may sit under.
    #[cfg(any(test, feature = "test-support"))]
    leaf_only: bool,
}

impl LogOpener {
    /// An opener that verifies directories under `profile`'s rule for `owner` and trips `failure` on a failed write.
    pub fn new(
        profile: DeploymentProfile,
        owner: Result<ExpectedOwner, ProfileError>,
        journal_stream: Option<OsString>,
        failure: LogFailure,
    ) -> Self {
        Self {
            profile,
            owner,
            journal_stream,
            failure,
            #[cfg(any(test, feature = "test-support"))]
            leaf_only: false,
        }
    }

    /// Checks each directory's leaf only, so an integration test can log to directories under the build tree.
    #[cfg(any(test, feature = "test-support"))]
    pub fn leaf_only(self) -> Self {
        Self { leaf_only: true, ..self }
    }

    /// Opens and verifies `destination`, creating `iron-vault.log` when it is missing.
    pub fn open(&self, destination: &LogDestination) -> Result<LogWriter, LogOpenError> {
        match destination {
            LogDestination::Stdout => LogStdout::open(self.journal_stream.as_deref(), self.failure.clone()).map(LogWriter::Stdout),
            LogDestination::Directory(path) => {
                let (dir, owner) = self.open_dir(path)?;
                LogFile::open(dir, owner, self.failure.clone()).map(LogWriter::File)
            }
        }
    }

    /// `config approve`'s check of a proposed destination, which creates nothing and opens nothing for writing: the
    /// directory through a descriptor it opens and closes, and an existing `iron-vault.log` by `fstatat`; or the journal
    /// check for stdout.
    pub fn precheck(&self, destination: &LogDestination) -> Result<(), LogOpenError> {
        match destination {
            LogDestination::Stdout => LogStdout::open(self.journal_stream.as_deref(), self.failure.clone()).map(drop),
            LogDestination::Directory(path) => {
                let (dir, owner) = self.open_dir(path)?;
                dir.check_log_file(owner)
            }
        }
    }

    /// Opens and verifies the directory at `path`, with the owner it was verified for.
    fn open_dir(&self, path: &Path) -> Result<(LogDir, ExpectedOwner), LogOpenError> {
        let owner = self.owner.clone()?;
        #[cfg(any(test, feature = "test-support"))]
        if self.leaf_only {
            return Ok((LogDir::open_leaf_only(path, owner)?, owner));
        }
        Ok((LogDir::open(path, self.profile, owner)?, owner))
    }
}

/// A destination opened and verified by a config check, which activation switches to.
#[derive(Debug)]
pub struct OpenedLog {
    destination: LogDestination,
    writer: LogWriter,
}

impl OpenedLog {
    /// Where the records will go.
    pub fn destination(&self) -> &LogDestination {
        &self.destination
    }
}

/// The subscriber's writer: the current log destination's, which activation can replace. Clones share it.
#[derive(Debug, Clone)]
pub struct LogSwitch(Arc<Shared>);

#[derive(Debug)]
struct Shared {
    bootstrap: LogDestination,
    opener: LogOpener,
    current: RwLock<Current>,
}

#[derive(Debug)]
struct Current {
    destination: LogDestination,
    writer: Arc<LogWriter>,
}

impl LogSwitch {
    /// Opens the `bootstrap` destination with `opener` and starts there.
    pub fn open(bootstrap: LogDestination, opener: LogOpener) -> Result<Self, LogOpenError> {
        let writer = Arc::new(opener.open(&bootstrap)?);
        let current = RwLock::new(Current {
            destination: bootstrap.clone(),
            writer,
        });
        Ok(Self(Arc::new(Shared {
            bootstrap,
            opener,
            current,
        })))
    }

    /// A switch on stdout that nothing writes to unless a test installs it, for tests that need a service but not its log.
    #[cfg(any(test, feature = "test-support"))]
    pub fn stdout_for_tests(owner: ExpectedOwner) -> Result<Self, LogOpenError> {
        let opener = LogOpener::new(DeploymentProfile::Development, Ok(owner), None, LogFailure::default());
        Self::open(LogDestination::Stdout, opener)
    }

    /// The destination in force when no approved config chooses one.
    pub fn bootstrap(&self) -> &LogDestination {
        &self.0.bootstrap
    }

    /// Where records go now.
    pub fn current(&self) -> LogDestination {
        self.read(|current| current.destination.clone())
    }

    /// The opener the bootstrap destination was opened with.
    pub fn opener(&self) -> &LogOpener {
        &self.0.opener
    }

    /// The latch every writer this switch holds trips on a failed write.
    pub fn failure(&self) -> &LogFailure {
        &self.0.opener.failure
    }

    /// Opens and verifies `destination`, for a later [`Self::switch`].
    pub fn open_destination(&self, destination: LogDestination) -> Result<OpenedLog, LogOpenError> {
        let writer = self.0.opener.open(&destination)?;
        Ok(OpenedLog { destination, writer })
    }

    /// Sends every record that begins from now on to `opened`, and returns the destination it replaced.
    pub fn switch(&self, opened: OpenedLog) -> LogDestination {
        let mut current = self.0.current.write().unwrap_or_else(PoisonError::into_inner);
        let replaced = std::mem::replace(
            &mut *current,
            Current {
                destination: opened.destination,
                writer: Arc::new(opened.writer),
            },
        );
        replaced.destination
    }

    /// Reads the current destination. A poisoned lock still holds a whole value, since a switch only ever replaces it
    /// in one assignment.
    fn read<T>(&self, f: impl FnOnce(&Current) -> T) -> T {
        f(&self.0.current.read().unwrap_or_else(PoisonError::into_inner))
    }
}

impl<'a> MakeWriter<'a> for LogSwitch {
    type Writer = SwitchedWriter;

    fn make_writer(&'a self) -> Self::Writer {
        SwitchedWriter(self.read(|current| Arc::clone(&current.writer)))
    }
}

/// One record's writer: the destination that was current when the record began, kept until the record is written.
#[derive(Debug)]
pub struct SwitchedWriter(Arc<LogWriter>);

impl io::Write for SwitchedWriter {
    fn write(&mut self, record: &[u8]) -> io::Result<usize> {
        RecordWriter(&*self.0).write(record)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;
    use crate::logging::{FileProblem, LOG_FILE_NAME};

    /// A fresh `0750` directory under the system temp directory, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let name = format!("iv-switch-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed));
            let dir = std::env::temp_dir().join(name);
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o750)).unwrap();
            Self(dir)
        }

        fn destination(&self) -> LogDestination {
            LogDestination::Directory(self.0.clone())
        }

        fn log(&self) -> String {
            fs::read_to_string(self.0.join(LOG_FILE_NAME)).unwrap_or_default()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn opener() -> LogOpener {
        let owner = ExpectedOwner {
            uid: rustix::process::getuid().as_raw(),
        };
        LogOpener::new(DeploymentProfile::Development, Ok(owner), None, LogFailure::default()).leaf_only()
    }

    fn write(switch: &LogSwitch, record: &str) -> io::Result<()> {
        switch.make_writer().write_all(record.as_bytes())
    }

    #[test]
    fn a_switch_sends_later_records_to_the_new_destination_and_returns_the_old_one() {
        let (old, new) = (Scratch::new(), Scratch::new());
        let switch = LogSwitch::open(old.destination(), opener()).unwrap();
        write(&switch, "before\n").unwrap();
        let opened = switch.open_destination(new.destination()).unwrap();
        assert_eq!(switch.switch(opened), old.destination());
        write(&switch, "after\n").unwrap();
        assert_eq!((old.log(), new.log()), ("before\n".to_owned(), "after\n".to_owned()));
        assert_eq!(switch.current(), new.destination());
        assert_eq!(switch.bootstrap(), &old.destination());
    }

    #[test]
    fn a_failed_write_to_the_new_destination_trips_the_shared_latch() {
        let (old, new) = (Scratch::new(), Scratch::new());
        let switch = LogSwitch::open(old.destination(), opener()).unwrap();
        switch.switch(switch.open_destination(new.destination()).unwrap());
        // With its directory gone, the writer finds the log file renamed and cannot create it again.
        fs::remove_dir_all(&new.0).unwrap();
        assert!(write(&switch, "lost\n").is_err());
        assert!(switch.failure().is_tripped());
    }

    #[test]
    fn the_precheck_creates_nothing_and_refuses_an_unsafe_log_file() {
        let dir = Scratch::new();
        opener().precheck(&dir.destination()).unwrap();
        assert!(!dir.0.join(LOG_FILE_NAME).exists());
        fs::write(dir.0.join(LOG_FILE_NAME), "").unwrap();
        fs::set_permissions(dir.0.join(LOG_FILE_NAME), fs::Permissions::from_mode(0o662)).unwrap();
        assert!(matches!(
            opener().precheck(&dir.destination()),
            Err(LogOpenError::UnsafeFile(FileProblem::Writable))
        ));
    }

    #[test]
    fn the_precheck_refuses_a_missing_directory_and_one_others_can_write() {
        let dir = Scratch::new();
        let missing = LogDestination::Directory(dir.0.join("missing"));
        assert!(opener().precheck(&missing).is_err());
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o757)).unwrap();
        assert!(matches!(opener().precheck(&dir.destination()), Err(LogOpenError::Untrusted(_))));
        assert!(!dir.0.join(LOG_FILE_NAME).exists());
    }
}
