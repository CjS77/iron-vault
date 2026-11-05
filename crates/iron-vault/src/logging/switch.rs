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
use crate::deployment::DeploymentProfile;
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
    owner: ExpectedOwner,
    /// The value of [`JOURNAL_STREAM`](super::JOURNAL_STREAM) at startup, read only to refuse stdout.
    journal_stream: Option<OsString>,
    failure: LogFailure,
    /// Apply the log directory rule to the leaf alone, for a test directory whose ancestors no log directory may sit under.
    #[cfg(any(test, feature = "test-support"))]
    leaf_only: bool,
}

impl LogOpener {
    /// An opener that verifies directories under `profile`'s rule for `owner` and trips `failure` on a failed write.
    pub fn new(profile: DeploymentProfile, owner: ExpectedOwner, journal_stream: Option<OsString>, failure: LogFailure) -> Self {
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
            LogDestination::Directory(path) => LogFile::open(self.open_dir(path)?, self.owner, self.failure.clone()).map(LogWriter::File),
        }
    }

    /// `config approve`'s check of a proposed destination, which creates nothing and opens nothing for writing: the
    /// directory through a descriptor it opens and closes, and an existing `iron-vault.log` by `fstatat`; or the journal
    /// check for stdout.
    pub fn precheck(&self, destination: &LogDestination) -> Result<(), LogOpenError> {
        match destination {
            LogDestination::Stdout => LogStdout::open(self.journal_stream.as_deref(), self.failure.clone()).map(drop),
            LogDestination::Directory(path) => self.open_dir(path)?.check_log_file(self.owner),
        }
    }

    fn open_dir(&self, path: &Path) -> Result<LogDir, LogOpenError> {
        #[cfg(any(test, feature = "test-support"))]
        if self.leaf_only {
            return LogDir::open_leaf_only(path, self.owner);
        }
        LogDir::open(path, self.profile, self.owner)
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
        let opener = LogOpener::new(DeploymentProfile::Development, owner, None, LogFailure::default());
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
