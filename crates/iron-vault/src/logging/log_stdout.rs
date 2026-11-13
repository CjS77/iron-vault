// SPDX-License-Identifier: MPL-2.0
//! The stdout writer, for Docker, where the container runtime collects the records
//! ([audit logging: stdout is never the journal](../../../../design/audit-logging.md#stdout-is-never-the-journal)).

use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::sync::Mutex;

use rustix::fs::fstat;
use tracing_subscriber::fmt::MakeWriter;

use super::destination::LogOpenError;
use super::writer::{Append, LogFailure, RecordWriter};
use crate::trusted_path::FileId;

/// The environment variable systemd sets to the `<dev>:<inode>` of the stream it connects to a service's stdout and stderr
/// (`systemd.exec(5)`). It is read only to refuse stdout, never to choose a destination.
pub const JOURNAL_STREAM: &str = "JOURNAL_STREAM";

/// Writes each record with one `write_all` to a duplicate of stdout, held for the life of the service.
///
/// A held duplicate rather than `std::io::stdout()`: the standard stream treats a closed stdout (`EBADF`) as success, and
/// it buffers, while an audit record must reach the kernel before the event it describes is reported. A closed pipe
/// returns `EPIPE` because Rust ignores `SIGPIPE`; that, like any failed write, trips the latch.
#[derive(Debug)]
pub struct LogStdout {
    out: Mutex<File>,
    failure: LogFailure,
}

impl LogStdout {
    /// Takes stdout unless it is the systemd journal. `journal_stream` is the value of [`JOURNAL_STREAM`], when set.
    pub fn open(journal_stream: Option<&OsStr>, failure: LogFailure) -> Result<Self, LogOpenError> {
        let fd = io::stdout().as_fd().try_clone_to_owned().map_err(stdout_error)?;
        Self::from_fd(fd, journal_stream, failure)
    }

    fn from_fd(fd: OwnedFd, journal_stream: Option<&OsStr>, failure: LogFailure) -> Result<Self, LogOpenError> {
        let stat = fstat(&fd).map_err(|errno| stdout_error(errno.into()))?;
        let id = FileId {
            dev: stat.st_dev,
            ino: stat.st_ino,
        };
        match could_be_journal(journal_stream, id) {
            true => Err(LogOpenError::StdoutIsJournal),
            false => Ok(Self {
                out: Mutex::new(File::from(fd)),
                failure,
            }),
        }
    }
}

/// A failure to duplicate or inspect stdout, by its kind only.
fn stdout_error(e: io::Error) -> LogOpenError {
    LogOpenError::Stdout { kind: e.kind() }
}

/// Returns `true` if and only if stdout, with the given device and inode, may be the journal's stream.
///
/// A `JOURNAL_STREAM` that is unset cannot be. One that is set is the journal's when it names stdout's device and inode.
/// One that is set but is not two decimal numbers joined by a colon is refused as if it matched: systemd never writes
/// one, so the journal cannot be ruled out, and failing closed costs only an administrator clearing a stray variable.
fn could_be_journal(journal_stream: Option<&OsStr>, stdout: FileId) -> bool {
    journal_stream.is_some_and(|value| match value.to_str().and_then(parse_stream) {
        Some((dev, ino)) => (dev, ino) == (stdout.dev, stdout.ino),
        None => true,
    })
}

/// `<dev>:<inode>`, both plain decimal digits.
fn parse_stream(value: &str) -> Option<(u64, u64)> {
    let decimal = |digits: &str| {
        Some(digits)
            .filter(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|d| d.parse().ok())
    };
    value.split_once(':').and_then(|(dev, ino)| Some((decimal(dev)?, decimal(ino)?)))
}

impl Append for LogStdout {
    fn append(&self, record: &[u8]) -> io::Result<()> {
        self.out
            .lock()
            .map_err(|_| io::Error::other("the stdout lock is poisoned"))?
            .write_all(record)
    }

    fn failure(&self) -> &LogFailure {
        &self.failure
    }
}

impl<'a> MakeWriter<'a> for LogStdout {
    type Writer = RecordWriter<'a, Self>;

    fn make_writer(&'a self) -> Self::Writer {
        RecordWriter(self)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::os::unix::net::UnixStream;

    use super::*;

    const STDOUT: FileId = FileId { dev: 44, ino: 9001 };

    #[test]
    fn an_unset_journal_stream_is_not_the_journal() {
        assert!(!could_be_journal(None, STDOUT));
    }

    #[test]
    fn a_journal_stream_naming_stdout_is_the_journal_and_one_naming_another_stream_is_not() {
        assert!(could_be_journal(Some(OsStr::new("44:9001")), STDOUT));
        assert!(!could_be_journal(Some(OsStr::new("44:9002")), STDOUT));
        assert!(!could_be_journal(Some(OsStr::new("45:9001")), STDOUT));
    }

    #[test]
    fn a_journal_stream_that_does_not_parse_is_refused_as_if_it_matched() {
        [
            "",
            "44",
            "44:",
            ":9001",
            "44:9001:1",
            "a:b",
            "+44:9001",
            "-1:2",
            "44: 9001",
            "0x2c:9001",
            "99999999999999999999:1",
        ]
        .into_iter()
        .for_each(|value| assert!(could_be_journal(Some(OsStr::new(value)), STDOUT), "{value:?}"));
    }

    #[test]
    fn a_journal_stream_that_is_not_utf8_is_refused() {
        use std::os::unix::ffi::OsStrExt;
        assert!(could_be_journal(Some(OsStr::from_bytes(b"44:\xff")), STDOUT));
    }

    fn pair() -> (UnixStream, OwnedFd) {
        let (ours, theirs) = UnixStream::pair().expect("socketpair");
        (ours, OwnedFd::from(theirs))
    }

    #[test]
    fn a_record_reaches_the_descriptor_whole_before_the_write_returns() {
        let (mut reader, fd) = pair();
        let out = LogStdout::from_fd(fd, None, LogFailure::default()).expect("open");
        out.make_writer().write_all(b"{\"a\":1}\n").expect("write");
        let mut got = [0_u8; 8];
        reader.read_exact(&mut got).expect("read");
        assert_eq!(&got, b"{\"a\":1}\n");
    }

    #[test]
    fn a_closed_reader_trips_the_latch_on_the_first_failed_write() {
        let (reader, fd) = pair();
        let failure = LogFailure::default();
        let out = LogStdout::from_fd(fd, None, failure.clone()).expect("open");
        drop(reader);
        let written = out.make_writer().write_all(b"x\n");
        assert_eq!(written.map_err(|e| e.kind()), Err(io::ErrorKind::BrokenPipe));
        assert!(failure.is_tripped());
    }

    #[test]
    fn a_stream_matching_the_journal_variable_is_not_opened() {
        let (_reader, fd) = pair();
        let stat = fstat(&fd).expect("fstat");
        let variable = format!("{}:{}", stat.st_dev, stat.st_ino);
        let opened = LogStdout::from_fd(fd, Some(OsStr::new(&variable)), LogFailure::default());
        assert!(matches!(opened, Err(LogOpenError::StdoutIsJournal)));
    }
}
