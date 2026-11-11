//! The one connection an instance answers: its peer check, its request deadline and its response.

use std::io::{self, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use anyhow::ensure;
use iron_vault_tpm_protocol::{ProtocolError, Response, read_frame};
use rustix::net::sockopt::socket_peercred;
use zeroize::Zeroizing;

/// How long the helper waits for a whole request, and for its response to be taken.
const REQUEST_DEADLINE: Duration = Duration::from_secs(5);

/// The connection systemd handed over as standard input, from an accepted peer.
pub struct Connection {
    stream: UnixStream,
    deadline: Instant,
}

impl Connection {
    /// Takes the connection on standard input and refuses it, before reading anything, unless the peer's uid is
    /// `peer_uid`. The socket's mode keeps other accounts away; this check is the control.
    pub fn accept(peer_uid: u32) -> anyhow::Result<Self> {
        let deadline = Instant::now() + REQUEST_DEADLINE;
        let stream = UnixStream::from(io::stdin().as_fd().try_clone_to_owned()?);
        let peer = socket_peercred(&stream)?.uid.as_raw();
        ensure!(peer == peer_uid, "refused a connection from uid {peer}");
        Ok(Self { stream, deadline })
    }

    /// The request's frame body, read within the deadline. Zeroized on drop: it holds an authorization value.
    pub fn read_request(&self) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        read_frame(&mut DeadlineReader {
            stream: &self.stream,
            deadline: self.deadline,
        })
    }

    /// Sends the response.
    pub fn write_response(&mut self, response: &Response) -> anyhow::Result<()> {
        self.stream.set_write_timeout(Some(REQUEST_DEADLINE))?;
        self.stream.write_all(&response.encode()?)?;
        Ok(())
    }
}

/// Reads that fail once the deadline has passed, however the request is split into writes.
struct DeadlineReader<'a> {
    stream: &'a UnixStream,
    deadline: Instant,
}

impl Read for DeadlineReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        self.stream.set_read_timeout(Some(left))?;
        (&mut &*self.stream).read(buf)
    }
}
