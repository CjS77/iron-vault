// SPDX-License-Identifier: MPL-2.0
//! The one connection a helper instance answers: it checks the peer, reads one request within a deadline and writes
//! one response.

use std::io::{self, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use anyhow::ensure;
use iron_vault_tpm_protocol::{ProtocolError, Response, read_frame};
use rustix::net::sockopt::socket_peercred;
use zeroize::Zeroizing;

/// How long the helper waits for a whole request, and for its response to be taken. A stalled peer cannot hold the
/// single helper instance, and so the TPM, for longer.
const REQUEST_DEADLINE: Duration = Duration::from_secs(5);

/// The connection systemd handed over as standard input, once its peer has passed the uid check.
pub struct Connection {
    stream: UnixStream,
    deadline: Instant,
}

impl Connection {
    /// Takes the connection on standard input and refuses it, before reading anything, unless the peer's uid is
    /// `peer_uid`.
    ///
    /// The socket's mode keeps other accounts away, but this `SO_PEERCRED` check is the control the design relies on.
    /// The request deadline starts here.
    pub fn accept(peer_uid: u32) -> anyhow::Result<Self> {
        let deadline = Instant::now() + REQUEST_DEADLINE;
        let stream = UnixStream::from(io::stdin().as_fd().try_clone_to_owned()?);
        let peer = socket_peercred(&stream)?.uid.as_raw();
        ensure!(peer == peer_uid, "refused a connection from uid {peer}");
        Ok(Self { stream, deadline })
    }

    /// Reads the request's frame body within the deadline.
    ///
    /// The body is zeroized on drop because it holds an authorization value.
    pub fn read_request(&self) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        read_frame(&mut DeadlineReader {
            stream: &self.stream,
            deadline: self.deadline,
        })
    }

    /// Sends the response, giving the peer [`REQUEST_DEADLINE`] to take it.
    pub fn write_response(&mut self, response: &Response) -> anyhow::Result<()> {
        self.stream.set_write_timeout(Some(REQUEST_DEADLINE))?;
        self.stream.write_all(&response.encode()?)?;
        Ok(())
    }
}

/// Wraps the stream so every read fails once the deadline has passed. A per-read timeout alone would let a peer that
/// sends one byte at a time stretch the request without limit.
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
