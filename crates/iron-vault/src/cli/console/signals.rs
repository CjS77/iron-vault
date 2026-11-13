// SPDX-License-Identifier: MPL-2.0
//! The signal watcher. Once the owner console is open, in either mode, SIGINT, SIGQUIT, SIGTERM and SIGHUP end the
//! command through it, so it can restore the terminal and tell the owner what to do with a recovery key already shown.

use std::io::{self, Write};
use std::os::unix::net::UnixDatagram;
use std::path::Path;

use tokio::signal::unix::{SignalKind, signal};

use super::{InputError, signal_advice, tty};

/// Where the system logger listens.
const SYSLOG_SOCKET: &str = "/dev/log";

/// Starts a thread that ends the command on SIGINT, SIGQUIT, SIGTERM or SIGHUP. Called once, when the console opens.
///
/// The handlers are registered here, before any prompt is read or any key is shown, so none of these signals finds its
/// default action, which would kill the process with echo still off or without the owner's advice.
pub(super) fn watch() -> Result<(), InputError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .map_err(InputError::Signals)?;
    let (mut interrupt, mut quit, mut terminate, mut hangup) = {
        let _context = runtime.enter();
        let watch = |kind| signal(kind).map_err(InputError::Signals);
        (
            watch(SignalKind::interrupt())?,
            watch(SignalKind::quit())?,
            watch(SignalKind::terminate())?,
            watch(SignalKind::hangup())?,
        )
    };
    std::thread::Builder::new()
        .name("console-signals".to_owned())
        .spawn(move || {
            let received = runtime.block_on(async {
                tokio::select! {
                    _ = interrupt.recv() => SignalKind::interrupt(),
                    _ = quit.recv() => SignalKind::quit(),
                    _ = terminate.recv() => SignalKind::terminate(),
                    _ = hangup.recv() => SignalKind::hangup(),
                }
            });
            end(received)
        })
        .map(drop)
        .map_err(InputError::Signals)
}

/// Restores the terminal if echo is off, gives the owner any advice the command set, and exits with the status a shell
/// reports for a process `received` killed: 128 plus the signal number, 130 for SIGINT.
fn end(received: SignalKind) -> ! {
    tty::restore_then(|| {
        if let Some(advice) = signal_advice() {
            // A hangup means the terminal has gone, and stderr may have gone with it. The logger goes first: a stderr
            // pipe whose reader has stalled would block the write, and the log line would never be sent.
            if received == SignalKind::hangup() {
                log_advice(Path::new(SYSLOG_SOCKET), &advice);
            }
            let _ = writeln!(io::stderr(), "iron-vault: {advice}");
        }
        std::process::exit(128 + received.as_raw_value())
    })
}

/// Sends `advice` to the system logger listening at `socket`. Best effort: without a logger only this copy is lost. The
/// advice is the command's fixed text and names no secret.
fn log_advice(socket: &Path, advice: &str) {
    let _ = UnixDatagram::unbound().and_then(|logger| logger.send_to(syslog_line(advice).as_bytes(), socket));
}

/// One syslog line at facility user and severity warning (`<12>`), tagged with the command and its pid. The logger adds
/// the time and the host.
fn syslog_line(advice: &str) -> String {
    format!("<12>iron-vault[{}]: {advice}", std::process::id())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::os::unix::net::UnixDatagram;

    use super::*;

    #[test]
    fn the_advice_reaches_the_logger_as_one_warning_line() {
        let dir = std::env::temp_dir().join(format!("iv-syslog-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let socket = dir.join("log");
        let logger = UnixDatagram::bind(&socket).unwrap();

        log_advice(&socket, "keep the recovery key");

        let mut line = [0; 256];
        let len = logger.recv(&mut line).unwrap();
        let expected = format!("<12>iron-vault[{}]: keep the recovery key", std::process::id());
        assert_eq!(line.get(..len), Some(expected.as_bytes()));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_missing_logger_is_ignored() {
        log_advice(Path::new("/nonexistent/iron-vault/log"), "keep the recovery key");
    }
}
