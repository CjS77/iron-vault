//! The controlling terminal, `/dev/tty`: echo is switched with `rustix::termios`, and restored by the guard, and by a
//! watcher thread on SIGINT, SIGQUIT or SIGTERM.

use std::fs::File;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use rustix::termios::{LocalModes, OptionalActions, Termios, tcgetattr, tcsetattr};
use tokio::signal::unix::{SignalKind, signal};

use super::{EchoControl, InputError, Terminal};

/// Opens the controlling terminal for prompting, and starts the watcher that restores it on SIGINT, SIGQUIT or SIGTERM.
pub(super) fn open() -> Result<Terminal<File, TtyEcho>, InputError> {
    let tty = File::options()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(InputError::Terminal)?;
    let echo = TtyEcho(Arc::new(Shared {
        fd: tty.as_fd().try_clone_to_owned().map_err(InputError::Terminal)?,
        saved: Mutex::new(None),
    }));
    restore_on_signal(echo.clone())?;
    Ok(Terminal::new(tty, echo))
}

/// Switches the terminal's echo, keeping the settings to restore where the signal watcher can reach them too.
#[derive(Clone)]
pub(super) struct TtyEcho(Arc<Shared>);

struct Shared {
    fd: OwnedFd,
    /// The terminal's settings from before echo went off, present only while it is off.
    saved: Mutex<Option<Termios>>,
}

impl TtyEcho {
    fn saved(&self) -> MutexGuard<'_, Option<Termios>> {
        // A panic while holding the lock leaves the settings intact, so a poisoned lock is still usable.
        self.0.saved.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Restores the settings in `slot`, if echo is off, through a lock the caller already holds.
    fn restore_from(&self, slot: &mut Option<Termios>) -> io::Result<()> {
        match slot.take() {
            Some(saved) => Ok(tcsetattr(&self.0.fd, OptionalActions::Now, &saved)?),
            None => Ok(()),
        }
    }
}

impl EchoControl for TtyEcho {
    fn echo_off(&self) -> io::Result<()> {
        let saved = tcgetattr(&self.0.fd)?;
        let mut quiet = saved.clone();
        quiet.local_modes.remove(LocalModes::ECHO);
        // The newline the owner types still shows, so the next output starts on a line of its own.
        quiet.local_modes.insert(LocalModes::ECHONL);
        // Held until echo is off, so the watcher's restore runs either before anything is saved or once echo is off,
        // never between the two, when it would find the settings and then see echo go off after restoring them.
        let mut slot = self.saved();
        *slot = Some(saved);
        // Flushing discards anything typed before the prompt, which was echoed and is not part of the answer.
        tcsetattr(&self.0.fd, OptionalActions::Flush, &quiet).map_err(|e| {
            *slot = None;
            io::Error::from(e)
        })
    }

    fn restore(&self) -> io::Result<()> {
        self.restore_from(&mut self.saved())
    }
}

/// Starts a thread that, on SIGINT, SIGQUIT or SIGTERM, restores the terminal if echo is off and exits.
///
/// The handlers are registered here, before any prompt is read, so none of these signals finds its default action,
/// which would kill the process with echo still off. From then on each of them goes through the watcher.
fn restore_on_signal(echo: TtyEcho) -> Result<(), InputError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .map_err(InputError::Terminal)?;
    let (mut interrupt, mut quit, mut terminate) = {
        let _context = runtime.enter();
        let watch = |kind| signal(kind).map_err(InputError::Terminal);
        (
            watch(SignalKind::interrupt())?,
            watch(SignalKind::quit())?,
            watch(SignalKind::terminate())?,
        )
    };
    std::thread::Builder::new()
        .name("tty-signals".to_owned())
        .spawn(move || {
            let received = runtime.block_on(async {
                tokio::select! {
                    _ = interrupt.recv() => SignalKind::interrupt(),
                    _ = quit.recv() => SignalKind::quit(),
                    _ = terminate.recv() => SignalKind::terminate(),
                }
            });
            restore_and_exit(&echo, received)
        })
        .map(drop)
        .map_err(InputError::Terminal)
}

/// Restores the terminal if echo is off and exits with the status a shell reports for a process `received` killed:
/// 128 plus the signal number, 130 for SIGINT.
fn restore_and_exit(echo: &TtyEcho, received: SignalKind) -> ! {
    // Held until the process exits, so no later prompt can turn echo off again after the restore.
    let mut slot = echo.saved();
    let _ = echo.restore_from(&mut slot);
    // The cursor sits after the label; the newline keeps the shell prompt off that line.
    let _ = rustix::io::write(&echo.0.fd, b"\n");
    std::process::exit(128 + received.as_raw_value())
}
