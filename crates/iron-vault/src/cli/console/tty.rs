//! The controlling terminal, `/dev/tty`: echo is switched with `rustix::termios`, and restored by the guard, and by the
//! signal watcher when a signal ends the command.

use std::fs::File;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use rustix::termios::{LocalModes, OptionalActions, Termios, tcgetattr, tcsetattr};

use super::{EchoControl, InputError, Terminal};

/// The echo of the terminal [`open`] opened, where the signal watcher can restore it. Registered before any prompt can
/// turn echo off, and held by the watcher until the process exits.
static OPEN_ECHO: Mutex<Option<TtyEcho>> = Mutex::new(None);

/// Opens the controlling terminal for prompting, and registers its echo for the signal watcher to restore.
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
    *OPEN_ECHO.lock().unwrap_or_else(PoisonError::into_inner) = Some(echo.clone());
    Ok(Terminal::new(tty, echo))
}

/// Opens the controlling terminal for writing only, to show a reveal when stdin is not a terminal. Nothing is read from
/// it and echo is never switched, so there is nothing to restore.
pub(super) fn open_for_reveal() -> io::Result<File> {
    File::options().write(true).open("/dev/tty")
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

/// Restores the open terminal's echo if it is off and ends its line, then runs `exit`, which ends the process. Both
/// locks are held until then, so neither [`open`] nor a later prompt can turn echo off again after the restore.
pub(super) fn restore_then<T>(exit: impl FnOnce() -> T) -> T {
    let registered = OPEN_ECHO.lock().unwrap_or_else(PoisonError::into_inner);
    let _saved = registered.as_ref().map(|echo| {
        let mut slot = echo.saved();
        let _ = echo.restore_from(&mut slot);
        // The cursor sits after the label; the newline keeps the shell prompt off that line.
        let _ = rustix::io::write(&echo.0.fd, b"\n");
        slot
    });
    exit()
}
