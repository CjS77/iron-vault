//! The controlling terminal, `/dev/tty`: echo is switched with `rustix::termios`, and restored on SIGINT by a watcher
//! thread as well as by the guard.

use std::fs::File;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use rustix::termios::{LocalModes, OptionalActions, Termios, tcgetattr, tcsetattr};
use tokio::signal::unix::{SignalKind, signal};

use super::{EchoControl, InputError, Terminal};

/// Exit status after SIGINT, as a shell reports a process the signal killed: 128 plus the signal number.
const INTERRUPTED: i32 = 130;

/// Opens the controlling terminal for prompting, and starts the watcher that restores it on SIGINT.
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
    restore_on_interrupt(echo.clone())?;
    Ok(Terminal::new(tty, echo))
}

/// Switches the terminal's echo, keeping the settings to restore where the SIGINT watcher can reach them too.
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
}

impl EchoControl for TtyEcho {
    fn echo_off(&self) -> io::Result<()> {
        let saved = tcgetattr(&self.0.fd)?;
        let mut quiet = saved.clone();
        quiet.local_modes.remove(LocalModes::ECHO);
        // The newline the owner types still shows, so the next output starts on a line of its own.
        quiet.local_modes.insert(LocalModes::ECHONL);
        // Kept before echo goes off, so a SIGINT from here on finds what to restore.
        *self.saved() = Some(saved);
        // Flushing discards anything typed before the prompt, which was echoed and is not part of the answer.
        tcsetattr(&self.0.fd, OptionalActions::Flush, &quiet).map_err(|e| {
            self.saved().take();
            io::Error::from(e)
        })
    }

    fn restore(&self) -> io::Result<()> {
        match self.saved().take() {
            Some(saved) => Ok(tcsetattr(&self.0.fd, OptionalActions::Now, &saved)?),
            None => Ok(()),
        }
    }
}

/// Starts a thread that, on SIGINT, restores the terminal if echo is off and exits.
///
/// The handler is registered here, before any prompt is read, so a SIGINT never finds the default action, which would
/// kill the process with echo still off. From then on every SIGINT goes through the watcher.
fn restore_on_interrupt(echo: TtyEcho) -> Result<(), InputError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(InputError::Terminal)?;
    let mut interrupt = {
        let _context = runtime.enter();
        signal(SignalKind::interrupt()).map_err(InputError::Terminal)?
    };
    std::thread::Builder::new()
        .name("sigint".to_owned())
        .spawn(move || {
            runtime.block_on(interrupt.recv());
            let _ = echo.restore();
            // The cursor sits after the label; the newline keeps the shell prompt off that line.
            let _ = rustix::io::write(&echo.0.fd, b"\n");
            std::process::exit(INTERRUPTED);
        })
        .map(drop)
        .map_err(InputError::Terminal)
}
