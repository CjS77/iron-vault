//! The owner console: where the CLI collects owner input for the service's prompts, and shows its notices and reveals
//! (`design/admin-protocol.md`, "Owner input").
//!
//! Each value goes from the input straight into a clearing buffer, and from there into one owner-input frame. A revealed
//! value goes from its clearing buffer straight to the terminal's descriptor. Neither passes through `String`,
//! formatting, `Debug` or a log call, and no error names a byte of either.

mod signals;
mod tty;

use std::fs::File;
use std::io::{self, IsTerminal, Read, Write};
use std::os::fd::AsFd;
use std::sync::{Mutex, PoisonError};

use iron_vault::admin::protocol::{MAX_BODY_LEN, OwnerInput, Prompt, PromptAnswer, RevealedSecret};
use qrcode::render::unicode::Dense1x2;
use qrcode::{EcLevel, QrCode};
use zeroize::Zeroizing;

/// The longest line a value may arrive in: the longest value, then `\r\n`.
const LINE_CAPACITY: usize = MAX_BODY_LEN + 2;

/// Ctrl-Y, which ends a terminal line asking to switch to the next approver (`design/approval-signers.md`, "Switching").
/// Linux gives it no other meaning in canonical mode, since it has no `VDSUSP`.
pub(super) const SWITCH_KEY: u8 = 0x19;

/// The shortest terminal line, line ending included, that Linux may have cut short. In canonical mode the terminal keeps
/// at most 4095 bytes of a line and silently discards the rest up to the newline, so a line that reaches this length
/// may not be what the owner typed.
const TERMINAL_LINE_LIMIT: usize = 4095;

/// Why no owner input was collected. The messages never hold what was typed.
#[derive(Debug, thiserror::Error)]
pub enum InputError {
    /// The input ended before a line.
    #[error("the input ended before a value was given")]
    NoInput,
    /// The value is longer than a frame body may be.
    #[error("the value is longer than {MAX_BODY_LEN} bytes, so it was not sent")]
    TooLong,
    /// The line typed at the terminal reached the terminal's line limit, so it may have been cut short.
    #[error(
        "the value typed at the terminal reached the terminal's limit of {TERMINAL_LINE_LIMIT} bytes a line, so it may \
         have been cut short and was not sent; pipe longer values through stdin"
    )]
    TerminalLineTooLong,
    /// The terminal could not be opened, written or switched.
    #[error("cannot use the terminal: {0}")]
    Terminal(io::Error),
    /// Reading the value failed.
    #[error("cannot read the value: {0}")]
    Read(io::Error),
    /// A notice from the service could not be shown.
    #[error("cannot show the service's notice: {0}")]
    Notice(io::Error),
    /// A reveal was sent, and there is no controlling terminal to show it on.
    #[error("the service sent a secret value, which is shown only on a terminal, and there is none: {0}")]
    NoTerminal(io::Error),
    /// A revealed value holds a byte outside printable ASCII, so none of it was shown.
    #[error("the service sent a secret value that is not printable text, so it was not shown")]
    UnprintableReveal,
    /// A revealed value could not be written to the terminal.
    #[error("cannot show the service's secret value: {0}")]
    Reveal(io::Error),
    /// The signal watcher could not be started, so a signal would end the command without restoring the terminal or
    /// giving the owner's advice.
    #[error("cannot watch for signals: {0}")]
    Signals(io::Error),
}

/// Collects one value from the owner for each prompt, and shows the owner each notice and reveal.
pub trait OwnerConsole {
    /// Shows the prompt's label and reads one value, never offering a switch.
    fn collect(&mut self, prompt: &Prompt) -> Result<OwnerInput, InputError>;

    /// Answers the prompt: a value, or a switch when the prompt is switchable and the owner asks for the next approver.
    /// Only a terminal offers the switch; elsewhere this is [`Self::collect`].
    fn answer(&mut self, prompt: &Prompt) -> Result<PromptAnswer, InputError> {
        self.collect(prompt).map(PromptAnswer::OwnerInput)
    }

    /// Shows a notice's text, after the text of the notice before it.
    fn notice(&mut self, text: &str) -> Result<(), InputError>;

    /// Shows a revealed value, then `\n`, then the value as a QR code, on the controlling terminal and nowhere else. A value with a byte outside
    /// printable ASCII is refused and nothing of it is shown.
    fn reveal(&mut self, secret: &RevealedSecret) -> Result<(), InputError>;
}

/// What the owner must be told if a signal ends the command now, such as what to do with a recovery key already shown.
/// Process-wide, because the signal watcher that ends the process is.
static SIGNAL_ADVICE: Mutex<Option<String>> = Mutex::new(None);

/// Sets what the signal watcher tells the owner on stderr if a signal ends the command from now on.
pub fn set_signal_advice(advice: Option<String>) {
    *SIGNAL_ADVICE.lock().unwrap_or_else(PoisonError::into_inner) = advice;
}

/// What the signal watcher tells the owner if a signal ends the command now.
pub(super) fn signal_advice() -> Option<String> {
    SIGNAL_ADVICE.lock().unwrap_or_else(PoisonError::into_inner).clone()
}

/// Checks that the controlling terminal opens, for a command that will reveal a secret, before it sends its request.
pub fn ensure_terminal() -> io::Result<()> {
    tty::open_for_reveal().map(drop)
}

/// The process's console, opened at the first prompt, notice or reveal, so a command the service never prompts for
/// touches neither the terminal nor stdin.
#[derive(Default)]
pub struct ProcessConsole(Option<Box<dyn OwnerConsole>>);

impl ProcessConsole {
    fn console(&mut self) -> Result<&mut Box<dyn OwnerConsole>, InputError> {
        let console = match self.0.take() {
            Some(console) => console,
            None => open()?,
        };
        Ok(self.0.insert(console))
    }
}

impl OwnerConsole for ProcessConsole {
    fn collect(&mut self, prompt: &Prompt) -> Result<OwnerInput, InputError> {
        self.console()?.collect(prompt)
    }

    fn answer(&mut self, prompt: &Prompt) -> Result<PromptAnswer, InputError> {
        self.console()?.answer(prompt)
    }

    fn notice(&mut self, text: &str) -> Result<(), InputError> {
        self.console()?.notice(text)
    }

    fn reveal(&mut self, secret: &RevealedSecret) -> Result<(), InputError> {
        self.console()?.reveal(secret)
    }
}

/// Opens the console and starts the signal watcher, in either mode.
fn open() -> Result<Box<dyn OwnerConsole>, InputError> {
    let console = open_mode()?;
    signals::watch()?;
    Ok(console)
}

/// The terminal when stdin is one; otherwise stdin itself, so a piped value (`pass show fx | sudo iron-vault add fx`)
/// is read from the pipe even when the shell has a terminal.
fn open_mode() -> Result<Box<dyn OwnerConsole>, InputError> {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return Ok(Box::new(tty::open()?));
    }
    // A handle of its own on stdin, because `io::Stdin` reads through a buffer that is never cleared.
    let raw = stdin.as_fd().try_clone_to_owned().map_err(InputError::Read)?;
    Ok(Box::new(Piped::new(File::from(raw), io::stderr().is_terminal())))
}

/// Reads each value as the next line of `input`. A label goes to stderr, and only when stderr is a terminal, so it
/// never mixes into output a script reads. A notice always goes to stderr, so a scripted approval still records the
/// summary it approved. A reveal goes to the controlling terminal, opened for it, and never to stderr, which a script
/// may capture.
pub struct Piped<R, W = io::Stderr, O = fn() -> io::Result<File>> {
    input: R,
    show_labels: bool,
    notices: W,
    open_tty: O,
}

impl<R: Read> Piped<R> {
    /// Reads values from `input`, showing labels on stderr when `show_labels` is set.
    pub fn new(input: R, show_labels: bool) -> Self {
        Self {
            input,
            show_labels,
            notices: io::stderr(),
            open_tty: tty::open_for_reveal,
        }
    }
}

impl<R: Read, W: Write, O: FnMut() -> io::Result<T>, T: Write> OwnerConsole for Piped<R, W, O> {
    fn collect(&mut self, prompt: &Prompt) -> Result<OwnerInput, InputError> {
        if self.show_labels {
            eprint!("{}: ", printable(&prompt.label));
        }
        let line = read_line(&mut self.input);
        if self.show_labels {
            eprintln!();
        }
        line.map(OwnerInput::new)
    }

    fn notice(&mut self, text: &str) -> Result<(), InputError> {
        self.notices
            .write_all(printable_notice(text).as_bytes())
            .and_then(|()| self.notices.flush())
            .map_err(InputError::Notice)
    }

    fn reveal(&mut self, secret: &RevealedSecret) -> Result<(), InputError> {
        let value = printable_reveal(secret)?;
        let mut tty = (self.open_tty)().map_err(InputError::NoTerminal)?;
        write_reveal(&mut tty, value)
    }
}

/// Turns terminal echo off and back on. A trait, so the guard that restores it is tested without a terminal.
pub trait EchoControl {
    /// Turns echo off, and when `switch_key` is set also makes [`SWITCH_KEY`] end a line, as Enter does.
    fn echo_off(&self, switch_key: bool) -> io::Result<()>;
    /// Restores the terminal as it was before [`Self::echo_off`]; restoring twice does nothing more.
    fn restore(&self) -> io::Result<()>;
}

/// Keeps echo off while it lives, and restores the terminal when dropped, on every path out of the read.
struct EchoOff<'a, E: EchoControl>(&'a E);

impl<'a, E: EchoControl> EchoOff<'a, E> {
    fn new(control: &'a E, switch_key: bool) -> Result<Self, InputError> {
        control.echo_off(switch_key).map_err(InputError::Terminal)?;
        Ok(Self(control))
    }
}

impl<E: EchoControl> Drop for EchoOff<'_, E> {
    fn drop(&mut self) {
        if let Err(e) = self.0.restore() {
            eprintln!("iron-vault: cannot turn terminal echo back on ({e}); run `stty echo`");
        }
    }
}

/// Shows labels on and reads values from a terminal, with echo off while the owner types a secret.
pub struct Terminal<T, E> {
    tty: T,
    echo: E,
}

impl<T: Read + Write, E: EchoControl> Terminal<T, E> {
    /// Prompts on `tty`, switching echo through `echo`.
    pub fn new(tty: T, echo: E) -> Self {
        Self { tty, echo }
    }

    /// Writes `label` and `: ` and flushes them, so the owner sees the prompt before the read starts.
    fn show_label(&mut self, label: &str) -> Result<(), InputError> {
        write!(self.tty, "{label}: ")
            .and_then(|()| self.tty.flush())
            .map_err(InputError::Terminal)
    }

    /// Reads a switchable prompt's line with echo off and Ctrl-Y ending a line. A line ending in Ctrl-Y asks to switch:
    /// what was typed before it is cleared, never sent, and the owner's cursor moves to a new line.
    fn switchable(&mut self, prompt: &Prompt) -> Result<PromptAnswer, InputError> {
        self.show_label(&format!("{} (Ctrl-Y to try another way)", printable(&prompt.label)))?;
        let line = {
            let _echo_off = EchoOff::new(&self.echo, true)?;
            read_raw_line(&mut self.tty, Some(SWITCH_KEY))?
        };
        if line.last() == Some(&SWITCH_KEY) {
            // Dropping the line clears it.
            drop(line);
            self.tty
                .write_all(b"\n")
                .and_then(|()| self.tty.flush())
                .map_err(InputError::Terminal)?;
            return Ok(PromptAnswer::Switch);
        }
        terminal_value(line).map(PromptAnswer::OwnerInput)
    }
}

impl<T: Read + Write, E: EchoControl> OwnerConsole for Terminal<T, E> {
    fn collect(&mut self, prompt: &Prompt) -> Result<OwnerInput, InputError> {
        self.show_label(&printable(&prompt.label))?;
        let line = if prompt.secret {
            let _echo_off = EchoOff::new(&self.echo, false)?;
            read_raw_line(&mut self.tty, None)
        } else {
            read_raw_line(&mut self.tty, None)
        }?;
        terminal_value(line)
    }

    fn answer(&mut self, prompt: &Prompt) -> Result<PromptAnswer, InputError> {
        if prompt.switchable {
            return self.switchable(prompt);
        }
        self.collect(prompt).map(PromptAnswer::OwnerInput)
    }

    fn notice(&mut self, text: &str) -> Result<(), InputError> {
        self.tty
            .write_all(printable_notice(text).as_bytes())
            .and_then(|()| self.tty.flush())
            .map_err(InputError::Notice)
    }

    fn reveal(&mut self, secret: &RevealedSecret) -> Result<(), InputError> {
        write_reveal(&mut self.tty, printable_reveal(secret)?)
    }
}

/// The value of a line read at the terminal, refused when it reached the terminal's line limit.
fn terminal_value(line: Zeroizing<Vec<u8>>) -> Result<OwnerInput, InputError> {
    if line.len() >= TERMINAL_LINE_LIMIT {
        return Err(InputError::TerminalLineTooLong);
    }
    strip_ending(line).map(OwnerInput::new)
}

/// The label without control characters, so a label cannot move the cursor or reprogram the terminal.
fn printable(label: &str) -> String {
    label.chars().filter(|c| !c.is_control()).collect()
}

/// A notice's text without control characters other than `\n`, which ends its lines.
fn printable_notice(text: &str) -> String {
    text.chars().filter(|c| *c == '\n' || !c.is_control()).collect()
}

/// The revealed value, when every byte of it is printable ASCII. Removing the other bytes instead would show the owner a
/// value that differs from the secret, which they would save in good faith; a terminal control byte could also hide or
/// rewrite what is shown.
fn printable_reveal(secret: &RevealedSecret) -> Result<&[u8], InputError> {
    let value = secret.expose_secret();
    value
        .iter()
        .all(|byte| *byte == b' ' || byte.is_ascii_graphic())
        .then_some(value)
        .ok_or(InputError::UnprintableReveal)
}

/// Writes `value` and then `\n` straight to `tty`, so the text passes through no other buffer, and then the same value as a
/// QR code on the same `tty`, so the owner can scan it into a password manager instead of retyping it.
fn write_reveal(tty: &mut impl Write, value: &[u8]) -> Result<(), InputError> {
    tty.write_all(value)
        .and_then(|()| tty.write_all(b"\n"))
        .and_then(|()| write_qr(tty, value))
        .and_then(|()| tty.flush())
        .map_err(InputError::Reveal)
}

/// Draws `value` as a QR code, two module rows to a text line, with a quiet zone, at error-correction level M. A value
/// too long for any QR code gets a one-line note instead, because the text above it is already shown.
///
/// The drawing holds the value, so it is overwritten before it is dropped. The library's own module buffers are not
/// cleared (`design/secret-handling.md`).
fn write_qr(tty: &mut impl Write, value: &[u8]) -> io::Result<()> {
    let Ok(code) = QrCode::with_error_correction_level(value, EcLevel::M) else {
        return tty.write_all(b"(too long for a QR code)\n");
    };
    let drawing = Zeroizing::new(code.render::<Dense1x2>().quiet_zone(true).build());
    drop(code);
    tty.write_all(drawing.as_bytes()).and_then(|()| tty.write_all(b"\n"))
}

/// Reads one line and strips one trailing `\n` and a `\r` before it. A last line without `\n` is still a value; input
/// that ends before any byte is not.
fn read_line(input: &mut impl Read) -> Result<Zeroizing<Vec<u8>>, InputError> {
    read_raw_line(input, None).and_then(strip_ending)
}

/// Reads one line, keeping its line ending: `\n`, or `also_ends` when given.
///
/// Bytes are read one at a time straight into a clearing buffer sized for the longest line, so nothing past the line is
/// consumed, no other buffer holds the value, and the buffer never reallocates and leaves a copy behind.
fn read_raw_line(input: &mut impl Read, also_ends: Option<u8>) -> Result<Zeroizing<Vec<u8>>, InputError> {
    let mut line = Zeroizing::new(Vec::with_capacity(LINE_CAPACITY));
    loop {
        match read_byte(input, &mut line)? {
            None if line.is_empty() => return Err(InputError::NoInput),
            None | Some(b'\n') => return Ok(line),
            Some(byte) if Some(byte) == also_ends => return Ok(line),
            // Without its `\n` the line already holds more than the longest value and a `\r`.
            Some(_) if line.len() >= LINE_CAPACITY => return Err(InputError::TooLong),
            Some(_) => {}
        }
    }
}

/// Strips one trailing `\n` and a `\r` before it, in place, and refuses a value longer than a frame body may be.
fn strip_ending(mut line: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, InputError> {
    if line.last() == Some(&b'\n') {
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
    }
    if line.len() > MAX_BODY_LEN {
        return Err(InputError::TooLong);
    }
    Ok(line)
}

/// Reads one byte onto the end of `line`, returning it, or `None` at the end of the input.
fn read_byte(input: &mut impl Read, line: &mut Vec<u8>) -> Result<Option<u8>, InputError> {
    let at = line.len();
    line.push(0);
    loop {
        match line.get_mut(at..).map_or(Ok(0), |slot| input.read(slot)) {
            Ok(0) => {
                line.truncate(at);
                return Ok(None);
            }
            Ok(_) => return Ok(line.last().copied()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                line.truncate(at);
                return Err(InputError::Read(e));
            }
        }
    }
}

#[cfg(test)]
mod tests;
