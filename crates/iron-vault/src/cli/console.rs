//! The owner console: where the CLI collects owner input for the service's prompts (`design/admin-protocol.md`, "Owner
//! input").
//!
//! Each value goes from the input straight into a clearing buffer, and from there into one owner-input frame. It never
//! passes through `String`, formatting, `Debug` or a log call, and no error names a byte of it.

mod tty;

use std::fs::File;
use std::io::{self, IsTerminal, Read, Write};
use std::os::fd::AsFd;

use iron_vault::admin::protocol::{MAX_BODY_LEN, OwnerInput, Prompt};
use zeroize::Zeroizing;

/// The longest line a value may arrive in: the longest value, then `\r\n`.
const LINE_CAPACITY: usize = MAX_BODY_LEN + 2;

/// Why no owner input was collected. The messages never hold what was typed.
#[derive(Debug, thiserror::Error)]
pub enum InputError {
    /// The input ended before a line.
    #[error("the input ended before a value was given")]
    NoInput,
    /// The value is longer than a frame body may be.
    #[error("the value is longer than {MAX_BODY_LEN} bytes, so it was not sent")]
    TooLong,
    /// The terminal could not be opened, written or switched.
    #[error("cannot use the terminal: {0}")]
    Terminal(io::Error),
    /// Reading the value failed.
    #[error("cannot read the value: {0}")]
    Read(io::Error),
}

/// Collects one value from the owner for each prompt.
pub trait OwnerConsole {
    /// Shows the prompt's label and reads one value.
    fn collect(&mut self, prompt: &Prompt) -> Result<OwnerInput, InputError>;
}

/// The process's console, opened at the first prompt, so a command the service never prompts for touches neither the
/// terminal nor stdin.
#[derive(Default)]
pub struct ProcessConsole(Option<Box<dyn OwnerConsole>>);

impl OwnerConsole for ProcessConsole {
    fn collect(&mut self, prompt: &Prompt) -> Result<OwnerInput, InputError> {
        let console = match &mut self.0 {
            Some(console) => console,
            None => self.0.insert(open()?),
        };
        console.collect(prompt)
    }
}

/// The terminal when stdin is one; otherwise stdin itself, so a piped value (`pass show fx | sudo iron-vault add fx`)
/// is read from the pipe even when the shell has a terminal.
fn open() -> Result<Box<dyn OwnerConsole>, InputError> {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return Ok(Box::new(tty::open()?));
    }
    // A handle of its own on stdin, because `io::Stdin` reads through a buffer that is never cleared.
    let raw = stdin.as_fd().try_clone_to_owned().map_err(InputError::Read)?;
    Ok(Box::new(Piped::new(File::from(raw), io::stderr().is_terminal())))
}

/// Reads each value as the next line of `input`. A label goes to stderr, and only when stderr is a terminal, so it
/// never mixes into output a script reads.
pub struct Piped<R> {
    input: R,
    show_labels: bool,
}

impl<R: Read> Piped<R> {
    /// Reads values from `input`, showing labels on stderr when `show_labels` is set.
    pub fn new(input: R, show_labels: bool) -> Self {
        Self { input, show_labels }
    }
}

impl<R: Read> OwnerConsole for Piped<R> {
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
}

/// Turns terminal echo off and back on. A trait, so the guard that restores it is tested without a terminal.
pub trait EchoControl {
    /// Turns echo off.
    fn echo_off(&self) -> io::Result<()>;
    /// Restores the terminal as it was before [`Self::echo_off`]; restoring twice does nothing more.
    fn restore(&self) -> io::Result<()>;
}

/// Keeps echo off while it lives, and restores the terminal when dropped, on every path out of the read.
struct EchoOff<'a, E: EchoControl>(&'a E);

impl<'a, E: EchoControl> EchoOff<'a, E> {
    fn new(control: &'a E) -> Result<Self, InputError> {
        control.echo_off().map_err(InputError::Terminal)?;
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
}

impl<T: Read + Write, E: EchoControl> OwnerConsole for Terminal<T, E> {
    fn collect(&mut self, prompt: &Prompt) -> Result<OwnerInput, InputError> {
        write!(self.tty, "{}: ", printable(&prompt.label))
            .and_then(|()| self.tty.flush())
            .map_err(InputError::Terminal)?;
        let line = if prompt.secret {
            let _echo_off = EchoOff::new(&self.echo)?;
            read_line(&mut self.tty)
        } else {
            read_line(&mut self.tty)
        };
        line.map(OwnerInput::new)
    }
}

/// The label without control characters, so a label cannot move the cursor or reprogram the terminal.
fn printable(label: &str) -> String {
    label.chars().filter(|c| !c.is_control()).collect()
}

/// Reads one line and strips one trailing `\n` and a `\r` before it. A last line without `\n` is still a value; input
/// that ends before any byte is not.
///
/// Bytes are read one at a time straight into a clearing buffer sized for the longest line, so nothing past the line is
/// consumed, no other buffer holds the value, and the buffer never reallocates and leaves a copy behind.
fn read_line(input: &mut impl Read) -> Result<Zeroizing<Vec<u8>>, InputError> {
    let mut line = Zeroizing::new(Vec::with_capacity(LINE_CAPACITY));
    let ended = loop {
        match read_byte(input, &mut line)? {
            None => break false,
            Some(b'\n') => break true,
            // Without its `\n` the line already holds more than the longest value and a `\r`.
            Some(_) if line.len() >= LINE_CAPACITY => return Err(InputError::TooLong),
            Some(_) => {}
        }
    };
    if !ended && line.is_empty() {
        return Err(InputError::NoInput);
    }
    if ended {
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
