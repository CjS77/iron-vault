// SPDX-License-Identifier: MPL-2.0
//! `iron-vault completions SHELL`: the shell completion script, generated from the same [`Cli`] the parser uses so the
//! two cannot drift. It reads nothing from the service, so a packaging script can run it at build time.

use std::io::{self, Write};

use clap::CommandFactory;
use clap_complete::Shell;

use super::{Cli, CompletionShell};

/// Why the completion script could not be written.
#[derive(Debug, thiserror::Error)]
pub enum CompletionsError {
    /// Writing to stdout failed, for example because the reader closed the pipe.
    #[error("cannot write the completion script: {0}")]
    Write(#[from] io::Error),
}

impl From<CompletionShell> for Shell {
    fn from(shell: CompletionShell) -> Self {
        match shell {
            CompletionShell::Bash => Shell::Bash,
        }
    }
}

/// The completion script for `shell`. `clap_complete::generate` panics when its writer fails, so it writes to memory
/// and the caller does the fallible I/O.
pub(super) fn script(shell: CompletionShell) -> Vec<u8> {
    let mut buf = Vec::new();
    clap_complete::generate(Shell::from(shell), &mut Cli::command(), "iron-vault", &mut buf);
    buf
}

/// Writes the completion script for `shell` to stdout.
pub fn completions(shell: CompletionShell) -> Result<(), CompletionsError> {
    write_script(&mut io::stdout().lock(), shell)
}

/// Writes the completion script for `shell` to `out` and flushes it.
pub(super) fn write_script(out: &mut impl Write, shell: CompletionShell) -> Result<(), CompletionsError> {
    out.write_all(&script(shell))?;
    Ok(out.flush()?)
}
