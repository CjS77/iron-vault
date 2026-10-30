//! The command line: one parser for running the service (`serve`) and for the thin CLI's commands (spec §3.2).
//!
//! The CLI only sends commands to the service over the admin socket and shows the answers. It never opens vault files,
//! calls a TPM or edits policy (§3.1): the service owns every operation, and judges whoever connects, including over
//! a socket forwarded with `--admin-socket`.
//!
//! **No argument ever takes a secret value.** Arguments end up in shell history, process listings and diagnostics,
//! where a prompted value must never appear (§3.2). A command that needs a secret has the service prompt for it over
//! the admin protocol, and the CLI reads it from the terminal. Diagnostics never echo a request's arguments either.

#[cfg(unix)]
mod client;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::LazyLock;

use clap::error::ErrorKind;
use clap::{CommandFactory, Parser, Subcommand};
use iron_vault::deployment;

/// `--version` prints the binary's name, then this: the version and the enabled build features. A release check reads
/// the feature list, so it must come from the same place as the service's own report.
static VERSION: LazyLock<String> = LazyLock::new(deployment::version);

/// The `--help` epilogue. Scripts act on these numbers, so they are part of the interface.
const EXIT_CODES: &str = "\
Exit codes:
  0  success
  1  the service answered with an error
  2  usage error
  3  no answer from the service: it is not running, this account may not connect, or the exchange failed";

/// The exit statuses listed in [`EXIT_CODES`]. Usage errors exit through clap, with its status 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// The command succeeded.
    Success = 0,
    /// The service answered with an error response.
    CommandError = 1,
    /// No admin response came back.
    Unreachable = 3,
}

impl From<Exit> for ExitCode {
    fn from(exit: Exit) -> Self {
        Self::from(exit as u8)
    }
}

/// Iron Vault: a local proxy that holds API credentials so the programs that use them never do.
#[derive(Debug, Parser)]
#[command(
    name = "iron-vault",
    version = VERSION.as_str(),
    after_help = EXIT_CODES,
    subcommand_required = true,
    arg_required_else_help = true
)]
pub struct Cli {
    /// Use the admin socket at PATH instead of this installation's, for example one forwarded over SSH.
    #[arg(long, global = true, value_name = "PATH")]
    pub admin_socket: Option<PathBuf>,
    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// The binary's commands: the service itself, and the client commands it answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Subcommand)]
pub enum Command {
    /// Run the service until SIGTERM or SIGINT.
    Serve,
    /// Check that the service is running and show its deployment profile.
    Ping,
}

impl Cli {
    /// Parses the process's arguments; a usage error, `--help` or `--version` prints and exits as clap does.
    pub fn parse_args() -> Self {
        Self::try_from_args(std::env::args_os()).unwrap_or_else(|e| e.exit())
    }

    /// Parses `args`, whose first item is the binary's name.
    pub fn try_from_args<I, T>(args: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        let cli = Self::try_parse_from(args)?;
        // The service binds its deployment's own socket; accepting the flag there would only mislead.
        match (cli.command, &cli.admin_socket) {
            (Command::Serve, Some(_)) => Err(Self::command().error(
                ErrorKind::ArgumentConflict,
                "`--admin-socket` is for client commands; `serve` always binds this installation's admin socket",
            )),
            _ => Ok(cli),
        }
    }
}

/// `iron-vault ping`: sends `ping` to the admin socket at `socket`, or this installation's, and shows the answer.
#[cfg(unix)]
pub fn ping(socket: Option<&Path>) -> ExitCode {
    client::ping(socket).into()
}

/// The client needs Unix sockets.
#[cfg(not(unix))]
pub fn ping(_socket: Option<&Path>) -> ExitCode {
    eprintln!("iron-vault: client commands are not supported on this platform yet");
    Exit::Unreachable.into()
}

#[cfg(test)]
mod tests;
