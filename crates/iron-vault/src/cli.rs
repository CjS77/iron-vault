//! The command line: one parser for running the service (`serve`) and for the thin CLI's commands (spec §3.2).
//!
//! The CLI only sends commands to the service over the admin socket and shows the answers. It never opens vault files,
//! calls a TPM or edits policy (§3.1): the service owns every operation, and judges whoever connects, including over
//! a socket forwarded with `--admin-socket`.
//!
//! **No argument ever takes a secret value.** Arguments end up in shell history, process listings and diagnostics,
//! where a prompted value must never appear (§3.2). A command that needs a secret has the service prompt for it over
//! the admin protocol, and the CLI reads it from the terminal or stdin. Diagnostics never echo a request's arguments
//! either.

// The client's terminal handling uses rustix and tokio, which this crate depends on only on Linux.
#[cfg(target_os = "linux")]
mod client;
#[cfg(target_os = "linux")]
mod console;
#[cfg(target_os = "linux")]
mod status;

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::LazyLock;

use clap::builder::TypedValueParser;
use clap::error::ErrorKind;
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use iron_vault::admin::protocol::MAX_ORIGINS;
use iron_vault::deployment;
use iron_vault_policy::{CredentialKind, Host, Port, parse_origin};

/// `--version` prints the binary's name, then this: the version and the enabled build features. A release check reads
/// the feature list, so it must come from the same place as the service's own report.
static VERSION: LazyLock<String> = LazyLock::new(deployment::version);

/// The `--help` epilogue. Scripts act on these numbers, so they are part of the interface.
const EXIT_CODES: &str = "\
Exit codes:
  0  success
  1  the service answered with an error
  2  usage error
  3  no answer from the service: it is not running, this account may not connect, the exchange failed, or a prompt
     got no value
  4  `status`: the service answered, and it is not Ready";

/// The exit statuses listed in [`EXIT_CODES`]. Usage errors exit through clap, with its status 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// The command succeeded.
    Success = 0,
    /// The service answered with an error response.
    CommandError = 1,
    /// No admin response came back.
    Unreachable = 3,
    /// `status` reached the service, which is in a state other than Ready.
    NotReady = 4,
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
#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum Command {
    /// Run the service until SIGTERM or SIGINT.
    Serve,
    /// Check that the service is running and show its deployment profile.
    Ping,
    /// Show the service, vault, approval, memory protection and credential states, without secrets.
    Status,
    /// Open the vault: the service prompts for the vault passphrase, read with echo off or from stdin.
    Unlock,
    /// Clear the vault identity and every cached secret from the service's memory, leaving it Locked.
    Lock,
    /// Enrol a new credential under NAME; the service prompts for the secret, read with echo off or from stdin, so
    /// `pass show fx | iron-vault add fx --origin api.fx.example` works. It never overwrites an existing name.
    Add {
        /// The credential name, which routes reference.
        name: String,
        /// The credential's kind: a static key, or a Basic username and password.
        #[arg(long, value_enum, default_value_t = KindArg::Static)]
        kind: KindArg,
        /// A permitted origin: `host`, `host:port`, `[v6]` or `[v6]:port`, without a scheme (HTTPS is implied); the port
        /// defaults to 443. Repeat for each origin, up to 32.
        #[arg(long = "origin", value_name = "ORIGIN", required = true, value_parser = OriginParser)]
        origins: Vec<(Host, Port)>,
    },
}

/// The credential kinds `add --kind` names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum KindArg {
    /// A provider key, sent as is.
    Static,
    /// A username and password, sent as `Authorization: Basic`.
    Basic,
}

impl From<KindArg> for CredentialKind {
    fn from(kind: KindArg) -> Self {
        match kind {
            KindArg::Static => CredentialKind::Static,
            KindArg::Basic => CredentialKind::Basic,
        }
    }
}

/// Parses `--origin` with the service's own origin rule. Its usage error names the rule and never the value, because
/// diagnostics never echo arguments.
#[derive(Debug, Clone, Copy)]
struct OriginParser;

impl TypedValueParser for OriginParser {
    type Value = (Host, Port);

    fn parse_ref(&self, cmd: &clap::Command, _arg: Option<&clap::Arg>, value: &OsStr) -> Result<Self::Value, clap::Error> {
        let rule = match value.to_str().map(parse_origin) {
            Some(Ok(origin)) => return Ok(origin),
            Some(Err(e)) => e.to_string(),
            None => "an origin must be UTF-8 text".to_owned(),
        };
        Err(cmd.clone().error(ErrorKind::ValueValidation, format!("invalid --origin: {rule}")))
    }
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
        match (&cli.command, &cli.admin_socket) {
            (Command::Serve, Some(_)) => Err(Self::command().error(
                ErrorKind::ArgumentConflict,
                "`--admin-socket` is for client commands; `serve` always binds this installation's admin socket",
            )),
            (Command::Add { origins, .. }, _) if origins.len() > MAX_ORIGINS => Err(Self::command().error(
                ErrorKind::TooManyValues,
                format!("`add` takes at most {MAX_ORIGINS} --origin values"),
            )),
            _ => Ok(cli),
        }
    }
}

/// `iron-vault ping`: sends `ping` to the admin socket at `socket`, or this installation's, and shows the answer.
#[cfg(target_os = "linux")]
pub fn ping(socket: Option<&Path>) -> ExitCode {
    client::ping(socket).into()
}

/// `iron-vault status`: sends `status` and prints the report; exits 0 only when the service is Ready.
#[cfg(target_os = "linux")]
pub fn status(socket: Option<&Path>) -> ExitCode {
    client::status(socket).into()
}

/// `iron-vault unlock`: sends `unlock` to the admin socket at `socket`, or this installation's, answers the passphrase
/// prompt, and shows the state the service settled in.
#[cfg(target_os = "linux")]
pub fn unlock(socket: Option<&Path>) -> ExitCode {
    client::unlock(socket).into()
}

/// The client is Linux-only for now, like the service.
#[cfg(not(target_os = "linux"))]
pub fn unlock(_socket: Option<&Path>) -> ExitCode {
    unsupported_platform()
}

/// `iron-vault lock`: sends `lock` to the admin socket at `socket`, or this installation's, and shows the new state.
#[cfg(target_os = "linux")]
pub fn lock(socket: Option<&Path>) -> ExitCode {
    client::lock(socket).into()
}

/// `iron-vault add`: sends `add` with the name, kind and origins, answers the service's secret prompts from the owner
/// console, and prints the new record's ID.
#[cfg(target_os = "linux")]
pub fn add(socket: Option<&Path>, name: String, kind: CredentialKind, origins: &[(Host, Port)]) -> ExitCode {
    client::add(socket, name, kind, origins).into()
}

/// The client is Linux-only for now, like the service.
#[cfg(not(target_os = "linux"))]
pub fn add(_socket: Option<&Path>, _name: String, _kind: CredentialKind, _origins: &[(Host, Port)]) -> ExitCode {
    unsupported_platform()
}

/// The client is Linux-only for now, like the service.
#[cfg(not(target_os = "linux"))]
pub fn ping(_socket: Option<&Path>) -> ExitCode {
    unsupported_platform()
}

/// The client is Linux-only for now, like the service.
#[cfg(not(target_os = "linux"))]
pub fn lock(_socket: Option<&Path>) -> ExitCode {
    unsupported_platform()
}

#[cfg(not(target_os = "linux"))]
fn unsupported_platform() -> ExitCode {
    eprintln!("iron-vault: client commands are not supported on this platform yet");
    Exit::Unreachable.into()
}

/// The client is Linux-only for now, like the service.
#[cfg(not(target_os = "linux"))]
pub fn status(_socket: Option<&Path>) -> ExitCode {
    unsupported_platform()
}

#[cfg(test)]
mod tests;
