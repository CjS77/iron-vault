//! The command line: one parser for running the service (`serve`) and for the thin CLI's commands (spec §5).
//!
//! The CLI only sends commands to the service over the admin socket and shows the answers. It never opens vault files,
//! calls a TPM or edits policy (§4): the service owns every operation, and judges whoever connects, including over
//! a socket forwarded with `--admin-socket`.
//!
//! **No argument ever takes a secret value.** Arguments end up in shell history, process listings and diagnostics,
//! where a prompted value must never appear (§5). A command that needs a secret has the service prompt for it over
//! the admin protocol, and the CLI reads it from the terminal or stdin. Diagnostics never echo a request's arguments
//! either.

// The client's terminal handling uses rustix and tokio, which this crate depends on only on Linux.
#[cfg(target_os = "linux")]
mod caller_token;
#[cfg(target_os = "linux")]
mod client;
mod completions;
pub use completions::completions;
#[cfg(target_os = "linux")]
mod console;
#[cfg(target_os = "linux")]
mod init;
#[cfg(target_os = "linux")]
mod list;
// Generates the Linux package's man pages; test-only, so the release binary carries none of it.
#[cfg(test)]
mod man_page;
#[cfg(target_os = "linux")]
mod recipient_add_recovery;
#[cfg(target_os = "linux")]
mod recipient_list;
// Generates the book's command reference; test-only, so the release binary carries none of it.
#[cfg(test)]
mod reference;
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
  3  no answer from the service: it is not running, this account may not connect, the exchange failed, a prompt
     got no value, or a secret value the service sent could not be shown on a terminal
  4  `status`: the service answered, and it is not Ready; `list`: no vault is open, so the credentials are unknown";

/// The exit statuses listed in [`EXIT_CODES`]. Usage errors exit through clap, with its status 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// The command succeeded.
    Success = 0,
    /// The service answered with an error response.
    CommandError = 1,
    /// The command was refused before anything was sent, such as a config file over the size limit.
    Usage = 2,
    /// No admin response came back.
    Unreachable = 3,
    /// `status` reached the service, which is in a state other than Ready; or `list` reached it with no vault open.
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
    /// Use the admin socket at PATH instead of this installation's, for example one forwarded over SSH. Every client
    /// command takes it; `serve` refuses it, because the service always binds its own installation's socket.
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
    ///
    /// In a protected installation systemd starts it as the `iron-vault` service account, so you never run it yourself.
    /// It starts Locked: run `unlock` after each start.
    Serve {
        /// Write the log to stdout until an approved config names a destination, as the Docker image does. The service
        /// refuses it when stdout is the systemd journal.
        #[arg(long)]
        log_to_stdout: bool,
    },
    /// Check that the service is running and show its deployment profile.
    Ping,
    /// Show the service, vault, approval, memory protection and credential states, without secrets. It exits 4 when
    /// the service answers and is not Ready.
    Status,
    /// List every credential with its kind, permitted origins and standing, never a secret. It needs an open vault,
    /// and exits 4 while none is open.
    List,
    /// Open the vault: the service prompts for the vault passphrase, read with echo off or from stdin.
    Unlock,
    /// Clear the vault identity and every cached secret from the service's memory, leaving it Locked.
    Lock,
    /// Create the vault: the service prompts for the vault and approval passphrases, shows the recovery key once on the
    /// controlling terminal, and once you confirm you saved it, writes the vault and approves the initial config as
    /// version 1. It needs a controlling terminal, and leaves the service Locked.
    Init {
        /// Also enrol the identity in the unlock handoff as a recipient, so a restart unlocks with no owner present. The
        /// service refuses to start `init` if the handoff is absent or untrusted. Only a Container build accepts this flag.
        #[cfg_attr(feature = "container", arg(long))]
        #[cfg_attr(not(feature = "container"), arg(skip))]
        host_unlock: bool,
    },
    /// Issue a fresh caller token: it goes to stdout once, and its token_hash line to stderr. The service keeps no copy;
    /// the token works once a config naming the hash is approved with `config approve`.
    CallerToken,
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
    /// Replace NAME's record with a new one, and with it the kind and the origins; the old record need not be readable,
    /// so this also repairs a damaged one. The service shows what changes, asks for the approval passphrase as owner
    /// presence, then prompts for the new secret. On stdin, the first line is the approval passphrase and the rest the
    /// secret. Routes that use NAME keep working only if the new kind and origins suit them; otherwise nothing changes.
    Replace {
        /// The credential name.
        name: String,
        /// The new kind: a static key, or a Basic username and password.
        #[arg(long, value_enum, default_value_t = KindArg::Static)]
        kind: KindArg,
        /// A new permitted origin, as for `add`. Repeat for each origin, up to 32; the old origins are not kept.
        #[arg(long = "origin", value_name = "ORIGIN", required = true, value_parser = OriginParser)]
        origins: Vec<(Host, Port)>,
    },
    /// Remove the credential NAME after you type the approval passphrase. It refuses while a route of the active config
    /// uses the name: approve a config without those routes first.
    Rm {
        /// The credential name to remove.
        name: String,
    },
    /// Change the approved configuration.
    #[command(subcommand)]
    Config(ConfigCommand),
    /// Check the owner's offline recovery key.
    #[command(subcommand)]
    Recovery(RecoveryCommand),
    /// Manage the keys that can open the vault.
    #[command(subcommand)]
    Recipient(RecipientCommand),
    /// Print a shell completion script to stdout. It never contacts the service, so it also runs at build time.
    Completions {
        /// The shell to generate the script for.
        #[arg(value_enum)]
        shell: CompletionShell,
    },
}

/// The shells `completions` can generate a script for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CompletionShell {
    /// Bash, through the bash-completion framework.
    Bash,
}

/// The credential kinds `add --kind` and `replace --kind` name.
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

/// `iron-vault config`'s commands.
#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum ConfigCommand {
    /// Propose FILE as the new config: the service shows its summary, asks for confirmation and the approval
    /// passphrase, then commits, publishes and activates it. Stdin is not read for the config, because it carries the
    /// answers to the prompts when it is not a terminal.
    Approve {
        /// The proposed config file.
        file: PathBuf,
    },
}

/// `iron-vault recovery`'s commands.
#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum RecoveryCommand {
    /// Prove that your offline recovery key opens this vault: the service prompts for the key, read with echo off or
    /// from stdin, so `pass show iron-vault-recovery | sudo iron-vault recovery check` works. It works while the service
    /// is Locked or Ready, changes nothing but the time it records, and keeps no copy of the key.
    Check,
}

/// `iron-vault recipient`'s commands.
#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum RecipientCommand {
    /// List every enrolled recipient, one line each: its `age1...` key, role, enrolment time and label. It works while the
    /// service is Ready, and refuses a missing or damaged recipient inventory without changing it.
    List,
    /// Enroll RECIPIENT, an `age1...` public key, as another way to open the vault. This is the alternate migration path:
    /// whoever holds the key can open the vault identity, and with it every credential. The service shows what changes,
    /// then asks for the vault passphrase, which an unlocked vault does not replace. Old copies of `identity.age` are not
    /// affected.
    ///
    /// With --recovery, the service instead generates a new offline recovery key and shows it once, as `init` does; save it,
    /// type yes, then authorize with the vault passphrase. Check it with `recovery check`, then remove the old recovery key
    /// with `recipient remove`.
    ///
    /// With --host-unlock, RECIPIENT is a host unlock identity's key, such as a new one provisioned after a lost TPM. It is
    /// enrolled with the `host-unlock` role and authorized the same way. Once a restart reaches Ready with no `unlock`,
    /// remove the old `host-unlock` recipient with `recipient remove`.
    Add {
        /// The `age1...` public key to enroll.
        #[arg(required_unless_present = "recovery", conflicts_with = "recovery")]
        recipient: Option<String>,
        /// Generate a new recovery key and enroll it, instead of enrolling a key you supply.
        #[arg(long)]
        recovery: bool,
        /// Enroll RECIPIENT as the host unlock identity's recipient, role `host-unlock`, rather than `added`.
        #[arg(long, conflicts_with = "recovery")]
        host_unlock: bool,
        /// Which device or copy the key is, 1 to 64 bytes: `alice laptop 2026`.
        #[arg(long)]
        label: String,
    },
    /// Remove an enrolled recipient by its `age1...` key. The service shows what will change, then asks for the approval
    /// passphrase. It refuses the operational recipient, the last recovery recipient and, in a Docker Compose stack, the
    /// `host-unlock` recipient whose identity the unlock handoff holds. It says that copies of `identity.age` made before
    /// still open with the removed key.
    Remove {
        /// The recipient's `age1...` key, as `recipient list` prints it.
        recipient: String,
    },
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
            (Command::Serve { .. }, Some(_)) => Err(Self::command().error(
                ErrorKind::ArgumentConflict,
                "`--admin-socket` is for client commands; `serve` always binds this installation's admin socket",
            )),
            (Command::Add { origins, .. }, _) if origins.len() > MAX_ORIGINS => Err(too_many_origins("add")),
            (Command::Replace { origins, .. }, _) if origins.len() > MAX_ORIGINS => Err(too_many_origins("replace")),
            _ => Ok(cli),
        }
    }
}

/// The error for more `--origin` values than `command` sends.
fn too_many_origins(command: &str) -> clap::Error {
    Cli::command().error(
        ErrorKind::TooManyValues,
        format!("`{command}` takes at most {MAX_ORIGINS} --origin values"),
    )
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

/// `iron-vault list`: sends `list` and prints one line per credential; exits 4 while no vault is open.
#[cfg(target_os = "linux")]
pub fn list(socket: Option<&Path>) -> ExitCode {
    client::list(socket).into()
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

/// `iron-vault init`: checks for a controlling terminal, sends `init`, answers the service's prompts, shows the
/// recovery key on the terminal only, and prints the new vault's ID.
#[cfg(target_os = "linux")]
pub fn init(socket: Option<&Path>, host_unlock: bool) -> ExitCode {
    init::run(socket, host_unlock).into()
}

/// The client is Linux-only for now, like the service.
#[cfg(not(target_os = "linux"))]
pub fn init(_socket: Option<&Path>, _host_unlock: bool) -> ExitCode {
    unsupported_platform()
}

/// `iron-vault caller-token`: sends `caller-token`, writes the token alone to stdout and its `token_hash` line to stderr.
#[cfg(target_os = "linux")]
pub fn caller_token(socket: Option<&Path>) -> ExitCode {
    caller_token::run(socket).into()
}

/// The client is Linux-only for now, like the service.
#[cfg(not(target_os = "linux"))]
pub fn caller_token(_socket: Option<&Path>) -> ExitCode {
    unsupported_platform()
}

/// `iron-vault add`: sends `add` with the name, kind and origins, answers the service's secret prompts from the owner
/// console, and prints the new record's ID.
#[cfg(target_os = "linux")]
pub fn add(socket: Option<&Path>, name: String, kind: CredentialKind, origins: &[(Host, Port)]) -> ExitCode {
    client::add(socket, name, kind, origins).into()
}

/// `iron-vault replace`: sends `replace` with the name, kind and origins, answers the service's prompts from the owner
/// console, and prints the new record's ID.
#[cfg(target_os = "linux")]
pub fn replace(socket: Option<&Path>, name: String, kind: CredentialKind, origins: &[(Host, Port)]) -> ExitCode {
    client::replace(socket, name, kind, origins).into()
}

/// `iron-vault rm`: sends `rm` with the name, answers the approval passphrase prompt from the owner console, and prints
/// `removed NAME`.
#[cfg(target_os = "linux")]
pub fn rm(socket: Option<&Path>, name: String) -> ExitCode {
    client::rm(socket, name).into()
}

/// `iron-vault config approve FILE`: sends FILE's bytes for approval, answers the service's prompts, and shows the
/// committed version.
#[cfg(target_os = "linux")]
pub fn config_approve(socket: Option<&Path>, file: &Path) -> ExitCode {
    client::config_approve(socket, file).into()
}

/// The client is Linux-only for now, like the service.
#[cfg(not(target_os = "linux"))]
pub fn add(_socket: Option<&Path>, _name: String, _kind: CredentialKind, _origins: &[(Host, Port)]) -> ExitCode {
    unsupported_platform()
}

/// The client is Linux-only for now, like the service.
#[cfg(not(target_os = "linux"))]
pub fn replace(_socket: Option<&Path>, _name: String, _kind: CredentialKind, _origins: &[(Host, Port)]) -> ExitCode {
    unsupported_platform()
}

/// `iron-vault recovery check`: sends `recovery check`, answers the key prompt from the owner console, and prints the
/// vault the key opened and the check time.
#[cfg(target_os = "linux")]
pub fn recovery_check(socket: Option<&Path>) -> ExitCode {
    client::recovery_check(socket).into()
}

/// The client is Linux-only for now, like the service.
#[cfg(not(target_os = "linux"))]
pub fn recovery_check(_socket: Option<&Path>) -> ExitCode {
    unsupported_platform()
}

/// `iron-vault recipient remove`: sends `recipient remove`, answers the approval passphrase prompt from the owner console, and
/// shows the service's notices, which end with what removal does not reach.
#[cfg(target_os = "linux")]
pub fn recipient_remove(socket: Option<&Path>, recipient: String) -> ExitCode {
    client::recipient_remove(socket, recipient).into()
}

/// The client is Linux-only for now, like the service.
#[cfg(not(target_os = "linux"))]
pub fn recipient_remove(_socket: Option<&Path>, _recipient: String) -> ExitCode {
    unsupported_platform()
}

/// `iron-vault recipient list`: sends `recipient list` and prints one line per enrolled recipient.
#[cfg(target_os = "linux")]
pub fn recipient_list(socket: Option<&Path>) -> ExitCode {
    client::recipient_list(socket).into()
}

/// `iron-vault recipient add`: sends `recipient add`, answers the vault passphrase prompt from the owner console, and
/// leaves the completion notice to stderr.
#[cfg(target_os = "linux")]
pub fn recipient_add(socket: Option<&Path>, recipient: String, label: String, host_unlock: bool) -> ExitCode {
    client::recipient_add(socket, recipient, label, host_unlock).into()
}

/// `iron-vault recipient add --recovery`: sends `recipient add` for a new recovery key, shows it on the terminal, and answers
/// the vault passphrase prompt from the owner console.
#[cfg(target_os = "linux")]
pub fn recipient_add_recovery(socket: Option<&Path>, label: String) -> ExitCode {
    recipient_add_recovery::run(socket, label).into()
}

/// The client is Linux-only for now, like the service.
#[cfg(not(target_os = "linux"))]
pub fn recipient_add_recovery(_socket: Option<&Path>, _label: String) -> ExitCode {
    unsupported_platform()
}

/// The client is Linux-only for now, like the service.
#[cfg(not(target_os = "linux"))]
pub fn recipient_add(_socket: Option<&Path>, _recipient: String, _label: String, _host_unlock: bool) -> ExitCode {
    unsupported_platform()
}

/// The client is Linux-only for now, like the service.
#[cfg(not(target_os = "linux"))]
pub fn recipient_list(_socket: Option<&Path>) -> ExitCode {
    unsupported_platform()
}

/// The client is Linux-only for now, like the service.
#[cfg(not(target_os = "linux"))]
pub fn rm(_socket: Option<&Path>, _name: String) -> ExitCode {
    unsupported_platform()
}

/// The client is Linux-only for now, like the service.
#[cfg(not(target_os = "linux"))]
pub fn config_approve(_socket: Option<&Path>, _file: &Path) -> ExitCode {
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
pub fn list(_socket: Option<&Path>) -> ExitCode {
    unsupported_platform()
}

/// The client is Linux-only for now, like the service.
#[cfg(not(target_os = "linux"))]
pub fn status(_socket: Option<&Path>) -> ExitCode {
    unsupported_platform()
}

#[cfg(test)]
mod tests;
