//! The admin protocol's frames and their pure codec (`design/admin-protocol.md`). Nothing here does I/O: the transport
//! hands [`decode`] the bytes it has read and sends what [`encode`] writes.

mod add;
mod body;
mod fields;
mod list;
mod status;
#[cfg(test)]
mod tests;

use std::fmt;

use thiserror::Error;
use zeroize::Zeroizing;

use crate::deployment::DeploymentProfile;
use crate::standing::CredentialStanding;
use iron_vault_policy::{CallerToken, CredentialKind, Port};
use iron_vault_store::{RecordId, VaultId};

pub use iron_vault_store::MAX_CONFIG_LEN;
pub use status::{MemoryStatus, StatusReport, UnlockedVault, VaultStatus};

/// The protocol version this code writes and the only one it reads.
pub const PROTOCOL_VERSION: u16 = 1;
/// The largest body a frame may carry; a declared length above it is refused before any body byte is read.
pub const MAX_BODY_LEN: usize = 64 * 1024;
/// The fixed header size: version (2), kind (1), body length (4).
pub const HEADER_LEN: usize = 7;
/// The most permitted origins one `add` or `replace` request carries.
pub const MAX_ORIGINS: usize = 32;
/// The longest requested origin host, in bytes: the DNS name limit.
pub const MAX_ORIGIN_HOST_LEN: usize = 253;

/// One command with its arguments, sent by the CLI as the first frame of an exchange.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdminRequest {
    /// Changes nothing; the service answers with its deployment profile. Command ID 1.
    Ping,
    /// Runs the approval transaction on the proposed config. Command ID 2.
    ConfigApprove(ProposedConfig),
    /// Generates a fresh caller token and returns it once; it touches neither the vault nor the policy. Command ID 3.
    CallerToken,
    /// Reports service, vault, approval, memory protection and credential states; allowed in every state. Command ID 6.
    Status,
    /// Opens the vault with the passphrase the service prompts for; no arguments and no result. Command ID 4.
    Unlock,
    /// Clears the vault identity and every cached secret from memory. Command ID 5.
    Lock,
    /// Creates the vault and approves the initial config as version 1; the service prompts for both passphrases and
    /// reveals the recovery key. Command ID 7.
    Init,
    /// Lists every credential with its kind, permitted origins and standing; allowed in every state. No arguments.
    /// Command ID 9.
    List,
    /// Enrols a new credential under a name the manifest does not hold; the service prompts for the material. Command
    /// ID 8.
    Add {
        /// The credential name, as the owner wrote it; the service validates it.
        name: String,
        /// The credential's kind, which decides what the service prompts for.
        kind: CredentialKind,
        /// The permitted origins, 1 to [`MAX_ORIGINS`] of them.
        origins: Vec<RequestedOrigin>,
    },
    /// Replaces a credential's record with a new one under a new record ID, after owner presence; the service prompts
    /// for the approval passphrase, then the material. Its arguments are `add`'s. Command ID 10.
    Replace {
        /// The credential name, as the owner wrote it; the service validates it.
        name: String,
        /// The new record's kind, which decides what the service prompts for.
        kind: CredentialKind,
        /// The new record's permitted origins, 1 to [`MAX_ORIGINS`] of them.
        origins: Vec<RequestedOrigin>,
    },
    /// Removes a credential record after owner presence, while no route of the active config uses the name; no result.
    /// Command ID 11.
    Rm {
        /// The credential name, as the owner wrote it; the service validates it.
        name: String,
    },
}

/// A requested origin: one permitted origin as an `add` or `replace` request carries it. The host stays text on the wire, at most
/// [`MAX_ORIGIN_HOST_LEN`] bytes, and the service parses it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestedOrigin {
    /// The host as the CLI sent it.
    pub host: String,
    /// The port; HTTPS is implied.
    pub port: Port,
}

impl AdminRequest {
    /// The command this request names, without its arguments.
    pub const fn command(&self) -> AdminCommand {
        match self {
            Self::Ping => AdminCommand::Ping,
            Self::ConfigApprove(_) => AdminCommand::ConfigApprove,
            Self::CallerToken => AdminCommand::CallerToken,
            Self::Status => AdminCommand::Status,
            Self::Unlock => AdminCommand::Unlock,
            Self::Lock => AdminCommand::Lock,
            Self::Init => AdminCommand::Init,
            Self::Add { .. } => AdminCommand::Add,
            Self::List => AdminCommand::List,
            Self::Replace { .. } => AdminCommand::Replace,
            Self::Rm { .. } => AdminCommand::Rm,
        }
    }
}

/// What an admin request asks the service to do; the value is the command ID on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdminCommand {
    /// `ping`.
    Ping = 1,
    /// `config approve`.
    ConfigApprove = 2,
    /// `caller-token`.
    CallerToken = 3,
    /// `status`.
    Status = 6,
    /// `unlock`.
    Unlock = 4,
    /// `lock`.
    Lock = 5,
    /// `init`.
    Init = 7,
    /// `add`.
    Add = 8,
    /// `list`.
    List = 9,
    /// `replace`.
    Replace = 10,
    /// `rm`.
    Rm = 11,
}

impl AdminCommand {
    /// The command's name as the CLI spells it, for logs.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ping => "ping",
            Self::ConfigApprove => "config approve",
            Self::CallerToken => "caller-token",
            Self::Status => "status",
            Self::Unlock => "unlock",
            Self::Lock => "lock",
            Self::Init => "init",
            Self::Add => "add",
            Self::List => "list",
            Self::Replace => "replace",
            Self::Rm => "rm",
        }
    }
}

/// No command accepts an external signature (§3.2): the service signs only the pending config of its own approval
/// transaction. The test lists every argument of every command through an exhaustive match, so a new command does not
/// compile until its arguments are listed and checked here.
#[cfg(test)]
mod no_external_signatures {
    use super::{AdminCommand, FrameError, body, fields};

    /// Every argument `command` takes, by name.
    fn arguments(command: AdminCommand) -> &'static [&'static str] {
        match command {
            AdminCommand::Ping
            | AdminCommand::CallerToken
            | AdminCommand::Status
            | AdminCommand::Unlock
            | AdminCommand::Lock
            | AdminCommand::Init
            | AdminCommand::List => &[],
            AdminCommand::ConfigApprove => &["config"],
            AdminCommand::Add | AdminCommand::Replace => &["name", "kind", "origins"],
            AdminCommand::Rm => &["name"],
        }
    }

    const COMMANDS: [AdminCommand; 10] = [
        AdminCommand::Ping,
        AdminCommand::ConfigApprove,
        AdminCommand::CallerToken,
        AdminCommand::Unlock,
        AdminCommand::Lock,
        AdminCommand::Status,
        AdminCommand::Init,
        AdminCommand::Add,
        AdminCommand::List,
        AdminCommand::Replace,
        AdminCommand::Rm,
    ];

    #[test]
    fn every_command_the_decoder_knows_is_listed() {
        let known: Vec<u16> = (0..=u16::MAX)
            .filter(|id| {
                let mut request = Vec::new();
                fields::put(&mut request, body::TAG_COMMAND, &id.to_be_bytes());
                !matches!(body::decode_request(&request), Err(FrameError::UnknownCommand(_)))
            })
            .collect();
        assert_eq!(known, COMMANDS.map(|command| command as u16));
    }

    #[test]
    fn no_command_takes_a_signature_an_envelope_or_a_key() {
        COMMANDS.iter().flat_map(|command| arguments(*command)).for_each(|argument| {
            ["sig", "envelope", "key", "approval"]
                .iter()
                .for_each(|word| assert!(!argument.contains(word), "argument `{argument}` looks like {word}"));
        });
    }
}

/// The exact config bytes the owner proposes for approval, at most [`MAX_CONFIG_LEN`] long.
///
/// They are not secret, but they are never echoed in a diagnostic: `Debug` shows only their length.
#[derive(Clone, PartialEq, Eq)]
pub struct ProposedConfig(Vec<u8>);

impl ProposedConfig {
    /// Wraps `bytes`, refusing more than [`MAX_CONFIG_LEN`] of them.
    pub fn new(bytes: Vec<u8>) -> Option<Self> {
        (bytes.len() <= MAX_CONFIG_LEN).then_some(Self(bytes))
    }

    /// The bytes as proposed.
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }

    /// The bytes, for the approval transaction that keeps them as its one byte snapshot.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for ProposedConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProposedConfig({} bytes)", self.0.len())
    }
}

/// The service asking the CLI to collect one value from the owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prompt {
    /// The text the CLI shows the owner.
    pub label: String,
    /// Whether the value is secret, so the CLI turns terminal echo off while the owner types.
    pub secret: bool,
}

/// Text the service needs the owner to read, such as an approval summary; it is never answered. Text longer than one
/// frame is sent as several notices ([`Notice::split`]), which the CLI shows one after another.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notice {
    /// The text, continuing the previous notice's; `\n` ends a line.
    pub text: String,
}

/// The longest notice text: the body bound less one field header.
pub const MAX_NOTICE_LEN: usize = MAX_BODY_LEN - fields::FIELD_HEADER_LEN;

impl Notice {
    /// `text` as notices that each fit one frame, split between UTF-8 characters and never truncated.
    pub fn split(text: &str) -> Vec<Self> {
        let mut rest = text;
        std::iter::from_fn(|| {
            (!rest.is_empty()).then(|| {
                let (head, tail) = rest.split_at(rest.floor_char_boundary(MAX_NOTICE_LEN));
                rest = tail;
                Self { text: head.to_owned() }
            })
        })
        .collect()
    }
}

/// The bytes the owner typed in answer to a prompt: a secret-bearing type (`design/secret-handling.md`).
///
/// It has no `Clone`, `Display` or serde impl, and its `Debug` shows no byte, so the value cannot be copied, printed
/// or serialized by accident. Its buffer clears itself on drop.
pub struct OwnerInput(Zeroizing<Vec<u8>>);

impl OwnerInput {
    /// Wraps a value already held in a clearing buffer, so building one never leaves an unwiped copy.
    pub fn new(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }

    /// The typed bytes, for the operation that turns them into its own secret type.
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for OwnerInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnerInput([REDACTED])")
    }
}

/// A secret value the service shows the owner once, received in a reveal frame: a secret-bearing type
/// (`design/secret-handling.md`).
///
/// Like [`OwnerInput`], it has no `Clone`, `Display` or serde impl, its `Debug` shows no byte, and its buffer clears
/// itself on drop. The service never builds one: it encodes a reveal straight from the secret's own type with
/// [`encode_reveal`].
pub struct RevealedSecret(Zeroizing<Vec<u8>>);

impl RevealedSecret {
    /// Wraps a value already held in a clearing buffer, so building one never leaves an unwiped copy.
    pub fn new(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }

    /// The value, for the owner console to show.
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for RevealedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RevealedSecret([REDACTED])")
    }
}

/// The final frame of an exchange. It holds a secret when it is `caller-token`'s result, so it is secret-bearing: it has
/// no `Clone`, `PartialEq` or `Display`, and its `Debug` shows no token byte, through [`CallerToken`]'s own.
#[derive(Debug)]
pub enum AdminResponse {
    /// The command completed, and it has no result.
    Success,
    /// `ping` completed: the service runs this deployment profile. Its protocol version is the frame header's.
    Ping {
        /// The service's deployment profile.
        profile: DeploymentProfile,
    },
    /// `status` completed. Boxed: the report is much larger than every other response.
    Status(Box<StatusReport>),
    /// `config approve` completed: the approved config is active.
    ConfigApprove(ApprovalResult),
    /// `lock` completed: the service is Locked.
    Lock {
        /// Whether every snapshot holding secrets was dropped within the lock drain. When false, a request that ignored
        /// its cancellation may still hold them, and the service has logged how many.
        cleared: bool,
    },
    /// `list` completed.
    List {
        /// Every credential in the vault manifest, in name order; `None` while no vault is open.
        credentials: Option<Vec<CredentialStanding>>,
    },
    /// `add` completed: the new credential record's ID.
    Add {
        /// The ID of the record the service wrote.
        record_id: RecordId,
    },
    /// `replace` completed: the ID of the record that replaced the old one. The old ID was shown in the summary.
    Replace {
        /// The ID of the record the service wrote.
        record_id: RecordId,
    },
    /// `caller-token` completed: a fresh caller token, shown to the owner once. The service keeps no copy.
    CallerToken {
        /// The new token.
        token: CallerToken,
    },
    /// `init` completed: the vault is written and its first approval committed; the service is still Locked.
    Init {
        /// The new vault's ID.
        vault_id: VaultId,
        /// The committed approval version, always 1.
        version: u64,
    },
    /// The command failed. The message is the service's own text and never contains owner input.
    Error {
        /// The stable code scripts act on.
        code: ErrorCode,
        /// Text for the owner; it may change between releases.
        message: String,
    },
}

/// What a completed `config approve` reports. The full summary was shown as notices before the confirmation; the result
/// carries only its headline, which is bounded whatever the config's size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalResult {
    /// The approval version committed.
    pub version: u64,
    /// The BLAKE2b-256 digest of the approved config.
    pub digest: [u8; 32],
    /// One line of counts per summary section.
    pub headline: String,
}

/// A config digest as the owner reads it: `blake2b:` and 64 lowercase hex digits.
pub fn digest_text(digest: &[u8; 32]) -> String {
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("blake2b:{hex}")
}

/// The stable reason an admin response reports an error; the numbers are part of the protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    /// The request frame's protocol version is not the service's.
    UnsupportedVersion = 1,
    /// The frame broke a rule of the protocol.
    MalformedFrame = 2,
    /// The command ID is not one the service knows.
    UnknownCommand = 3,
    /// A well-formed frame arrived out of turn in the exchange.
    UnexpectedFrame = 4,
    /// The connecting account is not an admin principal; nothing it sent was read.
    NotAdminPrincipal = 5,
    /// The service is already serving as many admin connections as it allows.
    Busy = 6,
    /// `config approve`: the proposed config fails parsing, validation or activation.
    ConfigInvalid = 7,
    /// The owner declined at a confirmation prompt.
    Declined = 8,
    /// `config approve`, `replace`, `rm`: owner presence failed: the approval passphrase did not open the pinned approver's key.
    ApprovalDenied = 9,
    /// `config approve`: the service cannot run an approval now; no version was reserved. `replace`, `rm`: owner presence
    /// could not be checked, or a `lock` cancelled the change at its passphrase prompt; nothing was written.
    ApprovalUnavailable = 10,
    /// `config approve`: failed after reserving a version, before committing it; the version is consumed.
    ApprovalFailed = 11,
    /// `config approve`: committed, but not published or active; the service is Unavailable. `replace`, `rm`: the change
    /// committed, but the config check after it left the service Unavailable.
    CommittedNotActive = 12,
    /// The command is not allowed in the service's current state; the message names the state.
    WrongState = 13,
    /// `unlock`: the vault passphrase was wrong.
    UnlockDenied = 14,
    /// `unlock`: the vault did not open, for a reason other than the passphrase; the service stays Locked.
    UnlockFailed = 15,
    /// `unlock`: the vault unlocked, but the config check left the service Unavailable; the message names the redacted
    /// reason.
    UnlockedUnavailable = 16,
    /// `init`: the directories hold an initialized vault, or files init did not write; nothing was changed.
    AlreadyInitialized = 17,
    /// `init`: a chosen passphrase broke a rule; the message names the rule, never the input.
    PassphraseRejected = 18,
    /// `init`: a write failed; the message names the step and what to do with the recovery key shown.
    InitFailed = 19,
    /// `add`: the name is already in the manifest, healthy or damaged; `add` never overwrites.
    NameTaken = 20,
    /// `add`: the name, an origin or the material breaks its rule; the message names the rule, never a typed byte.
    CredentialInvalid = 21,
    /// `add`, `replace`: writing the vault failed; the message says whether the write may have committed.
    VaultWriteFailed = 22,
    /// `replace`, `rm`: the manifest holds no credential of that name.
    UnknownCredential = 23,
    /// `replace`, `rm`: a route of the active config uses the name and would not activate after the change; the message
    /// names each route and why.
    CredentialInUse = 24,
    /// `caller-token`: the operating system's random source failed, so no token was made.
    RandomSourceFailed = 25,
    /// `list`: the credential list does not fit one frame; the message names the count.
    ListTooLarge = 26,
}

impl ErrorCode {
    /// The code's name in `design/admin-protocol.md`, for the CLI to show beside its number.
    pub const fn name(self) -> &'static str {
        match self {
            Self::UnsupportedVersion => "unsupported-version",
            Self::MalformedFrame => "malformed-frame",
            Self::UnknownCommand => "unknown-command",
            Self::UnexpectedFrame => "unexpected-frame",
            Self::NotAdminPrincipal => "not-admin-principal",
            Self::Busy => "busy",
            Self::ConfigInvalid => "config-invalid",
            Self::Declined => "declined",
            Self::ApprovalDenied => "approval-denied",
            Self::ApprovalUnavailable => "approval-unavailable",
            Self::ApprovalFailed => "approval-failed",
            Self::CommittedNotActive => "committed-not-active",
            Self::WrongState => "wrong-state",
            Self::UnlockDenied => "unlock-denied",
            Self::UnlockFailed => "unlock-failed",
            Self::UnlockedUnavailable => "unlocked-unavailable",
            Self::AlreadyInitialized => "already-initialized",
            Self::PassphraseRejected => "passphrase-rejected",
            Self::InitFailed => "init-failed",
            Self::NameTaken => "name-taken",
            Self::CredentialInvalid => "credential-invalid",
            Self::VaultWriteFailed => "vault-write-failed",
            Self::UnknownCredential => "unknown-credential",
            Self::CredentialInUse => "credential-in-use",
            Self::RandomSourceFailed => "random-source-failed",
            Self::ListTooLarge => "list-too-large",
        }
    }

    /// The code a frame the service could not decode is answered with.
    pub const fn for_frame_error(error: FrameError) -> Self {
        match error {
            FrameError::UnsupportedVersion(_) => Self::UnsupportedVersion,
            FrameError::UnknownCommand(_) => Self::UnknownCommand,
            _ => Self::MalformedFrame,
        }
    }
}

/// One message of the admin protocol. It holds a secret when it is an owner-input or a reveal frame, or `caller-token`'s
/// result, so it is secret-bearing and has no `Clone`.
#[derive(Debug)]
pub enum Frame {
    /// Kind 1, CLI to service.
    Request(AdminRequest),
    /// Kind 2, service to CLI.
    Prompt(Prompt),
    /// Kind 3, CLI to service.
    OwnerInput(OwnerInput),
    /// Kind 4 (success) or 5 (error), service to CLI.
    Response(AdminResponse),
    /// Kind 6, service to CLI.
    Notice(Notice),
    /// Kind 7, service to CLI.
    Reveal(RevealedSecret),
}

/// What [`decode`] found at the start of its input.
#[derive(Debug)]
pub enum Decoded {
    /// A whole frame, and how many input bytes it used; any bytes after those belong to the next frame.
    Frame {
        /// The decoded frame.
        frame: Frame,
        /// The frame's encoded length.
        used: usize,
    },
    /// The input is a valid but incomplete prefix: at least this many more bytes are needed to make progress.
    NeedMore(usize),
}

/// Why a frame could not be encoded or decoded. Variants name protocol numbers, never body bytes, so no error can
/// carry owner input into a log or a response message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum FrameError {
    /// The frame's protocol version is not [`PROTOCOL_VERSION`].
    #[error("unsupported admin protocol version {0}; this side speaks version {PROTOCOL_VERSION}")]
    UnsupportedVersion(u16),
    /// The frame kind is not one this version defines.
    #[error("unknown admin frame kind {0}")]
    UnknownKind(u8),
    /// The body is longer than [`MAX_BODY_LEN`].
    #[error("admin frame body is longer than {MAX_BODY_LEN} bytes")]
    BodyTooLong,
    /// A field's header or value runs past the end of the body.
    #[error("admin frame field runs past the end of the body")]
    TruncatedField,
    /// A tag appears twice.
    #[error("admin frame field tag {0} is repeated")]
    DuplicateTag(u16),
    /// A tag is lower than the one before it.
    #[error("admin frame field tag {0} is out of order")]
    TagOutOfOrder(u16),
    /// A tag this frame kind does not define.
    #[error("unknown admin frame field tag {0}")]
    UnknownTag(u16),
    /// A field this frame kind requires is absent.
    #[error("admin frame field tag {0} is missing")]
    MissingField(u16),
    /// A fixed-width field has the wrong length, or a flag is neither 0 nor 1.
    #[error("admin frame field tag {0} has an invalid value")]
    InvalidValue(u16),
    /// A text field is not UTF-8.
    #[error("admin frame field tag {0} is not UTF-8")]
    InvalidUtf8(u16),
    /// The command ID is not one this version defines.
    #[error("unknown admin command {0}")]
    UnknownCommand(u16),
    /// The error code is not one this version defines.
    #[error("unknown admin error code {0}")]
    UnknownErrorCode(u16),
    /// A frame of this kind, which must carry a value, has an empty body.
    #[error("admin frame kind {0} has an empty body")]
    EmptyBody(u8),
}

/// The frame kind byte, which selects how the body is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FrameKind {
    Request = 1,
    Prompt = 2,
    OwnerInput = 3,
    Success = 4,
    Error = 5,
    Notice = 6,
    Reveal = 7,
}

impl FrameKind {
    fn from_byte(byte: u8) -> Result<Self, FrameError> {
        [
            Self::Request,
            Self::Prompt,
            Self::OwnerInput,
            Self::Success,
            Self::Error,
            Self::Notice,
            Self::Reveal,
        ]
        .into_iter()
        .find(|kind| *kind as u8 == byte)
        .ok_or(FrameError::UnknownKind(byte))
    }
}

/// Appends `frame`'s one encoding to `out`. A caller sending owner input, a reveal or `caller-token`'s result passes a
/// clearing buffer, because the encoding holds the value; `out` is grown once, before writing, so no partial copy is left behind in a freed allocation.
pub fn encode(frame: &Frame, out: &mut Vec<u8>) -> Result<(), FrameError> {
    match frame {
        Frame::Request(request) => put_frame(out, FrameKind::Request, &body::encode_request(request)?),
        Frame::Prompt(prompt) => put_frame(out, FrameKind::Prompt, &body::encode_prompt(prompt)),
        Frame::OwnerInput(input) => put_frame(out, FrameKind::OwnerInput, input.expose_secret()),
        Frame::Response(AdminResponse::Success) => put_frame(out, FrameKind::Success, &[]),
        Frame::Response(AdminResponse::Ping { profile }) => put_frame(out, FrameKind::Success, &body::encode_ping_result(*profile)),
        Frame::Response(AdminResponse::Status(report)) => put_frame(out, FrameKind::Success, &body::encode_status_result(report)),
        Frame::Response(AdminResponse::Lock { cleared }) => put_frame(out, FrameKind::Success, &body::encode_lock_result(*cleared)),
        Frame::Response(AdminResponse::List { credentials }) => {
            put_frame(out, FrameKind::Success, &body::encode_list_result(credentials.as_deref())?)
        }
        Frame::Response(AdminResponse::Add { record_id }) => put_frame(out, FrameKind::Success, &body::encode_add_result(*record_id)),
        Frame::Response(AdminResponse::Replace { record_id }) => {
            put_frame(out, FrameKind::Success, &body::encode_replace_result(*record_id))
        }
        Frame::Response(AdminResponse::CallerToken { token }) => {
            put_frame(out, FrameKind::Success, &body::encode_caller_token_result(token))
        }
        Frame::Response(AdminResponse::Init { vault_id, version }) => {
            put_frame(out, FrameKind::Success, &body::encode_init_result(*vault_id, *version))
        }
        Frame::Response(AdminResponse::ConfigApprove(result)) => put_frame(out, FrameKind::Success, &body::encode_approval_result(result)),
        Frame::Response(AdminResponse::Error { code, message }) => put_frame(out, FrameKind::Error, &body::encode_error(*code, message)),
        Frame::Notice(notice) => put_frame(out, FrameKind::Notice, &body::encode_notice(notice)),
        Frame::Reveal(secret) => encode_reveal(secret.expose_secret(), out),
    }
}

/// Appends a reveal frame carrying `value` to `out`, which holds the value afterwards, so the caller passes a clearing
/// buffer. It takes the bytes rather than a [`Frame`], so the service encodes straight from the secret's own type
/// without a second copy. An empty value is refused: a reveal always shows something.
pub fn encode_reveal(value: &[u8], out: &mut Vec<u8>) -> Result<(), FrameError> {
    if value.is_empty() {
        return Err(FrameError::EmptyBody(FrameKind::Reveal as u8));
    }
    put_frame(out, FrameKind::Reveal, value)
}

/// Reads the frame at the start of `bytes`: a whole frame and its length, a request for more bytes, or the first rule
/// the input breaks. The header is checked (version, then kind, then length) before any body byte is looked at.
pub fn decode(bytes: &[u8]) -> Result<Decoded, FrameError> {
    let Some(header) = bytes.first_chunk::<HEADER_LEN>() else {
        return Ok(Decoded::NeedMore(HEADER_LEN - bytes.len()));
    };
    let (kind, body_len) = read_header(header)?;
    let used = HEADER_LEN + body_len;
    let Some(body) = bytes.get(HEADER_LEN..used) else {
        return Ok(Decoded::NeedMore(used - bytes.len()));
    };
    let frame = match kind {
        FrameKind::Request => Frame::Request(body::decode_request(body)?),
        FrameKind::Prompt => Frame::Prompt(body::decode_prompt(body)?),
        // The one copy of the value: straight from the received bytes into its clearing buffer, sized exactly.
        FrameKind::OwnerInput => Frame::OwnerInput(OwnerInput::new(Zeroizing::new(body.to_vec()))),
        FrameKind::Success => Frame::Response(body::decode_success(body)?),
        FrameKind::Error => Frame::Response(body::decode_error(body)?),
        FrameKind::Notice => Frame::Notice(body::decode_notice(body)?),
        FrameKind::Reveal if body.is_empty() => return Err(FrameError::EmptyBody(FrameKind::Reveal as u8)),
        // As for owner input: one copy, straight into its clearing buffer.
        FrameKind::Reveal => Frame::Reveal(RevealedSecret::new(Zeroizing::new(body.to_vec()))),
    };
    Ok(Decoded::Frame { frame, used })
}

fn put_frame(out: &mut Vec<u8>, kind: FrameKind, body: &[u8]) -> Result<(), FrameError> {
    let len = u32::try_from(body.len())
        .ok()
        .filter(|_| body.len() <= MAX_BODY_LEN)
        .ok_or(FrameError::BodyTooLong)?;
    out.reserve(HEADER_LEN + body.len());
    out.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    out.push(kind as u8);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    Ok(())
}

/// The frame kind and body length, after the version check, so a newer peer is told its version is unsupported even
/// when its kinds are unknown here.
fn read_header(header: &[u8; HEADER_LEN]) -> Result<(FrameKind, usize), FrameError> {
    let [v0, v1, kind, l0, l1, l2, l3] = *header;
    let version = u16::from_be_bytes([v0, v1]);
    if version != PROTOCOL_VERSION {
        return Err(FrameError::UnsupportedVersion(version));
    }
    let kind = FrameKind::from_byte(kind)?;
    let body_len = usize::try_from(u32::from_be_bytes([l0, l1, l2, l3]))
        .ok()
        .filter(|len| *len <= MAX_BODY_LEN)
        .ok_or(FrameError::BodyTooLong)?;
    Ok((kind, body_len))
}
