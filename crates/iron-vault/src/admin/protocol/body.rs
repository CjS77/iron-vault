//! The bodies of every frame kind except owner input, which is never read as fields.

use super::fields::{self, exact, first, read_flag, read_profile, read_text, read_u16, read_u64};
use super::status::{self, StatusReport};
use super::{AdminCommand, AdminRequest, AdminResponse, ApprovalResult, ErrorCode, FrameError, Notice, Prompt, ProposedConfig};
use super::{add, list, recipient_add, recipient_list};
use crate::deployment::DeploymentProfile;
use iron_vault_policy::CallerToken;
use iron_vault_policy::caller_token::CALLER_TOKEN_LEN;
use iron_vault_store::{RecipientEntry, RecipientKey, RecipientRole, RecordId, VaultId};
use zeroize::Zeroizing;

use crate::standing::CredentialStanding;

pub(super) const TAG_COMMAND: u16 = 1;
const TAG_LABEL: u16 = 1;
const TAG_SECRET: u16 = 2;
const TAG_CODE: u16 = 1;
const TAG_MESSAGE: u16 = 2;
const TAG_PROFILE: u16 = 2;
const TAG_CLEARED: u16 = 2;
const TAG_CONFIG: u16 = 2;
const TAG_VERSION: u16 = 2;
const TAG_DIGEST: u16 = 3;
const TAG_HEADLINE: u16 = 4;
const TAG_VAULT_ID: u16 = 2;
const TAG_COMMITTED: u16 = 3;
const TAG_RECIPIENTS: u16 = 4;
const TAG_HOST_UNLOCK: u16 = 2;
const TAG_TOKEN: u16 = 2;
const TAG_TEXT: u16 = 1;

const COMMAND_PING: u16 = AdminCommand::Ping as u16;
const COMMAND_CONFIG_APPROVE: u16 = AdminCommand::ConfigApprove as u16;
const COMMAND_CALLER_TOKEN: u16 = AdminCommand::CallerToken as u16;
const COMMAND_STATUS: u16 = AdminCommand::Status as u16;
const COMMAND_UNLOCK: u16 = AdminCommand::Unlock as u16;
const COMMAND_LOCK: u16 = AdminCommand::Lock as u16;
const COMMAND_INIT: u16 = AdminCommand::Init as u16;
const COMMAND_ADD: u16 = AdminCommand::Add as u16;
const COMMAND_LIST: u16 = AdminCommand::List as u16;
const COMMAND_REPLACE: u16 = AdminCommand::Replace as u16;
const COMMAND_RM: u16 = AdminCommand::Rm as u16;
const COMMAND_RECOVERY_CHECK: u16 = AdminCommand::RecoveryCheck as u16;
const COMMAND_RECIPIENT_LIST: u16 = AdminCommand::RecipientList as u16;
const COMMAND_RECIPIENT_ADD: u16 = AdminCommand::RecipientAdd as u16;
const COMMAND_RECIPIENT_REMOVE: u16 = AdminCommand::RecipientRemove as u16;
const TAG_RECIPIENT: u16 = 2;
const TAG_RECIPIENT_COUNT: u16 = 2;
const TAG_CHECKED_AT: u16 = 3;
const TAG_RECORDED: u16 = 4;
const TAG_NAME: u16 = 2;

/// A request body; only `add` and `replace`, whose origins have bounds, can be refused.
pub(super) fn encode_request(request: &AdminRequest) -> Result<Vec<u8>, FrameError> {
    match request {
        AdminRequest::Add { name, kind, origins } => return add::encode_request(COMMAND_ADD, name, *kind, origins),
        AdminRequest::Replace { name, kind, origins } => return add::encode_request(COMMAND_REPLACE, name, *kind, origins),
        AdminRequest::RecipientAdd { recipient, label } => {
            return Ok(recipient_add::encode_request(COMMAND_RECIPIENT_ADD, recipient, label));
        }
        _ => {}
    }
    let mut out = Vec::new();
    fields::put(&mut out, TAG_COMMAND, &(request.command() as u16).to_be_bytes());
    match request {
        AdminRequest::ConfigApprove(config) => fields::put(&mut out, TAG_CONFIG, config.bytes()),
        AdminRequest::Rm { name } => fields::put(&mut out, TAG_NAME, name.as_bytes()),
        AdminRequest::RecipientRemove { recipient } => fields::put(&mut out, TAG_RECIPIENT, recipient.as_bytes()),
        AdminRequest::Init { host_unlock } => fields::put(&mut out, TAG_HOST_UNLOCK, &[u8::from(*host_unlock)]),
        _ => {}
    }
    Ok(out)
}

/// The command is read first, so an unknown command is reported as such whatever arguments follow it.
pub(super) fn decode_request(body: &[u8]) -> Result<AdminRequest, FrameError> {
    let fields = fields::parse(body)?;
    match read_u16(TAG_COMMAND, first(&fields, TAG_COMMAND)?)? {
        COMMAND_PING => exact(&fields, [TAG_COMMAND]).map(|_| AdminRequest::Ping),
        COMMAND_CONFIG_APPROVE => {
            let [_, config] = exact(&fields, [TAG_COMMAND, TAG_CONFIG])?;
            ProposedConfig::new(config.to_vec())
                .map(AdminRequest::ConfigApprove)
                .ok_or(FrameError::InvalidValue(TAG_CONFIG))
        }
        COMMAND_CALLER_TOKEN => exact(&fields, [TAG_COMMAND]).map(|_| AdminRequest::CallerToken),
        COMMAND_STATUS => exact(&fields, [TAG_COMMAND]).map(|_| AdminRequest::Status),
        COMMAND_UNLOCK => exact(&fields, [TAG_COMMAND]).map(|_| AdminRequest::Unlock),
        COMMAND_LOCK => exact(&fields, [TAG_COMMAND]).map(|_| AdminRequest::Lock),
        COMMAND_INIT => {
            let [_, host_unlock] = exact(&fields, [TAG_COMMAND, TAG_HOST_UNLOCK])?;
            Ok(AdminRequest::Init {
                host_unlock: read_flag(TAG_HOST_UNLOCK, host_unlock)?,
            })
        }
        COMMAND_RECOVERY_CHECK => exact(&fields, [TAG_COMMAND]).map(|_| AdminRequest::RecoveryCheck),
        COMMAND_ADD => add::decode_request(&fields, |name, kind, origins| AdminRequest::Add { name, kind, origins }),
        COMMAND_LIST => exact(&fields, [TAG_COMMAND]).map(|_| AdminRequest::List),
        COMMAND_RECIPIENT_LIST => exact(&fields, [TAG_COMMAND]).map(|_| AdminRequest::RecipientList),
        COMMAND_RECIPIENT_ADD => recipient_add::decode_request(&fields),
        COMMAND_REPLACE => add::decode_request(&fields, |name, kind, origins| AdminRequest::Replace { name, kind, origins }),
        COMMAND_RM => {
            let [_, name] = exact(&fields, [TAG_COMMAND, TAG_NAME])?;
            Ok(AdminRequest::Rm {
                name: read_text(TAG_NAME, name)?,
            })
        }
        COMMAND_RECIPIENT_REMOVE => {
            let [_, recipient] = exact(&fields, [TAG_COMMAND, TAG_RECIPIENT])?;
            Ok(AdminRequest::RecipientRemove {
                recipient: read_text(TAG_RECIPIENT, recipient)?,
            })
        }
        unknown => Err(FrameError::UnknownCommand(unknown)),
    }
}

pub(super) fn encode_prompt(prompt: &Prompt) -> Vec<u8> {
    let mut out = Vec::new();
    fields::put(&mut out, TAG_LABEL, prompt.label.as_bytes());
    fields::put(&mut out, TAG_SECRET, &[u8::from(prompt.secret)]);
    out
}

pub(super) fn decode_prompt(body: &[u8]) -> Result<Prompt, FrameError> {
    let [label, secret] = exact(&fields::parse(body)?, [TAG_LABEL, TAG_SECRET])?;
    Ok(Prompt {
        label: read_text(TAG_LABEL, label)?,
        secret: read_flag(TAG_SECRET, secret)?,
    })
}

/// `ping`'s success body: the command it answers, then the deployment profile.
pub(super) fn encode_ping_result(profile: DeploymentProfile) -> Vec<u8> {
    let mut out = Vec::new();
    fields::put(&mut out, TAG_COMMAND, &COMMAND_PING.to_be_bytes());
    fields::put(&mut out, TAG_PROFILE, &[fields::profile_code(profile)]);
    out
}

/// `status`'s success body: the command it answers, then the report's fields.
pub(super) fn encode_status_result(report: &StatusReport) -> Vec<u8> {
    status::encode(COMMAND_STATUS, report)
}

/// `lock`'s success body: the command it answers, then whether every cached secret was confirmed cleared.
pub(super) fn encode_lock_result(cleared: bool) -> Vec<u8> {
    let mut out = Vec::new();
    fields::put(&mut out, TAG_COMMAND, &COMMAND_LOCK.to_be_bytes());
    fields::put(&mut out, TAG_CLEARED, &[u8::from(cleared)]);
    out
}

/// `add`'s success body: the command it answers, then the new record's ID.
pub(super) fn encode_add_result(record_id: RecordId) -> Vec<u8> {
    add::encode_result(COMMAND_ADD, record_id)
}

/// `replace`'s success body: the command it answers, then the new record's ID.
pub(super) fn encode_replace_result(record_id: RecordId) -> Vec<u8> {
    add::encode_result(COMMAND_REPLACE, record_id)
}

/// `caller-token`'s success body: the command it answers, then the token's text. It holds the token, so it is built in a
/// clearing buffer sized for it up front, which never reallocates.
pub(super) fn encode_caller_token_result(token: &CallerToken) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(2 * fields::FIELD_HEADER_LEN + 2 + CALLER_TOKEN_LEN));
    fields::put(&mut out, TAG_COMMAND, &COMMAND_CALLER_TOKEN.to_be_bytes());
    fields::put(&mut out, TAG_TOKEN, token.expose_secret().as_bytes());
    out
}

/// The token is parsed straight from the read buffer into its own secret type. A wrong length or an invalid token is
/// an invalid value: the error names the tag, and never the bytes.
fn decode_caller_token_result(fields: &[fields::Field<'_>]) -> Result<AdminResponse, FrameError> {
    let [_, token] = exact(fields, [TAG_COMMAND, TAG_TOKEN])?;
    CallerToken::parse(token)
        .map(|token| AdminResponse::CallerToken { token })
        .map_err(|_| FrameError::InvalidValue(TAG_TOKEN))
}

/// `list`'s success body: the command it answers, whether a vault is open, then the entries. An entry the wire cannot
/// carry is an error.
pub(super) fn encode_list_result(credentials: Option<&[CredentialStanding]>) -> Result<Vec<u8>, FrameError> {
    list::encode_result(COMMAND_LIST, credentials)
}

/// `recipient remove`'s success body: the command it answers, then the recipient count after the removal.
pub(super) fn encode_recipient_remove_result(recipients: u8) -> Vec<u8> {
    let mut out = Vec::new();
    fields::put(&mut out, TAG_COMMAND, &COMMAND_RECIPIENT_REMOVE.to_be_bytes());
    fields::put(&mut out, TAG_RECIPIENT_COUNT, &[recipients]);
    out
}

/// `recipient list`'s success body: the command it answers, then the entries.
pub(super) fn encode_recipient_list_result(entries: &[RecipientEntry]) -> Result<Vec<u8>, FrameError> {
    recipient_list::encode_result(COMMAND_RECIPIENT_LIST, entries)
}

/// `recipient add`'s success body: the command it answers, the enrolled key, then the recipient count.
pub(super) fn encode_recipient_add_result(recipient: &RecipientKey, recipients: u8) -> Vec<u8> {
    recipient_add::encode_result(COMMAND_RECIPIENT_ADD, recipient, recipients)
}

/// `init`'s success body: the command it answers, the new vault's ID as its 16 raw bytes (as `status` sends it), the
/// committed version, then the code of each recipient role enrolled, one byte each.
pub(super) fn encode_init_result(vault_id: VaultId, version: u64, recipients: &[RecipientRole]) -> Vec<u8> {
    let mut out = Vec::new();
    fields::put(&mut out, TAG_COMMAND, &COMMAND_INIT.to_be_bytes());
    fields::put(&mut out, TAG_VAULT_ID, vault_id.as_bytes());
    fields::put(&mut out, TAG_COMMITTED, &version.to_be_bytes());
    fields::put(
        &mut out,
        TAG_RECIPIENTS,
        &recipients.iter().map(|role| role.code()).collect::<Vec<_>>(),
    );
    out
}

fn decode_init_result(fields: &[fields::Field<'_>]) -> Result<AdminResponse, FrameError> {
    let [_, vault_id, version, recipients] = exact(fields, [TAG_COMMAND, TAG_VAULT_ID, TAG_COMMITTED, TAG_RECIPIENTS])?;
    Ok(AdminResponse::Init {
        vault_id: <[u8; 16]>::try_from(vault_id)
            .ok()
            .and_then(|bytes| VaultId::from_bytes(bytes).ok())
            .ok_or(FrameError::InvalidValue(TAG_VAULT_ID))?,
        version: read_u64(TAG_COMMITTED, version)?,
        recipients: recipients
            .iter()
            .map(|code| RecipientRole::from_code(*code).ok_or(FrameError::InvalidValue(TAG_RECIPIENTS)))
            .collect::<Result<_, _>>()?,
    })
}

/// `recovery check`'s success body: the command it answers, the vault ID as its 16 raw bytes, the check time in Unix
/// seconds, then whether the check record was written.
pub(super) fn encode_recovery_check_result(vault_id: VaultId, checked_at: u64, recorded: bool) -> Vec<u8> {
    let mut out = Vec::new();
    fields::put(&mut out, TAG_COMMAND, &COMMAND_RECOVERY_CHECK.to_be_bytes());
    fields::put(&mut out, TAG_VAULT_ID, vault_id.as_bytes());
    fields::put(&mut out, TAG_CHECKED_AT, &checked_at.to_be_bytes());
    fields::put(&mut out, TAG_RECORDED, &[u8::from(recorded)]);
    out
}

fn decode_recovery_check_result(fields: &[fields::Field<'_>]) -> Result<AdminResponse, FrameError> {
    let [_, vault_id, checked_at, recorded] = exact(fields, [TAG_COMMAND, TAG_VAULT_ID, TAG_CHECKED_AT, TAG_RECORDED])?;
    Ok(AdminResponse::RecoveryCheck {
        vault_id: <[u8; 16]>::try_from(vault_id)
            .ok()
            .and_then(|bytes| VaultId::from_bytes(bytes).ok())
            .ok_or(FrameError::InvalidValue(TAG_VAULT_ID))?,
        checked_at: read_u64(TAG_CHECKED_AT, checked_at)?,
        recorded: read_flag(TAG_RECORDED, recorded)?,
    })
}

/// `config approve`'s success body: the command it answers, the committed version, the config digest and the headline.
pub(super) fn encode_approval_result(result: &ApprovalResult) -> Vec<u8> {
    let mut out = Vec::new();
    fields::put(&mut out, TAG_COMMAND, &COMMAND_CONFIG_APPROVE.to_be_bytes());
    fields::put(&mut out, TAG_VERSION, &result.version.to_be_bytes());
    fields::put(&mut out, TAG_DIGEST, &result.digest);
    fields::put(&mut out, TAG_HEADLINE, result.headline.as_bytes());
    out
}

fn decode_approval_result(fields: &[fields::Field<'_>]) -> Result<AdminResponse, FrameError> {
    let [_, version, digest, headline] = exact(fields, [TAG_COMMAND, TAG_VERSION, TAG_DIGEST, TAG_HEADLINE])?;
    Ok(AdminResponse::ConfigApprove(ApprovalResult {
        version: <[u8; 8]>::try_from(version)
            .map(u64::from_be_bytes)
            .map_err(|_| FrameError::InvalidValue(TAG_VERSION))?,
        digest: <[u8; 32]>::try_from(digest).map_err(|_| FrameError::InvalidValue(TAG_DIGEST))?,
        headline: read_text(TAG_HEADLINE, headline)?,
    }))
}

pub(super) fn encode_notice(notice: &Notice) -> Vec<u8> {
    let mut out = Vec::new();
    fields::put(&mut out, TAG_TEXT, notice.text.as_bytes());
    out
}

pub(super) fn decode_notice(body: &[u8]) -> Result<Notice, FrameError> {
    let [text] = exact(&fields::parse(body)?, [TAG_TEXT])?;
    Ok(Notice {
        text: read_text(TAG_TEXT, text)?,
    })
}

/// A success without a result has only the empty body; one with a result names its command first, so the body
/// decodes without knowing which request it answers.
pub(super) fn decode_success(body: &[u8]) -> Result<AdminResponse, FrameError> {
    let fields = fields::parse(body)?;
    if fields.is_empty() {
        return Ok(AdminResponse::Success);
    }
    match read_u16(TAG_COMMAND, first(&fields, TAG_COMMAND)?)? {
        COMMAND_PING => {
            let [_, profile] = exact(&fields, [TAG_COMMAND, TAG_PROFILE])?;
            Ok(AdminResponse::Ping {
                profile: read_profile(TAG_PROFILE, profile)?,
            })
        }
        COMMAND_CONFIG_APPROVE => decode_approval_result(&fields),
        COMMAND_CALLER_TOKEN => decode_caller_token_result(&fields),
        COMMAND_STATUS => status::decode(&fields).map(|report| AdminResponse::Status(Box::new(report))),
        COMMAND_LOCK => {
            let [_, cleared] = exact(&fields, [TAG_COMMAND, TAG_CLEARED])?;
            Ok(AdminResponse::Lock {
                cleared: read_flag(TAG_CLEARED, cleared)?,
            })
        }
        COMMAND_INIT => decode_init_result(&fields),
        COMMAND_RECOVERY_CHECK => decode_recovery_check_result(&fields),
        COMMAND_ADD => add::decode_result(&fields).map(|record_id| AdminResponse::Add { record_id }),
        COMMAND_LIST => list::decode_result(&fields),
        COMMAND_RECIPIENT_LIST => recipient_list::decode_result(&fields),
        COMMAND_RECIPIENT_ADD => recipient_add::decode_result(&fields),
        COMMAND_RECIPIENT_REMOVE => {
            let [_, count] = exact(&fields, [TAG_COMMAND, TAG_RECIPIENT_COUNT])?;
            match count {
                &[recipients] => Ok(AdminResponse::RecipientRemove { recipients }),
                _ => Err(FrameError::InvalidValue(TAG_RECIPIENT_COUNT)),
            }
        }
        COMMAND_REPLACE => add::decode_result(&fields).map(|record_id| AdminResponse::Replace { record_id }),
        unknown => Err(FrameError::UnknownCommand(unknown)),
    }
}

pub(super) fn encode_error(code: ErrorCode, message: &str) -> Vec<u8> {
    let mut out = Vec::new();
    fields::put(&mut out, TAG_CODE, &(code as u16).to_be_bytes());
    fields::put(&mut out, TAG_MESSAGE, message.as_bytes());
    out
}

pub(super) fn decode_error(body: &[u8]) -> Result<AdminResponse, FrameError> {
    let [code, message] = exact(&fields::parse(body)?, [TAG_CODE, TAG_MESSAGE])?;
    Ok(AdminResponse::Error {
        code: error_code(read_u16(TAG_CODE, code)?)?,
        message: read_text(TAG_MESSAGE, message)?,
    })
}

fn error_code(number: u16) -> Result<ErrorCode, FrameError> {
    [
        ErrorCode::UnsupportedVersion,
        ErrorCode::MalformedFrame,
        ErrorCode::UnknownCommand,
        ErrorCode::UnexpectedFrame,
        ErrorCode::NotAdminPrincipal,
        ErrorCode::Busy,
        ErrorCode::ConfigInvalid,
        ErrorCode::Declined,
        ErrorCode::ApprovalDenied,
        ErrorCode::ApprovalUnavailable,
        ErrorCode::ApprovalFailed,
        ErrorCode::CommittedNotActive,
        ErrorCode::WrongState,
        ErrorCode::UnlockDenied,
        ErrorCode::UnlockFailed,
        ErrorCode::UnlockedUnavailable,
        ErrorCode::AlreadyInitialized,
        ErrorCode::PassphraseRejected,
        ErrorCode::InitFailed,
        ErrorCode::NameTaken,
        ErrorCode::CredentialInvalid,
        ErrorCode::VaultWriteFailed,
        ErrorCode::UnknownCredential,
        ErrorCode::CredentialInUse,
        ErrorCode::RandomSourceFailed,
        ErrorCode::ListTooLarge,
        ErrorCode::MemoryUnprotected,
        ErrorCode::MigrationDenied,
        ErrorCode::MigrationUnavailable,
        ErrorCode::RecoveryKeyInvalid,
        ErrorCode::RecoveryCheckFailed,
        ErrorCode::RecoveryCheckUnavailable,
        ErrorCode::MigrationRateLimited,
        ErrorCode::UnlockRateLimited,
        ErrorCode::RecipientInvalid,
        ErrorCode::RecipientEnrolled,
        ErrorCode::UnknownRecipient,
        ErrorCode::RecipientSetInvalid,
        ErrorCode::RecipientInventoryDamaged,
    ]
    .into_iter()
    .find(|code| *code as u16 == number)
    .ok_or(FrameError::UnknownErrorCode(number))
}
