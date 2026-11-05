//! The bodies of every frame kind except owner input, which is never read as fields.

use super::add;
use super::fields::{self, exact, first, read_flag, read_profile, read_text, read_u16, read_u64};
use super::status::{self, StatusReport};
use super::{AdminCommand, AdminRequest, AdminResponse, ApprovalResult, ErrorCode, FrameError, Notice, Prompt, ProposedConfig};
use crate::deployment::DeploymentProfile;
use iron_vault_store::{RecordId, VaultId};

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
const TAG_TEXT: u16 = 1;

const COMMAND_PING: u16 = AdminCommand::Ping as u16;
const COMMAND_CONFIG_APPROVE: u16 = AdminCommand::ConfigApprove as u16;
const COMMAND_STATUS: u16 = AdminCommand::Status as u16;
const COMMAND_UNLOCK: u16 = AdminCommand::Unlock as u16;
const COMMAND_LOCK: u16 = AdminCommand::Lock as u16;
const COMMAND_INIT: u16 = AdminCommand::Init as u16;
const COMMAND_ADD: u16 = AdminCommand::Add as u16;

/// A request body; only `add`, whose origins have bounds, can be refused.
pub(super) fn encode_request(request: &AdminRequest) -> Result<Vec<u8>, FrameError> {
    if let AdminRequest::Add { name, kind, origins } = request {
        return add::encode_request(COMMAND_ADD, name, *kind, origins);
    }
    let mut out = Vec::new();
    fields::put(&mut out, TAG_COMMAND, &(request.command() as u16).to_be_bytes());
    if let AdminRequest::ConfigApprove(config) = request {
        fields::put(&mut out, TAG_CONFIG, config.bytes());
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
        COMMAND_STATUS => exact(&fields, [TAG_COMMAND]).map(|_| AdminRequest::Status),
        COMMAND_UNLOCK => exact(&fields, [TAG_COMMAND]).map(|_| AdminRequest::Unlock),
        COMMAND_LOCK => exact(&fields, [TAG_COMMAND]).map(|_| AdminRequest::Lock),
        COMMAND_INIT => exact(&fields, [TAG_COMMAND]).map(|_| AdminRequest::Init),
        COMMAND_ADD => add::decode_request(&fields),
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

/// `init`'s success body: the command it answers, the new vault's ID as its 16 raw bytes (as `status` sends it), then the
/// committed version.
pub(super) fn encode_init_result(vault_id: VaultId, version: u64) -> Vec<u8> {
    let mut out = Vec::new();
    fields::put(&mut out, TAG_COMMAND, &COMMAND_INIT.to_be_bytes());
    fields::put(&mut out, TAG_VAULT_ID, vault_id.as_bytes());
    fields::put(&mut out, TAG_COMMITTED, &version.to_be_bytes());
    out
}

fn decode_init_result(fields: &[fields::Field<'_>]) -> Result<AdminResponse, FrameError> {
    let [_, vault_id, version] = exact(fields, [TAG_COMMAND, TAG_VAULT_ID, TAG_COMMITTED])?;
    Ok(AdminResponse::Init {
        vault_id: <[u8; 16]>::try_from(vault_id)
            .ok()
            .and_then(|bytes| VaultId::from_bytes(bytes).ok())
            .ok_or(FrameError::InvalidValue(TAG_VAULT_ID))?,
        version: read_u64(TAG_COMMITTED, version)?,
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
        COMMAND_STATUS => status::decode(&fields).map(|report| AdminResponse::Status(Box::new(report))),
        COMMAND_LOCK => {
            let [_, cleared] = exact(&fields, [TAG_COMMAND, TAG_CLEARED])?;
            Ok(AdminResponse::Lock {
                cleared: read_flag(TAG_CLEARED, cleared)?,
            })
        }
        COMMAND_INIT => decode_init_result(&fields),
        COMMAND_ADD => add::decode_result(&fields),
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
    ]
    .into_iter()
    .find(|code| *code as u16 == number)
    .ok_or(FrameError::UnknownErrorCode(number))
}
