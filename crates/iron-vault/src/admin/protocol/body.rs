//! The bodies of every frame kind except owner input, which is never read as fields.

use super::fields::{self, exact, first, read_flag, read_text, read_u16};
use super::{AdminCommand, AdminRequest, AdminResponse, ErrorCode, FrameError, Prompt};
use crate::deployment::DeploymentProfile;

const TAG_COMMAND: u16 = 1;
const TAG_LABEL: u16 = 1;
const TAG_SECRET: u16 = 2;
const TAG_CODE: u16 = 1;
const TAG_MESSAGE: u16 = 2;
const TAG_PROFILE: u16 = 2;

const COMMAND_PING: u16 = AdminCommand::Ping as u16;

const PROFILE_PROTECTED: u8 = 1;
const PROFILE_DEVELOPMENT: u8 = 2;

pub(super) fn encode_request(request: AdminRequest) -> Vec<u8> {
    let mut out = Vec::new();
    fields::put(&mut out, TAG_COMMAND, &(request.command() as u16).to_be_bytes());
    out
}

/// The command is read first, so an unknown command is reported as such whatever arguments follow it.
pub(super) fn decode_request(body: &[u8]) -> Result<AdminRequest, FrameError> {
    let fields = fields::parse(body)?;
    match read_u16(TAG_COMMAND, first(&fields, TAG_COMMAND)?)? {
        COMMAND_PING => exact(&fields, [TAG_COMMAND]).map(|_| AdminRequest::Ping),
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
    let profile = match profile {
        DeploymentProfile::Protected => PROFILE_PROTECTED,
        DeploymentProfile::Development => PROFILE_DEVELOPMENT,
    };
    let mut out = Vec::new();
    fields::put(&mut out, TAG_COMMAND, &COMMAND_PING.to_be_bytes());
    fields::put(&mut out, TAG_PROFILE, &[profile]);
    out
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
                profile: read_profile(profile)?,
            })
        }
        unknown => Err(FrameError::UnknownCommand(unknown)),
    }
}

fn read_profile(value: &[u8]) -> Result<DeploymentProfile, FrameError> {
    match value {
        [PROFILE_PROTECTED] => Ok(DeploymentProfile::Protected),
        [PROFILE_DEVELOPMENT] => Ok(DeploymentProfile::Development),
        _ => Err(FrameError::InvalidValue(TAG_PROFILE)),
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
    ]
    .into_iter()
    .find(|code| *code as u16 == number)
    .ok_or(FrameError::UnknownErrorCode(number))
}
