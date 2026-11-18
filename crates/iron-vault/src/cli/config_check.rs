// SPDX-License-Identifier: MPL-2.0
//! `iron-vault config check FILE`: parses and validates a config file with no service, no vault and no root.
//!
//! This is advisory. It runs the same parser and cross-section validation the service runs on `config approve`, but not
//! activation: whether each credential exists, permits its route's host and fits its slot, whether a peer caller's
//! account exists on this host, the upstream TLS settings and the log destination all need the vault or the host, so
//! only an approval learns them. The service never trusts this result; it checks again.

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::process::ExitCode;

use iron_vault::admin::protocol::{MAX_CONFIG_LEN, ProposedConfig};
use iron_vault_policy::{ParsedConfig, ValidatedConfig};

use super::Exit;

/// Why a config file did not pass the check.
#[derive(Debug, thiserror::Error)]
pub enum CheckError {
    /// The file could not be read, or is longer than [`MAX_CONFIG_LEN`]. The message never quotes the file's bytes.
    #[error("{0}")]
    Unreadable(String),
    /// The file was read, but is not a valid config. The text names the key and the line and column.
    #[error("{0}")]
    Invalid(String),
}

impl CheckError {
    /// The exit status: 2 when the file could not be read, 1 when it is not a valid config.
    pub fn exit(&self) -> Exit {
        match self {
            Self::Unreadable(_) => Exit::Usage,
            Self::Invalid(_) => Exit::CommandError,
        }
    }
}

/// The proposed config from `file`, read no further than one byte past the limit. `config approve` reads its file the
/// same way, so the two agree on what is too long.
pub(super) fn read_config(file: &Path) -> Result<ProposedConfig, String> {
    let limit = u64::try_from(MAX_CONFIG_LEN).unwrap_or(u64::MAX).saturating_add(1);
    let mut bytes = Vec::new();
    File::open(file)
        .and_then(|opened| opened.take(limit).read_to_end(&mut bytes))
        .map_err(|e| format!("cannot read the config file {}: {e}", file.display()))?;
    ProposedConfig::new(bytes).ok_or_else(|| format!("the config file {} is longer than {MAX_CONFIG_LEN} bytes", file.display()))
}

/// Parses and validates `bytes`, reporting every cross-section failure rather than the first.
pub fn check_bytes(bytes: &[u8]) -> Result<(), CheckError> {
    let parsed = ParsedConfig::from_toml(bytes).map_err(|e| CheckError::Invalid(format!("the config is not valid: {e}")))?;
    ValidatedConfig::try_from(parsed)
        .map(drop)
        .map_err(|failures| CheckError::Invalid(validation_text(&failures)))
}

/// The cross-section failures, one per line under a heading, so a long list stays readable.
fn validation_text(failures: &[iron_vault_policy::ValidationError]) -> String {
    let lines = failures.iter().map(|failure| format!("\n  - {failure}"));
    format!("the config is not valid:{}", lines.collect::<String>())
}

/// Checks the config at `file`.
pub fn check_file(file: &Path) -> Result<(), CheckError> {
    let config = read_config(file).map_err(CheckError::Unreadable)?;
    check_bytes(config.bytes())
}

/// `iron-vault config check FILE`: prints `Config ok` and exits 0, or says why on stderr and exits 1 (not a valid
/// config) or 2 (the file could not be read). It reads nothing from the service, so any account may run it.
pub fn config_check(file: &Path) -> ExitCode {
    match check_file(file) {
        Ok(()) => {
            println!("Config ok");
            Exit::Success.into()
        }
        Err(e) => {
            eprintln!("iron-vault: {e}");
            e.exit().into()
        }
    }
}

#[cfg(test)]
mod tests;
