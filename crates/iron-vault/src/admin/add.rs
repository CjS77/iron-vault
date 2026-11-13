// SPDX-License-Identifier: MPL-2.0
//! `add`: enrols a new credential record under a name the manifest does not hold (spec [§6][s6], [§16][s16];
//! [admin protocol: add](../../../../design/admin-protocol.md#add)).
//!
//! The state, the name and the origins are checked before any prompt, so the owner is never asked for a secret that
//! cannot be stored. The service, not the CLI, decides what to prompt for, by kind, and the material never travels as
//! an argument ([§5][s5]). The service-wide lock is taken only once the material is in hand, so a slow owner never
//! blocks an approval.
//!
//! [s5]: ../../../../design/iron-vault-specification.md#5-service-and-cli-separation-of-concerns
//! [s6]: ../../../../design/iron-vault-specification.md#6-credential-records-and-configuration
//! [s16]: ../../../../design/iron-vault-specification.md#16-administration-recovery-and-migration

use std::collections::BTreeSet;
use std::future::{self, Future};
use std::sync::Arc;

use iron_vault_kinds::CredentialMaterial;
use iron_vault_policy::{CredentialKind, CredentialName, Host, NameRule, Port, parse_origin};
use iron_vault_store::{PermittedOrigins, StoreFs};
use secrecy::SecretString;

use super::dispatch::{AdminHandler, HandlerFuture};
use super::principal::AdminPrincipal;
use super::protocol::{AdminRequest, AdminResponse, ErrorCode, OwnerInput, Prompt, RequestedOrigin};
use super::server::{Exchange, ExchangeError};
use super::unlock::state_name;
use crate::service_context::{ServiceContext, VaultChangeRefusal};
use crate::service_state::{AdminOperation, ServiceState};

/// `add`'s handler, acting on the running service.
pub(super) struct Add<F> {
    service: Arc<ServiceContext<F>>,
}

impl<F> Add<F> {
    pub(super) fn new(service: Arc<ServiceContext<F>>) -> Self {
        Self { service }
    }
}

impl<F: StoreFs + Send + Sync + 'static> AdminHandler for Add<F> {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, request: AdminRequest, exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        Box::pin(self.run(request, exchange))
    }
}

impl<F: StoreFs + Send + Sync + 'static> Add<F> {
    /// Checks the state, the name and the origins, prompts for the material, then writes; the context checks the state
    /// again under its mutex.
    async fn run(&self, request: AdminRequest, exchange: &mut Exchange) -> Result<AdminResponse, ExchangeError> {
        let AdminRequest::Add { name, kind, origins } = request else {
            return Ok(invalid("the request is not `add`".to_owned()));
        };
        let state = self.service.state().await;
        if !state.admin_allows(AdminOperation::VaultChange) {
            return Ok(refused(VaultChangeRefusal::WrongState(state)));
        }
        let (name, origins) = match checked_arguments(&name, &origins) {
            Ok(checked) => checked,
            Err(rule) => return Ok(invalid(rule)),
        };
        // Nothing cancels `add`'s prompts: it takes the service-wide lock only once the material is in hand.
        let material = match ask_material(kind, &name, exchange, future::pending).await? {
            MaterialAnswer::Typed(material) => material,
            MaterialAnswer::Invalid(rule) => return Ok(invalid(rule)),
            MaterialAnswer::CancelledByLock => return Ok(refused(VaultChangeRefusal::WrongState(ServiceState::Locked))),
        };
        Ok(match self.service.add_credential(name, material, origins).await {
            Ok(record_id) => AdminResponse::Add { record_id },
            Err(refusal) => refused(refusal),
        })
    }
}

/// Checks the name and the permitted origins. Returns the rule one of them breaks, without the value that broke it.
pub(super) fn checked_arguments(name: &str, origins: &[RequestedOrigin]) -> Result<(CredentialName, PermittedOrigins), String> {
    let name = CredentialName::try_from(name).map_err(|error| format!("invalid credential name: {}", name_rule(error.rule())))?;
    let origins = origins.iter().map(requested_origin).collect::<Result<BTreeSet<_>, _>>()?;
    let origins = PermittedOrigins::new(origins).map_err(|error| format!("invalid origins: {error}"))?;
    Ok((name, origins))
}

/// Parses a requested origin with the CLI's own origin rule, so a modified CLI gains nothing by skipping it. The host is
/// put back together with its port, so a host that carries a port, a scheme or a path of its own is refused.
fn requested_origin(origin: &RequestedOrigin) -> Result<(Host, Port), String> {
    parse_origin(&format!("{}:{}", origin.host, origin.port.get())).map_err(|error| format!("invalid origin: {error}"))
}

/// Describes the name rule broken, without the character that broke it.
pub(super) fn name_rule(rule: &NameRule) -> String {
    match rule {
        NameRule::BadStart { .. } => "it must start with a lowercase ASCII letter".to_owned(),
        NameRule::BadChar { .. } => "it may contain only a-z, 0-9, '_' and '-'".to_owned(),
        other => format!("it {other}"),
    }
}

/// The owner's answer to the secret prompts for a kind.
pub(super) enum MaterialAnswer {
    /// Material that follows its kind's rules.
    Typed(CredentialMaterial),
    /// The rule the typed material breaks, without a typed byte.
    Invalid(String),
    /// The cancel future completed while the owner was at a prompt; for `replace`, a `lock` came for the service-wide
    /// lock.
    CancelledByLock,
}

/// Prompts for `kind`'s fields and builds the material. Each prompt ends early once the future `cancel` makes completes.
/// The error is a prompt that got no owner input.
pub(super) async fn ask_material<C: Future<Output = ()>>(
    kind: CredentialKind,
    name: &CredentialName,
    exchange: &mut Exchange,
    cancel: impl Fn() -> C,
) -> Result<MaterialAnswer, ExchangeError> {
    let material = match kind {
        CredentialKind::Static => {
            let Some(key) = secret_text(exchange, format!("Secret for {name}"), cancel()).await? else {
                return Ok(MaterialAnswer::CancelledByLock);
            };
            key.map(|key| CredentialMaterial::Static { key })
        }
        CredentialKind::Basic => {
            let Some(username) = secret_text(exchange, format!("Username for {name}"), cancel()).await? else {
                return Ok(MaterialAnswer::CancelledByLock);
            };
            let Some(password) = secret_text(exchange, format!("Password for {name}"), cancel()).await? else {
                return Ok(MaterialAnswer::CancelledByLock);
            };
            username.and_then(|username| password.map(|password| CredentialMaterial::Basic { username, password }))
        }
    };
    let checked = material.and_then(|material| match material.validate() {
        Ok(()) => Ok(material),
        Err(error) => Err(format!("invalid credential material: {error}")),
    });
    Ok(checked.map_or_else(MaterialAnswer::Invalid, MaterialAnswer::Typed))
}

/// Asks for one secret value, or `None` once `cancel` completes. Both Basic fields are secret, since the username is the
/// secret when the password is empty.
async fn secret_text(
    exchange: &mut Exchange,
    label: String,
    cancel: impl Future<Output = ()>,
) -> Result<Option<Result<SecretString, String>>, ExchangeError> {
    let input = exchange
        .prompt_unless(
            &Prompt {
                label,
                secret: true,
                switchable: false,
            },
            cancel,
        )
        .await?;
    Ok(input.map(|input| secret_string(input).ok_or_else(|| "invalid credential material: a value must be UTF-8 text".to_owned())))
}

/// Reads the owner's input as text. Returns `None` when it is not UTF-8. The input's buffer is cleared when it drops
/// here.
fn secret_string(input: OwnerInput) -> Option<SecretString> {
    std::str::from_utf8(input.expose_secret()).ok().map(SecretString::from)
}

fn refused(refusal: VaultChangeRefusal) -> AdminResponse {
    let code = match refusal {
        VaultChangeRefusal::Busy => ErrorCode::Busy,
        VaultChangeRefusal::WrongState(state) => {
            return error(
                ErrorCode::WrongState,
                format!("`add` is allowed only while the service is Ready; it is {}", state_name(state)),
            );
        }
        VaultChangeRefusal::NameTaken(_) => ErrorCode::NameTaken,
        VaultChangeRefusal::Invalid(_) => ErrorCode::CredentialInvalid,
        VaultChangeRefusal::Failed(_) | VaultChangeRefusal::Uncertain { .. } => ErrorCode::VaultWriteFailed,
        // Only `replace` and `rm` plan a change of an existing record, so `add` never gets these.
        VaultChangeRefusal::UnknownCredential(_)
        | VaultChangeRefusal::InUse { .. }
        | VaultChangeRefusal::UsedByRoutes { .. }
        | VaultChangeRefusal::NotActive(_)
        | VaultChangeRefusal::ChangeUncertain { .. } => ErrorCode::VaultWriteFailed,
    };
    error(code, refusal.to_string())
}

fn invalid(rule: String) -> AdminResponse {
    error(ErrorCode::CredentialInvalid, rule)
}

fn error(code: ErrorCode, message: String) -> AdminResponse {
    AdminResponse::Error { code, message }
}
