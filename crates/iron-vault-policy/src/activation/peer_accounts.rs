//! Resolving each peer caller's `user` to the uid the kernel will report for it (spec §3.4).

use std::collections::BTreeMap;

use super::{AccountDirectory, ActivationError};
use crate::account_name::AccountName;
use crate::caller::CallerAuth;
use crate::name::{CallerName, ListenerName};
use crate::validated::ValidatedConfig;

/// The uid of root, which no peer caller may name.
const ROOT_UID: u32 = 0;

/// A peer caller whose account resolved to an acceptable uid.
type Resolved<'a> = (&'a CallerName, &'a ListenerName, u32);

/// Every peer caller's uid, or every reason one cannot be used: unknown and privileged accounts in caller name order,
/// then uids shared on one listener in listener and uid order.
pub(super) fn resolve(
    config: &ValidatedConfig,
    accounts: &impl AccountDirectory,
) -> Result<BTreeMap<CallerName, u32>, Vec<ActivationError>> {
    let service = accounts.service_account_uid();
    let (resolved, refused): (Vec<_>, Vec<_>) = config
        .callers()
        .iter()
        .filter_map(|(name, caller)| match caller.auth() {
            CallerAuth::Peer(user) => Some(resolve_caller(name, user, accounts, service).map(|uid| (name, caller.listener(), uid))),
            CallerAuth::Token(_) | CallerAuth::IsolatedNetwork => None,
        })
        .partition(Result::is_ok);
    let resolved: Vec<_> = resolved.into_iter().filter_map(Result::ok).collect();
    let errors: Vec<_> = refused.into_iter().filter_map(Result::err).chain(shared_uids(&resolved)).collect();
    match errors.is_empty() {
        true => Ok(resolved.into_iter().map(|(name, _, uid)| (name.clone(), uid)).collect()),
        false => Err(errors),
    }
}

/// The uid of `caller`'s account `user`, unless the account is missing, root or the service account.
fn resolve_caller(caller: &CallerName, user: &AccountName, accounts: &impl AccountDirectory, service: u32) -> Result<u32, ActivationError> {
    let uid = accounts.uid(user).ok_or_else(|| ActivationError::UnknownAccount {
        caller: caller.clone(),
        user: user.clone(),
    })?;
    match uid == ROOT_UID || uid == service {
        true => Err(ActivationError::PrivilegedAccount {
            caller: caller.clone(),
            user: user.clone(),
        }),
        false => Ok(uid),
    }
}

/// One error per uid that more than one caller on a listener resolved to.
///
/// Validation already refuses two callers naming the same account; this catches different names for one uid, such as
/// `passwd` aliases, which only the host can reveal.
fn shared_uids(resolved: &[Resolved<'_>]) -> Vec<ActivationError> {
    let groups = resolved.iter().fold(
        BTreeMap::<(&ListenerName, u32), Vec<CallerName>>::new(),
        |mut groups, (name, listener, uid)| {
            groups.entry((*listener, *uid)).or_default().push((*name).clone());
            groups
        },
    );
    groups
        .into_iter()
        .filter(|(_, callers)| callers.len() > 1)
        .map(|((listener, uid), callers)| ActivationError::SharedPeerAccount {
            listener: listener.clone(),
            uid,
            callers,
        })
        .collect()
}

#[cfg(test)]
mod tests;
