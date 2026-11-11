//! The admin interface: what the CLI and the service exchange over the admin socket (spec §5).

// The server and its socket use tokio and rustix, which this crate depends on only on Linux, like the peer-credential
// adapter the server relies on.
#[cfg(target_os = "linux")]
mod add;
#[cfg(target_os = "linux")]
mod approve;
#[cfg(target_os = "linux")]
mod approver_add;
#[cfg(target_os = "linux")]
mod approver_list;
#[cfg(target_os = "linux")]
pub mod dispatch;
#[cfg(target_os = "linux")]
mod init;
#[cfg(target_os = "linux")]
mod list;
#[cfg(target_os = "linux")]
pub mod migration_authorization;
#[cfg(target_os = "linux")]
mod owner_presence;
pub mod principal;
pub mod protocol;
#[cfg(target_os = "linux")]
mod recipient_add;
#[cfg(target_os = "linux")]
mod recipient_list;
#[cfg(target_os = "linux")]
mod recipient_remove;
#[cfg(target_os = "linux")]
mod recovery_check;
#[cfg(target_os = "linux")]
mod replace;
#[cfg(target_os = "linux")]
mod rm;
#[cfg(target_os = "linux")]
pub mod server;
#[cfg(target_os = "linux")]
pub mod socket;
#[cfg(target_os = "linux")]
mod unlock;

/// The admin socket's file name in the runtime directory, where the service binds it and the CLI looks for it.
pub const ADMIN_SOCKET_NAME: &str = "admin.sock";

/// What the owner does with a recovery key that `init` showed and then ended without writing a vault for: the service
/// says it with each such refusal or failure, and the CLI when the command is cancelled before `yes` was sent
/// (design/vault-initialization.md, "Failing after the reveal").
pub const DEAD_RECOVERY_KEY: &str = "the recovery key shown opens nothing: discard it";

/// What the owner does with a recovery key that `recipient add --recovery` showed, when the rewrap may or may not have
/// committed, as the CLI says it when the command ends after the vault passphrase was sent without an answer. The CLI never
/// sees the key's recipient key; the service names it with [`unconfirmed_rotated_key`]
/// (design/recipients.md, "`recipient add --recovery`").
pub const UNCONFIRMED_ROTATED_KEY: &str = "keep the recovery key and run `iron-vault recipient list`. If it lists the new recovery key, \
    the key is enrolled: check it with `iron-vault recovery check`. If it does not, discard the key";

/// [`UNCONFIRMED_ROTATED_KEY`] for the service, naming the new recovery key's recipient key, because `recipient list` shows
/// the old recovery key beside it.
pub fn unconfirmed_rotated_key(key: &impl std::fmt::Display) -> String {
    format!(
        "keep the recovery key and run `iron-vault recipient list`. If it lists {key}, the key is enrolled: check it with \
         `iron-vault recovery check`. If it does not, discard the key"
    )
}

/// What the owner does with a recovery key when `init` may or may not have written its vault: the service says it when
/// init's commit point may not survive power loss, and the CLI when the command ends after `yes` without an answer.
pub const UNCONFIRMED_RECOVERY_KEY: &str = "keep the recovery key and run `iron-vault init` again. If it starts over with a new \
    recovery key, this key is dead: discard it. If it answers `busy`, the first run is still writing: wait a few seconds and \
    run it again. If it answers `already-initialized` and says the vault is Initialized, a vault stands, but it may not be \
    the one this key opens: once the vault is unlocked, confirm the key with `iron-vault recovery check` and keep it only if \
    that passes. If it says Unrecognized, files init did not write are present and the key is not confirmed either";
