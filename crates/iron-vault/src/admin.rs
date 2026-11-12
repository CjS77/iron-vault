//! The admin interface: how the owner's CLI asks the running service to change the vault, over the admin socket
//! ([spec §5](../../../design/iron-vault-specification.md#5-service-and-cli-separation-of-concerns);
//! [admin protocol](../../../design/admin-protocol.md)).
//!
//! The service owns every operation, so the CLI only carries the owner's request and answers. The service decides
//! what to ask for, prompts for each secret itself, and checks who is connected before it reads a byte. One connection
//! carries one exchange:
//!
//! ```text
//! CLI ──connect──→ admin.sock                        (socket: mode 0600, owned by the service account)
//!                      │
//!                      ▼
//! server: the kernel's uid for the peer ──→ principal: an admin principal? ──no──→ not-admin-principal, close
//!                      │ yes: AdminPrincipal
//!                      ▼
//! server: read one admin request                    (protocol: frames and their codec)
//!                      │
//!                      ▼
//! dispatch: the command's handler                   (init, unlock, add, export, recipient add, ...)
//!                      │ prompts, notices, reveals and bundle data through the Exchange
//!                      ▼
//! server: one admin response, then close
//! ```
//!
//! Each command has a module of its own. The constants below are the owner guidance that both the service and the CLI
//! print, so the two always say the same thing.

// The server and its socket use tokio and rustix, which this crate depends on only on Linux, like the peer-credential
// adapter the server relies on.
#[cfg(target_os = "linux")]
mod add;
#[cfg(target_os = "linux")]
mod approve;
#[cfg(target_os = "linux")]
mod approver_add;
#[cfg(target_os = "linux")]
mod approver_answer;
#[cfg(target_os = "linux")]
mod approver_list;
#[cfg(target_os = "linux")]
mod approver_remove;
#[cfg(target_os = "linux")]
pub mod dispatch;
#[cfg(target_os = "linux")]
mod export;
mod forget_machine;
#[cfg(target_os = "linux")]
mod import;
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
mod reset;
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

/// What the owner does with a recovery key that `init` showed and then ended without writing a vault for. The service
/// says it with each such refusal or failure, and the CLI says it when the command is cancelled before `yes` was sent
/// ([vault initialization: Failing after the reveal](../../../design/vault-initialization.md#failing-after-the-reveal)).
pub const DEAD_RECOVERY_KEY: &str = "the recovery key shown opens nothing: discard it";

/// What the owner does with a recovery key that `recipient add --recovery` showed when the rewrap may or may not have
/// committed. The CLI says it when the command ends without an answer after the vault passphrase was sent. The CLI
/// never sees the key's recipient key, so this text cannot name it; the service names it with
/// [`unconfirmed_rotated_key`] ([recipients: `recipient add --recovery`](../../../design/recipients.md#recipient-add---recovery)).
pub const UNCONFIRMED_ROTATED_KEY: &str = "keep the recovery key and run `iron-vault recipient list`. If it lists the new recovery key, \
    the key is enrolled: check it with `iron-vault recovery check`. If it does not, discard the key";

/// Builds the service's form of [`UNCONFIRMED_ROTATED_KEY`], naming `key`, the new recovery key's recipient key. The
/// owner needs the name because `recipient list` shows the old recovery key beside the new one.
pub fn unconfirmed_rotated_key(key: &impl std::fmt::Display) -> String {
    format!(
        "keep the recovery key and run `iron-vault recipient list`. If it lists {key}, the key is enrolled: check it with \
         `iron-vault recovery check`. If it does not, discard the key"
    )
}

/// What the owner does with a recovery key when `init` may or may not have written its vault. The service says it when
/// the commit point of `init` may not survive power loss, and the CLI says it when the command ends without an answer
/// after `yes`.
pub const UNCONFIRMED_RECOVERY_KEY: &str = "keep the recovery key and run `iron-vault init` again. If it starts over with a new \
    recovery key, this key is dead: discard it. If it answers `busy`, the first run is still writing: wait a few seconds and \
    run it again. If it answers `already-initialized` and says the vault is Initialized, a vault stands, but it may not be \
    the one this key opens: once the vault is unlocked, confirm the key with `iron-vault recovery check` and keep it only if \
    that passes. If it says Unrecognized, files init did not write are present and the key is not confirmed either";

/// [`UNCONFIRMED_RECOVERY_KEY`] for `import`: what the owner does with a recovery key when `import` may or may not have
/// written its vault. The service says it when the commit point may not survive power loss, and the CLI says it when
/// the command ends without an answer after `yes`.
pub const UNCONFIRMED_IMPORT_KEY: &str = "keep the recovery key and run `iron-vault import` again. If it starts over with a new \
    recovery key, this key is dead: discard it. If it answers `busy`, the first run is still writing: wait a few seconds and \
    run it again. If it answers `already-initialized` and says the vault is Initialized, a vault stands, but it may not be \
    the one this key opens: once the vault is unlocked, confirm the key with `iron-vault recovery check` and keep it only if \
    that passes. If it says Unrecognized, files import did not write are present and the key is not confirmed either";
