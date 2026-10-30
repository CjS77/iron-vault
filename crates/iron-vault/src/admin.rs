//! The admin interface: what the CLI and the service exchange over the admin socket (spec §3.2).

// The server and its socket use tokio and rustix, which this crate depends on only on Linux, like the peer-credential
// adapter the server relies on.
#[cfg(target_os = "linux")]
pub mod dispatch;
pub mod principal;
pub mod protocol;
#[cfg(target_os = "linux")]
pub mod server;
#[cfg(target_os = "linux")]
pub mod socket;

/// The admin socket's file name in the runtime directory, where the service binds it and the CLI looks for it.
pub const ADMIN_SOCKET_NAME: &str = "admin.sock";
