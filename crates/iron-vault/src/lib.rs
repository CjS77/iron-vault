//! Iron Vault service library: the parts of the binary that are tested on their own or shared between its modules.

pub mod admin;
pub mod admin_file;
pub mod caller_token;
pub mod deployment;
pub mod logging;
pub mod path_metadata;
pub mod peer;
// The request socket accepts on tokio, which this crate depends on only on Linux.
#[cfg(target_os = "linux")]
pub mod request_socket;
// Adopting activated sockets uses listenfd and rustix, which this crate depends on only on Linux.
#[cfg(target_os = "linux")]
pub mod socket_activation;
// Binding socket files uses rustix, which this crate depends on only on Linux.
#[cfg(target_os = "linux")]
pub mod socket_file;
mod tls;
pub mod trusted_path;
pub mod trusted_path_report;
pub mod upstream;

#[cfg(test)]
mod secret_types_tests;
