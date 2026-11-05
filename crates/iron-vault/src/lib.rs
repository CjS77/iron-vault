//! Iron Vault service library: the parts of the binary that are tested on their own or shared between its modules.

pub mod admin;
pub mod admin_file;
pub mod caller_token;
pub mod config_check;
pub mod connection_tags;
pub mod content_coding;
pub mod deployment;
pub mod hardening;
pub mod library_error;
// The TLS acceptor runs on tokio and tokio-rustls, which this crate depends on only on Linux.
#[cfg(target_os = "linux")]
pub mod listener_tls;
pub mod logging;
pub mod path_metadata;
pub mod peer;
pub mod pipeline;
// The proxy handler answers through hyper on tokio, which this crate depends on only on Linux.
#[cfg(target_os = "linux")]
pub mod proxy_handler;
// The request listeners accept on tokio, which this crate depends on only on Linux.
#[cfg(target_os = "linux")]
pub mod request_listeners;
// The request server runs hyper on tokio, which this crate depends on only on Linux.
#[cfg(target_os = "linux")]
pub mod request_server;
// The request socket accepts on tokio, which this crate depends on only on Linux.
#[cfg(target_os = "linux")]
pub mod request_socket;
pub mod scrub;
// The service context serves its request listeners on tokio, which this crate depends on only on Linux.
#[cfg(target_os = "linux")]
pub mod service_context;
pub mod service_state;
pub mod serving_snapshot;
// Adopting activated sockets uses listenfd and rustix, which this crate depends on only on Linux.
#[cfg(target_os = "linux")]
pub mod socket_activation;
// Binding socket files uses rustix, which this crate depends on only on Linux.
#[cfg(target_os = "linux")]
pub mod socket_file;
pub mod standing;
mod tls;
pub mod trusted_path;
pub mod trusted_path_report;
pub mod upstream;
pub mod vault_change_check;
pub mod vault_change_summary;

#[cfg(test)]
mod secret_types_tests;
