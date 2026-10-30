//! Iron Vault service library: the parts of the binary that are tested on their own or shared between its modules.

pub mod admin;
pub mod admin_file;
pub mod caller_token;
pub mod deployment;
pub mod logging;
pub mod path_metadata;
pub mod peer;
// Binding socket files uses rustix, which this crate depends on only on Linux.
#[cfg(target_os = "linux")]
pub mod socket_file;
pub mod trusted_path;
pub mod trusted_path_report;

#[cfg(test)]
mod secret_types_tests;
