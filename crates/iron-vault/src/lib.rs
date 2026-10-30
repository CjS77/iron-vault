//! Iron Vault service library: the parts of the binary that are tested on their own or shared between its modules.

pub mod admin;
pub mod path_metadata;
pub mod trusted_path;
pub mod trusted_path_report;

#[cfg(test)]
mod secret_types_tests;
