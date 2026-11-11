//! The helper's parts: the connection it answers, the account it answers, and the TPM work.

mod connection;
mod passwd;
mod tpm;

pub use connection::Connection;
pub use passwd::uid_of;
pub use tpm::answer;
