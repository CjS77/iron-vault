//! The binary's I/O: the connection it answers, the account it accepts, and the TPM commands it runs.

mod connection;
mod passwd;
mod tpm;

pub use connection::Connection;
pub use passwd::uid_of;
pub use tpm::answer;
