//! `iron-vault-tpm-signer`, the TPM signing helper: the one process that opens the TPM to create and use TPM approval
//! keys for the service ([TPM approval signer: the helper process](../../../design/tpm-approval-signer.md#the-helper-process)).
//!
//! systemd starts one instance per connection to the helper socket (`Accept=yes`, `MaxConnections=1`), with the
//! connection as standard input (`StandardInput=socket`); the response goes back on that descriptor. Standard output
//! and error go to the journal (`StandardOutput=journal`), so a diagnostic never reaches the peer. Each instance lives
//! for one request:
//!
//! ```text
//! systemd accepts a connection ──▶ start one instance, connection on stdin
//!   mark the process non-dumpable
//!   check the peer's uid ─────────── not the service account ──▶ exit, nothing read
//!   read one frame within 5 s ────── bad frame or request ─────▶ answer Malformed
//!   answer the request on the TPM
//!   write one response and exit
//! ```
//!
//! Nothing runs between requests, and no request sees another's memory.

mod helper;

use std::process::ExitCode;

use clap::Parser;
use iron_vault_tpm_protocol::{ProtocolError, Request, Response};
use rustix::process::{DumpableBehavior, set_dumpable_behavior};

use crate::helper::{Connection, answer, uid_of};

/// Answers one TPM signing request from the Iron Vault service.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// The TPM to use, as a TCTI configuration. Tests point it at a software TPM; the systemd unit never passes it.
    #[arg(long, default_value = "device:/dev/tpmrm0")]
    tcti: String,
    /// The only account whose connection is answered; any other peer is refused before its request is read.
    #[arg(long, default_value = "iron-vault")]
    peer_user: String,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("iron-vault-tpm-signer: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> anyhow::Result<()> {
    // Before anything is read, so neither a core dump nor a same-uid ptrace sees an authorization value.
    set_dumpable_behavior(DumpableBehavior::NotDumpable)?;
    let args = Args::parse();
    let mut connection = Connection::accept(uid_of(&args.peer_user)?)?;
    let response = match connection.read_request() {
        Ok(body) => Request::decode(&body).map_or(Response::Malformed, |request| answer(&args.tcti, request)),
        Err(ProtocolError::Io(error)) => return Err(error.into()),
        Err(_) => Response::Malformed,
    };
    connection.write_response(&response)
}
