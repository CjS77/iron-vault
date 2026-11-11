//! `iron-vault-tpm-signer`, the TPM signing helper (`design/tpm-approval-signer.md` "The helper process").
//!
//! systemd starts one instance per connection to the helper socket (`Accept=yes`, `MaxConnections=1`), with the
//! connection as standard input and output (`StandardInput=socket`). The instance checks the peer, reads one request
//! within 5 seconds, answers it and exits: nothing runs between requests, and no request sees another's memory.

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
    /// The TPM, as a TCTI configuration. A test seam: the unit never passes it.
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
