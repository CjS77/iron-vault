// SPDX-License-Identifier: MPL-2.0
//! `iron-vault caller-token`: shows a newly issued caller token once, with the `token_hash` line the owner puts in their
//! config to enroll it ([admin protocol: `caller-token`](../../../../design/admin-protocol.md#caller-token-1)).

use std::fs::File;
use std::io::{self, Write};
use std::os::fd::AsFd;
use std::path::Path;

use iron_vault::admin::protocol::{AdminRequest, AdminResponse};
use iron_vault_policy::{CallerToken, TokenHash};
use secrecy::ExposeSecret;
use zeroize::Zeroizing;

use super::Exit;
use super::client::{fail, run_on, unexpected};
use super::console::ProcessConsole;

/// What the owner does next. Issuing enrolls nothing: only an approved config that names the hash does, and until then
/// any old token keeps working.
const ENROLL_NOTE: &str = "\
This token is shown once and the service keeps no copy of it.
Put the token_hash line on the caller's [callers.<name>] table and run `iron-vault config approve <file>`.
The token works only once that config is approved and active; the caller's old token, if any, keeps working until then.
";

/// Runs `caller-token`: the token alone on stdout, so `iron-vault caller-token > token` captures exactly it, and its
/// `token_hash` line and what to do with it on stderr.
pub fn run(socket: Option<&Path>) -> Exit {
    run_on(
        socket,
        AdminRequest::CallerToken,
        &mut ProcessConsole::default(),
        |response| match response {
            AdminResponse::CallerToken { token } => show(token),
            _ => unexpected(),
        },
    )
}

/// Shows `token` and its hash. The hash is taken before the token is consumed, so the two always match.
fn show(token: CallerToken) -> Exit {
    let hash = TokenHash::of(&token);
    if let Err(e) = write_token(token) {
        return fail(
            Exit::Unreachable,
            &format!("cannot write the caller token to stdout ({e}); nothing was enrolled: run the command again"),
        );
    }
    eprintln!("token_hash = \"{hash}\"");
    eprint!("{ENROLL_NOTE}");
    Exit::Success
}

/// Writes the token's text and a newline to stdout in one write, through a duplicate of fd 1: `io::Stdout` keeps a
/// buffer that is never cleared, and the line is built in a clearing buffer sized for it up front.
fn write_token(token: CallerToken) -> io::Result<()> {
    let text = token.expose_once();
    let mut line = Zeroizing::new(Vec::with_capacity(text.expose_secret().len() + 1));
    line.extend_from_slice(text.expose_secret().as_bytes());
    line.push(b'\n');
    let mut stdout = File::from(io::stdout().as_fd().try_clone_to_owned()?);
    stdout.write_all(&line)
}
