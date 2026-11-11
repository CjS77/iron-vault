//! `iron-vault reset` (`design/admin-protocol.md`, "reset"): the CLI's side of discarding the vault.
//!
//! The confirmation must be typed at a terminal, so the command checks for one before it connects: a pipe, a file, a
//! heredoc or a cron job is refused with exit code 3 and the service never hears of it. The service cannot see where an
//! answer came from, so this check is the CLI's rule. With stdin a terminal the console reads the confirmation from
//! `/dev/tty`.

use std::fs::File;
use std::io::{self, IsTerminal};
use std::path::Path;

use iron_vault::admin::protocol::{AdminRequest, AdminResponse};

use super::Exit;
use super::client::{fail, run, unexpected};

/// Runs `reset`. The service shows the summary and prompts for the confirmation; on success the result and the next step
/// go to stdout, and a warning to stderr when the vault identity may still be in memory.
pub fn run_reset(socket: Option<&Path>) -> Exit {
    if let Err(failed) = require_terminal(io::stdin().is_terminal(), || {
        File::options().read(true).write(true).open("/dev/tty")
    }) {
        let message = format!("reset's confirmation must be typed at a terminal, and {failed}; nothing was sent");
        return fail(Exit::Unreachable, &message);
    }
    run(socket, AdminRequest::Reset, |response| match response {
        AdminResponse::Reset {
            vault_id,
            removed,
            foreign,
            cleared,
            finish_uncertain,
        } => {
            let discarded = vault_id.map_or_else(|| "the vault files".to_owned(), |id| format!("vault {id}"));
            println!("reset: discarded {discarded}; {removed} files removed");
            foreign
                .iter()
                .for_each(|file| println!("left in place, move it aside before `init`: {file}"));
            if !cleared {
                eprintln!("iron-vault: warning: a request still holds secrets in the service's memory; see the service log");
            }
            if finish_uncertain {
                eprintln!(
                    "iron-vault: warning: reset.unfinished may come back after a power loss; run `iron-vault reset` again if it does"
                );
            }
            println!("next: run `iron-vault init`");
            Exit::Success
        }
        _ => unexpected(),
    })
}

/// Names the check that failed: stdin is not a terminal, or `/dev/tty` does not open.
fn require_terminal<T>(stdin_is_terminal: bool, open_tty: impl FnOnce() -> io::Result<T>) -> Result<(), String> {
    if !stdin_is_terminal {
        return Err("stdin is not a terminal".to_owned());
    }
    open_tty().map(drop).map_err(|e| format!("/dev/tty cannot be opened ({e})"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_piped_stdin_fails_the_first_check_without_opening_the_tty() {
        let failed = require_terminal(false, || -> io::Result<()> { panic!("must not open /dev/tty") });
        assert_eq!(failed, Err("stdin is not a terminal".to_owned()));
    }

    #[test]
    fn a_missing_tty_fails_the_second_check() {
        let failed = require_terminal(true, || Err::<(), _>(io::Error::from(io::ErrorKind::NotFound)));
        assert!(failed.is_err_and(|why| why.starts_with("/dev/tty cannot be opened")));
    }

    #[test]
    fn a_terminal_on_both_passes() {
        assert_eq!(require_terminal(true, || Ok(())), Ok(()));
    }
}
