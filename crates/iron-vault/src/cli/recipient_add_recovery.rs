//! `iron-vault recipient add --recovery` (`design/recipients.md`, "`recipient add --recovery`"): the CLI's side of
//! rotating the offline recovery key.
//!
//! Like `init`, it shows the new key on the controlling terminal only, so it checks for one before sending the request, and
//! it tells the owner what to do with the key if the command ends without a service answer.

use std::path::Path;

use iron_vault::admin::protocol::{AdminRequest, AdminResponse};

use super::Exit;
use super::client::{fail, run_on, unexpected};
use super::console::{self, ProcessConsole};
use super::init::RecoveryKeyWatch;

/// Runs `recipient add --recovery`. The service shows the summary, the new key and the completion notice; nothing but those
/// is printed on success.
pub fn run(socket: Option<&Path>, label: String) -> Exit {
    if let Err(e) = console::ensure_terminal() {
        let message = format!(
            "`recipient add --recovery` shows the recovery key on the controlling terminal only, and there is none ({e}); nothing was sent"
        );
        return fail(Exit::Unreachable, &message);
    }
    let mut console = RecoveryKeyWatch::rotation(ProcessConsole::default());
    let exit = run_on(
        socket,
        AdminRequest::RecipientAddRecovery { label },
        &mut console,
        |response| match response {
            AdminResponse::RecipientAdd { .. } => Exit::Success,
            _ => unexpected(),
        },
    );
    match (exit, console.advice()) {
        (Exit::Unreachable, Some(advice)) => fail(exit, &advice),
        _ => exit,
    }
}
