//! `iron-vault init` (`design/admin-protocol.md`, "init"): the CLI's side of creating the vault.
//!
//! The recovery key is shown on the controlling terminal only, so the command checks for one before it sends the
//! request: a CLI that could not show the key never has the service generate one. Once the key is shown, a command that
//! ends without a service answer (a dropped or timed-out connection, or a signal) must still tell the owner what to do
//! with it, because the service cannot answer a closed connection (design/vault-initialization.md, "Failing after the
//! reveal").

use std::path::Path;

use iron_vault::admin::protocol::{AdminRequest, AdminResponse, OwnerInput, Prompt, RevealedSecret};
use iron_vault::admin::{DEAD_RECOVERY_KEY, UNCONFIRMED_RECOVERY_KEY};

use super::Exit;
use super::client::{fail, run_on, unexpected};
use super::console::{self, InputError, OwnerConsole, ProcessConsole};

/// Runs `init` and prints the new vault's ID and the kinds of recipient enrolled. The recovery key never goes to stdout.
pub fn run(socket: Option<&Path>, host_unlock: bool) -> Exit {
    if let Err(e) = console::ensure_terminal() {
        let message = format!("`init` shows the recovery key on the controlling terminal only, and there is none ({e}); nothing was sent");
        return fail(Exit::Unreachable, &message);
    }
    let mut console = RecoveryKeyWatch::new(ProcessConsole::default());
    let exit = run_on(
        socket,
        AdminRequest::Init { host_unlock },
        &mut console,
        |response| match response {
            AdminResponse::Init {
                vault_id,
                version,
                recipients,
            } => {
                println!("initialized vault {vault_id}: approval version {version} committed");
                println!(
                    "recipients: {}",
                    recipients.iter().map(|role| role.name()).collect::<Vec<_>>().join(", ")
                );
                println!("run iron-vault unlock to start serving");
                Exit::Success
            }
            _ => unexpected(),
        },
    );
    match (exit, console.advice()) {
        (Exit::Unreachable, Some(advice)) => fail(exit, &advice),
        _ => exit,
    }
}

/// How far the exchange has got with the recovery key, as far as the CLI knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// No recovery key has been shown.
    Unseen,
    /// The key was shown and `yes` has not been sent, so the service writes nothing.
    Shown,
    /// `yes` was given after the key was shown, so the service may be writing the vault.
    Confirmed,
}

/// An owner console that passes everything through and remembers whether the recovery key was shown and confirmed, for
/// the advice the owner needs if the command ends without a service answer.
pub struct RecoveryKeyWatch<C> {
    console: C,
    stage: Stage,
}

impl<C> RecoveryKeyWatch<C> {
    /// Watches the exchange through `console`.
    pub fn new(console: C) -> Self {
        Self {
            console,
            stage: Stage::Unseen,
        }
    }

    /// What to do with the recovery key if the command ends now without a service answer; `None` before it is shown.
    pub fn advice(&self) -> Option<String> {
        match self.stage {
            Stage::Unseen => None,
            Stage::Shown => Some(format!(
                "init ended before the recovery key was confirmed, so the service wrote nothing; {DEAD_RECOVERY_KEY}"
            )),
            Stage::Confirmed => Some(format!(
                "init ended without an answer after `yes`, so the vault may or may not be written: {UNCONFIRMED_RECOVERY_KEY}"
            )),
        }
    }

    /// Moves to `stage`, and has the signal watcher give the advice for it too.
    fn reach(&mut self, stage: Stage) {
        self.stage = stage;
        console::set_signal_advice(self.advice());
    }
}

impl<C: OwnerConsole> OwnerConsole for RecoveryKeyWatch<C> {
    fn collect(&mut self, prompt: &Prompt) -> Result<OwnerInput, InputError> {
        let input = self.console.collect(prompt)?;
        // The input counts as sent once collected: if sending it fails, the unknown outcome's advice is still safe.
        if self.stage == Stage::Shown && input.expose_secret() == b"yes" {
            self.reach(Stage::Confirmed);
        }
        Ok(input)
    }

    fn notice(&mut self, text: &str) -> Result<(), InputError> {
        self.console.notice(text)
    }

    fn reveal(&mut self, secret: &RevealedSecret) -> Result<(), InputError> {
        self.console.reveal(secret)?;
        self.reach(Stage::Shown);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
