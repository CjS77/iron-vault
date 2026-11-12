//! `iron-vault forget-machine`: the CLI's side of the retired-machine check ([forget machine](../../../../design/forget-machine.md)).
//!
//! The service reports two facts; everything else printed here is fixed text. The CLI spawns no process: the commands in
//! the guidance are for the administrator to run on the retired machine, and this module only prints them.

use std::path::Path;

use iron_vault::admin::protocol::{AdminRequest, AdminResponse, RecoveryStatus};

use super::Exit;
use super::client::{run, unexpected};
use super::status::recovery_line;

/// The steps for the retired machine. They are the same for every call, so two runs print the same bytes.
const GUIDANCE: &str = "\
Iron Vault runs none of these steps. Steps 1 to 3 are for the retired machine, run as root there; the lost-or-stolen steps below
run on the vault that stays.

If this machine held TPM unlock, its recipient had the role host-unlock:

1. Find out what else uses the TPM. Clearing it destroys every key it holds.
   - disk encryption: `systemd-cryptenroll DEVICE` for each LUKS device lists its TPM keyslots;
   - other sealed credentials, in unit files and in the credstore directories:
     `grep -rlE 'LoadCredentialEncrypted|SetCredentialEncrypted|ImportCredential' /etc/systemd /run/systemd /usr/lib/systemd`
     and `ls /etc/credstore.encrypted /run/credstore.encrypted /usr/lib/credstore.encrypted /usr/local/lib/credstore.encrypted`;
   - persistent handles: `tpm2_getcap handles-persistent`. The handle 0x81000001 is systemd's storage root key, shared by every
     `systemd-creds` user on the machine;
   - NV indices: `tpm2_getcap handles-nv-index`. Clearing the TPM destroys them, and other software keeps state there: the
     systemd-pcrlock policy (LUKS keyslots enrolled with `--tpm2-pcrlock` depend on it) and tpm2-totp;
   - other software that keeps keys in the TPM, such as Clevis or tpm2-pkcs11, and every other user of the machine.
2. Delete the sealed credential: `systemctl stop iron-vault-host-unlock.service`, then `rm /etc/iron-vault-host/host-unlock.cred`.
   A copy of that file in a backup still opens on this TPM.
3. Clear the TPM only when step 1 found nothing else that needs it and the recovery path is verified (see the warnings above, if
   any). Use the firmware's clear-TPM setting, or `tpm2_clear`. If anything else uses the TPM, leave it: step 2 has retired the
   machine from this vault, and only old backup copies stay reachable through this TPM.

If the machine was lost or stolen, removing its recipient could not revoke what was already copied. On the vault that stays,
reissue every provider credential at its provider, then run `iron-vault replace NAME --origin ORIGIN` for each one. Give the
names and origins that `iron-vault list` shows.

If the machine held only an added or recovery key, there is no TPM step: delete that key where it was kept.
";

/// Runs `forget-machine` for `recipient`. A key that is still enrolled is the service's `machine-not-forgotten` error, exit 1;
/// otherwise any warnings go to stderr, then the facts and the guidance to stdout, with exit 0.
pub fn run_forget_machine(socket: Option<&Path>, recipient: String) -> Exit {
    let key = recipient.clone();
    run(socket, AdminRequest::ForgetMachine { recipient }, |response| match response {
        AdminResponse::ForgetMachine { independence, recovery } => {
            warnings(independence.as_deref(), &recovery)
                .iter()
                .for_each(|warning| eprintln!("iron-vault: warning: {warning}"));
            print!("{}", render(&key, independence.as_deref(), &recovery));
            Exit::Success
        }
        _ => unexpected(),
    })
}

/// The stdout text: the key as given, the two checks, then the guidance.
fn render(key: &str, independence: Option<&str>, recovery: &RecoveryStatus) -> String {
    let rule = independence.map_or_else(|| "holds".to_owned(), |part| format!("BROKEN ({part})"));
    format!(
        "{key} is not a recipient of this vault. Check that it is the key the retired machine had: this command cannot tell a \
         removed key from one that was never enrolled.\nindependence rule: {rule}\n{}\n\n{GUIDANCE}",
        recovery_line(recovery)
    )
}

/// What the administrator must fix before clearing any TPM; empty when the independence rule holds and a recovery check has
/// run with no reminder due. A vault that was never checked, or whose record is unusable, has not shown a second way in.
fn warnings(independence: Option<&str>, recovery: &RecoveryStatus) -> Vec<String> {
    let broken =
        independence.map(|part| format!("the vault no longer meets the independence rule ({part}); fix that before you clear any TPM"));
    let unverified = (!recovery.verified()).then(|| {
        let state = match recovery {
            RecoveryStatus::Checked { .. } => "overdue",
            RecoveryStatus::NeverChecked { .. } => "has never run",
            RecoveryStatus::Unknown { .. } => "is not on record",
        };
        format!("the recovery check {state}: run `iron-vault recovery check` with your offline recovery key before you clear any TPM")
    });
    broken.into_iter().chain(unverified).collect()
}

#[cfg(test)]
mod tests;
