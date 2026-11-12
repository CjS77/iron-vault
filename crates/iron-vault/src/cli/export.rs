//! `iron-vault export <bundle>`: the CLI's side of writing a migration bundle
//! ([migration bundle: transfer](../../../../design/migration-bundle.md#transfer)).
//!
//! The bundle path stays in the CLI, which writes the file as the owner. The bundle grows in a partial file beside it,
//! created before the request so a permission problem shows before any prompt, and appears under the name the owner
//! asked for only once the service's result vouches for every byte. A cut bundle never has the bundle's name.

use std::path::Path;

use iron_vault::admin::protocol::{AdminRequest, AdminResponse};
use iron_vault::bundle_file::PartialBundle;
use iron_vault_store::OsFs;

use super::Exit;
use super::client::{Bundle, Received, answered, fail, unexpected};
use super::console::ProcessConsole;

/// Runs `export`: refuses an existing `bundle` and a leftover partial file before it connects, receives the bundle into
/// the partial file, and keeps it under `bundle` only after a success whose byte count matches what arrived.
pub fn run_export(socket: Option<&Path>, bundle: &Path) -> Exit {
    let mut partial = match PartialBundle::create(&OsFs, bundle) {
        Ok(partial) => partial,
        Err(message) => return fail(Exit::Usage, &format!("{message}; nothing was sent")),
    };
    let (answer, received) = {
        let mut receiving = Bundle::receiving(&mut partial);
        let answer = answered(socket, AdminRequest::Export, &mut ProcessConsole::default(), &mut receiving);
        (answer, receiving.received().unwrap_or_default())
    };
    match answer {
        Ok(AdminResponse::Export { vault_id, records, bytes }) => match keep(&mut partial, received, bytes) {
            Ok(()) => {
                println!(
                    "exported vault {vault_id} to {}: {records} credentials, {bytes} bytes",
                    bundle.display()
                );
                println!("the source vault keeps serving until you retire it");
                println!("the bundle opens only with the export passphrase");
                Exit::Success
            }
            Err(message) => fail(Exit::Unreachable, &format!("{message}; no bundle was kept")),
        },
        Ok(_) => unexpected(),
        Err(exit) => exit,
    }
}

/// Keeps the bundle once it is whole: the empty frame arrived and the byte count is the result's. An error means no
/// bundle has the bundle's name.
fn keep(partial: &mut PartialBundle<'_, OsFs>, received: Received, expected: u64) -> Result<(), String> {
    if !received.ended || received.bytes != expected {
        return Err(format!(
            "the bundle is incomplete: {} bytes arrived, and the service sent {expected}",
            received.bytes
        ));
    }
    // The bundle is whole under its name once `keep` succeeds, so a failure to tidy up is a warning, not a failed export.
    if let Some(e) = partial.keep().map_err(|e| e.to_string())? {
        eprintln!(
            "iron-vault: warning: the bundle is written, but {} could not be synced or {} removed: {e}",
            partial.dir().display(),
            partial.path().display()
        );
    }
    Ok(())
}
