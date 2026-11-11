//! `iron-vault import <bundle>` (`design/migration-bundle.md`, "Transfer"): the CLI's side of making a
//! vault from a migration bundle.
//!
//! The bundle path stays in the CLI, which opens the file as the owner and streams it after the request. Like `init`, the
//! command shows the recovery key on the controlling terminal only, so it checks for one before it connects.

mod config_copy;

use std::fs::{self, File, Metadata};
use std::path::Path;

use iron_vault::admin::protocol::{AdminRequest, AdminResponse, ImportResult};
use iron_vault_store::migration_bundle::MAX_BUNDLE_LEN;

use super::Exit;
use super::client::{Bundle, answered, fail, unexpected};
use super::console::{self, ProcessConsole};
use super::init::RecoveryKeyWatch;
use config_copy::{ConfigCopy, shell_word};

/// Runs `import`: refuses without a terminal, a usable `bundle` or a free config copy name before it connects, streams the
/// bundle after the request, and prints the result with the steps that follow. The copy exists only after a success.
pub fn run_import(socket: Option<&Path>, bundle: &Path) -> Exit {
    if let Err(e) = console::ensure_terminal() {
        let message =
            format!("`import` shows the recovery key on the controlling terminal only, and there is none ({e}); nothing was sent");
        return fail(Exit::Unreachable, &message);
    }
    let mut file = match open_bundle(bundle) {
        Ok(file) => file,
        Err(message) => return fail(Exit::Usage, &format!("{message}; nothing was sent")),
    };
    let copy = match ConfigCopy::create(bundle) {
        Ok(copy) => copy,
        Err(message) => return fail(Exit::Usage, &format!("{message}; nothing was sent")),
    };
    let mut console = RecoveryKeyWatch::import(ProcessConsole::default());
    let answer = answered(
        socket,
        AdminRequest::Import { host_unlock: false },
        &mut console,
        &mut Bundle::Send(&mut file),
    );
    match (answer, console.advice()) {
        (Ok(AdminResponse::Import(result)), _) => {
            print_result(&result, kept_copy(copy, bundle, &result));
            Exit::Success
        }
        (Ok(_), _) => unexpected(),
        (Err(Exit::Unreachable), Some(advice)) => fail(Exit::Unreachable, &advice),
        (Err(exit), _) => exit,
    }
}

/// Opens `bundle` read-only and requires a regular file of at most [`MAX_BUNDLE_LEN`] bytes. The path is checked before it
/// is opened, since opening a pipe would wait for a writer, and the open file is checked again.
fn open_bundle(bundle: &Path) -> Result<File, String> {
    let name = bundle.display();
    let regular = |metadata: &Metadata| match (metadata.is_file(), metadata.len() <= MAX_BUNDLE_LEN) {
        (false, _) => Err(format!("{name} is not a regular file")),
        (true, false) => Err(format!("{name} is larger than the {MAX_BUNDLE_LEN} bytes a bundle may be")),
        (true, true) => Ok(()),
    };
    regular(&fs::metadata(bundle).map_err(|e| format!("cannot read {name}: {e}"))?)?;
    let file = File::open(bundle).map_err(|e| format!("cannot open {name}: {e}"))?;
    regular(&file.metadata().map_err(|e| format!("cannot read {name}: {e}"))?)?;
    Ok(file)
}

/// Fills the config copy from the bundle. The import committed whatever happens here, so a copy that cannot be made is
/// removed and reported as a warning, and the owner checks their own copy of the config against the printed digest.
fn kept_copy(copy: ConfigCopy, bundle: &Path, result: &ImportResult) -> Option<ConfigCopy> {
    copy.fill(bundle, &result.digest)
        .inspect_err(|reason| eprintln!("iron-vault: warning: the import committed, but no config copy was kept: {reason}"))
        .ok()
}

/// What the import made and what the owner does next. The vault is Locked and routes nothing until a config is approved.
fn print_result(result: &ImportResult, copy: Option<ConfigCopy>) {
    let digest: String = result.digest.iter().map(|byte| format!("{byte:02x}")).collect();
    println!(
        "imported vault {}: {} credentials, approval version {} committed, highest reserved version {}",
        result.vault_id, result.records, result.version, result.highest_reserved
    );
    println!(
        "recipients: {}",
        result.recipients.iter().map(|role| role.name()).collect::<Vec<_>>().join(", ")
    );
    println!("the source's committed config has the digest blake2b:{digest}");
    println!("next:");
    println!("  1. iron-vault unlock                    (the service then answers 503 until a config is approved)");
    println!("  2. {}", approve_step(copy.as_ref()));
    println!("  3. iron-vault recovery check            with the new recovery key");
    println!("  4. compare the versions above with the source's `iron-vault status`");
    println!("  5. only then retire the source");
}

/// Step 2: the exact approval command for the config copy, and which passphrase it asks for. Without a copy the owner
/// brings the source's config and checks it against the digest first.
fn approve_step(copy: Option<&ConfigCopy>) -> String {
    match copy {
        Some(copy) => format!(
            "iron-vault config approve {}\n     the source's config, copied beside the bundle. It asks for the approval passphrase of one \
             of the approvers the summary listed.\n     Approve an edited copy instead if the new host needs changes.",
            shell_word(copy.path())
        ),
        None => "iron-vault config approve <config>   your copy of the source's config, checked against the digest above".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("iron-vault-import-cli-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_regular_file_within_the_limit_opens() {
        let dir = scratch("regular");
        let path = dir.join("vault.bundle");
        fs::write(&path, b"bytes").unwrap();
        assert!(open_bundle(&path).is_ok());
        // A link to a regular file is read through, as for any other command that opens a path.
        symlink(&path, dir.join("link")).unwrap();
        assert!(open_bundle(&dir.join("link")).is_ok());
    }

    #[test]
    fn a_file_over_the_limit_is_refused_by_size() {
        let dir = scratch("large");
        let path = dir.join("vault.bundle");
        File::create(&path).unwrap().set_len(MAX_BUNDLE_LEN + 1).unwrap();
        let refused = open_bundle(&path).unwrap_err();
        assert!(refused.contains("larger than"), "{refused}");
        File::create(&path).unwrap().set_len(MAX_BUNDLE_LEN).unwrap();
        assert!(open_bundle(&path).is_ok());
    }

    #[test]
    fn a_directory_a_pipe_and_a_missing_file_are_refused_without_waiting() {
        let dir = scratch("irregular");
        let fifo = dir.join("pipe");
        assert!(std::process::Command::new("mkfifo").arg(&fifo).status().unwrap().success());
        [dir.clone(), fifo].iter().for_each(|path| {
            let refused = open_bundle(path).unwrap_err();
            assert!(refused.contains("not a regular file"), "{refused}");
        });
        assert!(open_bundle(&dir.join("absent")).unwrap_err().contains("cannot read"));
    }
}
