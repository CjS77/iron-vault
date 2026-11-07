use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use iron_vault_store::{RecipientKey, RecoveryKey};
use secrecy::ExposeSecret;

use super::*;
use crate::trusted_path::{ComponentKind, FileId, Mode, OwnerRequirement, Problem};

const PROFILE: DeploymentProfile = DeploymentProfile::Container;
const SECRET_PREFIX: &str = "AGE-SECRET-KEY";

fn me() -> u32 {
    rustix::process::getuid().as_raw()
}

fn owner() -> ExpectedOwner {
    ExpectedOwner { uid: me() }
}

/// Root-owned directories above the leaf. The real temp directory is a shared sticky directory the rule rightly
/// refuses, so these tests check the leaf through its open descriptor and leave the walk to the rule's own tests.
fn ancestors() -> Vec<PathComponent> {
    ["/", "/run"]
        .map(|path| PathComponent {
            path: PathBuf::from(path),
            uid: 0,
            owner_name: None,
            gid: 0,
            group_name: None,
            mode: Mode::new(0o755),
            kind: ComponentKind::Directory,
            id: FileId { dev: 0, ino: 0 },
        })
        .to_vec()
}

/// A fresh directory under the system temp directory, removed on drop.
struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "iv-handoff-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        Self(dir)
    }

    /// Writes `bytes` to `host-unlock` with `mode`.
    fn handoff(&self, bytes: &[u8], mode: u32) -> PathBuf {
        let path = self.0.join("host-unlock");
        let _ = fs::remove_file(&path);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        path
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn read(path: &Path) -> Result<RecipientIdentity, HandoffError> {
    read_leaf(PROFILE, owner(), path, &ancestors())
}

fn key() -> (String, RecipientKey) {
    let (secret, recipient) = RecoveryKey::generate();
    (secret.expose_secret().to_owned(), recipient)
}

/// The error for `bytes` written as a `0400` file.
fn refusal(bytes: &[u8]) -> HandoffError {
    let dir = Dir::new();
    read(&dir.handoff(bytes, 0o400)).map(|_| ()).unwrap_err()
}

#[test]
fn a_good_file_parses_to_its_recipient_key() {
    let (secret, expected) = key();
    let dir = Dir::new();
    let identity = read(&dir.handoff(secret.as_bytes(), 0o400)).unwrap();
    assert_eq!(identity.recipient_key(), expected);
}

#[test]
fn one_trailing_newline_is_accepted() {
    let (secret, expected) = key();
    let dir = Dir::new();
    let identity = read(&dir.handoff(format!("{secret}\n").as_bytes(), 0o600)).unwrap();
    assert_eq!(identity.recipient_key(), expected);
}

#[test]
fn a_missing_file_is_absent() {
    let dir = Dir::new();
    assert!(read_handoff(PROFILE, owner(), &dir.0.join("host-unlock")).unwrap().is_none());
    assert!(
        read_handoff(PROFILE, owner(), &dir.0.join("no-such-dir/host-unlock"))
            .unwrap()
            .is_none()
    );
}

#[test]
fn an_age_keygen_file_with_its_comments_is_refused() {
    let (secret, recipient) = key();
    let full = format!("# created: 2026-11-07T09:26:21Z\n# public key: {recipient}\n{secret}\n");
    assert_eq!(refusal(full.as_bytes()), HandoffError::TooLong);
    assert_eq!(
        refusal(format!("# host unlock\n{secret}\n").as_bytes()),
        HandoffError::NotAnIdentity
    );
}

#[test]
fn a_group_or_other_readable_file_is_refused() {
    let (secret, _) = key();
    let dir = Dir::new();
    [0o440, 0o640, 0o404, 0o604, 0o644].into_iter().for_each(|mode| {
        let error = read(&dir.handoff(secret.as_bytes(), mode)).map(|_| ()).unwrap_err();
        let HandoffError::Untrusted(unsafe_path) = error else {
            panic!("mode {mode:o}: {error:?}");
        };
        assert_eq!(
            unsafe_path.problem,
            Problem::ModeTooOpen {
                found: Mode::new(mode),
                allowed: Mode::new(0o600)
            }
        );
    });
}

#[test]
fn a_symlink_is_refused() {
    let (secret, _) = key();
    let dir = Dir::new();
    let target = dir.handoff(secret.as_bytes(), 0o400);
    let link = dir.0.join("link");
    symlink(&target, &link).unwrap();
    let error = read(&link).map(|_| ()).unwrap_err();
    assert_eq!(
        error,
        HandoffError::Untrusted(UnsafePath {
            path: link,
            problem: Problem::NotARegularFile
        })
    );
}

#[test]
fn a_directory_in_place_of_the_file_is_refused() {
    let dir = Dir::new();
    let path = dir.0.join("host-unlock");
    fs::create_dir(&path).unwrap();
    let error = read(&path).map(|_| ()).unwrap_err();
    assert!(matches!(
        error,
        HandoffError::Untrusted(UnsafePath {
            problem: Problem::NotARegularFile,
            ..
        })
    ));
}

#[test]
fn a_file_owned_by_another_account_is_refused() {
    let (secret, _) = key();
    let dir = Dir::new();
    let path = dir.handoff(secret.as_bytes(), 0o400);
    let stranger = ExpectedOwner { uid: me() + 1 };
    let error = read_leaf(PROFILE, stranger, &path, &ancestors()).map(|_| ()).unwrap_err();
    assert_eq!(
        error,
        HandoffError::Untrusted(UnsafePath {
            path,
            problem: Problem::WrongOwner {
                found: me(),
                expected: OwnerRequirement::Uid(me() + 1)
            }
        })
    );
}

#[test]
fn an_oversized_file_is_too_long_but_one_at_the_cap_is_only_not_an_identity() {
    assert_eq!(refusal(&[b'A'; MAX_HANDOFF_LEN + 1]), HandoffError::TooLong);
    assert_eq!(refusal(&[b'A'; MAX_HANDOFF_LEN]), HandoffError::NotAnIdentity);
}

#[test]
fn text_that_is_not_exactly_one_secret_key_is_refused() {
    let (secret, recipient) = key();
    let wrong: [Vec<u8>; 7] = [
        Vec::new(),
        b"\n".to_vec(),
        vec![0xff, 0xfe, 0x00, 0x80],
        recipient.to_string().into_bytes(),
        format!("{secret}\n\n").into_bytes(),
        format!(" {secret}").into_bytes(),
        format!("{secret}\r\n").into_bytes(),
    ];
    wrong
        .iter()
        .for_each(|bytes| assert_eq!(refusal(bytes), HandoffError::NotAnIdentity, "{bytes:?}"));
}

#[test]
fn no_error_shows_the_secret() {
    let (secret, recipient) = key();
    let errors = [
        refusal(format!("# comment\n{secret}\n").as_bytes()),
        refusal(format!("# {recipient}\n# created\n{secret}\n").as_bytes()),
        refusal(format!("{secret}\n\n").as_bytes()),
        HandoffError::Untrusted(UnsafePath {
            path: PathBuf::from(HANDOFF_PATH),
            problem: Problem::NotARegularFile,
        }),
        HandoffError::Unreadable(io::ErrorKind::PermissionDenied),
    ];
    errors.iter().for_each(|error| {
        assert!(!error.to_string().contains(SECRET_PREFIX), "{error}");
        assert!(!format!("{error:?}").contains(SECRET_PREFIX), "{error:?}");
        assert!(!error.to_string().contains(&secret), "{error}");
    });
}
