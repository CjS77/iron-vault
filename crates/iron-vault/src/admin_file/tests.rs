use super::*;

const WALKED_ID: FileId = FileId { dev: 2049, ino: 77 };

fn walked() -> PathComponent {
    PathComponent {
        path: PathBuf::from("/etc/iron-vault/tls/server.key"),
        uid: 997,
        owner_name: None,
        gid: 997,
        group_name: None,
        mode: Mode::new(0o600),
        kind: ComponentKind::RegularFile,
        id: WALKED_ID,
    }
}

fn opened() -> Opened {
    Opened {
        regular: true,
        uid: 997,
        gid: 997,
        mode: Mode::new(0o600),
        id: WALKED_ID,
        len: 42,
    }
}

#[test]
fn the_walked_file_matches_whatever_its_length() {
    assert!(matches_walk(&walked(), &opened()));
    assert!(matches_walk(&walked(), &Opened { len: 7, ..opened() }));
}

#[test]
fn a_different_inode_device_type_owner_group_or_mode_does_not_match() {
    let differing = [
        Opened {
            id: FileId { ino: 78, ..WALKED_ID },
            ..opened()
        },
        Opened {
            id: FileId { dev: 2050, ..WALKED_ID },
            ..opened()
        },
        Opened {
            regular: false,
            ..opened()
        },
        Opened { uid: 1001, ..opened() },
        Opened { gid: 1001, ..opened() },
        Opened {
            mode: Mode::new(0o644),
            ..opened()
        },
    ];
    differing
        .iter()
        .for_each(|other| assert!(!matches_walk(&walked(), other), "{other:?}"));
}

#[test]
fn a_walked_entry_that_is_not_a_regular_file_never_matches() {
    let walked = PathComponent {
        kind: ComponentKind::Directory,
        ..walked()
    };
    assert!(!matches_walk(&walked, &opened()));
}

#[test]
fn the_certificate_and_key_have_their_own_rules() {
    assert_eq!(AdminFile::Certificate.rule(), TrustedPathRule::AdminCertificate);
    assert_eq!(AdminFile::PrivateKey.rule(), TrustedPathRule::AdminPrivateKey);
}

/// Reads of real files. The walk itself is skipped: the system temp directory is a shared sticky directory, which
/// both rules rightly refuse, so each test collects the leaf as the walk would and reads through it.
#[cfg(target_os = "linux")]
mod real_files {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    static NEXT: AtomicU32 = AtomicU32::new(0);

    /// A fresh directory under the system temp directory, removed on drop.
    struct Dir(PathBuf);

    impl Dir {
        fn new(name: &str) -> Self {
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!("iv-admin-file-{name}-{}-{n}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir(&dir).unwrap();
            Self(dir)
        }

        /// Writes `bytes` to a new file in the directory and returns its path.
        fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, bytes).unwrap();
            path
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// The leaf component the path walk would have checked.
    fn walk(path: &Path) -> PathComponent {
        path_metadata::collect(path).unwrap().pop().unwrap()
    }

    #[test]
    fn the_walked_file_is_read_whole() {
        let dir = Dir::new("whole");
        let path = dir.file("server.crt", b"certificate");
        let bytes = read_walked(&path, &walk(&path), MAX_ADMIN_FILE_LEN).unwrap();
        assert_eq!(bytes.as_slice(), b"certificate");
        assert_eq!(bytes.capacity(), bytes.len());
    }

    #[test]
    fn a_file_of_exactly_the_cap_is_read() {
        let dir = Dir::new("cap");
        let path = dir.file("server.crt", &[7; 16]);
        assert_eq!(read_walked(&path, &walk(&path), 16).unwrap().len(), 16);
    }

    #[test]
    fn an_oversized_file_is_refused() {
        let dir = Dir::new("oversized");
        let path = dir.file("server.crt", &[7; 17]);
        assert_eq!(
            read_walked(&path, &walk(&path), 16),
            Err(AdminFileError::TooLarge { path, max_len: 16 })
        );
    }

    #[test]
    fn a_file_larger_than_the_default_cap_is_refused() {
        let dir = Dir::new("default-cap");
        let path = dir.file("server.crt", &vec![7; usize::try_from(MAX_ADMIN_FILE_LEN).unwrap() + 1]);
        assert!(matches!(
            read_walked(&path, &walk(&path), MAX_ADMIN_FILE_LEN),
            Err(AdminFileError::TooLarge { .. })
        ));
    }

    #[test]
    fn a_file_replaced_after_the_walk_is_refused() {
        let dir = Dir::new("replaced");
        let path = dir.file("server.key", b"walked");
        let walked = walk(&path);
        let swapped = dir.file("swapped", b"planted");
        fs::rename(&swapped, &path).unwrap();
        assert_eq!(
            read_walked(&path, &walked, MAX_ADMIN_FILE_LEN),
            Err(AdminFileError::Changed { path })
        );
    }

    #[test]
    fn a_symlink_swapped_in_after_the_walk_is_refused() {
        let dir = Dir::new("symlink");
        let path = dir.file("server.key", b"walked");
        let walked = walk(&path);
        let target = dir.file("target", b"planted");
        fs::remove_file(&path).unwrap();
        symlink(&target, &path).unwrap();
        assert_eq!(
            read_walked(&path, &walked, MAX_ADMIN_FILE_LEN),
            Err(AdminFileError::Changed { path })
        );
    }

    #[test]
    fn a_file_removed_after_the_walk_is_an_io_error() {
        let dir = Dir::new("removed");
        let path = dir.file("server.key", b"walked");
        let walked = walk(&path);
        fs::remove_file(&path).unwrap();
        assert_eq!(
            read_walked(&path, &walked, MAX_ADMIN_FILE_LEN),
            Err(AdminFileError::Io {
                path,
                kind: io::ErrorKind::NotFound
            })
        );
    }
}
