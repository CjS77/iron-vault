// SPDX-License-Identifier: MPL-2.0
use std::io;

use super::*;
use crate::OsFs;
use crate::fault_fs::{FaultFs, FsOp};
use crate::test_dir::TestDir;

fn locked(label: &str) -> (TestDir, StateDirLock) {
    let dir = TestDir::new(label);
    let lock = StateDirLock::acquire(dir.path()).unwrap();
    (dir, lock)
}

#[test]
fn the_file_is_empty_written_and_removed() {
    let (dir, lock) = locked("owner-lock-cycle");
    assert!(!owner_lock_present(&lock, &OsFs));
    write_owner_lock(&lock, &OsFs).unwrap();
    assert!(owner_lock_present(&lock, &OsFs));
    assert_eq!(std::fs::read(dir.path().join("locked-by-owner")).unwrap(), b"");
    write_owner_lock(&lock, &OsFs).unwrap();
    assert_eq!(remove_owner_lock(&lock, &OsFs), Ok(true));
    assert_eq!(remove_owner_lock(&lock, &OsFs), Ok(false));
    assert!(!owner_lock_present(&lock, &OsFs));
}

#[test]
fn a_directory_and_a_dangling_symlink_count_as_present() {
    let (dir, lock) = locked("owner-lock-types");
    let path = dir.path().join("locked-by-owner");
    std::fs::create_dir(&path).unwrap();
    assert!(owner_lock_present(&lock, &OsFs));
    std::fs::remove_dir(&path).unwrap();
    std::os::unix::fs::symlink(dir.path().join("nowhere"), &path).unwrap();
    assert!(owner_lock_present(&lock, &OsFs));
}

#[test]
fn a_directory_that_cannot_be_listed_counts_as_present() {
    let (_dir, lock) = locked("owner-lock-list-fault");
    let fs = FaultFs::new();
    fs.fail_first(FsOp::ListDir, io::ErrorKind::PermissionDenied);
    assert!(owner_lock_present(&lock, &fs));
    fs.fail_first(FsOp::ListDir, io::ErrorKind::NotFound);
    assert!(!owner_lock_present(&lock, &fs));
}

#[test]
fn a_failed_removal_is_an_error_and_leaves_the_file() {
    let (dir, lock) = locked("owner-lock-remove-fault");
    let fs = FaultFs::new();
    write_owner_lock(&lock, &fs).unwrap();
    fs.fail_first(FsOp::RemoveFile, io::ErrorKind::Other);
    assert!(remove_owner_lock(&lock, &fs).is_err());
    assert!(owner_lock_present(&lock, &fs));
    drop(dir);
}
