//! The Linux package's `postinst` check of an `iron-vault` account or group that existed before the package.
//!
//! The check is the block of `packaging/linux/debian/postinst` between its BEGIN and END markers. Each test runs that
//! block with `sh` against fixture `passwd`, `group`, `shadow`, `gshadow` and `login.defs` files in a temporary directory, so no
//! test reads the host's account files or needs root. The baseline is the account `systemd-sysusers` creates from the
//! package's `sysusers.d` line; each failing case changes one attribute of it.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

const POSTINST: &str = include_str!("../../../packaging/linux/debian/postinst");
const BEGIN: &str = "# BEGIN service account check.";
const END: &str = "# END service account check.";

/// The account database of a host where `systemd-sysusers` created `iron-vault`, beside root and a login account.
struct Accounts {
    passwd: Vec<String>,
    group: Vec<String>,
    shadow: Vec<String>,
    /// `None` is a host with no `/etc/gshadow`.
    gshadow: Option<Vec<String>>,
    login_defs: Option<String>,
}

impl Accounts {
    fn sysusers() -> Self {
        Self {
            passwd: lines(&[
                "root:x:0:0:root:/root:/bin/bash",
                "alice:x:1000:1000:Alice:/home/alice:/bin/bash",
                "iron-vault:x:998:998:Iron Vault credential proxy:/:/usr/sbin/nologin",
            ]),
            group: lines(&["root:x:0:", "sudo:x:27:alice", "alice:x:1000:", "iron-vault:x:998:"]),
            shadow: lines(&[
                "root:*:20000:0:99999:7:::",
                "alice:$6$salt$hash:20000:0:99999:7:::",
                "iron-vault:!*:20000::::::",
            ]),
            gshadow: Some(lines(&["root:*::", "sudo:*::alice", "alice:!::", "iron-vault:!*::"])),
            login_defs: Some("UID_MIN 1000\nSYS_UID_MIN 100\nSYS_UID_MAX 999\n".to_string()),
        }
    }

    /// The host before the package: no `iron-vault` account or group.
    fn without_service_account() -> Self {
        let mut accounts = Self::sysusers();
        [&mut accounts.passwd, &mut accounts.group, &mut accounts.shadow]
            .into_iter()
            .chain(accounts.gshadow.as_mut())
            .for_each(|file| file.retain(|line| !line.starts_with("iron-vault:")));
        accounts
    }

    /// Replaces the `iron-vault` entry of one file.
    fn service_entry(mut self, file: fn(&mut Self) -> &mut Vec<String>, entry: &str) -> Self {
        let lines = file(&mut self);
        let index = lines
            .iter()
            .position(|line| line.starts_with("iron-vault:"))
            .expect("an iron-vault entry");
        lines[index] = entry.to_string();
        self
    }

    fn gshadow_entry(self, entry: &str) -> Self {
        self.service_entry(|a| a.gshadow.as_mut().expect("a gshadow file"), entry)
    }

    fn passwd_entry(self, entry: &str) -> Self {
        self.service_entry(|a| &mut a.passwd, entry)
    }

    fn group_entry(self, entry: &str) -> Self {
        self.service_entry(|a| &mut a.group, entry)
    }

    fn shadow_entry(self, entry: &str) -> Self {
        self.service_entry(|a| &mut a.shadow, entry)
    }

    /// Runs the check against these files: `Ok` with no output, or `Err` with what it printed to stderr.
    fn check(&self) -> Result<(), String> {
        let dir = Scratch::new();
        fs::write(dir.0.join("passwd"), self.passwd.join("\n") + "\n").unwrap();
        fs::write(dir.0.join("group"), self.group.join("\n") + "\n").unwrap();
        fs::write(dir.0.join("shadow"), self.shadow.join("\n") + "\n").unwrap();
        if let Some(gshadow) = &self.gshadow {
            fs::write(dir.0.join("gshadow"), gshadow.join("\n") + "\n").unwrap();
        }
        if let Some(defs) = &self.login_defs {
            fs::write(dir.0.join("login.defs"), defs).unwrap();
        }
        let output = run_check(&dir.0, "shadow");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(output.stdout.is_empty(), "the check writes nothing to stdout, which debconf owns");
        match output.status.success() {
            true if stderr.is_empty() => Ok(()),
            true => panic!("the check passed but printed: {stderr}"),
            false => Err(stderr),
        }
    }
}

fn lines(entries: &[&str]) -> Vec<String> {
    entries.iter().map(ToString::to_string).collect()
}

/// The postinst's account check: its functions only, without the code that runs at configure.
fn check_block() -> &'static str {
    let start = POSTINST.find(BEGIN).expect("postinst has the BEGIN marker");
    let end = POSTINST.find(END).expect("postinst has the END marker");
    &POSTINST[start..end]
}

/// Runs the check in `dir`, which holds the fixture files, reading the shadow entries from `shadow`.
fn run_check(dir: &Path, shadow: &str) -> Output {
    let script = format!(
        "{}\npasswd_file=passwd group_file=group shadow_file={shadow} gshadow_file=gshadow \
         login_defs=login.defs\nrefuse_unsafe_service_account",
        check_block()
    );
    Command::new("sh").arg("-c").arg(script).current_dir(dir).output().expect("sh runs")
}

/// A temporary directory removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("iv-account-{}-{n}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Asserts the check refuses `accounts`, names `problem`, and says how to fix it.
fn assert_refused(accounts: &Accounts, problem: &str) {
    let message = accounts.check().expect_err("the check must refuse");
    assert!(message.contains(problem), "expected {problem:?} in:\n{message}");
    assert!(message.contains("userdel iron-vault"), "the refusal says how to fix it:\n{message}");
}

#[test]
fn sysusers_account_passes() {
    assert_eq!(Accounts::sysusers().check(), Ok(()));
}

#[test]
fn no_existing_account_passes() {
    assert_eq!(Accounts::without_service_account().check(), Ok(()));
}

#[test]
fn allowed_homes_shells_and_locked_passwords_pass() {
    [
        "iron-vault:x:998:998::/nonexistent:/usr/sbin/nologin",
        "iron-vault:x:998:998::/var/lib/iron-vault:/sbin/nologin",
        "iron-vault:x:998:998::/:/bin/false",
        "iron-vault:x:998:998::/:/usr/bin/false",
    ]
    .into_iter()
    .for_each(|entry| assert_eq!(Accounts::sysusers().passwd_entry(entry).check(), Ok(()), "{entry}"));
    [
        "iron-vault:!:20000::::::",
        "iron-vault:*:20000::::::",
        "iron-vault:!$6$salt$hash:20000::::::",
    ]
    .into_iter()
    .for_each(|entry| assert_eq!(Accounts::sysusers().shadow_entry(entry).check(), Ok(()), "{entry}"));
}

#[test]
fn missing_login_defs_means_sys_uid_max_999() {
    let accounts = Accounts {
        login_defs: None,
        ..Accounts::sysusers()
    };
    assert_eq!(accounts.check(), Ok(()));
    let accounts = Accounts {
        login_defs: None,
        ..Accounts::sysusers()
    }
    .passwd_entry("iron-vault:x:1000:998::/:/usr/sbin/nologin");
    assert_refused(&accounts, "uid 1000 is not a system uid (1 to 999)");
}

#[test]
fn login_shell_is_refused() {
    let accounts = Accounts::sysusers().passwd_entry("iron-vault:x:998:998::/:/bin/bash");
    assert_refused(&accounts, "shell /bin/bash allows a login");
    // An empty shell field means /bin/sh.
    let accounts = Accounts::sysusers().passwd_entry("iron-vault:x:998:998::/:");
    assert_refused(&accounts, "allows a login");
}

#[test]
fn unlocked_password_is_refused() {
    let accounts = Accounts::sysusers().shadow_entry("iron-vault:$6$salt$hash:20000::::::");
    assert_refused(&accounts, "the password is not locked");
    let accounts = Accounts::sysusers().shadow_entry("iron-vault::20000::::::");
    assert_refused(&accounts, "the password is not locked");
}

#[test]
fn password_in_passwd_is_refused() {
    let accounts = Accounts::sysusers().passwd_entry("iron-vault:$6$salt$hash:998:998::/:/usr/sbin/nologin");
    assert_refused(&accounts, "the password is not locked");
}

#[test]
fn uid_outside_the_system_range_is_refused() {
    let accounts = Accounts::sysusers().passwd_entry("iron-vault:x:1000:998::/:/usr/sbin/nologin");
    assert_refused(&accounts, "uid 1000 is not a system uid (1 to 999)");
    let accounts = Accounts::sysusers().passwd_entry("iron-vault:x:0:998::/:/usr/sbin/nologin");
    assert_refused(&accounts, "uid 0 is not a system uid");
}

#[test]
fn sys_uid_max_comes_from_login_defs() {
    let accounts = Accounts {
        login_defs: Some("SYS_UID_MAX\t499\n".to_string()),
        ..Accounts::sysusers()
    };
    assert_refused(&accounts, "uid 998 is not a system uid (1 to 499)");
}

#[test]
fn commented_out_sys_uid_max_is_ignored() {
    // Debian ships these lines commented out; a 499 that was read would refuse uid 998.
    let accounts = Accounts {
        login_defs: Some("UID_MIN\t\t\t 1000\n#SYS_UID_MIN\t\t  100\n#SYS_UID_MAX\t\t  499\n".to_string()),
        ..Accounts::sysusers()
    };
    assert_eq!(accounts.check(), Ok(()));
}

#[test]
fn home_outside_the_allowed_list_is_refused() {
    let accounts = Accounts::sysusers().passwd_entry("iron-vault:x:998:998::/home/iron-vault:/usr/sbin/nologin");
    assert_refused(&accounts, "home /home/iron-vault is not /, /nonexistent or /var/lib/iron-vault");
}

#[test]
fn other_primary_group_is_refused() {
    let accounts = Accounts::sysusers().passwd_entry("iron-vault:x:998:1000::/:/usr/sbin/nologin");
    assert_refused(&accounts, "the primary group is not iron-vault");
}

#[test]
fn supplementary_group_is_refused() {
    let mut accounts = Accounts::sysusers();
    accounts.group[1] = "sudo:x:27:alice,iron-vault".to_string();
    assert_refused(&accounts, "member of group sudo");
}

#[test]
fn supplementary_group_after_a_blank_is_refused() {
    // glibc skips the blank, so iron-vault is a member of sudo.
    let mut accounts = Accounts::sysusers();
    accounts.group[1] = "sudo:x:27:alice, iron-vault".to_string();
    assert_refused(&accounts, "member of group sudo");
}

#[test]
fn group_member_is_refused() {
    let accounts = Accounts::sysusers().group_entry("iron-vault:x:998:alice");
    assert_refused(&accounts, "group iron-vault: lists members alice");
}

#[test]
fn group_as_another_accounts_primary_group_is_refused() {
    let mut accounts = Accounts::sysusers();
    accounts.passwd.push("bob:x:1001:998:Bob:/home/bob:/bin/bash".to_string());
    assert_refused(&accounts, "group iron-vault: primary group of account bob");
}

#[test]
fn group_without_an_account_is_checked() {
    let mut accounts = Accounts::without_service_account();
    accounts.group.push("iron-vault:x:998:alice".to_string());
    assert_refused(&accounts, "group iron-vault: lists members alice");
}

#[test]
fn account_sharing_the_uid_is_refused() {
    let mut accounts = Accounts::sysusers();
    accounts.passwd.push("mallory:x:998:1000::/home/mallory:/bin/bash".to_string());
    assert_refused(&accounts, "account mallory: has the same uid as iron-vault");
}

#[test]
fn group_sharing_the_gid_is_refused() {
    let mut accounts = Accounts::sysusers();
    accounts.group.push("collectors:x:998:alice".to_string());
    assert_refused(&accounts, "group collectors: has the same gid as iron-vault");
}

/// Asserts the check fails closed when it cannot read a file, saying so rather than reporting an unsafe account.
fn assert_unreadable_refused(dir: &Path, shadow: &str) {
    let output = run_check(dir, shadow);
    assert!(!output.status.success(), "a check that cannot read a file must fail closed");
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(
        message.contains("iron-vault: could not check the account files for an existing iron-vault account"),
        "{message}"
    );
    assert!(
        !message.contains("already exists"),
        "an unread file says nothing about the account:\n{message}"
    );
}

/// Writes the passwd and group fixtures into a new directory, leaving the shadow file to the test.
fn without_shadow() -> Scratch {
    let accounts = Accounts::sysusers();
    let dir = Scratch::new();
    fs::write(dir.0.join("passwd"), accounts.passwd.join("\n") + "\n").unwrap();
    fs::write(dir.0.join("group"), accounts.group.join("\n") + "\n").unwrap();
    dir
}

#[test]
fn missing_shadow_is_refused() {
    let dir = without_shadow();
    assert_unreadable_refused(&dir.0, "missing");
}

#[test]
fn shadow_without_read_permission_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = without_shadow();
    let shadow = dir.0.join("shadow");
    fs::write(&shadow, Accounts::sysusers().shadow.join("\n") + "\n").unwrap();
    fs::set_permissions(&shadow, fs::Permissions::from_mode(0o000)).unwrap();
    // Root reads a mode-000 file anyway, so there is nothing to test when the tests run as root.
    if fs::read(&shadow).is_ok() {
        eprintln!("skipped: running as root");
        return;
    }
    assert_unreadable_refused(&dir.0, "shadow");
}

#[test]
fn gshadow_administrator_is_refused() {
    let accounts = Accounts::sysusers().gshadow_entry("iron-vault:!:alice:");
    assert_refused(&accounts, "group iron-vault: gshadow names administrators alice");
}

#[test]
fn gshadow_administrator_after_a_malformed_line_is_refused() {
    // gpasswd skips the bare line, so alice is still an administrator.
    let accounts = Accounts::sysusers().gshadow_entry("iron-vault\niron-vault:!:alice:");
    assert_refused(&accounts, "group iron-vault: gshadow names administrators alice");
}

#[test]
fn gshadow_group_password_is_refused() {
    let accounts = Accounts::sysusers().gshadow_entry("iron-vault:$6$salt$hash::");
    assert_refused(&accounts, "group iron-vault: gshadow sets a group password");
}

#[test]
fn gshadow_member_is_refused() {
    // /etc/group lists none, so only gshadow shows that alice can join.
    let accounts = Accounts::sysusers().gshadow_entry("iron-vault:!::alice");
    assert_refused(&accounts, "group iron-vault: gshadow lists members alice");
}

#[test]
fn locked_or_empty_gshadow_passwords_pass() {
    [
        "iron-vault:!::",
        "iron-vault:*::",
        "iron-vault:!!::",
        "iron-vault:::",
        "iron-vault:!$6$salt$hash::",
    ]
    .into_iter()
    .for_each(|entry| assert_eq!(Accounts::sysusers().gshadow_entry(entry).check(), Ok(()), "{entry}"));
}

#[test]
fn missing_gshadow_passes() {
    let accounts = Accounts {
        gshadow: None,
        ..Accounts::sysusers()
    };
    assert_eq!(accounts.check(), Ok(()));
}

#[test]
fn gshadow_without_read_permission_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let accounts = Accounts::sysusers();
    let dir = without_shadow();
    fs::write(dir.0.join("shadow"), accounts.shadow.join("\n") + "\n").unwrap();
    let gshadow = dir.0.join("gshadow");
    fs::write(&gshadow, accounts.gshadow.expect("a gshadow file").join("\n") + "\n").unwrap();
    fs::set_permissions(&gshadow, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::read(&gshadow).is_ok() {
        eprintln!("skipped: running as root");
        return;
    }
    assert_unreadable_refused(&dir.0, "shadow");
}
