//! The Linux package's systemd units and `sysusers.d`/`tmpfiles.d` files, read as text from `packaging/linux`.
//!
//! The unit decides the account, core-dump, memory-locking and sandbox properties of a protected install, so each
//! directive `design/linux-package.md` requires is pinned here: dropping one fails CI. The directory modes in
//! `tmpfiles.d` are checked by running the service's own trusted-path rules over a directory with that owner and
//! mode, so the two cannot drift apart.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

use iron_vault::deployment::{DeploymentProfile, SERVICE_ACCOUNT};
use iron_vault::trusted_path::{self, ComponentKind, ExpectedOwner, FileId, Mode, PathComponent, TrustedPathRule};

/// The uid the checks give the `iron-vault` account; the rules compare uids, so any non-root value will do.
const SERVICE_UID: u32 = 997;

fn packaging(file: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/linux").join(file);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// The `Key=value` lines of one unit-file section, in file order.
fn section(unit: &str, name: &str) -> Vec<(String, String)> {
    let header = format!("[{name}]");
    unit.lines()
        .map(str::trim)
        .scan(false, |inside, line| {
            if line.starts_with('[') {
                *inside = line == header;
            }
            Some((*inside, line))
        })
        .filter(|(inside, line)| *inside && !line.starts_with('[') && !line.starts_with('#'))
        .filter_map(|(_, line)| line.split_once('='))
        .map(|(key, value)| (key.trim().to_string(), value.trim().to_string()))
        .collect()
}

fn values<'a>(entries: &'a [(String, String)], key: &str) -> Vec<&'a str> {
    entries.iter().filter(|(k, _)| k == key).map(|(_, v)| v.as_str()).collect()
}

fn assert_directives(entries: &[(String, String)], required: &[(&str, &str)]) {
    required.iter().for_each(|(key, value)| {
        assert_eq!(values(entries, key), [*value], "{key} must appear exactly once, as {key}={value}");
    });
}

#[test]
fn service_unit_has_every_required_directive() {
    let unit = packaging("iron-vault.service");
    assert_directives(
        &section(&unit, "Service"),
        &[
            ("Type", "exec"),
            ("ExecStart", "/usr/bin/iron-vault serve"),
            ("ExecReload", "/bin/kill -HUP $MAINPID"),
            ("User", SERVICE_ACCOUNT),
            ("Group", SERVICE_ACCOUNT),
            ("Restart", "on-failure"),
            ("RestartSec", "1"),
            ("LimitCORE", "0"),
            ("LimitMEMLOCK", "infinity"),
            ("UMask", "0077"),
            ("LogsDirectory", "iron-vault"),
            ("LogsDirectoryMode", "0750"),
            ("ProtectSystem", "strict"),
            ("ReadWritePaths", "/etc/iron-vault /var/lib/iron-vault /run/iron-vault"),
            ("ProtectHome", "yes"),
            ("PrivateDevices", "yes"),
            ("PrivateTmp", "yes"),
            ("NoNewPrivileges", "yes"),
            ("CapabilityBoundingSet", ""),
            ("RestrictAddressFamilies", "AF_UNIX AF_INET AF_INET6"),
            ("SystemCallFilter", "@system-service"),
            ("MemoryDenyWriteExecute", "yes"),
        ],
    );
    // A start limit hit by a crash loop would fail every listener socket and release its port (specification §7).
    assert_directives(&section(&unit, "Unit"), &[("StartLimitIntervalSec", "0")]);
    assert_directives(&section(&unit, "Install"), &[("WantedBy", "multi-user.target")]);
}

#[test]
fn service_unit_sets_no_environment() {
    // The service must not inherit an administrator's proxy or trust-root variables (specification 3.7).
    let service = section(&packaging("iron-vault.service"), "Service");
    ["Environment", "EnvironmentFile", "PassEnvironment", "UnsetEnvironment"]
        .iter()
        .for_each(|key| assert!(values(&service, key).is_empty(), "the service unit must not set {key}="));
}

#[test]
fn listener_template_names_no_address_and_passes_its_socket_to_the_service() {
    let unit = packaging("iron-vault-listener@.socket");
    let socket = section(&unit, "Socket");
    assert_directives(&socket, &[("FileDescriptorName", "%i"), ("Service", "iron-vault.service")]);
    // The administrator's drop-in supplies the address, so an instance without one fails rather than binds by accident.
    ["ListenStream", "ListenDatagram", "ListenSequentialPacket", "ListenFIFO"]
        .iter()
        .for_each(|key| assert!(values(&socket, key).is_empty(), "the template must not set {key}="));
    // A restart of the service must leave the socket open, so the socket is not part of the service.
    ["PartOf", "BindsTo"]
        .iter()
        .for_each(|key| assert!(values(&section(&unit, "Unit"), key).is_empty(), "the template must not set {key}="));
    // systemd's default trigger limit stays, so a service that keeps exiting cleanly cannot spin forever
    // (design/linux-package.md, Listener socket units).
    ["TriggerLimitIntervalSec", "TriggerLimitBurst"]
        .iter()
        .for_each(|key| assert!(values(&socket, key).is_empty(), "the template must not set {key}="));
    assert_directives(&section(&unit, "Install"), &[("WantedBy", "sockets.target")]);
}

#[test]
fn sysusers_creates_the_service_account_with_no_login_shell() {
    let line = packaging("sysusers.d/iron-vault.conf");
    let fields: Vec<&str> = line.split_whitespace().collect();
    assert_eq!(
        fields,
        [
            "u",
            SERVICE_ACCOUNT,
            "-",
            "\"Iron",
            "Vault",
            "credential",
            "proxy\"",
            "-",
            "/usr/sbin/nologin"
        ]
    );
}

/// One `d` line of the tmpfiles file: path, mode, owner, group.
struct Directory {
    path: PathBuf,
    mode: u32,
    owner: String,
    group: String,
}

fn tmpfiles_directories() -> Vec<Directory> {
    packaging("tmpfiles.d/iron-vault.conf")
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            match fields[..] {
                ["d", path, mode, owner, group, "-"] => Directory {
                    path: PathBuf::from(path),
                    mode: u32::from_str_radix(mode, 8).unwrap(),
                    owner: owner.to_string(),
                    group: group.to_string(),
                },
                _ => panic!("unexpected tmpfiles line: {line}"),
            }
        })
        .collect()
}

fn component(path: &Path, uid: u32, mode: u32) -> PathComponent {
    PathComponent {
        path: path.to_path_buf(),
        uid,
        owner_name: None,
        gid: uid,
        group_name: None,
        mode: Mode::new(mode),
        kind: ComponentKind::Directory,
        id: FileId { dev: 0, ino: 0 },
    }
}

/// The chain the adapter would report for a directory `path` created as `leaf`: root-owned `0755` ancestors, which is
/// how the distributions ship `/`, `/etc`, `/var`, `/var/lib` and `/run`.
fn chain(path: &Path, leaf: PathComponent) -> Vec<PathComponent> {
    let mut ancestors: Vec<PathComponent> = path.ancestors().skip(1).map(|dir| component(dir, 0, 0o755)).collect();
    ancestors.reverse();
    ancestors.into_iter().chain([leaf]).collect()
}

fn rule_for(path: &Path) -> TrustedPathRule {
    match path.to_str() {
        Some("/etc/iron-vault") => TrustedPathRule::ConfigDir,
        Some("/var/lib/iron-vault") => TrustedPathRule::StateDir,
        Some("/run/iron-vault") => TrustedPathRule::RuntimeDir,
        other => panic!("tmpfiles creates {other:?}, which has no trusted-path rule here; add it to this test"),
    }
}

#[test]
fn tmpfiles_creates_exactly_the_three_service_directories() {
    let paths: Vec<PathBuf> = tmpfiles_directories().into_iter().map(|d| d.path).collect();
    assert_eq!(
        paths,
        ["/etc/iron-vault", "/var/lib/iron-vault", "/run/iron-vault"].map(PathBuf::from)
    );
}

#[test]
fn tmpfiles_directories_pass_the_trusted_path_rules() {
    tmpfiles_directories().iter().for_each(|dir| {
        assert_eq!(
            (dir.owner.as_str(), dir.group.as_str()),
            (SERVICE_ACCOUNT, SERVICE_ACCOUNT),
            "{}",
            dir.path.display()
        );
        let components = chain(&dir.path, component(&dir.path, SERVICE_UID, dir.mode));
        let checked = trusted_path::check(
            rule_for(&dir.path),
            DeploymentProfile::Protected,
            ExpectedOwner { uid: SERVICE_UID },
            &components,
        );
        assert!(
            checked.is_ok(),
            "{} at {:04o} is refused by its rule: {checked:?}",
            dir.path.display(),
            dir.mode
        );
    });
}

#[test]
fn log_directory_mode_passes_the_log_dir_rule() {
    let mode = values(&section(&packaging("iron-vault.service"), "Service"), "LogsDirectoryMode")
        .first()
        .map(|mode| u32::from_str_radix(mode, 8).unwrap())
        .expect("LogsDirectoryMode is set");
    let path = Path::new("/var/log/iron-vault");
    let checked = trusted_path::check(
        TrustedPathRule::LogDir,
        DeploymentProfile::Protected,
        ExpectedOwner { uid: SERVICE_UID },
        &chain(path, component(path, SERVICE_UID, mode)),
    );
    assert!(
        checked.is_ok(),
        "LogsDirectoryMode={mode:04o} is refused by the LogDir rule: {checked:?}"
    );
}
