// SPDX-License-Identifier: MPL-2.0
use std::path::PathBuf;

use iron_vault::admin::protocol::MAX_CONFIG_LEN;

use super::*;

const REFERENCE: &str = include_str!("../../../../../book/src/reference/configuration-example.toml");
const COMPOSE: &str = include_str!("../../../../../packaging/compose/config.example.toml");

/// A value that must never appear in a diagnostic about the file's size.
const MARKER: &str = "SENTINEL-NOT-IN-DIAGNOSTICS";

/// A temporary config file holding the given bytes, removed on drop.
struct ConfigFile(PathBuf);

impl ConfigFile {
    fn new(name: &str, bytes: &[u8]) -> Self {
        let path = std::env::temp_dir().join(format!("iv-config-check-{}-{name}.toml", std::process::id()));
        std::fs::write(&path, bytes).unwrap();
        Self(path)
    }
}

impl Drop for ConfigFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn invalid_text(bytes: &[u8]) -> String {
    match check_bytes(bytes) {
        Err(e @ CheckError::Invalid(_)) => e.to_string(),
        other => panic!("expected an invalid config, got {other:?}"),
    }
}

#[test]
fn the_reference_configs_pass() {
    check_bytes(REFERENCE.as_bytes()).unwrap();
    check_bytes(COMPOSE.as_bytes()).unwrap();
}

#[test]
fn a_file_that_is_not_utf8_is_invalid() {
    assert!(invalid_text(&[0xff, 0xfe, 0x00]).contains("not valid UTF-8"));
}

#[test]
fn a_missing_or_unsupported_schema_version_is_invalid() {
    assert!(invalid_text(b"[listeners.l]\n").contains("schema_version"));
    assert!(invalid_text(b"schema_version = 99\n").contains("unsupported schema version 99"));
}

#[test]
fn a_toml_error_names_its_line_and_column() {
    let text = invalid_text(b"schema_version = 1\n[callers\n");
    assert!(text.contains("line 2"), "{text}");
}

#[test]
fn every_cross_section_failure_is_listed() {
    let hash = "0".repeat(64);
    let config =
        format!("schema_version = 1\n[callers.me]\nlistener = \"nowhere\"\ntoken_hash = \"blake2b:{hash}\"\nroutes = [\"missing\"]\n");
    let text = invalid_text(config.as_bytes());
    assert!(text.contains("listener nowhere, which is not defined"), "{text}");
    assert!(text.contains("route missing, which is not defined"), "{text}");
}

#[test]
fn a_file_that_passes_exits_zero_and_a_bad_one_exits_one() {
    let good = ConfigFile::new("good", REFERENCE.as_bytes());
    assert!(check_file(&good.0).is_ok());
    let bad = ConfigFile::new("bad", b"schema_version = 99\n");
    assert_eq!(check_file(&bad.0).unwrap_err().exit(), Exit::CommandError);
}

#[test]
fn a_file_that_cannot_be_read_is_a_usage_error() {
    let missing = std::env::temp_dir().join("iv-config-check-does-not-exist.toml");
    let error = check_file(&missing).unwrap_err();
    assert_eq!(error.exit(), Exit::Usage);
    assert!(error.to_string().contains("cannot read the config file"), "{error}");
}

#[test]
fn a_file_over_the_limit_is_refused_without_quoting_it() {
    let longest = ConfigFile::new("longest", &[b'#'; MAX_CONFIG_LEN]);
    assert_eq!(read_config(&longest.0).unwrap().bytes().len(), MAX_CONFIG_LEN);
    let over = ConfigFile::new("over", &[MARKER.as_bytes(), &[b'#'; MAX_CONFIG_LEN]].concat());
    let error = check_file(&over.0).unwrap_err();
    assert_eq!(error.exit(), Exit::Usage);
    let message = error.to_string();
    assert!(message.contains("longer than") && !message.contains(MARKER), "{message}");
}
