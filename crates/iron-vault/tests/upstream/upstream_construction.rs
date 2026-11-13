// SPDX-License-Identifier: MPL-2.0
//! Implementation spec §1 asks for one controlled outbound-client constructor. `clippy.toml` refuses reqwest's named
//! constructors, but clippy cannot name a trait method such as `Client::default`, so this test searches every Rust
//! source in the workspace for the forms clippy misses.

use std::fs;
use std::path::{Path, PathBuf};

/// The one file that may name reqwest's client types: the upstream client's constructor lives there.
const CONSTRUCTOR_FILE: &str = "crates/iron-vault/src/upstream/client.rs";

/// The one test file that may build a reqwest client: it shows reqwest's default retry policy, which the constructor
/// replaces, so it cannot go through the constructor.
const RETRY_CONTROL_FILE: &str = "crates/iron-vault/tests/upstream/reqwest_retry_control.rs";

/// The one other test file that may build a reqwest client: it needs a raw `reqwest::Error`, which the constructor's
/// client never hands out, to show that its error kind label drops the URL.
const LIBRARY_ERROR_FILE: &str = "crates/iron-vault/tests/logging/library_error_redaction.rs";

/// Constructions clippy cannot refuse, which no file may contain.
const REFUSED_EVERYWHERE: [&str; 2] = ["Client::default", "ClientBuilder::default"];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Every `.rs` file under `dir`, in path order.
fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir).unwrap().map(|entry| entry.unwrap().path()).collect();
    entries.sort();
    entries
        .into_iter()
        .flat_map(|path| match path.is_dir() {
            true => rust_files(&path),
            false if path.extension().is_some_and(|extension| extension == "rs") => vec![path],
            false => Vec::new(),
        })
        .collect()
}

/// Each `(file, line)` in the workspace's crates that contains a refused form. A file other than the constructor's
/// may not name a reqwest client type at all, so a `Default::default()` typed as one is caught where it is named.
///
/// The search reads one line at a time, so it is a backstop, not a proof. It misses `let c: Client = Default::default()`
/// in the constructor's own file, which names `Client` freely, and in any file that imports the type over several
/// lines (`use reqwest::{` on one line, `Client,` on the next).
fn violations() -> Vec<String> {
    let root = workspace_root();
    let this_file = Path::new(file!()).file_name().unwrap();
    rust_files(&root.join("crates"))
        .into_iter()
        .filter(|path| path.file_name() != Some(this_file))
        .flat_map(|path| {
            let relative = path.strip_prefix(&root).unwrap().to_string_lossy().into_owned();
            let text = fs::read_to_string(&path).unwrap();
            let may_build_client = [CONSTRUCTOR_FILE, RETRY_CONTROL_FILE, LIBRARY_ERROR_FILE].contains(&relative.as_str());
            text.lines()
                .enumerate()
                .filter(|(_, line)| refused(line, may_build_client))
                .map(|(number, line)| format!("{relative}:{}: {}", number + 1, line.trim()))
                .collect::<Vec<_>>()
        })
        .collect()
}

fn refused(line: &str, may_build_client: bool) -> bool {
    REFUSED_EVERYWHERE.iter().any(|form| line.contains(form)) || (!may_build_client && names_reqwest_client(line))
}

fn names_reqwest_client(line: &str) -> bool {
    line.contains("reqwest") && line.contains("Client")
}

#[test]
fn only_the_upstream_client_constructor_builds_a_reqwest_client() {
    let violations = violations();
    assert!(
        violations.is_empty(),
        "reqwest client built outside UpstreamClient::new:\n{}",
        violations.join("\n")
    );
}

#[test]
fn the_search_sees_the_constructor_file() {
    let root = workspace_root();
    assert!(rust_files(&root.join("crates")).contains(&root.join(CONSTRUCTOR_FILE)));
    assert!(refused("let client = reqwest::Client::default();", true));
    assert!(refused("let client: reqwest::Client = Default::default();", false));
}
