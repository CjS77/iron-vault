// SPDX-License-Identifier: MPL-2.0
//! `design/v0-acceptance.md`, checked against the files it names.
//!
//! The index maps each v0 release check to the tests that show it, as `path::function` relative to the repository root.
//! A renamed or deleted test would leave the index claiming evidence that no longer runs, so every reference must name
//! a file that exists and, when it names a function, a file holding `fn function`. Release script items and evidence
//! files are checked for the file only.

use std::fs;
use std::path::{Path, PathBuf};

/// The top-level directories a reference may start with; any other backticked text is prose, not a reference.
const ROOTS: [&str; 5] = ["crates/", "scripts/", "design/", "packaging/", ".github/"];

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(relative)
}

/// Every backticked span of the index that starts with one of [`ROOTS`].
fn references(index: &str) -> Vec<&str> {
    index
        .split('`')
        .skip(1)
        .step_by(2)
        .filter(|span| ROOTS.iter().any(|root| span.starts_with(root)))
        .collect()
}

/// Why `reference` points at nothing, or `None` when its file (and function, if it names one) exists.
fn broken(reference: &str) -> Option<String> {
    let (file, function) = reference
        .split_once("::")
        .map_or((reference, None), |(file, function)| (file, Some(function)));
    let path = repo_path(file);
    if !path.exists() {
        return Some(format!("{reference}: no file {file}"));
    }
    let function = function?;
    let source = fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let declared = ["(", "<"].iter().any(|after| source.contains(&format!("fn {function}{after}")));
    (!declared).then(|| format!("{reference}: no fn {function} in {file}"))
}

#[test]
fn every_test_the_acceptance_index_names_exists() {
    let index_path = repo_path("design/v0-acceptance.md");
    let index = fs::read_to_string(&index_path).unwrap_or_else(|e| panic!("cannot read {}: {e}", index_path.display()));
    let references = references(&index);
    assert!(
        references.iter().filter(|reference| reference.contains("::")).count() > 50,
        "parsed only {} references",
        references.len()
    );
    let broken: Vec<_> = references.iter().filter_map(|reference| broken(reference)).collect();
    assert!(broken.is_empty(), "v0-acceptance.md names missing tests or files: {broken:#?}");
}
