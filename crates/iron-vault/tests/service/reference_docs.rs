//! The book's reference pages, checked against the code they describe.
//!
//! `book/src/reference/errors.md` must give every admin `ErrorCode` a table row that starts with its number and name, and
//! `book/src/reference/audit-log.md` every typed audit event name. A code or event added without its row would leave
//! an operator with an error or a log line the manual cannot explain, so a missing row fails CI. The sources are read
//! as text, because the event names' constructor is private and the code list is the enum's own declaration.

use std::fs;
use std::path::{Path, PathBuf};

fn crate_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read(relative: &str) -> String {
    let path = crate_path(relative);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// The text from `start` to the first `end` after it: the closing brace at the item's indentation.
fn block<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let rest = &source[source.find(start).unwrap_or_else(|| panic!("{start:?} not found"))..];
    &rest[..rest.find(end).unwrap_or_else(|| panic!("end of {start:?} not found"))]
}

/// `(variant, number)` for each `Variant = N,` line of the `ErrorCode` declaration.
fn error_numbers(protocol: &str) -> Vec<(String, u16)> {
    block(protocol, "pub enum ErrorCode {", "\n}\n")
        .lines()
        .filter_map(|line| line.trim().strip_suffix(','))
        .filter_map(|line| line.split_once(" = "))
        .map(|(variant, number)| (variant.to_owned(), number.parse().expect("error code number")))
        .collect()
}

/// `(variant, name)` for each `Self::Variant => "name",` line of `ErrorCode::name`.
fn error_names(protocol: &str) -> Vec<(String, String)> {
    let declaration = protocol.find("impl ErrorCode {").expect("impl ErrorCode");
    block(&protocol[declaration..], "pub const fn name(self)", "\n    }\n")
        .lines()
        .filter_map(|line| line.trim().strip_prefix("Self::"))
        .filter_map(|line| line.split_once(" => \""))
        .filter_map(|(variant, name)| name.strip_suffix("\",").map(|name| (variant.to_owned(), name.to_owned())))
        .collect()
}

/// Every `.rs` file under `dir`, at any depth, so an event declared in a nested submodule is not missed.
fn rust_sources(dir: &Path) -> Vec<PathBuf> {
    fs::read_dir(dir)
        .expect("source dir")
        .map(|entry| entry.expect("dir entry").path())
        .flat_map(|path| match path.is_dir() {
            true => rust_sources(&path),
            false => vec![path],
        })
        .collect()
}

/// Every `EventName("...")` in the audit module's sources.
fn event_names() -> Vec<String> {
    std::iter::once(crate_path("src/audit.rs"))
        .chain(rust_sources(&crate_path("src/audit")))
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .map(|path| fs::read_to_string(path).expect("audit source"))
        .flat_map(|source| {
            source
                .split("EventName(\"")
                .skip(1)
                .filter_map(|tail| tail.split_once('"').map(|(name, _)| name.to_owned()))
                .collect::<Vec<_>>()
        })
        .collect()
}

#[test]
fn errors_page_lists_every_error_code() {
    let protocol = read("src/admin/protocol.rs");
    let numbers = error_numbers(&protocol);
    let names = error_names(&protocol);
    assert!(numbers.len() > 30, "parsed only {} error codes", numbers.len());
    let numbered: Vec<_> = numbers.iter().map(|(variant, _)| variant).collect();
    let named: Vec<_> = names.iter().map(|(variant, _)| variant).collect();
    assert_eq!(
        numbered, named,
        "the ErrorCode declaration and ErrorCode::name list different variants"
    );

    let page = read("../../book/src/reference/errors.md");
    let missing: Vec<_> = numbers
        .iter()
        .zip(&names)
        .map(|((_, number), (_, name))| format!("| `{number}` | `{name}` |"))
        .filter(|row| !page.lines().any(|line| line.starts_with(row.as_str())))
        .collect();
    assert!(missing.is_empty(), "errors.md does not list error codes {missing:?}");
}

#[test]
fn audit_log_page_lists_every_event() {
    let events = event_names();
    assert!(events.len() > 40, "parsed only {} event names", events.len());
    let page = read("../../book/src/reference/audit-log.md");
    let missing: Vec<_> = events.iter().filter(|name| !page.contains(&format!("`{name}`"))).collect();
    assert!(missing.is_empty(), "audit-log.md does not list events {missing:?}");
}
