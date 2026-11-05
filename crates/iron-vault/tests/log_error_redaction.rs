//! A log record never formats a library error: it records `error_kind = %error.kind_label()` instead (specification
//! §3.15, `design/audit-logging.md` "Library errors"). This test searches every log macro in the workspace's sources
//! for a formatted value bound to an error name (`e`, `err`, `error`, `cause`, `source`) and fails on any that is not
//! a known domain error.
//!
//! A source search cannot see types, so the names stand in for them, as they do throughout the workspace. clippy cannot
//! do better: `disallowed-macros` refuses a macro whatever its arguments, and `disallowed-methods` does not see the
//! `Display::fmt` call a format macro expands to. The search is a backstop for review, not a proof: an error bound to
//! another name, or formatted into a string before the macro, passes it. Text built before the log site, such as a
//! config check failure's `detail()`, is outside what the search can see; its error types must keep library text out of
//! their messages themselves.

// Test helpers outside `#[test]` functions: an unreadable source tree should stop the test where it happened.
#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::{Path, PathBuf};

/// Names the workspace binds errors to.
const ERROR_NAMES: [&str; 5] = ["e", "err", "error", "cause", "source"];

/// The log macros, with or without a `tracing::` prefix.
const LOG_MACROS: [&str; 6] = ["trace!(", "debug!(", "info!(", "warn!(", "error!(", "event!("];

/// Formatted errors that are domain errors of this workspace, whose `Display` carries fixed text, configured names,
/// file names and `io::ErrorKind`s, never a library error's text. Some also render a full configured path (`OpenError`,
/// `AdoptError`, `InitError`), which the design does not yet rule on; this list is about library text only. Each is
/// `(file, formatted expression)`, once per site.
const DOMAIN_ERRORS: [(&str, &str); 13] = [
    // `FrameError`: the admin protocol's own decoding errors.
    ("crates/iron-vault/src/admin/server.rs", "{e}"),
    // `HandshakeError`: a TLS handshake's timeout or its `io::ErrorKind`.
    ("crates/iron-vault/src/request_server.rs", "{e}"),
    // `AdoptError`: an activated socket's checks.
    ("crates/iron-vault/src/serve.rs", "{error}"),
    // The store's `WriteError` and `ConfigWriteError` from a stale temp sweep.
    ("crates/iron-vault/src/service_context.rs", "{error}"),
    // `OpenError`: a request listener that did not open.
    ("crates/iron-vault/src/service_context.rs", "{error}"),
    ("crates/iron-vault/src/service_context.rs", "{error}"),
    // The store's `ApprovalError`, and its `SignError` for a wrong passphrase or key.
    ("crates/iron-vault/src/service_context/approval.rs", "%error"),
    // The store's `RemoveStagingError` and `VerifyError`.
    ("crates/iron-vault-store/src/approval/recovery.rs", "%error"),
    ("crates/iron-vault-store/src/approval/recovery.rs", "%error"),
    // The store's `WriteError`.
    ("crates/iron-vault-store/src/approval/state.rs", "%error"),
    ("crates/iron-vault-store/src/approval/transaction.rs", "%error"),
    ("crates/iron-vault-store/src/approval/transaction.rs", "%error"),
];

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

/// The sources of every crate's `src`, unit tests included, except the `tests.rs` modules.
fn sources() -> Vec<(String, String)> {
    let root = workspace_root();
    let crates: Vec<PathBuf> = fs::read_dir(root.join("crates"))
        .unwrap()
        .map(|entry| entry.unwrap().path().join("src"))
        .collect();
    crates
        .iter()
        .flat_map(|src| rust_files(src))
        .filter(|path| !path.to_string_lossy().ends_with("tests.rs"))
        .map(|path| {
            let relative = path.strip_prefix(&root).unwrap().to_string_lossy().into_owned();
            (relative, fs::read_to_string(&path).unwrap())
        })
        .collect()
}

/// The argument text of each log macro call in `text`, up to its closing parenthesis, with each run of whitespace
/// made one space, so an argument rustfmt puts on a line of its own reads as it would on one line.
fn log_calls(text: &str) -> Vec<String> {
    LOG_MACROS
        .iter()
        .flat_map(|name| text.match_indices(name).map(move |(at, _)| (at, at + name.len())))
        .filter(|(at, _)| !text[..*at].ends_with(|c: char| c.is_alphanumeric() || c == '_'))
        .map(|(_, start)| {
            text[start..start + argument_len(&text[start..])]
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect()
}

fn argument_len(args: &str) -> usize {
    args.char_indices()
        .scan(1_i32, |depth, (index, c)| {
            *depth += i32::from(c == '(') - i32::from(c == ')');
            Some((index, *depth))
        })
        .find(|(_, depth)| *depth == 0)
        .map_or(args.len(), |(index, _)| index)
}

/// Each way `call` formats an error-named value: `%name`/`?name` fields (a path through an error name that does not
/// end in `kind_label()`), `{name}` in the message, `name` as a positional argument, and `field = name.to_string()`.
fn formatted_errors(call: &str) -> Vec<String> {
    let fields = call
        .match_indices(['%', '?'])
        .filter_map(|(at, sigil)| field_expression(&call[at + 1..]).map(|expression| format!("{sigil}{expression}")));
    let inline = ERROR_NAMES
        .iter()
        .flat_map(|name| {
            [
                format!("{{{name}}}"),
                format!("{{{name}:?}}"),
                format!("{{{name}:#?}}"),
                format!("{{{name}:#}}"),
            ]
        })
        .flat_map(|form| call.matches(form.as_str()).map(str::to_owned).collect::<Vec<_>>());
    let closed = format!("{call})");
    let positional = ERROR_NAMES
        .iter()
        .flat_map(|name| {
            [
                format!(", {name})"),
                format!(", {name},"),
                format!(", &{name})"),
                format!(", &{name},"),
            ]
        })
        .flat_map(|form| closed.matches(form.as_str()).map(str::to_owned).collect::<Vec<_>>());
    let rendered = ERROR_NAMES
        .iter()
        .map(|name| format!("{name}.to_string()"))
        .filter(|form| call.contains(&format!("={form}")) || call.contains(&format!("= {form}")))
        .collect::<Vec<_>>();
    fields.chain(inline).chain(positional).chain(rendered).collect()
}

/// The expression after a `%` or `?` sigil when it formats an error-named value; `kind_label()` makes it safe.
fn field_expression(after: &str) -> Option<String> {
    let expression: String = after
        .chars()
        .take_while(|c| c.is_alphanumeric() || ['_', '.', '(', ')'].contains(c))
        .collect();
    let segments: Vec<&str> = expression.split('.').map(|segment| segment.trim_end_matches("()")).collect();
    let names_error = segments.iter().any(|segment| ERROR_NAMES.contains(segment));
    let labelled = segments.last() == Some(&"kind_label");
    (names_error && !labelled).then_some(expression)
}

/// Each `(file, formatted expression)` in the workspace's log macros, in path order.
fn formatted_error_sites() -> Vec<(String, String)> {
    sources()
        .into_iter()
        .flat_map(|(file, text)| {
            log_calls(&text)
                .into_iter()
                .flat_map(|call| formatted_errors(&call))
                .map(|expression| (file.clone(), expression))
                .collect::<Vec<_>>()
        })
        .collect()
}

#[test]
fn no_log_record_formats_a_library_error() {
    let mut found = formatted_error_sites();
    let mut allowed: Vec<(String, String)> = DOMAIN_ERRORS
        .iter()
        .map(|(file, form)| (file.to_string(), form.to_string()))
        .collect();
    found.sort();
    allowed.sort();
    assert_eq!(
        found, allowed,
        "a log macro formats an error-named value: log a library error as `error_kind = %e.kind_label()`, or add a domain \
         error whose Display holds no library text to DOMAIN_ERRORS"
    );
}

#[test]
fn the_search_sees_a_formatted_error() {
    let one_line = log_calls(r#"tracing::warn!("accept failed: {e}"); tracing::error!(error = %error, "x"); warn!("{}", err)"#);
    let rendered = log_calls(r#"info!(cause = cause.to_string(), "x"); debug!("ended: {source:#}")"#);
    let multi_line = log_calls("tracing::warn!(\n    \"listener {}: accept failed: {}\",\n    listener,\n    error\n)");
    let trailing_comma = log_calls("tracing::warn!(\n    \"accept failed: {}\",\n    &e,\n)");
    let calls = [one_line, rendered, multi_line, trailing_comma].concat();
    let mut found: Vec<String> = calls.iter().flat_map(|call| formatted_errors(call)).collect();
    found.sort();
    assert_eq!(
        found,
        ["%error", ", &e,", ", err)", ", error)", "cause.to_string()", "{e}", "{source:#}"]
    );
}

#[test]
fn the_search_passes_a_kind_label() {
    let calls = log_calls(r#"tracing::warn!(error_kind = %e.kind_label(), "accept failed: {listener}")"#);
    assert_eq!(calls.iter().flat_map(|call| formatted_errors(call)).count(), 0);
}
