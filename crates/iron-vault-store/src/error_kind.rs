//! The error kind label: how a log records a library error
//! ([audit logging, "Library errors"](../../../design/audit-logging.md#library-errors)).
//!
//! A library error's `Display` and `Debug` may hold a URL with its query, a header value or a path, so a log records
//! only a label chosen from the error's kind or type: `io::ErrorKind::PermissionDenied` is logged as
//! `permission_denied`. This crate is the lowest that logs, so the label lives here. The service crate adds the labels
//! of its own dependencies' errors.

use std::borrow::Cow;
use std::{fmt, io};

/// A library error reduced to a fixed `snake_case` label for a log record's `error_kind` field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorKindLabel(Cow<'static, str>);

impl ErrorKindLabel {
    /// Creates a label fixed in the source, for an error type whose kinds are not worth telling apart or cannot be read.
    pub const fn fixed(label: &'static str) -> Self {
        Self(Cow::Borrowed(label))
    }

    /// Returns the label of an `io::Error`: its kind only, because its message may name a path.
    pub fn of_io(error: &io::Error) -> Self {
        Self::from(error.kind())
    }

    /// Returns the label as written in a log record.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<io::ErrorKind> for ErrorKindLabel {
    /// Labels `kind` with its variant name in `snake_case`.
    ///
    /// `ErrorKind`'s `Debug` is its variant name, which std fixes and which holds nothing from the failure. Its
    /// `Display` is a prose description, not a label.
    fn from(kind: io::ErrorKind) -> Self {
        Self(Cow::Owned(snake_case(&format!("{kind:?}"))))
    }
}

impl fmt::Display for ErrorKindLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Converts a `CamelCase` name to `snake_case`: `PermissionDenied` becomes `permission_denied`.
fn snake_case(camel: &str) -> String {
    camel
        .chars()
        .enumerate()
        .flat_map(|(index, c)| {
            let separator = (index > 0 && c.is_ascii_uppercase()).then_some('_');
            separator.into_iter().chain(c.to_lowercase())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_io_error_is_labelled_by_its_kind_in_snake_case() {
        let error = io::Error::new(io::ErrorKind::PermissionDenied, "cannot open /home/owner/secret-path");
        let label = ErrorKindLabel::of_io(&error).to_string();
        assert_eq!(label, "permission_denied");
        assert!(!label.contains("secret-path"));
    }

    #[test]
    fn an_io_error_from_the_os_is_labelled_without_its_path() {
        let path = std::env::temp_dir().join("iron-vault-missing-dir-for-label-test/file");
        let error = std::fs::read(&path).unwrap_err();
        assert_eq!(ErrorKindLabel::of_io(&error).as_str(), "not_found");
    }

    #[test]
    fn one_word_kinds_stay_one_word() {
        assert_eq!(ErrorKindLabel::from(io::ErrorKind::Other).as_str(), "other");
        assert_eq!(ErrorKindLabel::from(io::ErrorKind::StorageFull).as_str(), "storage_full");
    }
}
