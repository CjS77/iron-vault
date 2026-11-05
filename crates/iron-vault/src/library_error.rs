//! Library errors and their error kind labels (`design/audit-logging.md`, "Library errors"; specification §3.15).
//!
//! A library error's `Display` and `Debug` may hold a URL with its query, a header value or a path, and a query-slot
//! credential puts the secret in the URL. A log records such an error only as `error_kind = %error.kind_label()`,
//! chosen from its kind, predicates or type, so a log site never formats the error itself.

use std::io;

pub use iron_vault_store::ErrorKindLabel;

use crate::caller_token::RandomSourceError;
use crate::upstream::transport_error::TransportError;

/// An error from a dependency that a log records only by its error kind label.
pub trait LibraryError {
    /// The error's label, built without calling its `Display` or `Debug`.
    fn kind_label(&self) -> ErrorKindLabel;
}

impl LibraryError for io::Error {
    fn kind_label(&self) -> ErrorKindLabel {
        ErrorKindLabel::of_io(self)
    }
}

/// The upstream transport error class, which the request interface already answers with.
impl LibraryError for reqwest::Error {
    fn kind_label(&self) -> ErrorKindLabel {
        ErrorKindLabel::fixed(TransportError::of(self).label())
    }
}

/// `rand_core`'s error text is the random source's diagnostic, which says nothing an administrator can act on.
impl LibraryError for RandomSourceError {
    fn kind_label(&self) -> ErrorKindLabel {
        ErrorKindLabel::fixed("random_source")
    }
}

/// A connection error, by hyper's predicates; an I/O failure under it is labelled by its kind.
#[cfg(target_os = "linux")]
impl LibraryError for hyper::Error {
    fn kind_label(&self) -> ErrorKindLabel {
        let fixed = [
            (self.is_parse_too_large(), "parse_too_large"),
            (self.is_parse(), "parse"),
            (self.is_timeout(), "timeout"),
            (self.is_incomplete_message(), "incomplete_message"),
            (self.is_canceled(), "canceled"),
            (self.is_closed(), "closed"),
            (self.is_body_write_aborted(), "body_write_aborted"),
            (self.is_user(), "user"),
        ];
        let io_kind = || {
            std::error::Error::source(self)
                .and_then(|source| source.downcast_ref::<io::Error>())
                .map(ErrorKindLabel::of_io)
        };
        fixed
            .into_iter()
            .find_map(|(holds, label)| holds.then(|| ErrorKindLabel::fixed(label)))
            .or_else(io_kind)
            .unwrap_or(ErrorKindLabel::fixed("http"))
    }
}

/// A task's end; a panic message may hold anything the panicking code formatted.
#[cfg(target_os = "linux")]
impl LibraryError for tokio::task::JoinError {
    fn kind_label(&self) -> ErrorKindLabel {
        ErrorKindLabel::fixed(if self.is_panic() { "task_panicked" } else { "task_cancelled" })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_io_error_renders_without_its_path() {
        let path = std::env::temp_dir().join("iron-vault-no-such-dir/owner-secret-file");
        let error = std::fs::read(&path).unwrap_err();

        let label = error.kind_label().to_string();

        assert_eq!(label, "not_found");
        assert!(!label.contains("owner-secret-file"));
    }

    #[test]
    fn an_io_error_with_a_path_in_its_message_renders_only_its_kind() {
        let error = io::Error::new(io::ErrorKind::PermissionDenied, "/var/lib/iron-vault/record-1.age");
        assert_eq!(error.kind_label().as_str(), "permission_denied");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_panicked_task_renders_without_its_panic_message() {
        let error = tokio::spawn(async { std::panic::panic_any("secret=VALUE".to_owned()) })
            .await
            .unwrap_err();
        assert_eq!(error.kind_label().as_str(), "task_panicked");
    }
}
