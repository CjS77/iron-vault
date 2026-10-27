//! Caller grants, routes, slots, markers, path and method rules, confirmation requirements, and the final
//! outgoing-request decision.
//!
//! This crate performs no I/O: every decision is a pure function of its inputs, so policy can be tested exhaustively
//! and cannot be bypassed by an adapter.

pub mod host;
pub mod method;
pub mod name;
pub mod path_pattern;
pub mod port;
pub mod upstream;

pub use host::{Host, HostError};
pub use method::{Method, MethodError};
pub use name::{CallerName, CredentialName, ListenerName, NameError, NameRule, RouteName};
pub use path_pattern::{PathPattern, PathPatternError, PathPatterns};
pub use port::{Port, PortError};
pub use upstream::{UpstreamUrl, UpstreamUrlError};
