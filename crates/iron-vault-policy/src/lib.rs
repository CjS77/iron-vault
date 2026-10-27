//! Caller grants, routes, slots, markers, path and method rules, confirmation requirements, and the final
//! outgoing-request decision.
//!
//! This crate performs no I/O: every decision is a pure function of its inputs, so policy can be tested exhaustively
//! and cannot be bypassed by an adapter.

pub mod confirmation;
mod display;
pub mod header_name;
pub mod host;
pub mod limits;
pub mod method;
pub mod name;
pub mod path_pattern;
pub mod port;
pub mod rate_limit;
pub mod reserved_headers;
pub mod slot;
pub mod slot_format;
pub mod upstream;

pub use confirmation::Confirmation;
pub use header_name::{HeaderName, HeaderNameError};
pub use host::{Host, HostError};
pub use limits::{Limits, LimitsError};
pub use method::{Method, MethodError};
pub use name::{CallerName, CredentialName, ListenerName, NameError, NameRule, RouteName};
pub use path_pattern::{PathPattern, PathPatternError, PathPatterns};
pub use port::{Port, PortError};
pub use rate_limit::RateLimit;
pub use slot::{HeaderSlot, QueryParamName, Slot, SlotError};
pub use slot_format::{SlotFormat, SlotFormatError};
pub use upstream::{UpstreamUrl, UpstreamUrlError};
