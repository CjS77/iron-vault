//! Caller grants, routes, slots, markers, path and method rules, confirmation requirements, and the final
//! outgoing-request decision.
//!
//! This crate performs no I/O: every decision is a pure function of its inputs, so policy can be tested exhaustively
//! and cannot be bypassed by an adapter.

pub mod activation;
pub mod authorization;
pub mod bound_credential;
pub mod caller;
pub mod caller_token;
pub mod config;
pub mod config_path;
pub mod confirmation;
pub mod credential_kind;
mod display;
mod escape;
pub mod final_check;
pub mod header_name;
pub mod header_value;
pub mod host;
pub mod limits;
pub mod listener;
pub mod marker;
pub mod method;
pub mod name;
pub mod outgoing_headers;
pub mod outgoing_request;
pub mod path_pattern;
pub mod port;
pub mod query_value;
pub mod rate_limit;
pub mod rate_limiter;
pub mod request_target;
pub mod reserved_headers;
pub mod route;
pub mod route_prefix;
#[cfg(test)]
mod secret_types_tests;
pub mod slot;
pub mod slot_format;
pub mod slot_value;
#[cfg(test)]
mod spec_example;
pub mod token_bucket;
pub mod token_hash;
pub mod upstream;
pub mod upstream_target;
pub mod validated;

pub use activation::{ActivationError, ActivePolicy, Capabilities, CatalogEntry, CredentialCatalog, activate};
pub use authorization::{AuthorizedRequest, AuthzError, Refusal, authorize};
pub use bound_credential::BoundCredential;
pub use caller::{CallerAuth, CallerConfig, CallerError};
pub use caller_token::{CallerToken, CallerTokenError};
pub use config::{ConfigError, Location, ParsedConfig, SCHEMA_VERSION};
pub use config_path::{ConfigPath, ConfigPathError};
pub use confirmation::Confirmation;
pub use credential_kind::CredentialKind;
pub use final_check::{CheckedRequest, FinalCheckError, final_check};
pub use header_name::{HeaderName, HeaderNameError};
pub use header_value::{HeaderValue, HeaderValueError};
pub use host::{Host, HostError};
pub use limits::{Limits, LimitsError};
pub use listener::{Endpoint, ListenerConfig, ListenerError, TlsFiles};
pub use marker::{MarkerError, markers};
pub use method::{Method, MethodError};
pub use name::{CallerName, CredentialName, ListenerName, NameError, NameRule, RouteName};
pub use outgoing_headers::{OutgoingHeaders, OutgoingHeadersError, SanitizeError, sanitize};
pub use outgoing_request::{AssembleError, OutgoingRequest};
pub use path_pattern::{PathPattern, PathPatternError, PathPatterns};
pub use port::{Port, PortError};
pub use query_value::encode_query_value;
pub use rate_limit::RateLimit;
pub use rate_limiter::{ChargeError, ExhaustedLimit, RateLimited, RateLimiter};
pub use request_target::{NormalizedPath, RawQuery, RequestTarget, TargetError};
pub use route::{RouteConfig, RouteError};
pub use route_prefix::{RoutePrefix, RoutePrefixError};
pub use slot::{HeaderSlot, QueryParamName, Slot, SlotError};
pub use slot_format::{SlotFormat, SlotFormatError};
pub use slot_value::{SlotValue, SlotValueError};
pub use token_bucket::{RetryAfter, TokenBucket};
pub use token_hash::{TokenHash, TokenHashError};
pub use upstream::{UpstreamUrl, UpstreamUrlError};
pub use upstream_target::{UpstreamTarget, UpstreamTargetError};
pub use validated::{ValidatedConfig, ValidationError};
