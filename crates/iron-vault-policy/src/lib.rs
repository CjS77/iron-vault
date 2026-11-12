//! Policy: every decision about who may send which request where, and how the credential goes into it.
//!
//! This crate is the policy bounded context. It parses and checks the configuration, identifies callers, selects and
//! authorizes routes, charges rate limits, builds the upstream URL, fills the route's slot and makes the final
//! outgoing-request check. The `iron-vault` service calls it at each step and does the I/O itself. Every decision is a
//! pure function of its inputs, so policy can be tested exhaustively and no adapter can bypass it.
//!
//! A configuration becomes the policy that requests are served under in three steps:
//!
//! ```text
//! config.toml bytes ──ParsedConfig::from_toml──▶ ParsedConfig        each section's own rules (config)
//!                   ──ValidatedConfig::try_from─▶ ValidatedConfig    rules across sections (validated)
//!                   ──activate──────────────────▶ ActivePolicy       facts from the running service (activation):
//!                                                                    credential records, peer uids
//! ```
//!
//! Each request then passes through these steps
//! ([spec §8](../../../design/iron-vault-specification.md#8-request-flow)). Between rate limiting and URL building,
//! the store resolves the route's credential through its kind (`iron-vault-kinds`):
//!
//! ```text
//! RequestTarget::parse        origin-form target, normalized path          (request_target)
//! identify_caller             listener + peer uid or caller token → caller (caller_identity)
//! authorize                   route, method and path restrictions          (authorization) ─▶ AuthorizedRequest
//! RateLimiter::charge         route bucket and caller bucket, both or none (rate_limiter)
//!      ── iron-vault-kinds resolves the credential into a SlotValue ──
//! UpstreamTarget::build       URL built through the url API               (upstream_target)
//! sanitize                    caller headers minus reserved headers        (outgoing_headers)
//! OutgoingRequest::assemble   slot filled exactly once                     (outgoing_request)
//! final_check                 read back the URL and headers before sending (final_check) ─▶ CheckedRequest
//!      ── the service sends the request ──
//! rewrite_location            what the caller sees of a redirect           (location_rewrite)
//! ```

pub mod account_name;
pub mod activation;
pub mod approval_summary;
pub mod authorization;
pub mod bound_credential;
pub mod caller;
pub mod caller_identity;
pub mod caller_token;
pub mod config;
pub mod config_path;
pub mod confirmation;
pub mod credential_kind;
mod display;
pub use display::escaped;
mod escape;
pub mod final_check;
pub mod header_name;
pub mod header_value;
pub mod host;
pub mod limits;
pub mod listener;
pub mod location_rewrite;
pub mod log_destination;
pub mod marker;
pub mod method;
pub mod name;
pub mod origin;
pub mod outgoing_headers;
pub mod outgoing_request;
pub mod path_pattern;
pub mod port;
pub mod query_value;
pub mod rate_limit;
pub mod rate_limiter;
pub mod reminder_interval;
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
#[cfg(test)]
mod test_accounts;
pub mod token_bucket;
pub mod token_hash;
pub mod upstream;
pub mod upstream_target;
pub mod validated;

pub use account_name::{AccountName, AccountNameError};
pub use activation::{AccountDirectory, ActivationError, ActivePolicy, CatalogEntry, CredentialCatalog, UnavailableCause, activate};
pub use approval_summary::{ApprovalSummary, summarize};
pub use authorization::{AuthorizedRequest, AuthzError, Refusal, authorize};
pub use bound_credential::BoundCredential;
pub use caller::{CallerAuth, CallerConfig, CallerError};
pub use caller_identity::{Unauthenticated, identify_caller};
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
pub use location_rewrite::{LocationRefusal, LocationRewrite, rewrite_location};
pub use log_destination::{LogDestinationError, LogDestinationSetting};
pub use marker::{MarkerError, markers};
pub use method::{Method, MethodError};
pub use name::{CallerName, CredentialName, ListenerName, NameError, NameRule, RouteName};
pub use origin::{OriginError, parse_origin};
pub use outgoing_headers::{OutgoingHeaders, OutgoingHeadersError, SanitizeError, sanitize};
pub use outgoing_request::{AssembleError, OutgoingRequest};
pub use path_pattern::{PathPattern, PathPatternError, PathPatterns};
pub use port::{Port, PortError};
pub use query_value::encode_query_value;
pub use rate_limit::RateLimit;
pub use rate_limiter::{ChargeError, ExhaustedLimit, RateLimited, RateLimiter};
pub use reminder_interval::{ReminderInterval, ReminderIntervalError};
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
