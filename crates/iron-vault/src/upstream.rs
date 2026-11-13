// SPDX-License-Identifier: MPL-2.0
//! The outbound side of the proxy: how the service reaches an upstream ([spec §10][s10]). The proxy handler hands this
//! module a checked request and gets back the upstream's response, streaming; nothing else in the service opens a
//! connection to an upstream.
//!
//! Clients are built when a policy is activated, one per distinct trust, and a request only picks its route's:
//!
//! ```text
//! route ── trust::trust_for ──► UpstreamTrust: built-in webpki roots, or the route's pinned CA file
//!                                   │ client_config: rustls over exactly those roots
//!                                   ▼
//!                               UpstreamClient: https only, no proxy, no redirects, no retries
//!                                   │ one per distinct trust, kept in the serving snapshot
//!                                   ▼
//!                               UpstreamClients ── for_route ──► send(CheckedRequest, UpstreamBody)
//!                                                                   │
//!                                                                   ▼
//!                                       UpstreamResponse, body streaming, or TransportError: 502, 504 on timeout
//! ```
//!
//! [s10]: ../../../design/iron-vault-specification.md#10-outbound-tls-and-environment

pub mod body;
pub mod client;
pub mod clients;
pub mod transport_error;
pub mod trust;
