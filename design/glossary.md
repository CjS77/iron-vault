# Iron Vault glossary

One name per concept, in docs and code alike. Definitions follow the
[product specification](iron-vault-specification.md).

**Adding a term:** add it here before the code that uses it. Keep entries alphabetical, give one one-sentence
definition, name the owning bounded context, and cite the specification section that introduces it. Fill in the Rust
type once one exists.

## Bounded contexts

From specification §7. Each crate owns its model; crates do not reach into each other's private storage models.

| Crate               | Owns                                                                                                    |
|---------------------|---------------------------------------------------------------------------------------------------------|
| `iron-vault-policy` | Caller grants, routes, slots, markers, and the final outgoing-request decision; pure, no I/O            |
| `iron-vault-kinds`  | Credential resolution, token lifecycle, and provider signing rules                                      |
| `iron-vault-store`  | Vault identity, recipient envelopes, record files, approval metadata, durable transactions and recovery |
| `iron-vault`        | Service binary, HTTP/admin interfaces, CLI client, config loading, deployment adapters and scrubbing    |

## Terms

| Term              | Definition                                                                                                                  | Context             | Rust type | Spec |
|-------------------|-----------------------------------------------------------------------------------------------------------------------------|---------------------|-----------|------|
| Active policy     | A validated config activated against this service's capabilities and credential catalog: the routes it may serve, with routes whose credential record is unusable marked unavailable. | `iron-vault-policy` | `ActivePolicy` | §3.3, §3.9 |
| Approval version  | A per-vault unsigned 64-bit counter that strictly increases for every reserved signing attempt.                             | `iron-vault-store`  |           | §1.3 |
| Authorized request | The immutable plan for one request: the route it selected, its method, its upstream path and its query, after the caller's grant and the route's method and path restrictions all passed. | `iron-vault-policy` | `AuthorizedRequest` | §3.3, §3.5, §3.6 |
| Basic token       | The base64 encoding, standard alphabet with padding, of a Basic credential's UTF-8 `username:password`; the slot value a Basic slot writes as `Basic <token>`. The username is non-empty and has no `:` (RFC 7617 §2). | `iron-vault-kinds` | `CredentialMaterial::Basic` | §3.6, §5.2 |
| Capabilities      | Facts about this service installation that activation checks routes against, such as whether a touch confirmation provider exists. | `iron-vault-policy` | `Capabilities` | §2, §8.2 |
| Caller            | An authenticated program identity with grants to named routes.                                                              | `iron-vault-policy` | `CallerName`, `CallerConfig` | §1.3, §3.4 |
| Caller token      | A high-entropy secret a caller presents in `Proxy-Authorization` or its listener's `token_header`; only its BLAKE2b-256 hash is stored. | `iron-vault-policy` | `TokenHash` | §3.3, §3.4 |
| Checked request   | An outgoing request that passed the final outgoing-request check against its authorized request, its route's upstream and slot, and its credential record's permitted origins; the only form the transport accepts. | `iron-vault-policy` | `CheckedRequest` | §3.3, §3.6, §7 |
| Config approval   | A service-generated signature binding a vault identifier, approval version, and exact configuration hash.                   | `iron-vault-store`  |           | §1.3 |
| Confirmation      | A route's owner-confirmation policy: `none` (the default) or `touch`, which v0 parses but refuses to activate. | `iron-vault-policy` | `Confirmation` | §2, §3.3, §5.1 |
| Credential        | A named provider secret and the rules that govern its use.                                                                  | `iron-vault-kinds`  |           | §1.3 |
| Credential catalog | The service's view of the vault for activation: per credential name, unknown, unusable (damaged or needing login), or usable with its permitted host and port pairs. | `iron-vault-policy` | `CredentialCatalog`, `CatalogEntry` | §3.3, §3.9 |
| Credential material | The decrypted secret fields of one credential record, in the shape its kind consumes; the store maps a record into it, and a kind never reads records itself. | `iron-vault-kinds` | `CredentialMaterial` | §3.3, §5.2 |
| Credential kind   | The name of the kind a credential record declares, `static` or `basic`; activation uses it to check that the route's slot suits the kind, without implementing the kind. A static key fills a header or query slot; a Basic credential fills only a Basic slot. | `iron-vault-policy` | `CredentialKind` | §3.3, §5.2 |
| Credential record | The encrypted record containing a credential's secret, kind, permitted origins, and provider settings.                      | `iron-vault-store`  |           | §1.3 |
| Destination invariant | A credential leaves only for its route upstream's host and port, only when its credential record permits that pair, only inside the upstream base path, and only in the route's slot; property-tested from request parsing to the final outgoing-request check. | `iron-vault-policy` | | §3.6, §8 |
| Hardware key      | A removable device, initially a YubiKey, that protects keys and supports PIN and touch policies.                            | `iron-vault-store`  |           | §1.3 |
| Header value      | The bytes of one HTTP field value; never contains CR, LF or NUL, may contain obs-text, and is never rendered in logs or errors. | `iron-vault-policy` | `HeaderValue` | §3.6 |
| Host              | An upstream host name or IP literal in its one canonical form; hosts compare exactly, never by suffix or wildcard.          | `iron-vault-policy` | `Host`    | §3.6 |
| Kind              | The operation that turns a credential into request bytes, such as a static key, an OAuth access token, or a signature.      | `iron-vault-kinds`  |           | §1.3 |
| Listener          | A configured endpoint, a Unix socket or TCP address, on which callers reach the request interface.                          | `iron-vault-policy` | `ListenerName`, `ListenerConfig` | §3.3, §3.4 |
| Marker            | An inert SDK placeholder such as `{iv:fx_key}` that Iron Vault interprets only in the selected slot, where it must name the route's own credential; it never selects a credential. | `iron-vault-policy` | `markers`, `MarkerError` | §1.3, §3.6, §8.2 |
| Method            | An HTTP method from the allowlist a route may grant; `CONNECT` and `TRACE` are never allowed.                               | `iron-vault-policy` | `Method` | §3.3, §3.5 |
| Normalized path   | A caller's validated request path, unreserved escapes decoded and others in uppercase hex; authorized and forwarded as is.  | `iron-vault-policy` | `NormalizedPath` | §3.3, §3.6 |
| Operational limits | Service-wide bounds on request head and body size, decompressed response size, timeouts, and concurrent connections. | `iron-vault-policy` | `Limits` | §9 |
| Outgoing headers  | The ordered header list an upstream request carries; built from sanitized caller headers and never holding a reserved header. | `iron-vault-policy` | `OutgoingHeaders` | §3.6 |
| Outgoing request  | The request about to leave the service: the authorized method, the upstream target and the outgoing headers, with the route's slot filled exactly once; the input to the final outgoing-request check. | `iron-vault-policy` | `OutgoingRequest` | §3.5, §3.6 |
| Owner             | The person authorized to enroll credentials, approve policy, recover the vault, and authorize destructive changes.          | `iron-vault`        |           | §1.3 |
| Parsed config     | A configuration document whose listeners, callers, routes and limits each passed their own validation, before cross-references are checked. | `iron-vault-policy` | `ParsedConfig` | §3.3 |
| Path pattern      | A route restriction on the normalized upstream path, built from literal, `*` and `**` segments and matching the whole path. | `iron-vault-policy` | `PathPattern` | §3.3 |
| Rate limit        | A route's token-bucket allowance: `requests` per `per_seconds`, with at most `burst` available at once.      | `iron-vault-policy` | `RateLimit` | §3.3, §3.5 |
| Rate limiter      | The token buckets for one active policy: one per route shared by all its callers, plus one per caller/route pair with a stricter limit; a request takes a token from both or neither, and a reload starts every bucket empty. | `iron-vault-policy` | `RateLimiter` | §3.5, §3.12, §3.15 |
| Recipient         | A public key or hardware-backed mechanism that can unwrap the vault identity.                                               | `iron-vault-store`  |           | §1.3 |
| Recovery key      | A generated offline `age` X25519 identity that opens the vault identity independently of the primary recipient.             | `iron-vault-store`  |           | §1.3 |
| Reserved header   | A caller-authentication or transport-control header that is stripped before forwarding and can never be a slot.         | `iron-vault-policy` | `reserved_headers` | §3.6 |
| Route             | A caller grant and upstream mapping that selects one credential, its slot, and usage restrictions.                          | `iron-vault-policy` | `RouteName`, `RouteConfig` | §1.3, §3.3 |
| Route prefix      | The literal leading request-path segments, such as `/fx`, that select a route; never `/` alone and never a wildcard.        | `iron-vault-policy` | `RoutePrefix` | §3.3, §3.6 |
| Scrub patterns    | Every byte form of the secret a kind injected that response scrubbing watches for: the exact value, its URL-encoded forms in both hex cases, and its base64 encodings; for a Basic credential, the Basic token, the complete `Basic <token>` value, and `username:password` and the password with their URL-encoded forms, but never the username alone; never case-folded. | `iron-vault-kinds` | `ScrubPatterns` | §3.8 |
| Sealed file       | Binary `age` ciphertext encrypted to the vault public key whose header holds only X25519 stanzas, besides the inert grease stanza `age` writes into every file; the on-disk form of credential records and control metadata. A file with a passphrase (scrypt) or plugin stanza is refused before any key work. | `iron-vault-store` | `seal`, `open` | §3.10 |
| Slot              | The route's permitted credential location: a named header, a named query parameter (RFC 3986 unreserved characters only, so the URL keeps it unchanged), or Basic authorization.                 | `iron-vault-policy` | `Slot` | §1.3, §3.3 |
| Slot format       | The fixed text around a header slot's credential, with exactly one `{}` substitution point, such as `Bearer {}`.          | `iron-vault-policy` | `SlotFormat` | §3.6 |
| Slot value        | The credential text a kind produces for the route's slot, before the slot's format or encoding is applied. | `iron-vault-policy` | `SlotValue` | §3.6, §3.11, §5.2 |
| Source            | The origin of a credential imported into the vault, initially direct entry and later password-manager sync.                 | `iron-vault-store`  |           | §1.3 |
| State directory   | The service-owned directory holding vault, control and lock files; the binary resolves it from the deployment profile.    | `iron-vault-store`  |           | §3.10 |
| State-directory lock | An exclusive, non-blocking lock on `<state directory>/lock`, held for the service's lifetime; a second writer fails to start. | `iron-vault-store` | `StateDirLock` | §3.1 |
| Token bucket      | A route's rate-limit counter: it starts empty, refills at `requests / per_seconds` up to `burst`, and spends one token per request. | `iron-vault-policy` | `TokenBucket` | §3.5, §3.12 |
| Upstream          | The HTTPS service to which Iron Vault forwards an authorized request.                                                       | `iron-vault-policy` | `UpstreamUrl` | §1.3 |
| Upstream target   | The URL the service will send to, built from the configured upstream and the authorized request and checked to read back as exactly the authorized path and query. | `iron-vault-policy` | `UpstreamTarget` | §3.5, §3.6 |
| Validated config  | A parsed config whose cross-references all resolve and whose listeners, token hashes, route prefixes and slots cannot conflict. | `iron-vault-policy` | `ValidatedConfig` | §3.3, §3.4, §3.5, §3.6 |
| Vault             | The service-owned encrypted storage and protected metadata on disk.                                                         | `iron-vault-store`  |           | §1.3 |
| Vault identity    | The generated `age` X25519 private key that decrypts individual credential files.                                           | `iron-vault-store`  | `VaultIdentity` | §1.3, §3.10 |
| Vault public key  | The public half of the vault identity, written as an `age1…` string; anything sealed to it only the vault identity opens, and it is safe to log. Not a recipient: a recipient unwraps the vault identity itself. | `iron-vault-store` | `VaultPublicKey` | §3.10 |

Context notes for terms that span crates:

- **Credential:** `iron-vault-kinds` owns resolving a credential into request bytes; its encrypted form is the
  credential record in `iron-vault-store`.
- **Owner:** the binary's admin interface authenticates the owner; store and policy only act on approved changes.
- **Hardware key, Source:** `iron-vault-store` holds recipient envelopes and connector storage, so it owns both.
- **Upstream:** `iron-vault-policy` decides whether a request may go to an upstream; the binary performs transport.
