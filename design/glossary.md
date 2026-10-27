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
| Approval version  | A per-vault unsigned 64-bit counter that strictly increases for every reserved signing attempt.                             | `iron-vault-store`  |           | §1.3 |
| Caller            | An authenticated program identity with grants to named routes.                                                              | `iron-vault-policy` | `CallerName`, `CallerConfig` | §1.3, §3.4 |
| Caller token      | A high-entropy secret a caller presents in `Proxy-Authorization` or its listener's `token_header`; only its BLAKE2b-256 hash is stored. | `iron-vault-policy` | `TokenHash` | §3.3, §3.4 |
| Config approval   | A service-generated signature binding a vault identifier, approval version, and exact configuration hash.                   | `iron-vault-store`  |           | §1.3 |
| Confirmation      | A route's owner-confirmation policy: `none` (the default) or `touch`, which v0 parses but refuses to activate. | `iron-vault-policy` | `Confirmation` | §2, §3.3, §5.1 |
| Credential        | A named provider secret and the rules that govern its use.                                                                  | `iron-vault-kinds`  |           | §1.3 |
| Credential record | The encrypted record containing a credential's secret, kind, permitted origins, and provider settings.                      | `iron-vault-store`  |           | §1.3 |
| Hardware key      | A removable device, initially a YubiKey, that protects keys and supports PIN and touch policies.                            | `iron-vault-store`  |           | §1.3 |
| Host              | An upstream host name or IP literal in its one canonical form; hosts compare exactly, never by suffix or wildcard.          | `iron-vault-policy` | `Host`    | §3.6 |
| Kind              | The operation that turns a credential into request bytes, such as a static key, an OAuth access token, or a signature.      | `iron-vault-kinds`  |           | §1.3 |
| Listener          | A configured endpoint, a Unix socket or TCP address, on which callers reach the request interface.                          | `iron-vault-policy` | `ListenerName`, `ListenerConfig` | §3.3, §3.4 |
| Marker            | An inert SDK placeholder such as `{iv:fx_key}` that Iron Vault interprets only in the selected slot.                        | `iron-vault-policy` |           | §1.3 |
| Method            | An HTTP method from the allowlist a route may grant; `CONNECT` and `TRACE` are never allowed.                               | `iron-vault-policy` | `Method` | §3.3, §3.5 |
| Operational limits | Service-wide bounds on request head and body size, decompressed response size, timeouts, and concurrent connections. | `iron-vault-policy` | `Limits` | §9 |
| Owner             | The person authorized to enroll credentials, approve policy, recover the vault, and authorize destructive changes.          | `iron-vault`        |           | §1.3 |
| Path pattern      | A route restriction on the normalized upstream path, built from literal, `*` and `**` segments and matching the whole path. | `iron-vault-policy` | `PathPattern` | §3.3 |
| Rate limit        | A route's token-bucket allowance: `requests` per `per_seconds`, with at most `burst` available at once.      | `iron-vault-policy` | `RateLimit` | §3.3, §3.5 |
| Recipient         | A public key or hardware-backed mechanism that can unwrap the vault identity.                                               | `iron-vault-store`  |           | §1.3 |
| Recovery key      | A generated offline `age` X25519 identity that opens the vault identity independently of the primary recipient.             | `iron-vault-store`  |           | §1.3 |
| Reserved header   | A caller-authentication or transport-control header that is stripped before forwarding and can never be a slot.         | `iron-vault-policy` | `reserved_headers` | §3.6 |
| Route             | A caller grant and upstream mapping that selects one credential, its slot, and usage restrictions.                          | `iron-vault-policy` |           | §1.3 |
| Slot              | The route's permitted credential location: a named header, a named query parameter, or Basic authorization.                 | `iron-vault-policy` | `Slot` | §1.3, §3.3 |
| Slot format       | The fixed text around a header slot's credential, with exactly one `{}` substitution point, such as `Bearer {}`.          | `iron-vault-policy` | `SlotFormat` | §3.6 |
| Source            | The origin of a credential imported into the vault, initially direct entry and later password-manager sync.                 | `iron-vault-store`  |           | §1.3 |
| Upstream          | The HTTPS service to which Iron Vault forwards an authorized request.                                                       | `iron-vault-policy` | `UpstreamUrl` | §1.3 |
| Vault             | The service-owned encrypted storage and protected metadata on disk.                                                         | `iron-vault-store`  |           | §1.3 |
| Vault identity    | The generated `age` X25519 private key that decrypts individual credential files.                                           | `iron-vault-store`  |           | §1.3 |

Context notes for terms that span crates:

- **Credential:** `iron-vault-kinds` owns resolving a credential into request bytes; its encrypted form is the
  credential record in `iron-vault-store`.
- **Owner:** the binary's admin interface authenticates the owner; store and policy only act on approved changes.
- **Hardware key, Source:** `iron-vault-store` holds recipient envelopes and connector storage, so it owns both.
- **Upstream:** `iron-vault-policy` decides whether a request may go to an upstream; the binary performs transport.
