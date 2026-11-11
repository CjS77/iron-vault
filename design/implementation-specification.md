## 1. Implementation structure

Build one Rust workspace using edition 2024 with a pinned toolchain and shared dependency versions. Keep policy
decisions pure and perform filesystem, HTTP, process, device, and notification I/O through adapters. Establish
bounded contexts before adding abstractions; crates must not reach into each other's private storage models.

| Crate               | Responsibility                                                                                                                         |
|---------------------|----------------------------------------------------------------------------------------------------------------------------------------|
| `iron-vault-policy` | Caller grants, routes, slots, markers, path/method rules, confirmation requirements, and the final outgoing-request decision; no I/O   |
| `iron-vault-kinds`  | Credential resolution, token lifecycle, provider signing rules, and constrained token-endpoint adapters                                |
| `iron-vault-store`  | Vault identity, recipient envelopes, record files, manifests, approval metadata, durable transactions, recovery, and connector storage |
| `iron-vault`        | Service binary, HTTP/admin interfaces, CLI client, config loading, deployment adapters, scrubbing, logging, and notifications          |
| `iron-vault-notify` | From v1: desktop notification agent; runs as the owner's login account; no access to vault, config or admin interfaces                 |

Use value objects that reject invalid hosts, ports, paths, names, versions, and slots on construction. Libraries
return typed errors with `thiserror`; the binary may use `anyhow` for context. Avoid `unwrap`, `expect`, and `panic!`
outside tests. A corrupt file or hostile request must produce an error, not a crash. Keep generated configuration,
payload encodings, manifests, and logs deterministic; never depend on hash-map iteration order for persisted data.

The initial dependency candidates remain `tokio`, `hyper` or `axum`, `reqwest` with `rustls`, `age`,
`secrecy`/`zeroize`, `tss-esapi`, and platform service APIs. OAuth later adds `oauth2`; JWT and AWS providers may add
`jsonwebtoken` and `aws-sigv4`. `keyring` remains optional and constrained by the service-account rule. Validate
plugins and host-helper formats before choosing them; candidate names do not establish interoperability.

The HTTP adapter must make unsafe behavior difficult to enable: one controlled outbound-client constructor,
automatic redirects disabled, no ambient proxy/trust settings, and a final policy decision immediately before
transport. Provider adapters must not create their own unrestricted clients or log raw requests.

## 2. Verification and deferred security work

Use focused acceptance tests at the boundaries that can expose credentials or corrupt durable state. Property-test
URL construction and the final destination invariant with hostile path and header inputs. Use deterministic fault
injection at file write, fsync, rename, signing, and token-response boundaries. Use a mock upstream to observe
exactly which requests and credentials left the service; checking only the constructed URL is insufficient.

Release checks must also inspect actual process permissions, socket ownership, environment handling, memory-dump
settings, recovery behavior, and hardware/session behavior on each supported deployment. Do not claim platform or
hardware support solely from a plugin README. Keep performance checks representative of streamed LLM responses,
compressed API results, concurrent refresh, and signing-body limits; define supported limits before packaging.

### 2.1 Deferred security and compatibility work

The v0 design addresses the earlier findings through the requirements and threat notes in [product spec §1](iron-vault-specification.md#1-product-and-scope)–[§19](iron-vault-specification.md#19-v0-user-acceptance). Those controls
remain mandatory; removing duplicate findings does not claim that an implementation has passed verification.
Hardware and platform validation remains subject to [§3](#3-implementation-gates-and-unresolved-details). Later features inherit the same controls and must pass
their own release checks before activation.

Only the following follow-up work remains in this section:

| Follow-up | Remaining work | Release gate |
|---|---|---|
| OAuth refresh-token rotation | Implement and fault-test the durable refresh transaction and `needs login` recovery in [future spec §1.3](future-specifications.md#13-refresh-token-rotation-and-crash-recovery) and [future spec §1.5](future-specifications.md#15-v1-release-checks). A provider can rotate a token before the service persists its replacement; an unresolved operation must never retry the old token. | v1 |
| CLI and MCP compatibility | Verify complete base-URL workflows for each advertised client ([future spec §3](future-specifications.md#3-conditional-phase-forward-proxy-and-cli-compatibility)). If a required workflow cannot use those overrides, decide between a client patch and the conditional interception phase before claiming support. | Each integration claim |

### 2.2 Product decisions and resulting behavior

| Decision                                 | Specification result                                                                                                            |
|------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------|
| Q-1: marker syntax                       | Use `{iv:name}` only as a slot placeholder; never expand it through arbitrary request text ([product spec §9](iron-vault-specification.md#9-url-header-and-slot-rules))                               |
| Q-3: forward-proxy need                  | Keep base-URL mode; test actual callers and require a separate interception design ([future spec §3](future-specifications.md#3-conditional-phase-forward-proxy-and-cli-compatibility))                                         |
| Q-4: no TPM                              | Offer service-owned interactive passphrase unlock; validate Secure Enclave where available; retain independent recovery ([product spec §14](iron-vault-specification.md#14-recipients-startup-and-memory)) |
| Q-5: reload                              | Restart or explicit signal; verify signature, counter, record restrictions, and config; stop proxying on failure ([product spec §12](iron-vault-specification.md#12-configuration-approval-and-reload))         |
| Q-6: compressed responses                | Decompress, scrub, and recompress when required; do not depend on stripping Accept-Encoding alone ([product spec §11](iron-vault-specification.md#11-responses-redirects-and-scrubbing))                        |
| Q-7: license                             | Release Iron Vault under Apache-2.0 ([§4](#4-license-and-design-references))                                                                                       |
| Q-9: one approval flow                   | Use one versioned signature envelope for TPM, YubiKey, and software signers; keep the version in protected state ([product spec §12](iron-vault-specification.md#12-configuration-approval-and-reload))         |
| Config approval retained                 | Retain it for grants and route policy while credential records independently restrict destinations ([product spec §6](iron-vault-specification.md#6-credential-records-and-configuration), [product spec §12](iron-vault-specification.md#12-configuration-approval-and-reload))             |
| Touch policy without a device            | Refuse to activate a touch-required route; never silently downgrade ([product spec §6](iron-vault-specification.md#6-credential-records-and-configuration), [future spec §2.1](future-specifications.md#21-hardware-key-recipients-signers-and-touch-confirmation))                                                  |

## 3. Implementation gates and unresolved details

The following items require engineering evidence or a published default before the relevant release. They do not
weaken the security requirements above.

| Gate                                    | Evidence required                                                                                                                                                                                                                                                                                                                                                                                                    | Blocks                           |
|-----------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------|
| Schema and operational limits           | Versioned TOML/envelope formats; explicit request, header, body-buffer, decompression, queue, connection, confirmation, and timeout limits                                                                                                                                                                                                                                                                           | v0                               |
| Initial hardware and OS support matrix  | TPM wrap/unwrap, service account, recovery, signer provisioning, and permission checks on each advertised platform; explicit fallback for unsupported hardware                                                                                                                                                                                                                                                       | Each platform package            |
| Windows TPM approval provisioning       | Demonstrate signing-key provisioning through the platform provider without assuming access to owner authorization or an NV index                                                                                                                                                                                                                                                                                     | Windows package                  |
| TPM authorization and power failure     | Demonstrate protected authorization sessions, dictionary-attack settings, restart behavior, and recovery after unclean power loss                                                                                                                                                                                                                                                                                    | TPM profile                      |
| TPM unlock binding                      | Demonstrate interoperable wrap, recovery and restart through the `systemd-creds` host unlock adapter. Bind to PCR 7, which records Secure Boot policy but does not identify the installed OS; avoid PCR 0–4, which routine firmware updates change; evaluate signed PCR 11 later. The service account gets no TPM device: root's init system unseals the identity and hands it over                                  | TPM profile                      |
| Host unlock handoff                     | Prove `systemd-creds` or equivalent can supply the same recoverable vault identity without persistent plaintext or exposing a signing oracle                                                                                                                                                                                                                                                                         | Host-unlock container profile    |
| Streamed response compatibility         | Measure overlap buffering, decompression limits, SSE latency, rewritten headers, and supported encodings with target APIs                                                                                                                                                                                                                                                                                            | v0                               |
| Caller compatibility                    | End-to-end results for target MCP servers and each advertised CLI integration                                                                                                                                                                                                                                                                                                                                        | Each integration claim           |
| Google operational setup                | Confirm application publishing state, consent, scopes, renewal behavior, and account verification for Naomi                                                                                                                                                                                                                                                                                                          | v1 Google integration            |
| Touch policy defaults                   | Publish route/provider guidance, confirmation expiry, cancellation behavior, and supported hardware policy                                                                                                                                                                                                                                                                                                           | Working touch feature            |
| Password-manager connector trust        | Demonstrate service-owned secret transfer, authentication storage, replacement authorization, and failure isolation                                                                                                                                                                                                                                                                                                  | Each sync connector              |
| Optional whole-storage rollback defense | Select an independent monotonic state authority and design provisioning, migration, backup, and crash recovery                                                                                                                                                                                                                                                                                                       | Any stronger anti-rollback claim |

The project must not advertise complete support where an adapter still relies only on an untested plugin README.
The product may release a narrower validated platform matrix and mark the remaining adapters as planned.

## 4. License and design references

Release Iron Vault under Apache-2.0. Check the licenses of chosen dependencies, adapters, and bundled helpers before
distribution. The comparison below records design references; it does not establish current feature parity,
audited security, or verified interoperability with those projects.

| Reference                                                                                                                                                                                         | Design question it informs                                                                                                            |
|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------|
| [Fly.io tokenizer](https://github.com/superfly/tokenizer), [tokenized tokens](https://fly.io/blog/tokenized-tokens/), and [SSOkenizer](https://github.com/superfly/ssokenizer)                    | Bind allowed destinations to the secret; separate credential transformation from caller-held material and consent                     |

This specification supplies the complete release requirements, security boundaries, mitigation notes, and
product decisions. Section 2 tracks deferred follow-up work; the requirements explain the controls themselves.