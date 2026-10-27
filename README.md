# Iron Vault

A small local proxy that holds API credentials so the programs that use them never do.

Point an application's base URL at Iron Vault and give it a placeholder instead of a provider key. Iron Vault
authenticates the caller, checks its route, adds the credential, and forwards the request over verified TLS.
The application holds at most a local caller token that grants specific routes; it never needs the provider secret.

**Status:** specification stage; implementation has not started. The
[product specification](iron-vault-specification.md) defines the requirements, roadmap, threat mitigations, and
release checks.

## Planned features

- **Credential injection:** static API keys and Basic authentication first; OAuth login and refresh next; JWT,
  GitHub App, HMAC, and AWS Signature Version 4 providers later.
- **Restricted routes:** authenticate callers and limit each route by credential, upstream destination, HTTP method,
  path, and request rate. Store permitted destinations with the encrypted credential so a route edit cannot send
  an existing secret to another host.
- **Protected storage:** run under a dedicated service identity, encrypt credential records with `age`, and unlock
  through a TPM or an interactive passphrase. Add YubiKey recipients and PIN/touch policies in a later phase.
- **Versioned configuration approval:** sign configuration changes and check a strictly increasing approval version
  against protected service state. Reject old configuration/signature pairs after a newer approval.
- **Recovery and migration:** maintain independent recovery paths and check recovery keys. Require the existing TPM
  PIN, a fresh YubiKey touch, or the original vault passphrase before migration, then protect the export bundle with
  a new passphrase without writing plaintext secrets to disk.
- **Response handling and audit:** scrub supported secret representations from headers, compressed bodies, and
  streamed responses. Record request and administrative events without logging secret values.
- **Managed deployment:** support desktop system services and administrator-controlled Docker Compose deployments,
  with separate caller and administrative interfaces.

## Use cases

| Use case | What Iron Vault provides |
|---|---|
| AI agents and MCP servers | Use FX, Brave, Venice, and other configured APIs without real keys in agent-readable configuration or environment variables |
| Naomi back-office applications | Share installation credentials through isolated routes; add Google consent and token refresh in the OAuth phase |
| Server and Compose applications | Keep credentials in one protected service while application containers receive only the proxy access they need |
| Developer CLI tools | Avoid provider credentials in application files where a tested base-URL integration supports the complete workflow |

## Roadmap

| Phase | Scope |
|---|---|
| v0 | Base-URL proxy; static and Basic credentials; caller authentication; route restrictions and rate limits; encrypted storage; versioned approval; scrubbing; recovery and migration |
| v1 | Service-owned OAuth consent, account identity, access-token caching, and safe refresh-token rotation |
| Later | YubiKey unlock/signing and per-request touch confirmation; additional credential kinds; password-manager sync |
| Conditional | Forward-proxy interception if required callers cannot use base-URL mode |

Integrations with `gh`, `npm`, and `cargo` require end-to-end compatibility checks. Setting `HTTPS_PROXY` alone does
not enable credential injection in base-URL mode. Routes that require touch must stay unavailable until a supported
confirmation provider exists.

## Security boundary

Iron Vault aims to prevent callers from extracting provider credentials. Malware that can read a caller's local
token can still use that caller's granted routes. Restrictions and rate limits bound that access; response
scrubbing reduces accidental disclosure but cannot recognize every transformed secret.

The host and runtime administrators remain trusted. Anyone who controls Iron Vault's Docker daemon can replace or
inspect it; TPM encryption does not protect secrets after the service unwraps them into memory. Protected deployments
must keep vault storage, unlock material, and deployment files outside ordinary callers' control. See the
[security requirements](iron-vault-specification.md#12-security-promise-and-limits) and
[deployment requirements](iron-vault-specification.md#314-docker-remote-servers-and-appliances).
