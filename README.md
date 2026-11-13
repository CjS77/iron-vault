[![Coverage Status](https://coveralls.io/repos/github/CjS77/iron-vault/badge.svg?branch=main)](https://coveralls.io/github/CjS77/iron-vault?branch=main)

# Iron Vault

A small local proxy that holds API credentials so the programs that use them never do.

Point an application's base URL at Iron Vault and give it a placeholder instead of a provider key. Iron Vault
authenticates the caller, checks its route, adds the credential, and forwards the request over verified TLS.
The application holds at most a local caller token that grants specific routes; it never needs the provider secret.

**Status:** v0 in progress, Linux only. The proxy works end to end in [development mode](book/src/installation/development-mode.md): you
can create a vault, store credentials, approve a config and send requests through it. The Debian package for a
[protected Linux installation](#protected-installation-linux) is built from this repository, but it has not had a release
check on a real machine yet, so don't rely on it to protect real secrets. The
[product specification](design/iron-vault-specification.md) defines the requirements, roadmap, threat mitigations, and
release checks.

## Features

Done in v0:

- **Credential injection:** static API keys and Basic authentication, placed in a header or query parameter that the
  route names.
- **Restricted routes:** callers authenticate by Unix peer account, caller token, or isolated-network listener. Each
  route is limited by credential, HTTP method, path and request rate. Permitted destinations are stored with the
  encrypted credential, so a route edit cannot send an existing secret to another host.
- **Listeners:** Unix sockets and TCP. A non-loopback TCP listener requires TLS, and a protected install takes TCP
  sockets from systemd socket activation.
- **Outbound requests:** HTTPS only, with verified TLS. Upstream redirects are never followed with credentials attached.
- **Encrypted storage:** credential records are encrypted with `age` and unlocked with an interactive passphrase.
  `init` creates an offline recovery key.
- **Versioned configuration approval:** each config change is signed and checked against a strictly increasing
  approval version. Old config/signature pairs are rejected after a newer approval, and an approved config takes
  effect without a restart.
- **Credential commands:** `add`, `replace`, `rm` and `list`; `replace` and `rm` need the approval passphrase.
- **Response scrubbing:** removes the credential's known forms from response headers, compressed bodies and streamed
  responses.
- **Approval signers:** more than one approver can sign config approvals, each with its own approval passphrase.
  `approver add` and `approver remove` rotate them; only a pinned approver authorizes the change, never the vault
  passphrase or a recovery key, so keep a second approver (`reset` is the only way out when none can answer).
- **Recipients:** `recipient list` shows who can open the vault. `recipient add` needs the vault passphrase;
  `recipient add --recovery` generates and shows a new recovery key, to rotate the old one. `recipient remove` needs
  the approval passphrase; removal protects future copies of `identity.age` only.
- **Docker Compose profile:** the service in a container, one isolated network and TLS listener per caller, and a host
  unlock that opens the vault at startup from a TPM-sealed identity. See the
  [Compose install guide](book/src/installation/compose-install.md); it has had no release check on a real machine yet.
- **Recovery key check:** `recovery check` proves the offline recovery key still opens the vault, in Locked or Ready, and
  records when.
- **Vault passphrase attempt limit:** after 5 wrong vault passphrases, `unlock` and migration authorization share one
  cooldown, starting at 30 s and doubling to 15 min. A limited owner is refused before any prompt, and `lock` does not
  clear the count.
- **Reset:** `reset` discards a vault whose every way in is lost, after a confirmation typed at a terminal, so you can `init`
  again and rebuild from your own copy of the config. It is not secure erasure.
- **Retiring a machine:** `forget-machine <age1…>` checks that a retired machine's recipient key is gone from the vault,
  warns when the recovery path is not verified, and prints the steps to delete the machine's sealed unlock credential and
  clear its TPM only if nothing else uses it. It runs nothing itself. See the [recipe](book/src/cookbook/forget-machine.md).
- **TPM unlock (Ubuntu 24.04 only):** a protected Linux install can open its vault at boot from an identity that
  `systemd-creds` seals to the machine's TPM and Secure Boot policy, with the vault passphrase and recovery key still
  working. v0 has no TPM PIN: a laptop relies on a full-disk-encryption pre-boot secret that the provisioning helper
  checks once, and a Secure Boot update ends unattended unlock until you provision again. It has had no release check on
  a real machine yet. See the [recipe](book/src/cookbook/tpm-unlock.md) and the
  [install guide](book/src/installation/linux-install.md#tpm-unlock).
- **Migration:** `export` writes the vault as an encrypted bundle after a fresh proof of the vault passphrase (or a
  `tpm` approver's TPM approval PIN), sealed with an export passphrase you choose; `import` makes the vault from it on a
  new machine, with a new vault passphrase and recovery key, and the source's records and approval counters unchanged.
  No plaintext secret is written on the way, and the new machine routes only after a config approval above every
  version the source reserved. See the [recipe](book/src/cookbook/move-vault.md).
- **TPM approval signer (Ubuntu 24.04 only):** a protected Linux install can pin a TPM-resident signing key as an
  approver. It signs a config approval, or proves your presence for `replace`, `rm` and the migration commands, once you
  type its PIN (at least 6 characters). A helper process of its own reaches the TPM, so the service never does, and it
  holds back half the TPM's wrong-PIN tries for other users. Keep a software approver beside it: a forgotten PIN is
  recovered through another approver. It has had no release check on a real machine yet. See the
  [recipe](book/src/cookbook/tpm-approval.md).
- **Audit logging:** typed JSON records of request and administrative events, which never log secret values. See the
  [log operations guide](book/src/reference/log-operations.md).

Still to come in v0:

- the v0 release acceptance suite.

Later phases add OAuth login and refresh, owner notifications, more credential kinds
(JWT, GitHub App, HMAC, AWS Signature Version 4), YubiKey recipients with PIN/touch policies, and macOS and Windows
services.

## Use cases

| Use case                        | What Iron Vault provides                                                                                                                                                                                     |
|---------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| AI agents and MCP servers       | Use FX, Brave, Venice, and other configured APIs without real keys in agent-readable configuration or environment variables ([recipe](book/src/cookbook/agent-api-key.md))                                   |
| Naomi back-office applications  | Share installation credentials through isolated routes ([recipe](book/src/cookbook/two-callers.md)); add Google consent and token refresh in the OAuth phase ([planned](book/src/cookbook/roadmap/oauth.md)) |
| Shared Linux workstations       | Give each OS account only its own routes, recognised from the connecting account, with no keys in any home directory ([guide](book/src/installation/multiuser-linux.md))                                     |
| Server and Compose applications | Keep credentials in one protected service while application containers receive only the proxy access they need ([guide](book/src/installation/compose-install.md))                                           |
| Developer CLI tools             | Avoid provider credentials in application files where a tested base-URL integration supports the complete workflow ([recipe](book/src/cookbook/real-application.md))                                         |

## Roadmap

| Phase       | Scope                                                                                                                                                                                                                                             |
|-------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| v0          | Base-URL proxy; static and Basic credentials; caller authentication; route restrictions and rate limits; encrypted storage; versioned approval; vault passphrase attempt limits; scrubbing; recovery and migration                                |
| v1          | Service-owned OAuth consent, account identity, access-token caching, and safe refresh-token rotation; owner notifications; request-content restrictions (allow-lists on query parameters and JSON body fields, such as the models a key may call) |
| Later       | YubiKey unlock/signing and per-request touch confirmation; additional credential kinds; password-manager sync                                                                                                                                     |
| Conditional | Forward-proxy interception if required callers cannot use base-URL mode                                                                                                                                                                           |

Integrations with `gh`, `npm`, and `cargo` require end-to-end compatibility checks. Setting `HTTPS_PROXY` alone does
not enable credential injection in base-URL mode. Until a supported confirmation provider exists, a config with a
route that requires touch is refused when it is read.

## Security boundary

Iron Vault aims to prevent callers from extracting provider credentials. Malware that can read a caller's local
token can still use that caller's granted routes. Restrictions and rate limits bound that access; response
scrubbing reduces accidental disclosure but cannot recognize every transformed secret.

The host and runtime administrators remain trusted. Anyone who controls Iron Vault's Docker daemon can replace or
inspect it; TPM encryption does not protect secrets after the service unwraps them into memory. Protected deployments
must keep vault storage, unlock material, and deployment files outside ordinary callers' control. See the
[security requirements](design/iron-vault-specification.md#2-security-promise-and-limits) and
[deployment requirements](design/iron-vault-specification.md#17-docker-remote-servers-and-appliances). The manual's
[security model](book/src/security-model.md) explains how the vault is locked.

## Protected installation (Linux)

On Linux the `.deb` package runs Iron Vault as the `iron-vault` system service, with its vault in `/var/lib/iron-vault`
out of reach of ordinary accounts:

```sh
sudo apt install libtss2-dev pkg-config lintian   # once: the TPM signing helper links libtss2
cargo install cargo-deb --locked                   # once
scripts/build-deb.sh                               # builds both binaries, checks the package, writes target/debian/
sudo apt install ./target/debian/iron-vault_*.deb
sudo iron-vault init
sudo iron-vault unlock
```

The [installation guide](book/src/installation/linux-install.md) covers what the protection depends on: `sudo` credential caching and a
second factor, encrypted swap and hibernation storage. It also covers adding a TCP listener, upgrading (the service
restarts Locked, so run `unlock` again, unless TPM unlock is set up), and uninstalling and purging (the vault is kept unless you say otherwise). The
[multi-user guide](book/src/installation/multiuser-linux.md) shows a complete setup.

## Quickstart

This runs Iron Vault in [development mode](book/src/installation/development-mode.md): as your own user, with **no
isolation from malware running as you**. Use it to try Iron Vault, never to protect real secrets. It needs Linux, a
Rust toolchain and `curl`.

```sh
cargo install --path crates/iron-vault --features dev-mode --root ~/.local/iron-vault-dev
chmod -R go-w ~/.local/iron-vault-dev && export PATH="$HOME/.local/iron-vault-dev/bin:$PATH"
iron-vault serve &                                   # or in a terminal of its own; give it a second to start
iron-vault init                                      # sets two passphrases and shows the recovery key once
iron-vault unlock
iron-vault add httpbin_key --origin httpbin.org      # type any test value: httpbin checks no keys
mkdir -m 700 -p ~/.iron-vault-tokens
iron-vault caller-token > ~/.iron-vault-tokens/me    # prints the token_hash line for the config
```

Save this as `dev-config.toml`, with your `token_hash` line in place of the placeholder:

```toml
schema_version = 1

[listeners.loopback]
address = "127.0.0.1:7878"

[callers.me]
listener = "loopback"
token_hash = "blake2b:<the 64 hex digits caller-token printed>"
routes = ["httpbin"]

[routes.httpbin]
prefix = "/httpbin"
upstream = "https://httpbin.org"
credential = "httpbin_key"
slot = { header = "Authorization", format = "Bearer {}" }
methods = ["GET"]
paths = ["/headers"]
rate_limit = { requests = 30, per_seconds = 60, burst = 5 }
```

```sh
iron-vault config approve dev-config.toml            # shows a summary; type yes, then the approval passphrase
curl -s -H "Proxy-Authorization: Bearer $(cat ~/.iron-vault-tokens/me)" http://127.0.0.1:7878/httpbin/headers
```

httpbin echoes the request it received: its `Authorization` header reads `Bearer [iron-vault:scrubbed]`, because
Iron Vault added the key and then scrubbed it from the response. The route's bucket starts empty after the approval,
so a request sent at once may get `429`; wait a few seconds. Stop the service with `kill %1` when you're done. The
[getting started recipe](book/src/cookbook/getting-started.md) walks through each step and what it prints.

## The manual

The user manual is an mdBook in [`book/`](book/src/SUMMARY.md):

- **Installation:** [development mode](book/src/installation/development-mode.md),
  [protected Linux](book/src/installation/linux-install.md),
  [a shared Linux workstation](book/src/installation/multiuser-linux.md) and
  [Docker Compose](book/src/installation/compose-install.md).
- **Cookbook:** short recipes, each ending with something that works, starting with
  [getting started](book/src/cookbook/getting-started.md). Recipes for features not yet built are under
  [not yet available](book/src/cookbook/roadmap/index.md).
- **Reference:** the [CLI](book/src/reference/cli.md), [configuration](book/src/reference/configuration.md),
  [errors](book/src/reference/errors.md), [service states](book/src/reference/states.md),
  [audit log](book/src/reference/audit-log.md) and [files and locations](book/src/reference/files.md).
- **[Security model](book/src/security-model.md):** how the vault is locked.
- **[Glossary](design/glossary.md):** the terms the manual and the code share.

Design documents and the [product specification](design/iron-vault-specification.md) are in `design/`. The
[visual design](design/visual-design.md) covers the logo, typefaces and CSS, and [design reviews](design/reviews/README.md)
are indexed in `design/reviews/`. The [v0 acceptance index](design/v0-acceptance.md) maps each release check to the tests that show it.
