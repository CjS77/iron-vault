# Changelog

All notable changes to Iron Vault are recorded here. Versions follow [Semantic Versioning](https://semver.org/); the
Linux package carries the same version with `~` before the pre-release tag (`0.4.0-alpha` is `0.4.0~alpha-1`).

## [0.4.0-alpha] - 2026-11-13

### Breaking changes

A config approved under 0.3.0-alpha can stop working under 0.4.0-alpha. Check each route against the first item below
before you approve it again.

- **Route `paths` now match the request path after the route `prefix`, not the full path sent upstream.** In
  0.3.0-alpha a pattern had to name the upstream's base path (the path part of `upstream`) followed by the rest of the
  request path. Patterns now name only the path the provider documents. The service adds the base path when it forwards
  the request, so the forwarded URL is unchanged.
  - **Who is affected:** every route whose `upstream` has a path, such as `https://api.venice.ai/api/v1`,
    `https://api.search.brave.com/res` or `https://openexchangerates.org/api`. A route whose `upstream` is a bare origin
    (`https://api.search.brave.com`) matches as before.
  - **What an unmigrated route does:** the config still reads and approves, but its patterns repeat the base path, so
    the client's usual requests are refused with `403 path_not_allowed` before anything is sent. A request that happens
    to repeat the base path itself is forwarded with the base path twice (`/api/v1/api/v1/...`), and the provider
    answers `404`. The change never lets a route reach a path it could not reach before.
  - **How to migrate:** remove the upstream's base path from the start of each pattern, then approve the config again:

    | `upstream`                          | `paths` in 0.3.0-alpha         | `paths` in 0.4.0-alpha  |
    | ----------------------------------- | ------------------------------ | ----------------------- |
    | `https://api.venice.ai/api/v1`      | `["/api/v1/chat/completions"]` | `["/chat/completions"]` |
    | `https://api.search.brave.com/res`  | `["/res/v1/web/search"]`       | `["/v1/web/search"]`    |
    | `https://openexchangerates.org/api` | `["/api/latest.json"]`         | `["/latest.json"]`      |
    | `https://api.svc.example/v1`        | `["/v1/**"]`                   | `["/**"]`               |

    Clients keep their base URL (`http://127.0.0.1:7878/venice` and so on). Only the config changes. See
    [`paths`](book/src/reference/configuration.md) in the configuration reference.
- **`X-Iron-Vault-Token` is a reserved header.** Every listener strips it from a request before forwarding, whether or
  not that listener reads its caller token from it. A route `slot` can no longer name it: a config whose slot does is
  refused when it is read. A listener's `token_header` may still be `X-Iron-Vault-Token` or `Proxy-Authorization`.
- **`[limits] upstream_timeout_secs` is now enforced.** In 0.3.0-alpha it was approved but ignored, and every route
  waited up to a fixed 300 s for response headers. Now a request waits as long as the approved value. A config set
  below 300 s gets `504` sooner than before. A config set above 300 s now waits that long, where it used to stop at
  300 s.
- **A protected install's admin socket accepts only root.** The service account can no longer run admin commands.
  Run them with `sudo iron-vault ...`.

### Added

- **Migration:** `export` writes the vault as an encrypted migration bundle, through a partial file, after a fresh
  proof of the vault passphrase or a TPM approver's PIN. `import` makes a vault from the bundle on a new machine, with
  a new vault passphrase and recovery key, and leaves a checked config copy beside the bundle. `import --host-unlock`
  enrols the host unlock identity. `status`, `init` and `reset` report an unfinished import. Export refuses when no
  software approver is pinned, and never bundles a TPM key file.
- **Approval signers:** more than one approver can be pinned. `approver list`, `approver add` and `approver remove`
  manage them. The approval envelope and the audit records name the signing approver, and an owner can switch approver
  at a prompt.
- **TPM approval signer:** `approver add --kind tpm` enrols a TPM-resident ECDSA P-256 signing key. A separate helper,
  `iron-vault-tpm-signer`, reaches the TPM; its PIN is at least 6 characters, and the authorization value is
  personalized with `iv-tpm-pin-v1`. The service verifies its approvals as signer algorithm `02`.
- **TPM unlock:** in the Protected profile the service tries host unlock at startup and reports a failed unseal as
  `unseal_failed`. `recipient add --host-unlock` enrols a host unlock key. The package installs the host unlock
  handoff unit and provisioning helper. The provisioning helper's `--portable` check looks for a pre-boot secret,
  walks every member of a multi-device btrfs or bcachefs, and warns on a crypttab keyscript that unlocks unattended.
- **Reset:** `reset` discards a vault whose every way in is lost, after a confirmation typed at a terminal, with an
  unfinished-reset marker.
- **Retiring a machine:** `forget-machine` checks that a retired machine's recipient key is gone from the vault, warns
  when the recovery path is not verified, and prints the decommission steps.
- **Lock across restarts:** `lock` survives a service restart through an owner-lock file.
- **Status:** lists approved listeners that failed to open.
- **Policy:** an approval says when it repeats the active config. A config with a route that sets
  `confirm = "touch"` is refused when it is read, so `config approve` refuses it before any prompt. In 0.3.0-alpha
  the refusal came only at activation; v0 has no touch confirmation provider, so such a route never served either way.
- **Linux package:** man pages; the TPM signing helper, its socket and service units, enabled and checked on install.
  `configure` refuses an existing `iron-vault` login account, and an `iron-vault` group with a password,
  administrators or members in `/etc/gshadow` or `/etc/group`.
- **Release:** a release workflow builds and checks the `.deb` for each release and release tag, with a tag check
  against the crate version. Coverage is measured on release tags and pull requests. Release checks added for TPM
  unlock and the TPM signer, the latter also run against an emulated TPM.

### Changed

- The licence is now MPL-2.0 (was Apache-2.0).
- Dev builds keep line-table debug info only, and the release profile is stripped.

### Fixed

- `SO_PEERCRED` is read safely when the peer is in another PID namespace.
- The Linux package lifts the service start limit, so a crash loop keeps listener ports held.
- `discard` removes the config temp file an interrupted import leaves.
- Export retries an interrupted write to its sink, stops after the sink fails, and syncs the bundle directory even
  when unlinking the partial file fails.
- Memory is locked before `init` handles a secret.
- The Compose profile creates the unlock mount point as root `0711`.
- An approval with no active config shows the whole config as added.

### Dependency updates

- bitfield: (new) => 0.19.5
- clap_mangen: (new) => 0.3.3
- p256: (new) => 0.13.2
- sha2: (new) => 0.10.9
- tss-esapi: (new) => 7.7.0

[0.4.0-alpha]: https://github.com/CjS77/iron-vault/compare/v0.3.0-alpha...v0.4.0-alpha
