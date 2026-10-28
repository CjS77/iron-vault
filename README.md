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

## How the vault is locked

Iron Vault encrypts with [`age`](https://age-encryption.org). You don't need to know any cryptography to follow
this section.

### One vault identity opens everything

Each vault has one secret key, its **vault identity**. Every stored credential is locked with it, along with the
vault's list of which credentials exist. When the service starts, it unlocks the vault identity once and keeps it in
memory. It never needs a key per credential.

### Several people or devices can unlock the vault identity

The vault identity lives in one file, `identity.age`. Think of that file as a safe with one copy of the vault
identity inside. Fixed to the outside of the safe are several small lockboxes, one for each **recipient**: this
machine, your offline recovery key, and later a TPM or YubiKey. Every lockbox holds the same thing, the combination to
the safe.

- Each lockbox opens only with its own recipient's private key.
- Any one recipient can open their lockbox, read the combination, open the safe and take out the vault identity.
- The recipients never share a secret with each other. Each has their own lockbox.
- A seal over all the lockboxes catches any damage to them, or a lockbox added, removed or swapped, when the safe is
  opened. The seal is made with the combination itself, so it doesn't stop someone who can already open a lockbox
  from building a new safe. That is why only the service may write the vault's files.

Adding or removing a recipient only rebuilds `identity.age` with a different set of lockboxes. The stored
credentials don't change.

Every vault has at least two recipients, so losing one device or forgetting one passphrase doesn't lose the vault.

### How a lockbox is locked for one recipient

Each recipient has a key pair: a public key that anyone may see, and a private key only they hold. To lock a
lockbox for a recipient, Iron Vault:

1. makes a brand-new, single-use key pair of its own;
2. combines its single-use private key with the recipient's public key to get a shared secret;
3. uses that shared secret to lock the combination inside the lockbox;
4. stores its single-use public key on the outside of the lockbox, then throws away the single-use private key.

To open the lockbox, the recipient combines their own private key with the single-use public key stored on it. The
maths gives them the same shared secret, which opens the lockbox. Nobody else can work it out from the public parts.

For readers who want the names: the key pairs are X25519, the shared secret goes through HKDF-SHA256, the
locking is ChaCha20-Poly1305, and the seal over the lockboxes is HMAC-SHA256.

### Unlocking with a passphrase

`age` won't put a passphrase lockbox on the same safe as key-pair lockboxes. So for passphrase unlock, Iron Vault
makes one extra key pair, the **operational identity**:

- its public half gets an ordinary lockbox on `identity.age`;
- its private half is kept in a separate file, `operational.age`, locked only by your passphrase.

Unlocking goes: passphrase → operational identity → vault identity.

### What this doesn't protect against

- **Removing a recipient doesn't reach old copies.** It only changes future versions of `identity.age`. A backup
  made earlier can still be opened with the removed key. If a machine is lost, rotate the provider credentials it
  could reach.
- **Encryption doesn't say who wrote a file.** Anyone with the vault's public key can create a file that looks like
  a stored credential. So the vault keeps its own list of which credential files are real, sealed with a code that
  only the holder of the vault identity can produce. A file missing from that list is never trusted.
