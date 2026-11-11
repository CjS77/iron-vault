# Security model

The [security promise and limits](../../design/iron-vault-specification.md#2-security-promise-and-limits) in the
specification say what Iron Vault protects against and what it doesn't. This page explains how the vault is locked.

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

### Several approval signers

Approving a config, and the changes that need your presence, is a separate lock from unlocking the vault. The vault
pins one or more **approvers**, each backed by an approval signer, and any one of them speaks for you. The vault
passphrase and the recovery key open the vault identity but never count as approval: the vault passphrase can mint a
new recovery key, so a stolen vault passphrase would otherwise approve any config. Only a pinned approver's
passphrase enrolls or removes an approver. The price is that losing every approver's passphrase leaves
[`reset`](cookbook/reset-vault.md) as the only way out, so
[keep a second one](cookbook/approval-signers.md#why-keep-a-second-approver).

An approver can be a key held in the machine's TPM behind a PIN ([recipe](cookbook/tpm-approval.md)). The service never
opens the TPM: a separate helper, running as its own account and reachable only by the service account, signs the three fixed
payloads the service sends it, and only under the PIN you typed. The TPM limits guessing by itself, and the helper refuses to
work on a TPM whose lockout interval is under 600 seconds, so a compromised service gets 16 guesses and then about one per ten
minutes; the PIN is at least 6 characters for that reason. The TPM keeps no copy of the PIN, so a forgotten PIN is recovered
through another approver, and a vault whose only approver is a lost TPM one is back to `reset`. This protects the approval from
a stolen vault passphrase or a service that took over a running process. It does not protect against someone who controls the
host: root, or any member of the `tss` group, can weaken the TPM's lockout settings, and the helper then refuses to sign.

### What this doesn't protect against

- **Removing a recipient doesn't reach old copies.** It only changes future versions of `identity.age`. A backup
  made earlier can still be opened with the removed key. If a machine is lost, rotate the provider credentials it
  could reach.
- **Encryption doesn't say who wrote a file.** Anyone with the vault's public key can create a file that looks like
  a stored credential. So the vault keeps its own list of which credential files are real, sealed with a code that
  only the holder of the vault identity can produce. A file missing from that list is never trusted.
