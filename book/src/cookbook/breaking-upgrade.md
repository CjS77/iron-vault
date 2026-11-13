# Recover from an upgrade that cannot open the vault

*Written from the code of `iron-vault 0.4.0-alpha` for an upgrade from 0.3.0-alpha. The steps have not been run end to
end on a real machine.*

At the end of this recipe a release that cannot read the vault an older release made is running a new, empty vault, with
your config approved again and your credentials added again. Use it only when the release's
[changelog](https://github.com/CjS77/iron-vault/blob/main/CHANGELOG.md) says, under **Breaking changes**, that a vault
made by the older release cannot be opened. Upgrading from 0.3.0-alpha to 0.4.0-alpha is such a case.

Iron Vault is pre-release, and a pre-release may change a file format without carrying the old one forward. When it
does, the new release cannot open the old vault, and no command recovers its credentials: neither the vault passphrase
nor the recovery key helps, because the identity opens and it is the files after it that the new code cannot read. The
credential values have to come from the providers again.

The commands below are for a [protected Linux install](protected-linux.md). In
[development mode](../installation/development-mode.md), drop `sudo`, and the config is
`~/.config/iron-vault-dev/config.toml`. In a [Docker Compose install](compose.md), run the host CLI as its guide says.

## Prerequisites

- The new release installed, the service running, and `unlock` ending as in step 1.
- An administrator account and a terminal: [`reset`](reset-vault.md) asks for a confirmation typed at one.
- A way to get a new value for each credential from its provider.

## Steps

### 1. Check that this is the format change, not damage

```sh
sudo iron-vault unlock
sudo iron-vault status
```

After a 0.3.0-alpha to 0.4.0-alpha upgrade, `unlock` takes the vault passphrase, then ends with
`unlocked-unavailable` (error 16): "the vault unlocked, but the config check failed: the service is Unavailable
(recovery needed)". `status` shows:

```text
service: unavailable
reason: recovery needed
```

Every request gets `503` with reason `recovery needed`. The log names the file the new release could not read:

```sh
sudo jq -c 'select(.event == "vault.shared-state-damaged") | {timestamp, file, damage}' /var/log/iron-vault/iron-vault.log
```

```json
{"timestamp":"…","file":"approval.age","damage":"approval_state"}
```

The record's `remediation` says not to delete or re-initialize the state directory. That advice is for damage, where a
backup or the recovery key can bring the vault back. Here the file is intact; no release from 0.4.0-alpha on reads
its layout. Go on only if:

- the record appeared right after the upgrade, and
- the changelog says this upgrade cannot open the old vault.

If either is not true, stop: something else damaged the vault. Follow [tamper detection and recovery](tamper-detection.md)
and keep the state directory as it is.

### 2. Save the config and the credential names

`reset` deletes the published config, and `list` needs a vault the service can open, so take both from the config:

```sh
sudo cat /etc/iron-vault/config.toml > ~/iron-vault-config.toml
grep -E '^\s*(credential|upstream)\s*=' ~/iron-vault-config.toml
```

Each `credential` line names a credential to add again, and the `upstream` beside it gives the host its value is sent
to. Caller tokens are not stored in the vault, so the `token_hash` lines still match the tokens your callers hold.

### 3. Update the config for the release's other breaking changes

Read the rest of **Breaking changes** for the release and change your copy to match, so that the approval in step 6
gives you a config that serves. For 0.4.0-alpha:

- **Route `paths` match after the prefix.** For a route whose `upstream` has a path, remove that path from the start of
  each pattern: with `upstream = "https://api.venice.ai/api/v1"`, `"/api/v1/chat/completions"` becomes
  `"/chat/completions"`. A route you miss still approves, but its requests get `403 path_not_allowed`.
- **`X-Iron-Vault-Token` is reserved.** A route `slot` that names it is refused.
- **`[limits] upstream_timeout_secs` is enforced.** Check that it is long enough for your slowest provider.

### 4. Reset the old vault

```sh
sudo iron-vault reset
```

`reset` reads the vault ID from the manifest's clear header, so it works on a vault the new release cannot open. It
shows what it will discard, then asks you to type the vault ID. Once you do, it removes the vault and the config:

```text
reset: discarded vault 3f1c9a5e-0b9c-4f7e-8a41-6d2b7e0c1a55; 7 files removed
next: run `iron-vault init`
```

[Reset the vault](reset-vault.md) explains the summary and what is kept: the audit log, TLS files and the host unlock
credential stay.

Reset removes only files whose names the running release writes. A file the old release named differently is left, and
`init` refuses until it is gone. From 0.3.0-alpha, that is the old approver key, `approver.age` (0.4.0-alpha names
approver keys `approver-<id>.age`):

```text
left in place, move it aside before `init`: approver.age
```

It is the old vault's approver key, sealed under the old approval passphrase, and the vault it signed for is gone.
Delete it:

```sh
sudo rm /var/lib/iron-vault/approver.age
```

### 5. Create the new vault

```sh
sudo iron-vault init
sudo iron-vault unlock
```

`init` sets a new vault passphrase and approval passphrase, and shows a new recovery key once. The old recovery key opens
nothing now: store the new one as in [check and store your recovery key](recovery-key.md). If you used
[TPM unlock](tpm-unlock.md), run `sudo iron-vault init --host-unlock` instead. If you had a [TPM approver](tpm-approval.md)
or a second software approver, enroll it again with `approver add`.

`init` commits an empty config, so `unlock` reports the service Ready. It has no routes yet, so every request is refused
until step 6.

### 6. Add the credentials and approve the config

Add each credential from step 2 with the value its provider gives you, and the host from its route's `upstream`:

```sh
sudo iron-vault add venice_key --origin api.venice.ai
sudo iron-vault config approve ~/iron-vault-config.toml
```

`config approve` shows the whole config as added, because nothing is active yet. Type `yes`, then the new approval
passphrase.

Revoke the old keys at each provider. `reset` is not secure erasure, and a backup of the old vault still opens with the
old vault passphrase or recovery key.

### 7. Check

```sh
sudo iron-vault status
sudo iron-vault list
```

`status` shows `service: ready` and the new vault ID, and `list` shows the credentials you added. Send a request through
a route you use, as [getting started](getting-started.md) does.

## Before the next breaking upgrade

The old release can still read its own vault, so do these before you install a release whose changelog lists a format
change:

```sh
sudo cp /etc/iron-vault/config.toml ~/iron-vault-config.toml
sudo iron-vault list > ~/iron-vault-credentials.txt
```

If both releases have `export` and `import`, and the changelog says the new release imports the old release's bundle,
[move the vault](move-vault.md) instead. That keeps the credentials, so the providers need not reissue them.

## What can go wrong

- **`reset` exits with code 3.** It found no terminal. Run it from an interactive shell.
- **`config approve` refuses with `config-invalid`.** The message names the route or field. It is usually a change from
  step 3 that was missed, or a credential from step 2 that has not been added yet.
- **Requests get `403 path_not_allowed` after the approval.** A route's `paths` still repeat its `upstream` path. Fix them
  as in step 3 and approve again.

## Reference

- [Reset the vault](reset-vault.md), [errors](../reference/errors.md) and [service states](../reference/states.md).
- [Audit log](../reference/audit-log.md): `vault.shared-state-damaged` and `config.check-failed`.
- [Upgrade a protected install](../installation/linux-install.md#upgrade).
