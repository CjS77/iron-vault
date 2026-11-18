# Recover from an upgrade that cannot open the vault

*Written from the code of `iron-vault 0.4.0-alpha` for an upgrade from 0.3.0-alpha. The steps have not been run end to
end on a real machine.*

Replace a vault the new release cannot read with a new one, and add your config and credentials again. Use it only
when the release's [changelog](https://github.com/CjS77/iron-vault/blob/main/CHANGELOG.md) says, under **Breaking
changes**, that a vault made by the older release cannot be opened, as for 0.3.0-alpha to 0.4.0-alpha. No command
recovers the old credentials: each must be reissued by its provider.

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

The record's `remediation` says not to delete or re-initialize the state directory; that is for damage. Go on only if:

- the record appeared right after the upgrade, and
- the changelog says this upgrade cannot open the old vault.

If either is not true, stop: something else damaged the vault. Follow [tamper detection and recovery](tamper-detection.md)
and keep the state directory as it is.

### 2. Save the config and the credential names

`reset` deletes the published config, and `list` cannot read this vault, so take both from the config:

```sh
sudo cat /etc/iron-vault/config.toml > ~/iron-vault-config.toml
grep -E '^\s*(credential|upstream)\s*=' ~/iron-vault-config.toml
```

Each `credential` line names a credential to add again, and the `upstream` beside it gives its host. The `token_hash`
lines still match the tokens your callers hold.

### 3. Update the config for the release's other breaking changes

Change your copy to match the rest of the release's **Breaking changes**. For 0.4.0-alpha:

- **Route `paths` match after the prefix.** For a route whose `upstream` has a path, remove that path from the start of
  each pattern: with `upstream = "https://api.venice.ai/api/v1"`, `"/api/v1/chat/completions"` becomes
  `"/chat/completions"`. A route you miss still approves, but its requests get `403 path_not_allowed`.
- **`X-Iron-Vault-Token` is reserved.** A route `slot` that names it is refused.
- **`[limits] upstream_timeout_secs` is enforced.** Check that it is long enough for your slowest provider.

### 4. Reset the old vault

```sh
sudo iron-vault reset
```

It works on a vault the new release cannot open. Type the vault ID when asked:

```text
reset: discarded vault 3f1c9a5e-0b9c-4f7e-8a41-6d2b7e0c1a55; 7 files removed
next: run `iron-vault init`
```

See [reset the vault](reset-vault.md). A file the old release named differently is left, and `init` refuses until it is
gone. From 0.3.0-alpha, that is the old approver key:

```text
left in place, move it aside before `init`: approver.age
```

Delete it:

```sh
sudo rm /var/lib/iron-vault/approver.age
```

### 5. Create the new vault

```sh
sudo iron-vault init
sudo iron-vault unlock
```

Store the new recovery key as in [check and store your recovery key](recovery-key.md). If you used
[TPM unlock](tpm-unlock.md), run `sudo iron-vault init --host-unlock` instead. If you had a [TPM approver](tpm-approval.md)
or a second software approver, enroll it again with `approver add`.

The service is Ready with no routes; every request is refused until step 6.

### 6. Add the credentials and approve the config

Add each credential from step 2 with the value its provider gives you, and the host from its route's `upstream`:

```sh
sudo iron-vault add venice_key --origin api.venice.ai
sudo iron-vault config approve ~/iron-vault-config.toml
```

The summary lists the whole config as added. Type `yes`, then the new approval passphrase.

**Revoke the old keys at each provider:** `reset` is not secure erasure, and a backup of the old vault still opens with
the old vault passphrase or recovery key.

### 7. Check

```sh
sudo iron-vault status
sudo iron-vault list
```

`status` shows `service: ready` and the new vault ID, and `list` shows the credentials you added. Send a request through
a route you use, as [getting started](getting-started.md) does.

## Before the next breaking upgrade

Before you install a release whose changelog lists a format change, while the old release can still read the vault:

```sh
sudo cp /etc/iron-vault/config.toml ~/iron-vault-config.toml
sudo iron-vault list > ~/iron-vault-credentials.txt
```

If the changelog says the new release imports the old release's `export` bundle, [move the vault](move-vault.md)
instead, keeping the credentials.

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
