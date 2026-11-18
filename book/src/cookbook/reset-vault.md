# Reset the vault

Discard the vault and its config and make a new, empty vault. Use it only when no way in is left: neither the vault
passphrase nor the recovery key opens the vault, or no approver can answer
([why to keep a second approver](approval-signers.md#why-keep-a-second-approver)). If the vault passphrase works and an
approver answers, [rotate the recovery key](recipients.md) or [the approval passphrase](approval-signers.md) instead.
After an upgrade that cannot read the vault, see [Recover from an upgrade](breaking-upgrade.md) first.

**`reset` cannot be undone.** Every credential, the config and its signatures are deleted. **It is not secure
erasure:** a backup of the old vault still opens with the old recovery key and vault passphrase, so rotate at the
provider any credential that may have leaked.

The commands are for [development mode](../installation/development-mode.md). In a protected installation, use `sudo`
and read the config from `/etc/iron-vault/config.toml`; see
[`sudo` in a protected installation](../reference/cli.md#sudo-in-a-protected-installation).

## Prerequisites

- The service running, Ready, Locked or Unavailable.
- An administrator account: `reset` is refused to anyone else.
- A terminal. The confirmation must be typed at one; `reset` cannot be scripted or fed from a pipe.

## Steps

### 1. Keep what you will need

Reset keeps no copy of anything. Save:

- **Your own copy of the config.** If you have lost it, copy the published one before you confirm.
- **The output of `iron-vault list`** (needs the vault unlocked), so you know which credentials to reissue.

```sh
cp ~/.config/iron-vault-dev/config.toml ~/iron-vault-config.toml
iron-vault list > ~/iron-vault-credentials.txt
```

Credential values cannot be recovered. Each key is reissued by its provider.

### 2. Reset

```sh
iron-vault reset
```

It shows what it will discard, then asks you to type the vault ID:

```text
Type 3f1c9a5e-0b9c-4f7e-8a41-6d2b7e0c1a55 to discard this vault
```

Type or paste the ID; anything else, or Ctrl-C, removes nothing. When no vault is Initialized (a half-finished
`init`), type the state directory's path instead. The service keeps serving until you confirm, then stays Locked.

On success it prints how many files it removed, and any file it left in place:

```text
reset: discarded vault 3f1c9a5e-0b9c-4f7e-8a41-6d2b7e0c1a55; 7 files removed
next: run `iron-vault init`
```

The audit log, TLS files, the host unlock credential and any file it did not recognise stay. If it names a file it
left in place, move that aside before the next step.

### 3. Create the new vault

```sh
iron-vault init
iron-vault unlock
```

Store the new recovery key as in [check and store your recovery key](recovery-key.md). On a Compose or host-unlock
installation, run `iron-vault init --host-unlock` instead.

### 4. Rebuild

Add each credential again with the value its provider reissued, then approve your copy of the config:

```sh
iron-vault add fx_key --origin openexchangerates.org
iron-vault config approve ~/iron-vault-config.toml
```

Your callers' tokens still match the `token_hash` lines in your copy of the config.

### 5. Check

```sh
iron-vault status
iron-vault list
```

`status` shows `service: ready` and the new vault ID, and `list` shows the credentials you added.

## What can go wrong

- **`reset` exits with code 3.** It found no terminal; it refuses a pipe or file. Run it from an interactive shell.
- **`nothing-to-reset`.** No vault file is there. Run `iron-vault init`, or move the file the message names aside.
- **`declined`.** What you typed did not match, or the vault changed while the summary was on screen. Nothing was removed;
  run `reset` again.
- **`reset-failed`.** A file could not be removed. Unless the message says the vault is intact, `status` shows
  `reset unfinished`: fix the cause the message names and run `iron-vault reset` again. Until it finishes, `unlock` and
  `init` refuse.

## Reference

- [CLI](../reference/cli.md#iron-vault-reset) and [errors](../reference/errors.md#reset).
- [Audit log](../reference/audit-log.md): `vault.reset-confirmed`, `vault.reset` and `vault.reset-failed`.
- [Reset design](../../../design/reset.md): what is removed, in what order, and why.
- Related: [start over in development mode](start-over.md), [retire a machine](forget-machine.md).
