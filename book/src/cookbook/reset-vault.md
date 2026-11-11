# Reset the vault

At the end of this recipe the vault and its config are gone, and a new, empty vault with new passphrases is running
under the same service. Use it when no way into the vault works any more: you have lost the vault passphrase and the
recovery key, or every approval passphrase (see [why to keep a second approver](approval-signers.md#why-keep-a-second-approver)).
If the vault still opens, [rotating](recipients.md) is cheaper.

`reset` is destructive and cannot be undone. Every credential in the vault is deleted, and the config with its
signatures goes too. Removal is not secure erasure: a backup of the old vault still opens with the old recovery key
and vault passphrase, so rotate at the provider any credential that may have leaked.

## Prerequisites

- The service running, in any state: Ready, Locked or Unavailable.
- An administrator account: `reset` is refused to anyone else.
- A terminal. The confirmation must be typed at one; `reset` cannot be scripted or fed from a pipe.

## Steps

### 1. Keep what you will need

Reset keeps no copy of anything. Before you start, save:

- **Your own copy of the config.** The approved `config.toml` is deleted, so the file you approved from is the one
  you rebuild from. If you have lost it, `/etc/iron-vault/config.toml` is still on disk until you confirm, readable only by the service account (a development
  install keeps it under `~/.config/iron-vault-dev`).
- **The output of `iron-vault list`**, if the vault opens, so you know which credentials to reissue. The reset summary
  also lists the credential names, but only while the vault is readable.

```sh
sudo cp /etc/iron-vault/config.toml ~/iron-vault-config.toml
iron-vault list > ~/iron-vault-credentials.txt
```

Credential values cannot be recovered. Each key is reissued by its provider.

### 2. Reset

```sh
iron-vault reset
```

The service stops serving, then shows what it will discard: the vault ID, the credential names, the config files,
any file it does not recognise (these stay), and what to keep. It then asks you to type the vault ID:

```text
Type 3f1c9a5e-0b9c-4f7e-8a41-6d2b7e0c1a55 to discard this vault
```

Type the ID, or paste it. `yes` is not accepted, and neither is an empty line. Anything else, or Ctrl-C, removes
nothing. When no vault is Initialized (a half-finished `init`), you type the state directory's path instead.

The confirmation must come from a terminal. With standard input a pipe, a file or `/dev/null`, or with no terminal
for the process, the command exits with code 3 before it connects, and nothing is removed.

On success it prints how many files it removed, and any file it left in place. Move a file it left aside before the
next step.

### 3. Create the new vault

```sh
iron-vault init
iron-vault unlock
```

`init` makes a new vault with a new vault ID, new passphrases and a new recovery key. Store the key as in
[check and store your recovery key](recovery-key.md). The old config and its signature are refused by the new vault,
even if you put them back.

### 4. Rebuild

Add each credential again with the value its provider reissued, then approve your copy of the config:

```sh
iron-vault add fx_key --origin api.fx.example
iron-vault config approve ~/iron-vault-config.toml
```

Caller tokens are not stored in the vault, so the `token_hash` lines in your copy of the config still match the tokens
your callers hold.

### 5. Check

```sh
iron-vault status
iron-vault list
```

`status` shows `service: ready` and the new vault ID, and `list` shows the credentials you added.

## What can go wrong

- **`reset` exits with code 3.** It found no terminal. Run it from an interactive shell.
- **`nothing-to-reset`.** No vault file is there. Run `iron-vault init`, or move the file the message names aside.
- **`declined`.** What you typed did not match, or the vault changed while the summary was on screen. Nothing was
  removed; run `reset` again.
- **`reset-failed`.** A file could not be removed. `status` shows `reset unfinished`; fix the cause the message names
  and run `iron-vault reset` again. Until it finishes, `unlock`, `init` and `import` refuse.

## Reference

- [CLI](../reference/cli.md#iron-vault-reset) and [errors](../reference/errors.md#reset).
- [Audit log](../reference/audit-log.md): `vault.reset-confirmed`, `vault.reset` and `vault.reset-failed`.
- [Reset design](../../../design/reset.md): what is removed, in what order, and why.
- Related: [start over in development mode](start-over.md), [retire a machine](roadmap/forget-machine.md) (not yet available).
