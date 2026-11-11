# Start over in development mode

*Checked with `iron-vault 0.2.0-alpha (features: dev-mode)`, built from `main` at `378d57d`.*

At the end of this recipe a development install has no vault, no config and no log, and the service starts as it did
the first time, ready for `init`. Do this when you have finished experimenting, or to try a recipe from a clean start.
It deletes every credential in the development vault, and the recovery key cannot bring them back.

The commands below were run with `XDG_CONFIG_HOME` and `XDG_STATE_HOME` pointing at scratch directories. The tokens
and the `tee` copy of the log were in a scratch directory too, and were removed from there.

This is for development mode only. A protected install is removed with `apt purge`, which asks before it deletes the
vault; see [Uninstall and purge](../installation/linux-install.md#uninstall-and-purge). To keep the installation and replace the vault, use
[`iron-vault reset`](../reference/cli.md#iron-vault-reset).

## Prerequisites

- A development install, as in [getting started](getting-started.md).
- Nothing in the vault you still need. Run `iron-vault list` first if you're not sure.

## Steps

### 1. Stop the service

Press Ctrl-C in the service's terminal. Its last two log records are:

```json
{"message":"stopping on SIGINT"}
{"message":"stopped"}
```

### 2. Remove its files

```sh
rm -rf "${XDG_CONFIG_HOME:-$HOME/.config}/iron-vault-dev" \
       "${XDG_STATE_HOME:-$HOME/.local/state}/iron-vault-dev" \
       "${XDG_STATE_HOME:-$HOME/.local/state}/iron-vault-dev-log" \
       ~/.iron-vault-tokens ~/iron-vault-dev.log
```

That removes the published config and its signature, the vault (`identity.age`, the records, the approval state and
`recovery.toml`), the log directory, the caller tokens, and the `tee` copy of the log. It prints nothing. Your own
`dev-config.toml` is kept; its `token_hash` lines are useless now, since the tokens are gone.

### 3. Check

Start the service again, as in [getting started](getting-started.md#2-start-the-service), and in a second terminal:

```sh
iron-vault ping
iron-vault status
```

```text
the service is running: development profile, admin protocol version 1
service: locked
profile: development — no isolation from malware running as alice
vault: not initialized (run iron-vault init)
vault id: unknown
approval committed: unknown while the vault is locked
approval highest reserved: unknown while the vault is locked
memory protection: NOT protected, swap protection unavailable (RLIMIT_MEMLOCK soft limit is 8315834368 bytes, not unlimited)
recovery last checked: unknown (the vault is not initialized)
credentials: unknown while the vault is locked
```

Carry on from [create the vault](getting-started.md#3-create-the-vault). Throw away the old recovery key: it opens
nothing now.

### 4. Uninstall, if you're done

```sh
rm -rf ~/.local/iron-vault-dev
```

Also remove the bash completion file, if you installed one.

## What can go wrong

- **`status` still shows a vault.** The service was still running when you deleted the files, or it uses different
  `XDG_*` directories from your shell. Stop it, check the variables, and remove the files again.
- **You removed a vault you needed.** There is no undo. Reissue each key from its provider, using your copies of
  the config and `list` output.

## Reference

- [Files and locations](../reference/files.md): every file a development install writes.
- Related: [check and store your recovery key](recovery-key.md).
