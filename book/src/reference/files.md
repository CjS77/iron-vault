# Files and locations

Iron Vault keeps its files in four directories: one for the config, one for the vault (the state directory), one for
the log and one at runtime for the sockets. Where they are depends on the deployment profile, which is fixed when the
binary is built ([Service states](states.md#development-mode-and-a-protected-install)). The file names inside each
directory are the same for every profile.

Before the service unlocks anything, it checks each path it reads: every directory above the file must be owned by
root or the service account and not writable by anyone else, and the file must have the owner and mode below. It
refuses to start on an unsafe path and names the path that failed. An existing directory with the wrong mode is
refused, never repaired.

## Protected install

The `.deb` package runs the service as the `iron-vault` system account.

| Path | Owner | Mode | Made by | What it is |
|---|---|---|---|---|
| `/usr/bin/iron-vault` | root | `0755` | the package | The binary. |
| `/etc/iron-vault/` | `iron-vault` | `0700` | the package (tmpfiles.d) | The config directory. |
| `/etc/iron-vault/config.toml` | `iron-vault` | `0600` | the service | The published approved config. |
| `/etc/iron-vault/config.toml.sig` | `iron-vault` | `0600` | the service | Its approval signature. |
| `/var/lib/iron-vault/` | `iron-vault` | `0700` | the package (tmpfiles.d) | The state directory: the vault. |
| `/var/log/iron-vault/` | `iron-vault` | `0750` | systemd (`LogsDirectory=`) | The log directory, until an approved config names another. |
| `/var/log/iron-vault/iron-vault.log` | `iron-vault` | `0640` | the service | The log. |
| `/run/iron-vault/` | `iron-vault` | `0711` | the package (tmpfiles.d) | The runtime directory. |
| `/run/iron-vault/admin.sock` | `iron-vault` | `0600` | the service | The admin socket; you reach it with `sudo`. |
| a listener's `unix_socket`, such as `/run/iron-vault/proxy.sock` | `iron-vault` | `0666` | the service | A request socket. Callers are told apart by peer account or token, not by the socket's mode. |
| `/usr/lib/systemd/system/iron-vault.service`, `iron-vault-listener@.socket` | root | `0644` | the package | The service unit, and the template for TCP listener sockets. |
| `/usr/lib/sysusers.d/iron-vault.conf`, `/usr/lib/tmpfiles.d/iron-vault.conf` | root | `0644` | the package | Create the account and the directories above. |
| `/etc/logrotate.d/iron-vault` | root | `0644` | the package | Log rotation ([log operations](log-operations.md#rotation)). |

The unit lets the service write only `/etc/iron-vault`, `/var/lib/iron-vault`, `/run/iron-vault` and its log
directory. Uninstalling keeps the vault and the config. Purging deletes `/etc/iron-vault` and asks before it deletes the vault
([installation guide](../installation/linux-install.md#uninstall-and-purge)).

## Development mode

A build with `--features dev-mode` runs as you and keeps its files in your XDG directories. Every file and directory
is owned by you.

| Path | Mode | What it is |
|---|---|---|
| `$XDG_CONFIG_HOME/iron-vault-dev/` (default `~/.config/iron-vault-dev/`) | `0700` | The config directory. |
| `.../iron-vault-dev/config.toml` and `config.toml.sig` | `0600` | The published approved config and its signature. |
| `$XDG_STATE_HOME/iron-vault-dev/` (default `~/.local/state/iron-vault-dev/`) | `0700` | The state directory. |
| `$XDG_STATE_HOME/iron-vault-dev-log/` | `0700` when created; up to `0750` accepted | The log directory. It sits beside the state directory, not inside it, because any other file in the state directory is a foreign file. |
| `.../iron-vault-dev-log/iron-vault.log` | `0640` | The log. With `serve --log-to-stdout` the log goes to stdout instead, until an approved config names a destination. |
| `$XDG_RUNTIME_DIR/iron-vault-dev/` | `0711` | The runtime directory. `XDG_RUNTIME_DIR` must be set; it has no default. |
| `.../iron-vault-dev/admin.sock` | `0600` | The admin socket. |

The service creates each missing directory with the mode shown. The binary and every directory above it must be owned
by you or root and not writable by group or others ([Development mode](../installation/development-mode.md)). A Unix
socket path must be under 108 bytes, so keep these directories short.

## Container

A build with `--features container` uses the protected install's paths inside the container: `/etc/iron-vault`,
`/var/lib/iron-vault` and `/run/iron-vault`, owned by `iron-vault` with the same modes. The image creates them, so
Docker copies those owners and modes into new named volumes. The binary is `/usr/bin/iron-vault`, owned by root,
`0755`. The image runs `serve --log-to-stdout`, so the log goes to the container runtime
([log operations](log-operations.md#docker)). See [docker-compose.md](../../../design/docker-compose.md).

## The config directory

| File | What it is |
|---|---|
| `config.toml` | The active config, as last approved. |
| `config.toml.sig` | The active config's approval: a signature over the vault ID, the approval version and the config's digest. |
| `config.toml.pending` | A config being approved, before it is published. |
| `config.toml.sig.staged` | An approval being committed, before it is published. |
| `config.toml.lock` | The lock that keeps one writer at a time. |
| `.<name>.tmp` | A temporary file a durable write uses before its rename. |

All are `0600` and owned by the service account. The pending, staged and temporary files exist only while an approval
runs, or after one was interrupted; the next config check finishes or discards them and logs
`config.recovery-published` or `config.recovery-discarded`.

The `dev-config.toml` you edit is yours, anywhere you like. `config approve` sends its text to the service, which
writes its own copy.

## The state directory

| File | What it is |
|---|---|
| `identity.age` | The identity envelope: the vault identity, sealed to each recipient. |
| `operational.age` | The passphrase envelope: the operational identity, sealed with the vault passphrase. |
| `approver.age` | The approver key envelope: the key that signs config approvals, sealed with the approval passphrase. |
| `approval.age` | The approval state: the committed and highest reserved approval versions. |
| `manifest.age` | The vault manifest: which credential records exist, sealed with a code only the vault identity can make. |
| `record-<id>.age` | One credential record: its kind, secret and permitted origins. |
| `recovery.toml` | When `recovery check` last proved the recovery key. Holds no secret. |
| `init.unfinished` | An empty marker of an `init` that has not finished. `init` run again discards it. |
| `lock` | The lock that keeps one writer at a time. |
| `.<name>.tmp` | A temporary file a durable write uses before its rename. |

All are `0600` and owned by the service account. Any other file in the state directory is a foreign file: `unlock`
refuses with `unrecognized-files` and logs `vault.foreign-file`, so nothing is opened beside a file the service did
not write. [How the vault is locked](../../../README.md#how-the-vault-is-locked) explains the envelopes.

## The log

`iron-vault.log`, `0640`, in a directory the service account owns with a mode of at most `0750`. An approved config
can move it to another directory, which must pass the same rule; `service.log-destination-changed` records the move
in both places. The [audit log reference](audit-log.md) lists what it holds, and the
[log operations guide](log-operations.md#location-and-permissions) covers reading it, rotation and collectors.

## Never edit these files by hand

Every file the service writes is either signed or sealed, so a change the service did not make is caught, not obeyed.
Editing one by hand, even to fix a typo, makes the service refuse it.

- **`config.toml` and `config.toml.sig`.** On a SIGHUP, or at unlock, the service reads the pair and checks the
  signature against the vault ID and the committed approval version. A config changed without approval does not
  verify: the service goes to Unavailable (`policy invalid`), answers every request with `503`, and logs
  `config.reload-failed` or `config.check-failed`. An older config with its own valid signature is refused too,
  because its version is below the committed one. To recover, approve a good config:
  `iron-vault config approve dev-config.toml`. See
  [Tamper detection and recovery](../cookbook/tamper-detection.md).
- **`manifest.age` and `record-<id>.age`.** Anyone with the vault's public key can write a file that looks like a
  credential record, so a record is trusted only when the manifest lists it. A record file the manifest does not list
  is never loaded (`vault.unindexed-file`). A listed record that is missing, swapped for another or unreadable is
  reported as damaged (`vault.record-damaged`); only the routes that use it answer `503`. `iron-vault replace` writes
  a good record.
- **`identity.age`, `operational.age`, `approver.age` and `approval.age`.** Damage to the shared state makes `unlock`
  refuse, or sends the service to Unavailable (`recovery needed`), with `vault.shared-state-damaged` in the log.
- **The lock files and temporary files.** Removing them while the service runs can let two writers race. Leave them;
  the service cleans up after itself.

To change the config, approve a new one. To change a credential, use `add`, `replace` or `rm`. To start again from
nothing, see [Start over](../cookbook/start-over.md).
