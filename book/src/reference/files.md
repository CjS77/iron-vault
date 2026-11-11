# Files and locations

Iron Vault keeps its files in four directories: one for the config, one for the vault (the state directory), one for
the log and one at runtime for the sockets. Where they are depends on the deployment profile, which is fixed when the
binary is built ([Service states](states.md#development-mode-and-a-protected-install)). The file names inside each
directory are the same for every profile.

Before the service unlocks anything, it checks each path it reads: every directory above the file must be owned by
root or the service account and not writable by anyone else, and the file must have the owner and mode below. The log
directory is the exception: a directory above it may be group-writable when root owns it, because Debian and Ubuntu
ship `/var/log` as `drwxrwxr-x root syslog`. The service refuses to start on an unsafe path and names the path that
failed. The service never repairs a directory: an existing one with the wrong mode is refused. On a protected install,
the package's `tmpfiles.d` puts back the owner and mode of its three directories (`/etc/iron-vault`,
`/var/lib/iron-vault` and `/run/iron-vault`) at boot and on upgrade, so that refusal shows only until then.

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
| `/usr/lib/systemd/system/iron-vault-host-unlock.service` | root | `0644` | the package | The handoff unit: at each boot it unseals the host unlock blob and installs the [handoff](#host-unlock-handoff). It has no `[Install]` section; `iron-vault.service` pulls it in at every start. |
| `/usr/sbin/iron-vault-provision-host-unlock` | root | `0755` | the package | The provisioning helper, `iron-vault-provision-host-unlock(8)`. It seals a new host unlock identity to the TPM ([TPM unlock](../installation/linux-install.md#tpm-unlock)). |
| `/etc/iron-vault-host/` | root | `0700` | the helper | The host unlock directory. The service cannot see it. Kept when the package is removed; purged only when the vault is. |
| `/etc/iron-vault-host/host-unlock.cred` | root | `0600` | the helper | The host unlock blob: the host unlock identity sealed by `systemd-creds` to this TPM and PCR 7. It opens only on this machine at this Secure Boot policy, and a backup copy opens there too. |
| `/etc/iron-vault-host/provisioning.txt` | root | `0600` | the helper | The acceptance record of the last provisioning: the mode (`server` or `portable`), each `--portable` warning, how it was accepted (`terminal` or `flag`) and `SUDO_USER`, with the time. Replaced whole each time; the same lines are in the journal under `iron-vault-host-unlock`. |

The unit lets the service write only `/etc/iron-vault`, `/var/lib/iron-vault`, `/run/iron-vault` and its log
directory. A protected install also reads the host unlock handoff when it is there; its two paths are in the [handoff table](#host-unlock-handoff) below. Uninstalling keeps the vault and the config. Purging deletes `/etc/iron-vault` and asks before it deletes the vault
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
`/var/lib/iron-vault` and `/run/iron-vault`, owned by `iron-vault` with the same modes. They are mounted in two ways:

- **The config and state directories are named volumes.** The image creates both directories, so Docker copies their
  owners and modes into new volumes.
- **`/run/iron-vault` is a host directory**, bind-mounted read-write. The host's tmpfiles.d creates it at boot, owned
  by `iron-vault` with mode `0711`, and the mount hides the image's copy. The service binds `admin.sock` there, so
  host root reaches it.

Listener TLS certificates and keys are mounted read-only at `/etc/iron-vault-tls`. The binary is
`/usr/bin/iron-vault`, owned by root, `0755`. The image runs `serve --log-to-stdout`, so the log goes to the
container runtime ([log operations](log-operations.md#docker)). The
[host layout](../../../design/docker-compose.md#host-layout) and [mounts](../../../design/docker-compose.md#mounts)
tables in docker-compose.md list every host path and mount.

### Host unlock handoff

The Protected and Container profiles read one more file when it is there, the host unlock handoff:

| Path | Owner | Mode | Made by | What it is |
|---|---|---|---|---|
| `/run/iron-vault-unlock/` | root | `0711` on its ramfs; neither group nor others may write it | the host's handoff unit | In the Container profile, the host directory, bind-mounted read-only into the container at the same path. The directory is mounted, not the file, so a file missing or replaced on the host is seen as such. In a protected install it is the host's own ramfs, which the package's handoff unit `iron-vault-host-unlock.service` mounts over a root `0711` directory that `tmpfiles.d` creates. |
| `/run/iron-vault-unlock/host-unlock` | `iron-vault` | `0400` (no group or other bits; at most `0600` is accepted) | the host's handoff unit | The host unlock identity's secret text, one `AGE-SECRET-KEY-1…` line of at most 128 bytes. It lets the service unlock at startup without a passphrase. |

The file must be a regular file, never a symlink, and no directory above it may be writable by group or others, not
even a sticky one such as `/tmp`. A file that breaks the rule is refused, not read. At startup a
Protected or Container service reads this file. When it opens the vault, the service goes from Starting to Checking with no
passphrase. A missing file means no handoff, and a refused one (an unsafe path, an unreadable file, a key that is not
one of the vault's recipients, or memory not locked against swap) is not: either way the service stays
Locked, and a passphrase `unlock` still works. Each start writes one `vault.host-unlock` record
([audit log](audit-log.md#service-and-lock-state)).
When the file is missing, the service also looks for the **unseal-failure file**, `/run/iron-vault-unlock/unseal-failed`: an
empty file that the host's handoff unit leaves when it fails, such as when a firmware update changes PCR 7. It counts only
as a regular file owned by root, not a symlink. Present, the record says `unseal_failed` instead of `absent`; either way the
service stays Locked, so it is a diagnostic only. The file is not read when the handoff is there. The host side, which unseals the identity from the TPM onto a ramfs, is in
[docker-compose.md](../../../design/docker-compose.md#host-unlock).

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
| `recipients.age` | The recipient inventory: who can open the vault (the vault passphrase and the recovery key), each with its role, label and enrolment time. `init` writes it. |
| `recipients.age.staged` | A recipient change being committed. The next recipient command finishes or discards it. |
| `operational.age` | The passphrase envelope: the operational identity, sealed with the vault passphrase. |
| `approver-<id>.age` | An approver key envelope, one per software approver: the key that signs config approvals for it, sealed with its approval passphrase. `init` writes one for its approver. |
| `approver-<id>.tpm` | A TPM key blob, one per TPM approver: the wrapped key only the TPM that made it can load. It is not secret. |
| `approval.age` | The approval state: the committed and highest reserved approval versions. |
| `manifest.age` | The vault manifest: which credential records exist, sealed with a code only the vault identity can make. |
| `record-<id>.age` | One credential record: its kind, secret and permitted origins. |
| `recovery.toml` | When `recovery check` last proved the recovery key. Holds no secret. |
| `init.unfinished` | An empty marker of an `init` that has not finished. `init` run again discards it. |
| `locked-by-owner` | An empty file that `lock` writes and a passphrase `unlock` removes. While it is there, a starting service skips host unlock and stays Locked, so a lock survives a restart. `init` and `reset` remove it. |
| `lock` | The lock that keeps one writer at a time. |
| `.<name>.tmp` | A temporary file a durable write uses before its rename. |

All are `0600` and owned by the service account. Any other file in the state directory is a foreign file, except
`lost+found`, which is ignored. What a foreign file does depends on whether the manifest is there:

- **With `manifest.age`,** the foreign file is never read, and the unlock goes on without it. `unlock` logs
  `vault.foreign-file` for each one.
- **Without it,** the service cannot tell a vault from files someone else left there, so it touches nothing. `unlock`
  refuses with `unlock-failed` (`15`), naming up to five of the files, and logs `vault.unlock-refused` with refusal
  `unrecognized_files`. `init` refuses with `already-initialized`.

[How the vault is locked](../security-model.md#how-the-vault-is-locked) explains the envelopes.

## The log

`iron-vault.log`, `0640`, in a directory the service account owns with a mode of at most `0750`. An approved config
can move it to another directory, which must pass the same rule; `service.log-destination-changed` records the move
in both places. The [audit log reference](audit-log.md) lists what it holds, and the
[log operations guide](log-operations.md#location-and-permissions) covers reading it, rotation and collectors.

## Never edit these files by hand

The config pair is signed and the `.age` vault files are sealed, so a change the service did not make to any of them
is caught, not obeyed. Editing one by hand, even to fix a typo, makes the service refuse it. `recovery.toml`,
`init.unfinished`, the lock files, the temporary files and the log are neither signed nor sealed: only the owner and
mode rules above protect them.

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
- **`identity.age`, `operational.age` and `approval.age`.** Damage to the shared state makes `unlock`
  refuse, or sends the service to Unavailable (`recovery needed`), with `vault.shared-state-damaged` in the log.
- **`approver-<id>.age`.** Only that approver's prompt reads it: a damaged or swapped key file makes its answer fail
  for `config approve`, `replace`, `rm` and `recipient remove`, and signs nothing.
- **`recovery.toml`** is plain text, so reminders work while the vault is locked. It holds only two times, when
  reminders started counting and when the last recovery check ran, so an edit can change no more than when `status`
  reminds you to check the recovery key.
- **The lock files and temporary files.** Removing them while the service runs can let two writers race. Leave them;
  the service cleans up after itself.

To change the config, approve a new one. To change a credential, use `add`, `replace` or `rm`. To start again from
nothing, see [Start over](../cookbook/start-over.md).
