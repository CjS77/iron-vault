# Check and store your recovery key

*Checked with `iron-vault 0.2.0-alpha (features: dev-mode)`, built from `main` at `378d57d`.*

At the end of this recipe your recovery key is stored where you can find it in a few years, and you have proved that
it opens your vault. The **recovery key** is the `AGE-SECRET-KEY-1…` line `init` showed you once. It is the second way
into the vault if the vault passphrase or the machine is lost, and the service keeps no copy. You use it so rarely that
it is easy to lose, mistype when you saved it, or keep for a vault that no longer exists. The check finds that out
while you can still do something about it.

Every command below was run as shown, except that `pass show` was replaced by `cat` of a file holding the key. The
wrong key in [What can go wrong](#what-can-go-wrong) was a freshly generated key for no vault.

## Prerequisites

- The service running, Locked or Ready. The check works in both.
- The recovery key from `init`.

## Steps

### 1. Store the key

Keep it apart from the vault and from the machine:

- **An independent password manager**, one this machine doesn't sync from, or **paper**, kept somewhere safe. `init`
  also shows the key as a QR code, which you can print.
- If you like, also in a passphrase-encrypted file of your own, such as `age -p`.
- Never beside the vault or in the same backup. An encrypted file must live off this machine too.

Keep two more things with it: a copy of your approved config, and the output of `iron-vault list`. If the vault is
ever lost, they are your list of which credentials to reissue from each provider. The service keeps no other
inventory.

### 2. Check the key

```sh
iron-vault recovery check
```

The service asks for the key with echo off:

```text
Recovery key:
the recovery key opens vault 8c597c79-…: checked 2026-11-07T10:24:07Z
```

Or pipe it in from where you keep it, so it never reaches your shell history:

```sh
pass show iron-vault-recovery | iron-vault recovery check
```

The check proves the key against the vault as it is on disk. It changes nothing in the vault, and works the same
while Locked: here it was run after `iron-vault lock`, and the service stayed Locked.

```text
locked
the recovery key opens vault 8c597c79-…: checked 2026-11-07T10:24:09Z
```

### 3. See when you last checked

```sh
iron-vault status | grep recovery
```

```text
recovery last checked: 2026-11-07 (today)
```

The service records only the time, in `recovery.toml` beside the vault:

```text
since = 2026-11-07T10:20:14Z
last_checked = 2026-11-07T10:24:09Z
```

It is plain text with no seal, so that reminders keep working while the vault is locked. An edit to it can only change
when reminders appear.

### 4. Answer the reminders

Every 90 days without a check, the service logs a `recovery.reminder` record (INFO, at most once a week), and `status`
adds `, overdue`. In v0 the log is the only reminder, so alert on that event in your log collector; the
[log operations guide](../reference/log-operations.md#querying) has the query. Set the interval, from 7 to 365 days,
in the approved config:

```toml
[recovery]
reminder_days = 90
```

Run the check again whenever you move the key to a new place.

## What can go wrong

- **`iron-vault: the service answered error 30 (recovery-key-invalid): the text is not an AGE-SECRET-KEY-1... recovery
  key`.** What you typed is not a recovery key at all: a truncated paste, a missing line, or a different kind of key.
- **`iron-vault: the service answered error 31 (recovery-check-failed): the recovery key does not open this vault`.**
  It is a recovery key, but not this vault's: one from an older vault, or one copied wrong. If you can't find the right
  one, the vault has only its passphrase left as a way in. Adding a new recovery key is
  [not yet available](roadmap/recipients.md); until it is, keep the vault passphrase safe, and keep the config and
  `list` copies from [step 1](#1-store-the-key) so you can rebuild.
- **`recovery-check-unavailable`.** The check could not run, because a vault file could not be read. This says
  nothing about the key. `status` and the log name the file.

Each check logs a `recovery.checked` record with `recovery_outcome` `opened`, `invalid`, `failed` or
`unavailable`. It never holds
the key.

## Reference

- [CLI](../reference/cli.md#iron-vault-recovery-check): `recovery check`.
- The [recovery design](../../../design/recovery.md): what the check proves, and the reminder schedule.
- [§3.13](../../../design/iron-vault-specification.md#313-administration-recovery-and-migration) of the
  specification.
