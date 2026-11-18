# Check and store your recovery key

*Checked with `iron-vault 0.2.0-alpha (features: dev-mode)`, built from `main` at `378d57d`.*

Store the **recovery key**, the `AGE-SECRET-KEY-1…` line `init` showed you once, and prove it opens your vault. The
service keeps no copy. Check it while the vault passphrase still works, so a bad copy can still be replaced. See the
[recovery design](../../../design/recovery.md) for what the check proves.

## Prerequisites

- The service running, Locked or Ready. The check works in both.
- The recovery key from `init`.

## Steps

### 1. Store the key

Keep it apart from the vault and from the machine:

- **An independent password manager**, one this machine doesn't sync from, or **paper**, kept somewhere safe. `init`
  also shows the key as a QR code, which you can print.
- Optionally, a passphrase-encrypted file of your own as well, such as one made with `age -p`.
- Never beside the vault or in the same backup. An encrypted file must live off this machine too.

Keep a copy of your approved config and the output of `iron-vault list` with it: if the vault is lost, they list the
credentials to reissue.

### 2. Check the key

```sh
iron-vault recovery check
```

It asks for the key with echo off:

```text
Recovery key:
the recovery key opens vault 8c597c79-…: checked 2026-11-07T10:24:07Z
```

Or pipe it in:

```sh
pass show iron-vault-recovery | iron-vault recovery check
```

It changes nothing in the vault, and works while Locked (here after `iron-vault lock`):

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


### 4. Answer the reminders

After 90 days without a check, the service logs a `recovery.reminder` record at INFO (at most once a week), and
`status` adds `, overdue`. The log is the only reminder, so alert on that event; the
[log operations guide](../reference/log-operations.md#querying) has the query. Set the interval, 7 to 365 days, in the
approved config:

```toml
[recovery]
reminder_days = 90
```

Run the check again whenever you move the key to a new place.

## What can go wrong

- **`iron-vault: the service answered error 30 (recovery-key-invalid): the text is not an AGE-SECRET-KEY-1... recovery
  key`.** Not a recovery key: a truncated paste, a missing line, or another kind of key.
- **`iron-vault: the service answered error 31 (recovery-check-failed): the recovery key does not open this vault`.**
  Not this vault's key. If you can't find the right one, the vault has only its passphrase left:
  [add a new recovery key](recipients.md) now, then remove the lost one.
- **`recovery-check-unavailable`.** A vault file could not be read; this says nothing about the key.
  `status` and the log name the file.

Each check logs a `recovery.checked` record with `recovery_outcome` `opened`, `invalid`, `failed` or
`unavailable`.

## Reference

- [CLI](../reference/cli.md#iron-vault-recovery-check): `recovery check`.
- The [recovery design](../../../design/recovery.md): what the check proves, and the reminder schedule.
- [§16](../../../design/iron-vault-specification.md#16-administration-recovery-and-migration) of the
  specification.
