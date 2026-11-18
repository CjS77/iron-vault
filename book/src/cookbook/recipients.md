# Rotate the recovery key, or add a machine's key

Replace the recovery key with a new one, and enrol an `age` key that you hold on another machine. A **recipient** is a
key the vault identity is wrapped for; see the [security model](../security-model.md).

## Prerequisites

- The service running and Ready, as at the end of [getting started](getting-started.md).
- The vault passphrase, for `recipient add`, and the approval passphrase, for `recipient remove`.
- The recovery key you keep now, and somewhere safe to store a new one; see
  [check and store your recovery key](recovery-key.md).

## Steps

### 1. List the recipients

```sh
iron-vault recipient list
```

```text
age10dvnun…  operational  2026-11-08T14:54:27Z  vault passphrase
age1vhncy4…  recovery     2026-11-08T14:54:27Z  recovery key
```

Commands name a recipient by its `age1…` key, never its label. Note the old recovery key's for step 4.

### 2. Add a new recovery key

The service shows the new key once, like `init`; save it, type `yes`, then type the vault passphrase:

```sh
iron-vault recipient add --recovery --label "recovery key 2026"
```

```text
add a new recovery key to the vault
  vault: 3c3bc52f-…
  recipient: age1lvqkl6…
  role: recovery
  label: recovery key 2026
  recipients after the change: 3 (operational 1, recovery 2)
  next: the new recovery key is shown once; save it, then type yes
  authorize with: the vault passphrase
The recovery key follows. It is shown this once, and the service keeps no copy.
…
AGE-SECRET-KEY-1…
…
Type yes once you have saved the recovery key: yes
Vault passphrase:
enrolled age1lvqkl6… as recovery; the vault has 3 recipients.
Removing a recipient protects future copies of identity.age only.
Old copies of identity.age, and backups, still open with a removed key.
If a machine was lost, rotate the provider credentials it could reach.
Check the new key with iron-vault recovery check, then remove the old recovery key with iron-vault recipient remove.
```

### 3. Check the new key

Paste the **new** key at the prompt (the old one also passes until step 4):

```sh
iron-vault recovery check
```

```text
Recovery key:
the recovery key opens vault 3c3bc52f-…: checked …
```

If the check fails, stop here: the old recovery key still works. Remove the new key by the `age1…` key step 2 showed,
with `iron-vault recipient remove`, then run step 2 again. See
[what can go wrong](recovery-key.md#what-can-go-wrong).

### 4. Remove the old recovery key

Name it by the `age1…` key from step 1, and type the approval passphrase:

```sh
iron-vault recipient remove age1vhncy4…
```

```text
remove a recipient from the vault
  vault: 3c3bc52f-…
  recipient: age1vhncy4…
  role: recovery
  label: recovery key
  enrolled: 2026-11-08T14:54:27Z
  recipients after the change: 2 (operational 1, recovery 1)
  removing a recipient protects future copies of identity.age only; copies made before still open with this key
  authorize with: the approval passphrase
Approval passphrase for "approval passphrase":
removed age1vhncy4…; the vault has 2 recipients.
Removing a recipient protects future copies of identity.age only.
Old copies of identity.age, and backups, still open with a removed key.
If a machine was lost, rotate the provider credentials it could reach.
Check the recovery key you keep with iron-vault recovery check.
```

The old key now fails `recovery check`:

```text
iron-vault: the service answered error 31 (recovery-check-failed): the recovery key does not open this vault
```

Copies of `identity.age` and backups made before the removal still open with the old key. If the old key or a machine
was lost, rotate the provider credentials too.

### 5. Add another machine's key

Whoever holds an enrolled key's secret half can open every credential. **Enrol only a key you control.** It is used by
the [host unlock handoff](../reference/files.md#container) in the [Container profile](../installation/compose-install.md);
no other v0 command uses it.

Generate the key on the other machine, for example with `age-keygen`, and enrol its public `age1…` key:

```sh
iron-vault recipient add age1v4q6gq… --label "bob's new laptop"
```

```text
add a recipient to the vault
  vault: 3c3bc52f-…
  recipient: age1v4q6gq…
  role: added
  label: bob's new laptop
  recipients after the change: 3 (operational 1, recovery 1, added 1)
  this key will open the vault identity, and with it every credential, in every copy of identity.age written from now on
  authorize with: the vault passphrase
Vault passphrase:
enrolled age1v4q6gq… as added; the vault has 3 recipients.
Removing a recipient protects future copies of identity.age only.
Old copies of identity.age, and backups, still open with a removed key.
If a machine was lost, rotate the provider credentials it could reach.
```

`recipient list` now has a third line, with role `added`. It never counts as a recovery key. Remove it with
`recipient remove` when the machine is retired.

## What can go wrong

- **`declined`.** You didn't type `yes` after the new recovery key was shown. Nothing changed; discard the key shown.
- **`recipient-set-invalid`.** The change would leave the vault without its vault passphrase recipient or without a
  recovery key, or with more than 64 recipients. Add the new recovery key before you remove the old one.
- **`unknown-recipient`** or **`recipient-invalid`.** The key doesn't match an enrolled recipient, or isn't an `age1…`
  key. Copy it from `recipient list`.
- **`recipient-enrolled`.** The key is already enrolled.
- **`migration-denied`** from `recipient add`, or **`approval-denied`** from `recipient remove`. The wrong passphrase:
  `add` takes the vault passphrase, `remove` the approval passphrase. Nothing was written.
- **`wrong-state`.** The service is Locked. Run `iron-vault unlock`; every recipient command needs Ready.

The [errors reference](../reference/errors.md#recipient-list-recipient-add-and-recipient-remove) lists every code.

## Reference

- [CLI](../reference/cli.md#iron-vault-recipient): `recipient list`, `add` and `remove`.
- [Recipients design](../../../design/recipients.md): the independence rule, and why old copies still open.
- [Reset the vault](reset-vault.md), when no way into it is left.
- [Retire a machine](forget-machine.md), once its recipient is removed.
- [Move a vault to a new machine](move-vault.md).
