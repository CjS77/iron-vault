# Rotate the recovery key, or add a machine's key

At the end of this recipe your vault opens with a new recovery key, and new copies of `identity.age` no longer open
with the old one. The last step
enrols an `age` key you hold on another machine, ready for when moving a vault there is supported.

A **recipient** is a key the vault identity is wrapped for (the [security model](../security-model.md) explains the
lockboxes). `init` enrols two: your vault passphrase and the offline recovery key. The `recipient` commands add and
remove recipients without re-encrypting the credentials. The service refuses any change that would leave the vault
without its vault passphrase recipient or without a recovery key.


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

Each line is the recipient's `age1…` key, its role, when it was enrolled, and its label. The commands below name a
recipient by its key, never by its label. Note the old recovery key's `age1…` key for step 4.

### 2. Add a new recovery key

Have the service generate the new key. It shows the key once, like `init`; save it, type `yes`, then authorize with
the vault passphrase:

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

It asks for the vault passphrase, not the approval passphrase, because a new recipient can open every credential. The
service treats adding one like moving the vault to another machine.

### 3. Check the new key

Prove that the key you saved opens the vault before you remove the old one. Paste the new key at the prompt: the old
one also passes until step 4.

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

Name it by the `age1…` key from step 1. The service shows what changes, then asks for the approval passphrase:

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

Removal does not reach copies of `identity.age` or backups made before it: anyone holding one and the old key can
still open it. If the old key or a machine was lost, rotate the provider credentials too.

### 5. Add another machine's key

Whoever holds an enrolled key's secret half can decrypt every copy of `identity.age` written from now on, and with it
every credential. In the [Container profile](../installation/compose-install.md), a key placed in the
[host unlock handoff](../reference/files.md#container) also opens the vault at startup, with no passphrase. Otherwise
no v0 command uses the key: `unlock` takes only the vault passphrase. The key is meant as the destination for
[moving a vault to a new machine](roadmap/migration.md), which is not yet available. Enrol only a key you control.

Generate the key on the other machine, for example with `age-keygen`, and enrol its public `age1…` key. The secret half
never leaves that machine. `--label` says which machine it is:

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

`recipient list` now has a third line, with role `added`. An added key never counts as a recovery key, because the
service can't tell who holds it, so it doesn't let you remove the last `recovery` recipient. Remove it with
`recipient remove` when the machine is retired.

## What can go wrong

- **`declined`.** You didn't type `yes` after the new recovery key was shown. Nothing changed, and the key shown opens
  nothing: discard it.
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
- Not yet available: [move a vault to a new machine](roadmap/migration.md) and
  [retire a machine, or reset the vault](roadmap/reset.md).
