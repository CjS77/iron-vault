# Rotate the approval passphrase, and keep a second approver

*Checked with `iron-vault 0.3.0-alpha (features: dev-mode)`, built from `main` at `539cea4`.*

Enrol a new approval passphrase, approve the active config with it, then remove the old one; every route keeps serving
throughout. Each **approver** is a pinned approval signer, and any one of them gives your approval.

## Why keep a second approver

Only a pinned approver can enrol or remove an approver: never the vault passphrase or a recovery key
([security model](../security-model.md#several-approval-signers)). **If you forget every approval passphrase, you can
never approve a config, replace or remove a credential, or change approvers again; [`reset`](reset-vault.md) is the
only way out.**

So do steps 1 and 2 to enrol a second approver, with a passphrase kept apart from the first. Then a forgotten
passphrase costs one `approver remove` (after step 3, if the forgotten one is `active`). Keep a software approver
beside a [TPM approver](tpm-approval.md) too.

## Prerequisites

- The service running and Ready, with a config approved as in [getting started](getting-started.md).
- The current approval passphrase, and a new one of at least 12 characters, different from the vault passphrase.
- `dev-config.toml`, the config you last approved.

## Steps

### 1. List the approvers

```sh
iron-vault approver list
```

```text
d69d992b-fcf3-481b-b12d-1ec89a59ae67  software  2026-11-11T01:21:45Z  active  approval passphrase
```

`active` marks the approver that signed the config in force. Note the old approver's ID for step 4; commands name an
approver by ID, never by label.

### 2. Enroll the new approver

Type the current approval passphrase, then the new one twice:

```sh
iron-vault approver add --label "approval passphrase 2026"
```

```text
enroll an approval signer
  vault: 4c3dce89-4e6e-42ad-830b-e0bb5eb39c36
  kind: software
  label: approval passphrase 2026
  approvers after the change: 2
  the new signer alone can approve a config and authorize replace, rm, recipient remove and approver changes
  next: choose its approval passphrase, different from the vault passphrase
  authorize with: any pinned approver
Approval passphrase for "approval passphrase":
New approval passphrase for "approval passphrase 2026":
Repeat the new approval passphrase:
enrolled approver a53f9f72-74c7-403e-82a7-c34f9474ce25 (software); the vault has 2 approvers.
a53f9f72-74c7-403e-82a7-c34f9474ce25
```

Only the bare approver ID goes to stdout. If you are only adding a second approver, stop here and store its passphrase.

### 3. Approve the active config with the new approver

Approve the same config again, so the old approver no longer signs the config in force. At the first prompt press
Ctrl-Y to switch to the new approver, then type the new passphrase:

```sh
iron-vault config approve dev-config.toml
```

```text
Approval summary
vault: 4c3dce89-4e6e-42ad-830b-e0bb5eb39c36
version to commit: 3
config digest: blake2b:10cef10967fbeeaece8a5f087bf247f8e3ad253a88f1fc96e2db4d449122e0c7
committed version: 2
no change; same config as version 2
Approve this config as version 3? Type yes to approve: yes
Approval passphrase for "approval passphrase" (Ctrl-Y to try another way): ^Y
Approval passphrase for "approval passphrase 2026" (Ctrl-Y to try another way):
approved version 3 (blake2b:10cef10967fbeeaece8a5f087bf247f8e3ad253a88f1fc96e2db4d449122e0c7)
callers: none; route grants: none; routes: none; listeners: none; limits: none; logging: none; recovery: none
```

Nothing echoes; `^Y` marks where Ctrl-Y was pressed. `approver list` now marks the new approver `active`.

### 4. Remove the old approver



```sh
iron-vault approver remove d69d992b-fcf3-481b-b12d-1ec89a59ae67
```

Type the new approver's passphrase:

```text
remove an approval signer
  vault: 4c3dce89-4e6e-42ad-830b-e0bb5eb39c36
  approver: d69d992b-fcf3-481b-b12d-1ec89a59ae67
  kind: software
  label: approval passphrase
  enrolled: 2026-11-11T01:21:45Z
  approvers after the change: 1
  it can no longer approve or give owner presence; copies of the state directory made before still pin it
  authorize with: any pinned approver
Approval passphrase for "approval passphrase 2026" (Ctrl-Y to try another way):
removed approver d69d992b-fcf3-481b-b12d-1ec89a59ae67; the vault has 1 approvers.
```

The old approval passphrase no longer works.

### 5. Check that it worked

```sh
iron-vault approver list
```

```text
a53f9f72-74c7-403e-82a7-c34f9474ce25  software  2026-11-11T01:22:04Z  active  approval passphrase 2026
```

Check that a route still serves:

```sh
curl -s -H "Proxy-Authorization: Bearer $(cat ~/.iron-vault-tokens/me)" http://127.0.0.1:7878/httpbin/headers
```

The reply's `Authorization` header reads `Bearer [iron-vault:scrubbed]`.

## What can go wrong

- **`approver-in-use`.** The approver signed the active config (`this approver signed the active approval; approve the
  config with another approver first; nothing was changed`). Do step 3, then remove it.
- **`approver-set-invalid`.** `remove` named the last approver: enroll another first. `add` found 16 already pinned:
  remove one first.
- **`approval-denied`.** The wrong passphrase for the approver the prompt names. Nothing was changed: run the command
  again, pressing Ctrl-Y first to use another approver.
- **`passphrase-rejected`.** The new passphrase is under 12 characters, or the two entries differ.
- **`wrong-state`.** The service is Locked. Run `iron-vault unlock`.

Copies of the state directory made before a removal still pin the removed approver. The
[errors reference](../reference/errors.md#approver-add-and-approver-remove) lists every code.

## Reference

- [CLI](../reference/cli.md#iron-vault-approver): `approver list`, `add` and `remove`.
- [Approval signers design](../../../design/approval-signers.md): authorization, approver order and the release checks.
- [Security model](../security-model.md#several-approval-signers): why unlocking never grants approval.
