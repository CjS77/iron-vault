# Rotate the approval passphrase, and keep a second approver

*Checked with `iron-vault 0.3.0-alpha (features: dev-mode)`, built from `main` at `539cea4`.*

At the end of this recipe your vault has a new approval passphrase, the old one no longer approves anything, and every
route kept serving throughout. It also shows why to keep a second approver.

An **approval signer** is whatever signs your config approvals; in v0 it is a key sealed under an approval passphrase.
The vault pins one **approver** for each signer, and any one of them gives the service your approval: for `config
approve`, and for `replace`, `rm`, `recipient remove`, `approver add` and `approver remove`. Rotating means enrolling the new
approver, approving the active config with it, then removing the old one.

## Why keep a second approver

Only a pinned approver's passphrase can enroll or remove an approver. The vault passphrase cannot, and neither can a
recovery key. The vault passphrase can mint a new recovery key, so if it could enroll an approver, a stolen vault
passphrase would be enough to approve a config. A recovery key is no approver either: it opens the vault, and
approving is a separate lock. See the [security model](../security-model.md#several-approval-signers).

So if you forget every approval passphrase, nothing can enroll a replacement. The vault still unlocks and serves its
active config, but you can never approve a config, replace or remove a credential, remove a recipient or change the
approvers again. [`reset`](reset-vault.md), which discards the vault so you rebuild it from reissued credentials,
is the only way out.

Enroll a second approver while one still answers, with a passphrase kept apart from the first: another password
manager entry, or a sealed envelope. Then a forgotten passphrase costs one `approver remove`.

If the approver you forgot signed the config now in force (it shows `active` in `approver list`), approve the config
with the other approver first, as in step 3, or the remove fails with `approver-in-use`. Only then remove the
forgotten one.

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

Each line is the approver ID, its signer kind, when it was enrolled, `active` (or `-`) for whether it signed the config
now in force, and its label. Note the old approver's ID for step 4. The commands name an approver by ID, never by
label.

### 2. Enroll the new approver

The service shows what changes and asks for the passphrase of an approver already pinned, then for the new one, twice:

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

The last line, the bare approver ID, is the only thing written to stdout; the rest goes to the terminal, so
`NEW=$(iron-vault approver add --label ...)` captures just the ID.

If you are only adding a second approver, stop here and store its passphrase. Until you approve a config with the new
approver, the old one is still the active signer and every route keeps serving.

### 3. Approve the active config with the new approver

The old approver signed the config now in force, and the service will not remove it while it does. Approve the same
config again. The prompt asks the old approver first; press Ctrl-Y to switch to the next one, then type the new
passphrase:

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

The file is unchanged, so the summary says "no change; same config as version 2" instead of listing a diff. The
approval still commits version 3, signed by the approver that answered.

Nothing echoes while you type a passphrase or press Ctrl-Y; `^Y` above marks where it was pressed. `approver list`
now marks the new approver `active` and lists it first. A wrong passphrase ends the exchange: the service never goes on
to ask another approver by itself.

### 4. Remove the old approver

An approver that signed the active config cannot be removed. Here the old one no longer does, so this works:

```sh
iron-vault approver remove d69d992b-fcf3-481b-b12d-1ec89a59ae67
```

The service shows the approver and asks for any pinned approver's passphrase. The first prompt is the new approver,
because it signed the active config. Type its passphrase:

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

The old approval passphrase is now just a wrong answer, and its key file is deleted.

### 5. Check that it worked

```sh
iron-vault approver list
```

```text
a53f9f72-74c7-403e-82a7-c34f9474ce25  software  2026-11-11T01:22:04Z  active  approval passphrase 2026
```

Send a request through a route to see it still served, as at the end of [getting started](getting-started.md):

```sh
curl -s -H "Proxy-Authorization: Bearer $(cat ~/.iron-vault-tokens/me)" http://127.0.0.1:7878/httpbin/headers
```

The reply's `Authorization` header reads `Bearer [iron-vault:scrubbed]`, as before the rotation.

## What can go wrong

- **`approver-in-use`.** The approver signed the active config (`this approver signed the active approval; approve the
  config with another approver first; nothing was changed`). Do step 3, then remove it.
- **`approver-set-invalid`.** `remove` named the last approver: enroll another first. `add` found 16 already pinned:
  remove one first.
- **`approval-denied`.** The wrong passphrase for the approver the prompt names. The vault passphrase and recovery
  keys never work here. The exchange has ended and nothing was changed: run the command again and press Ctrl-Y at the
  prompt before answering if you mean to use another approver.
- **`passphrase-rejected`.** The new passphrase is under 12 characters, or the two entries differ.
- **`wrong-state`.** The service is Locked. Run `iron-vault unlock`.

Copies of the state directory made before a removal still pin the removed approver. The
[errors reference](../reference/errors.md#approver-add-and-approver-remove) lists every code.

## Reference

- [CLI](../reference/cli.md#iron-vault-approver): `approver list`, `add` and `remove`.
- [Approval signers design](../../../design/approval-signers.md): authorization, approver order and the release checks.
- [Security model](../security-model.md#several-approval-signers): why unlocking never grants approval.
