# Rotate the approval passphrase, and keep a second approver

At the end of this recipe your vault has a new approval passphrase, the old one no longer approves anything, and every
route kept serving throughout. It also shows why to keep a second approver.

An **approval signer** is whatever signs your config approvals; in v0 it is a key sealed under an approval passphrase.
The vault pins one **approver** for each signer, and any one of them gives the service your approval: for `config
approve`, and for `replace`, `rm`, `recipient remove` and the `approver` commands. Rotating means enrolling the new
approver, approving the active config with it, then removing the old one.

## Why keep a second approver

Only a pinned approver's passphrase can enroll or remove an approver. The vault passphrase cannot, and neither can a
recovery key, because either can be used to make a key the vault would then trust: a stolen vault passphrase must never
be enough to approve a config.

So if you forget every approval passphrase, nothing can enroll a replacement. The vault still unlocks and serves its
active config, but you can never approve a config, replace or remove a credential, remove a recipient or change the
approvers again. [`reset`](roadmap/reset.md), which discards the vault so you rebuild it from reissued credentials,
is the only way out, and it is not yet available.

Enroll a second approver while one still answers, with a passphrase kept apart from the first: another password
manager entry, or a sealed envelope. Then a forgotten passphrase costs one `approver remove`.

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
8d1c6f0e-2b7a-4c59-9e3d-5a4b3c2d1e0f  software  2026-11-06T09:49:13Z  active  approval passphrase
```

Each line is the approver ID, its signer kind, when it was enrolled, `active` if it signed the config now in force,
and its label. Note the old approver's ID for step 4. The commands name an approver by ID, never by label.

### 2. Enroll the new approver

The service shows what changes and asks for the passphrase of an approver already pinned, then for the new one, twice:

```sh
iron-vault approver add --label "approval passphrase 2026"
```

```text
enroll an approval signer
  vault: 2a682de7-b14d-4900-9ea9-0c968e1a6589
  kind: software
  label: approval passphrase 2026
  approvers after the change: 2
  the new signer alone can approve a config and authorize replace, rm, recipient remove and approver changes
  next: choose its approval passphrase, different from the vault passphrase
  authorize with: any pinned approver
Approval passphrase for "approval passphrase":
New approval passphrase for "approval passphrase 2026":
Repeat the new approval passphrase:
enrolled approver 4b0e3d2c-1a9f-4e8d-8c7b-6a5f4e3d2c1b (software); the vault has 2 approvers.
```

If you are only adding a second approver, stop here and store its passphrase.

### 3. Approve the active config with the new approver

The old approver signed the config now in force, and the service will not remove it while it does. Approve the same
config again. The prompt asks the old approver first; press Ctrl-Y to switch to the next one, then type the new
passphrase:

```sh
iron-vault config approve dev-config.toml
```

```text
Approval passphrase for "approval passphrase" (Ctrl-Y to try another way):
Approval passphrase for "approval passphrase 2026" (Ctrl-Y to try another way):
```

`approver list` now marks the new approver `active` and lists it first. A wrong passphrase ends the exchange: the
service never goes on to ask another approver by itself.

### 4. Remove the old approver

```sh
iron-vault approver remove 8d1c6f0e-2b7a-4c59-9e3d-5a4b3c2d1e0f
```

The service shows the approver and asks for any pinned approver's passphrase. The first prompt is the new approver,
because it signed the active config. Type its passphrase. The command prints nothing on success. The old approval
passphrase is now just a wrong answer, and its key file is deleted.

### 5. Check that it worked

```sh
iron-vault approver list
```

```text
4b0e3d2c-1a9f-4e8d-8c7b-6a5f4e3d2c1b  software  2026-11-08T10:12:44Z  active  approval passphrase 2026
```

Send a request through a route to see it still served, as at the end of [getting started](getting-started.md).

## What can go wrong

- **`approver-in-use`.** The approver signed the active config. Do step 3, then remove it.
- **`approver-set-invalid`.** `remove` named the last approver, or `add` found 16 already. Enroll another first.
- **`approval-denied`.** The wrong passphrase for the approver the prompt names. The vault passphrase and recovery
  keys never work here. Press Ctrl-Y to try another approver; nothing was changed.
- **`passphrase-rejected`.** The new passphrase is under 12 characters, or the two entries differ.
- **`wrong-state`.** The service is Locked. Run `iron-vault unlock`.

Copies of the state directory made before a removal still pin the removed approver. The
[errors reference](../reference/errors.md#approver-add-and-approver-remove) lists every code.

## Reference

- [CLI](../reference/cli.md#iron-vault-approver): `approver list`, `add` and `remove`.
- [Approval signers design](../../../design/approval-signers.md): authorization, approver order and the release checks.
- [Security model](../security-model.md#several-approval-signers): why unlocking never grants approval.
