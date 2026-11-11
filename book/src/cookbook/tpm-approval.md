# Approve configs with a TPM PIN

*The prompts below match the code; the test suite runs the same steps against a software TPM without asserting their text.
**This has had no release check on a real machine yet**, so don't rely on it for real secrets. Ubuntu 24.04 LTS on a protected install only.*

At the end of this recipe a signing key held in your machine's TPM approves your configs once you type its PIN, and a
software approver beside it means a forgotten PIN costs you one command, not the vault.

A TPM approver is one more [approver](approval-signers.md): the vault pins its public key, and any one pinned approver speaks
for you at `config approve`, `replace`, `rm`, `recipient remove`, `recipient add`, `export` and the approver commands. The
private key never leaves the TPM and works only on this machine. The service never opens the TPM itself: a separate helper
program, `iron-vault-tpm-signer`, does, and it signs only the three fixed payloads the service sends it, each under a PIN you
typed. A vault that unlocks at boot with [TPM unlock](tpm-unlock.md) still needs you, with the PIN, to change its policy.

## Before you start

- The package from [the Linux install guide](../installation/linux-install.md), with the service Ready and a config approved.
  A development build never offers the TPM kind.
- A TPM 2.0 at `/dev/tpmrm0`, readable by the `tss` group. Ubuntu's `tpm-udev` package sets that up, and installing the Iron Vault
  package installs it too (the TPM libraries depend on it).
- A TPM whose dictionary-attack settings limit guessing: a lockout recovery interval of **at least 600 seconds** and a maximum
  of at least 2 failed tries. Firmware TPMs usually ship with far more. `tpm2_getcap properties-variable` shows them. With weaker
  settings the helper refuses to work until an administrator raises them.
- A PIN of **at least 6 characters**, different from the vault passphrase. It is not the approval passphrase and it is not a
  TPM unlock PIN: v0 has none of those.
- The approval passphrase of the approver you already have. Keep that approver. See [forgotten PIN](#a-forgotten-pin-or-a-replaced-tpm).

## Steps

### 1. Check that the kind is offered

```sh
ls -l /run/iron-vault-tpm/signer.sock
```

```text
srw------- 1 iron-vault root 0 Nov 11 09:12 /run/iron-vault-tpm/signer.sock
```

The service offers the `tpm` kind while this socket exists. Only the service account and root can connect to it.

### 2. Enroll the TPM approver

```sh
sudo iron-vault approver add --kind tpm --label "laptop TPM"
```

The service asks for the passphrase of an approver already pinned, then for the new PIN twice:

```text
enroll an approval signer
  vault: 92e20af6-d193-401c-9e0f-87bf5069adb3
  kind: tpm
  label: laptop TPM
  approvers after the change: 2
  the new signer alone can approve a config and authorize replace, rm, recipient remove and approver changes
  next: choose its TPM approval PIN, at least 6 characters
  the key works only on this machine's TPM and will not move with a migration bundle
  a forgotten PIN is recovered only through another approver, so keep a software approver
  authorize with: any pinned approver
Approval passphrase for "approval passphrase":
New TPM approval PIN for "laptop TPM":
Repeat the new TPM approval PIN:
enrolled approver 1f0c5c0e-3a9c-4a58-8f5d-6a1f3b4c9d21 (tpm); the vault has 2 approvers.
1f0c5c0e-3a9c-4a58-8f5d-6a1f3b4c9d21
```

The TPM made the key and signed a test payload before the vault pinned it, so a TPM that cannot sign enrolls nothing. The
key's wrapped blob is `approver-<id>.tpm` in the state directory.

### 3. Approve a config with the PIN

The software approver signed the config in force, so it is asked first. Press Ctrl-Y to switch to the TPM approver, then type
the PIN:

```sh
sudo iron-vault config approve dev-config.toml
```

```text
Approve this config as version 3? Type yes to approve: yes
Approval passphrase for "approval passphrase" (Ctrl-Y to try another way): ^Y
TPM approval PIN for "laptop TPM" (Ctrl-Y to try another way):
approved version 3 (blake2b:10cef10967fbeeaece8a5f087bf247f8e3ad253a88f1fc96e2db4d449122e0c7)
```

Nothing echoes while you type. Once the TPM approver signs, it is first in the order, and `approver list` marks it `active`.

### 4. Check that it worked

```sh
sudo iron-vault approver list
```

```text
1f0c5c0e-3a9c-4a58-8f5d-6a1f3b4c9d21  tpm       2026-11-11T09:14:02Z  active  laptop TPM
d69d992b-fcf3-481b-b12d-1ec89a59ae67  software  2026-11-11T01:21:45Z  -       approval passphrase
```

## What a wrong PIN costs

Every wrong PIN counts against the TPM's own dictionary-attack counter, which every PIN-protected object on the machine shares,
including a disk-encryption slot opened with a PIN. So the helper never spends more than half of the TPM's tries, and at most
16 at a time. When it has spent its share it answers `tpm-locked-out` with the seconds to wait (the TPM forgets one failed try
per lockout interval), and the software approver still works. The reserve is the other half, for everyone else.

A guess at the PIN is also the cost of a power cut: the TPM counts one failed try after an unclean shutdown if the key was used
since the last orderly one. Approvals are rare, and the same reserve bounds it.

## A forgotten PIN, or a replaced TPM

The TPM keeps no copy of the PIN and no way round it. A forgotten PIN, a TPM cleared by a firmware reset and a replaced board
all leave the TPM approver unusable (`approval-denied`, or `approval-unavailable` saying `not this TPM`). Another approver is
the way out:

1. `sudo iron-vault approver add --label "backup passphrase"`, authorized by the software approver (Ctrl-Y at the first prompt).
2. If the TPM approver signed the config in force (`active` in `approver list`), approve the config again with another
   approver, or the remove fails with `approver-in-use`.
3. `sudo iron-vault approver remove <the TPM approver's ID>`, which also deletes its blob.

Both approval counters carry over. A vault whose only approver is a lost TPM approver has no way left to authorize anything:
[`reset`](reset-vault.md) is the only way out, which is why this recipe keeps a software approver. The TPM approver's key
cannot move with a [migration bundle](move-vault.md); a software approver is needed on the destination.

## What can go wrong

- **`approval-denied`.** The PIN was wrong, and it counted against the TPM's lockout. Nothing was reserved or changed.
- **`tpm-locked-out`.** The TPM is in lockout, or the helper is holding back its share. Wait the seconds the message gives, or
  switch to the software approver.
- **`approval-unavailable`.** The helper refused for a reason other than the PIN or a lockout; the message names the helper's
  status: `not this TPM`, dictionary-attack settings too weak (raise the interval to 600 seconds or more), or a TPM error.
- **`approver-kind-unavailable`.** This install does not offer the kind, or the helper cannot start. The usual cause is no
  `/dev/tpmrm0`, or a udev rule that does not give the `tss` group that device.

The [errors reference](../reference/errors.md#tpm-approvers) lists the codes.

## Reference

- [CLI](../reference/cli.md#iron-vault-approver-add): `approver add --kind tpm`.
- [Files and locations](../reference/files.md): the `.tpm` blob and the helper's socket.
- [Security model](../security-model.md#several-approval-signers).
- [TPM approval signer design](../../../design/tpm-approval-signer.md).
