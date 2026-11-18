# Approve configs with a TPM PIN

*The prompts below match the code; the test suite runs the same steps against a software TPM without asserting their text.
**This has had no release check on a real machine yet**, so don't rely on it for real secrets. Ubuntu 24.04 LTS on a protected install only.*

Enrol a signing key held in your machine's TPM as an [approver](approval-signers.md), used once you type its PIN.
**Keep a software approver beside it:** a forgotten PIN is recovered only through another approver. See the
[TPM approval signer design](../../../design/tpm-approval-signer.md) for how the helper reaches the TPM.

## Before you start

- The package from [the Linux install guide](../installation/linux-install.md), with the service Ready and a config approved.
  A development build never offers the TPM kind.
- A TPM 2.0 at `/dev/tpmrm0`, readable by the `tss` group. The package pulls in `tpm-udev`, which sets that up.
- A TPM whose dictionary-attack settings limit guessing: a lockout recovery interval of **at least 600 seconds** and a maximum
  of at least 2 failed tries. `tpm2_getcap properties-variable` shows them; with weaker settings the
  helper refuses to work.
- A PIN of **at least 6 characters**, different from the vault passphrase.
- The approval passphrase of the approver you already have. Keep that approver. See [forgotten PIN](#a-forgotten-pin-or-a-replaced-tpm).

## Steps

### 1. Check that the kind is offered

```sh
ls -l /run/iron-vault-tpm/signer.sock
```

```text
srw------- 1 iron-vault root 0 Nov 11 09:12 /run/iron-vault-tpm/signer.sock
```

The service offers the `tpm` kind while this socket exists.

### 2. Enroll the TPM approver

```sh
sudo iron-vault approver add --kind tpm --label "laptop TPM"
```

Type the current approval passphrase, then the new PIN twice:

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

A TPM that cannot sign enrolls nothing.

### 3. Approve a config with the PIN

At the first prompt press Ctrl-Y to switch to the TPM approver, then type the PIN:

```sh
sudo iron-vault config approve dev-config.toml
```

```text
Approve this config as version 3? Type yes to approve: yes
Approval passphrase for "approval passphrase" (Ctrl-Y to try another way): ^Y
TPM approval PIN for "laptop TPM" (Ctrl-Y to try another way):
approved version 3 (blake2b:10cef10967fbeeaece8a5f087bf247f8e3ad253a88f1fc96e2db4d449122e0c7)
```

Nothing echoes while you type.

### 4. Check that it worked

```sh
sudo iron-vault approver list
```

```text
1f0c5c0e-3a9c-4a58-8f5d-6a1f3b4c9d21  tpm       2026-11-11T09:14:02Z  active  laptop TPM
d69d992b-fcf3-481b-b12d-1ec89a59ae67  software  2026-11-11T01:21:45Z  -       approval passphrase
```

## What a wrong PIN costs

Every wrong PIN, and an unclean shutdown after the key was used, counts against the TPM's dictionary-attack counter,
shared with every PIN-protected object on the machine. The helper spends at most half the TPM's tries, then answers
`tpm-locked-out` with the seconds to wait; the software approver still works. See the design's
[lockout reserve](../../../design/tpm-approval-signer.md#lockout-reserve).

## A forgotten PIN, or a replaced TPM

A forgotten PIN, a cleared TPM or a replaced board leave the TPM approver unusable (`approval-denied`, or
`approval-unavailable` saying `not this TPM`). Use another approver:

1. `sudo iron-vault approver add --label "backup passphrase"`, authorized by the software approver (Ctrl-Y at the first prompt).
2. If the TPM approver signed the config in force (`active` in `approver list`), approve the config again with another
   approver, or the remove fails with `approver-in-use`.
3. `sudo iron-vault approver remove <the TPM approver's ID>`, which also deletes its blob.

If a lost TPM approver was the only one, [`reset`](reset-vault.md) is the only way out. The TPM approver's key cannot
move with a [migration bundle](move-vault.md); the destination needs a software approver.

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
