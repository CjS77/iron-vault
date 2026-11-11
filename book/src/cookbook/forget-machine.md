# Retire a machine

At the end of this recipe a machine that used to open your vault is no longer one of its recipients, and you have the
steps to retire what it held: its sealed unlock credential and, if nothing else needs it, its TPM. Iron Vault checks and
advises; you run every step on the retired machine yourself. `forget-machine` never removes a recipient, deletes a file or
runs a TPM tool.

Removing a recipient protects future copies of `identity.age` only. Old copies and backups still open with the removed key,
so a machine that was lost, as opposed to retired, also means rotating the provider credentials it could reach.

The commands below are for a protected installation: run every `iron-vault` command through `sudo` (see [`sudo` in a
protected installation](../reference/cli.md#sudo-in-a-protected-installation)).

## Prerequisites

- **The vault that stays**, running and Ready, on another machine. `forget-machine` reads its recipient list; the retired
  machine's own copy of the vault still lists the machine's key, so the command is not run there.
- **The retired machine's recipient key**, the `age1…` text. For a machine with TPM unlock it is the `host-unlock` line of
  `iron-vault recipient list`, or what the provisioning script printed. If the machine's vault was moved with
  `export` and `import`, the new vault never held the old key; use the one the old machine's `recipient list` or
  provisioning output showed.
- **Your approval passphrase**, if the key is still a recipient (step 1).

## Steps

### 1. Remove the recipient, if it is still one

```sh
iron-vault recipient list
iron-vault recipient remove age1…
```

`recipient remove` asks for the approval passphrase. It refuses the `operational` recipient, the last `recovery`
recipient and a host unlock identity that this service's own unlock handoff holds; see [manage recipients](recipients.md).

### 2. Check that it is gone

```sh
iron-vault forget-machine age1…
```

If the key is still a recipient, the command exits with code 1 and the code `machine-not-forgotten`; the message gives
the key's role and says to run `recipient remove` with the same key. Nothing is changed.

If the key is not a recipient, the command prints three facts and then the steps for the retired machine:

```text
age1… is not a recipient of this vault. Check that it is the key the retired machine had: this command cannot tell a removed key from one that was never enrolled.
independence rule: holds
recovery last checked: 2026-11-04 (7 days ago)
```

It cannot tell a removed key from one that was never a recipient, so a mistyped key reads as gone. Compare the key it
repeats with the one on the retired machine.

Any warnings are printed first, on stderr, above the steps. A warning means something needs fixing before you clear any TPM:

- **`the recovery check is overdue`, `has never run` or `is not on record`.** Run [`recovery check`](recovery-key.md) with
  your offline recovery key. Retiring a machine removes one way into the vault; the check proves another still works. A new
  vault that has never run the check gets this warning too, however young it is.
- **`the vault no longer meets the independence rule`.** The vault lacks an `operational` or `recovery` recipient, or has
  too few recipients. Add the missing one with `recipient add` before you go on.

### 3. Follow the steps it prints, on the retired machine

Steps 1 to 3 run as root on the retired machine. In order:

1. **Find out what else uses the TPM.** Clearing it destroys every key it holds. List the TPM keyslots of each LUKS
   device with `systemd-cryptenroll DEVICE`; look for other sealed credentials with
   `grep -rlE 'LoadCredentialEncrypted|SetCredentialEncrypted|ImportCredential' /etc/systemd /run/systemd /usr/lib/systemd`
   and `ls /etc/credstore.encrypted /run/credstore.encrypted /usr/lib/credstore.encrypted /usr/local/lib/credstore.encrypted`;
   list the persistent handles with `tpm2_getcap handles-persistent`. The handle `0x81000001` is systemd's storage root key,
   shared by every `systemd-creds` user on the machine. List the NV indices with `tpm2_getcap handles-nv-index`: clearing
   the TPM destroys them, and other software keeps state there (the systemd-pcrlock policy, which LUKS keyslots enrolled with
   `--tpm2-pcrlock` depend on, and `tpm2-totp`). Remember other software that keeps keys in the TPM, and the machine's other users.
2. **Delete the sealed credential.** `systemctl stop iron-vault-host-unlock.service`, then
   `rm /etc/iron-vault-host/host-unlock.cred`. A copy of that file in a backup still opens on this TPM.
3. **Clear the TPM only if nothing else needs it.** Use the firmware's clear-TPM setting, or `tpm2_clear`. If step 1 found
   another user, leave the TPM alone: step 2 has retired the machine from this vault, and only old backup copies stay
   reachable through this TPM. Do not clear a shared TPM.

If the machine held only an added or recovery key, there is no TPM step: delete that key where it was kept.

The machine may also still hold its own copy of the vault. Retire it with [`iron-vault reset`](reset-vault.md) or by
purging the package, and delete `/etc/iron-vault-host/provisioning.txt` beside the sealed credential.

### 4. If the machine was lost or stolen, rotate

Run this on the vault that stays. Removing a recipient cannot revoke ciphertext an attacker already holds. For each
credential in `iron-vault list`, have the provider reissue the key, then give the name and the origins `list` shows:

```sh
iron-vault replace NAME --origin api.fx.example
```

See [rotate a key](rotate-key.md).

## What can go wrong

- **`machine-not-forgotten`.** The key is still a recipient. Run `recipient remove` with the same key. If
  that is refused because the key is the host unlock identity this service holds, you ran the command on the machine being
  retired; run it on the vault that stays.
- **`wrong-state`.** The service is not Ready. Run `iron-vault unlock`.
- **`recipient-invalid`.** The argument is not an `age1…` key.
- **`busy`.** Another operation holds the service-wide lock; try again.
- **`recipient-inventory-damaged`.** The recipient inventory is missing or damaged; nothing was changed. See
  [errors](../reference/errors.md#recipient-list-recipient-add-and-recipient-remove).

## Reference

- [CLI](../reference/cli.md#iron-vault-forget-machine) and [errors](../reference/errors.md#forget-machine).
- [Audit log](../reference/audit-log.md): `recipient.forget-checked`.
- [Forget machine design](../../../design/forget-machine.md): what it checks, and why it runs on the vault that stays.
- Related: [manage recipients](recipients.md), [reset the vault](reset-vault.md), [unlock at boot with a TPM](roadmap/tpm-unlock.md)
  (not yet available).
