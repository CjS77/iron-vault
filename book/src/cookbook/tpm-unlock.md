# Unlock at boot with a TPM

*Not run: this recipe needs root, systemd 255 and a TPM 2.0 on Ubuntu 24.04, and none was available when it was checked, so no
output is shown. Every command comes from the [TPM unlock section](../installation/linux-install.md#tpm-unlock) of the
Linux install guide.*

Make a protected Linux install reach Ready after a reboot with no `iron-vault unlock`, from a key that `systemd-creds`
seals to the machine's TPM. The vault passphrase and recovery key still work.

**TPM unlock has had no release check on a real machine yet, so don't rely on it to protect real secrets.**

Before you start:

- **There is no TPM PIN.** Anyone who can boot the machine into a trusted image can start the vault. On a laptop, use
  `--portable` with a disk encrypted under a pre-boot secret.
- **A Secure Boot update ends it.** The service starts Locked; unlock with the passphrase, then provision again (see
  [before a Secure Boot key or firmware update](../installation/linux-install.md#before-a-secure-boot-key-or-firmware-update)).
- **Ubuntu 24.04 LTS only.** Elsewhere the service starts Locked.

## Prerequisites

- Ubuntu 24.04 LTS with Secure Boot on and a TPM 2.0, and the package installed as in the
  [install guide](../installation/linux-install.md#install).
- `age-keygen` (Ubuntu package `age`).
- Encrypted swap and hibernation storage ([guide](../installation/linux-install.md#encrypt-swap-and-hibernation-storage)).
- The vault passphrase, the approval passphrase and a place to keep the recovery key offline.

## Steps

1. Seal an identity to the TPM. Use `--server` for a server, or `--portable` for a laptop whose disk is encrypted with a
   pre-boot secret. Type `yes` when it asks:

   ```sh
   sudo iron-vault-provision-host-unlock --server
   ```

   It prints a recipient key, `age1…`, and writes `/etc/iron-vault-host/host-unlock.cred`. Note the key.

2. Start the handoff unit:

   ```sh
   sudo systemctl start iron-vault-host-unlock.service
   ```

3. Enrol the identity. For a new vault, `init` does it, and shows the recovery key once: store it offline.

   ```sh
   sudo iron-vault init --host-unlock
   sudo iron-vault unlock
   ```

   For an existing vault, enrol the key from step 1 instead, with the vault passphrase:

   ```sh
   sudo iron-vault recipient add --host-unlock age1… --label "host unlock"
   ```

4. Prove the recovery key still opens the vault:

   ```sh
   sudo iron-vault recovery check
   ```

5. Reboot, and look at the service without typing anything:

   ```sh
   sudo reboot
   # after the machine is back
   sudo iron-vault status
   ```

The recipe ends when `status` shows the service Ready and the host unlock outcome `unlocked`, with no `unlock` since the
reboot:

```text
service: ready
…
host unlock: unlocked
```

## What can go wrong

- **`host unlock: unseal_failed`.** The TPM would not unseal the key, as after a Secure Boot or firmware update. Type the
  passphrase with `sudo iron-vault unlock`, then follow
  [After the update](../installation/linux-install.md#after-the-update).
- **`host unlock: absent`.** No blob, or the handoff unit did not run. Check `systemctl status iron-vault-host-unlock.service`
  and that `/etc/iron-vault-host/host-unlock.cred` exists.
- **`host unlock: refused`.** The service would not use the handoff. The `vault.host-unlock`
  record in the [audit log](../reference/audit-log.md#service-and-lock-state) gives the reason. Run
  `sudo iron-vault unlock`, fix the cause, and restart the service.
- **`host unlock: owner_locked`.** An earlier `lock` is still in force. A passphrase `unlock` clears it
  ([lock, unlock and restart](lock-unlock-restart.md#a-lock-survives-a-restart)).
- **The helper fails with an error from `systemd-creds`.** Another operating system may have set the TPM's owner password.

## Reference

- [TPM unlock in the install guide](../installation/linux-install.md#tpm-unlock), including
  [retiring it](../installation/linux-install.md#retire-tpm-unlock)
- [Files and locations](../reference/files.md#host-unlock-handoff)
- [Design](../../../design/tpm-unlock.md) and
  [§14](../../../design/iron-vault-specification.md#14-recipients-startup-and-memory) of the specification.
