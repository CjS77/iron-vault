# Run Iron Vault in Docker Compose

*Not run: this recipe needs root, Docker, systemd and a TPM 2.0 on a host, and none was available when it was
checked, so no output is shown. Every command comes from the [Compose install guide](../installation/compose-install.md).*

At the end of this recipe Iron Vault runs as a container, with one isolated network and one TLS listener per caller
container. The host hands the service its unlock identity at startup, sealed to the host's TPM, so after a restart or
reboot the service comes back Ready with no one typing a passphrase. A caller container is recognised by the network it
is on and sends no token.

**The Compose profile has had no release check on a real machine yet, so don't rely on it to protect real secrets.**

Whoever controls the Docker daemon is root on the host and can read the service's memory after unlock, so the
daemon's administrators are trusted. Use [protected Linux](protected-linux.md) on a desktop or a shared workstation.

This page is the order of work. The [install guide](../installation/compose-install.md) holds the detail, and each
step links to its section.

## Prerequisites

- A Linux host with systemd and `systemd-creds`, a TPM 2.0 and Secure Boot on (the identity is sealed to PCR 7).
- Rootful Docker Engine with the Compose plugin, `age-keygen`, `openssl` and `curl`.
- This repository checked out, for `packaging/compose/`.

## Steps

1. [Check the host](../installation/compose-install.md#before-you-start): who may control the Docker daemon, encrypted
   swap and hibernation storage, and a hardened `sudo`.
2. [Install the host files](../installation/compose-install.md#1-install-the-host-files), then
   [build the image](../installation/compose-install.md#2-build-or-pull-the-image) and
   [write the Compose file](../installation/compose-install.md#3-write-the-compose-file).
3. [Provision the host unlock identity](../installation/compose-install.md#4-provision-the-host-unlock-identity) and
   [start the unlock unit](../installation/compose-install.md#5-start-the-unlock-unit).
4. [Make the certificates](../installation/compose-install.md#6-make-the-certificates), one TLS listener per caller.
5. [Start the stack](../installation/compose-install.md#7-start-the-stack), then create the vault with
   `sudo iron-vault init --host-unlock` and restart the service container
   ([step 8](../installation/compose-install.md#8-create-the-vault-and-enrol-the-host-unlock-identity)). Store the
   recovery key offline.
6. [Add the credentials and approve the config](../installation/compose-install.md#9-add-the-credentials-and-approve-the-config).
7. [Send a request](../installation/compose-install.md#10-send-a-request) from a caller container:

   ```sh
   curl --cacert /ca.crt -X POST https://172.30.1.2:8443/venice-chat/chat/completions
   ```

The recipe ends when `sudo iron-vault status` shows Ready after `docker compose restart iron-vault`, and that request
reaches its route.

## Not yet built

- **A TPM approval key.** The service signs each approval with a key opened by the approval passphrase, which you
  type over the admin socket. A key in the host's TPM, reached through a host-side helper that signs only the service's
  approval transaction, is built for the [Linux package](tpm-approval.md) but not yet wired into this profile.

## Reference

- [Docker Compose install guide](../installation/compose-install.md), including the
  [hardening checklist](../installation/compose-install.md#hardening-checklist),
  [restarts and reboots](../installation/compose-install.md#restarts-and-reboots) and
  [a lost TPM](../installation/compose-install.md#a-lost-tpm-or-a-cleared-credential).
- [Design](../../../design/docker-compose.md) and
  [§17](../../../design/iron-vault-specification.md#17-docker-remote-servers-and-appliances) of the specification.
