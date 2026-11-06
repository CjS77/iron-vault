# Installing Iron Vault on Linux

This guide installs the protected Linux deployment ([§3.1](iron-vault-specification.md#31-installation-and-ownership)): the
service runs as the `iron-vault` system account, its vault is in `/var/lib/iron-vault`, and no ordinary account can read
it. [linux-package.md](linux-package.md) says what the package installs and why. For a worked example with several
accounts, see [multiuser-linux.md](multiuser-linux.md). To try Iron Vault as your own user instead, use the
[development mode tutorial](../README.md#development-mode), which gives no isolation from malware running as you.

The protection depends on the host, not only the package. Do the two checks under
[Before you install](#before-you-install) first.

## Before you install

### Harden `sudo`

Every admin command runs through `sudo` ([§3.2](iron-vault-specification.md#32-service-and-cli-boundary)): your login
account is never an admin principal, so malware running as you cannot reach the admin socket. That barrier is only as
strong as your `sudo` setup. By default `sudo` remembers your password for 5 minutes, and for every terminal of the same
login, so malware that can type into a terminal you used a moment ago may run admin commands without a prompt.

- **Cache per terminal, or not at all.** Create `/etc/sudoers.d/iron-vault-sudo` with `sudo visudo -f` and put one of these
  in it:

  ```
  Defaults timestamp_type=tty
  ```

  or, to ask for the password every time:

  ```
  Defaults timestamp_timeout=0
  ```

- **Add a hardware key where you have one.** `pam_u2f` (Debian and Ubuntu package `libpam-u2f`) makes `sudo` ask for a
  touch on a FIDO2 key as well as the password. Register the key with `pamu2fcfg`, then add `auth required pam_u2f.so` to
  `/etc/pam.d/sudo`. Test it from a second terminal before closing the first, so a mistake doesn't lock you out of `sudo`.

Approving a config also needs the approval passphrase, so a borrowed `sudo` session alone cannot approve one. Still,
anyone who can run `sudo` as you can unlock the vault and use every route.

### Encrypt swap and hibernation storage

Iron Vault locks its memory with `mlockall`, so the service's secrets are not paged out to swap. Locking does not stop
hibernation: the kernel writes all of RAM to the hibernation image, locked pages included
([§3.11](iron-vault-specification.md#311-recipients-startup-and-memory)). Swap and hibernation storage must therefore be
encrypted whenever either is enabled, normally by full-disk encryption. Encrypted swap is also a second layer if memory
locking is ever off, since the page lock is a property of the unit and a changed unit loses it.

Check what the machine uses:

```sh
swapon --show
lsblk -o NAME,TYPE,FSTYPE
```

Every swap device or file listed by `swapon --show` should sit on a `crypt` device (TYPE column) in the `lsblk` tree, with
`swap` in FSTYPE for the swap partition itself. A swap partition directly on a plain disk partition is unencrypted. If
`swapon --show` prints nothing and you never hibernate, there is no swap to protect. If you hibernate, the resume device is
the swap device: check it the same way.

## Install

Build the package from source, or use one you were given. `scripts/build-deb.sh` builds it with `cargo-deb` and checks it;
it needs `lintian` (`sudo apt install lintian`), or `IRON_VAULT_SKIP_LINTIAN=1` to skip that one check
([details](linux-package.md#building-and-checking-the-package)).

```sh
sudo apt install ./iron-vault_*.deb
```

The package creates the `iron-vault` account and its directories, and enables and starts `iron-vault.service`. The
service starts Locked with no vault, and the installer prints the next command.

```sh
sudo iron-vault init      # prompts for the vault and approval passphrases; shows the recovery key once
sudo iron-vault unlock    # prompts for the vault passphrase
sudo iron-vault status    # service: ready
```

`init` is described in [vault-initialization.md](vault-initialization.md). Store the recovery key offline.

`unlock` is refused with `memory-unprotected` if the service could not lock its memory, and `status` names the cause. The
packaged unit sets `LimitMEMLOCK=infinity`, which is what allows the lock, so the usual cause is an edited unit or a drop-in
that lowers the limit. Fix the limit and `sudo systemctl restart iron-vault`; the service does not restart itself, because
it has not failed.

Then add credentials, write a config and approve it, as in [multiuser-linux.md](multiuser-linux.md#setting-it-up):

```sh
sudo iron-vault add github --origin api.github.com
sudo iron-vault config approve config.toml
```

The config can be anywhere `sudo` can read it. The service publishes the approved copy to `/etc/iron-vault/config.toml`.

## Send a request

A config with a Unix socket listener needs no listener socket unit: the service binds the socket itself in
`/run/iron-vault`.

```sh
curl --unix-socket /run/iron-vault/proxy.sock http://localhost/gh/user
```

## Add a TCP listener

In a protected install, systemd holds every TCP port, so the service never binds one itself
([§3.4](iron-vault-specification.md#34-caller-authentication-and-listeners)). Each listener is an instance
`iron-vault-listener@<name>.socket` of the packaged template, and `<name>` must be the listener's name in the config. A
non-loopback address also needs `tls_certificate` and `tls_key` in the config.

1. Give the instance its address in a drop-in:

   ```sh
   sudo systemctl edit iron-vault-listener@loopback.socket
   ```

   ```ini
   [Socket]
   ListenStream=127.0.0.1:7878
   ```

   An address that appears only after boot, such as a Docker bridge, also needs `FreeBind=yes` in the drop-in.
2. Start it now and at every boot:

   ```sh
   sudo systemctl enable --now iron-vault-listener@loopback.socket
   ```

3. Restart the service so it receives the socket, and unlock it again:

   ```sh
   sudo systemctl restart iron-vault
   sudo iron-vault unlock
   ```

4. Approve a config that names the listener with the same address:

   ```toml
   [listeners.loopback]
   address = "127.0.0.1:7878"
   ```

   ```sh
   sudo iron-vault config approve config.toml
   ```

The service serves on a passed socket only if an approved listener of the same name has exactly that address, so editing
a socket unit can remove a listener but never widen one. To remove a listener, approve a config without it, then run
`sudo systemctl disable --now iron-vault-listener@loopback.socket`.

## Upgrade

```sh
sudo apt install ./iron-vault_*.deb
sudo iron-vault unlock
```

The upgrade restarts `iron-vault.service`, and it comes back Locked: requests get `503` with reason `locked` until you
unlock it ([§3.12](iron-vault-specification.md#312-service-states-and-errors)). Listener socket units are not restarted, so
they keep their ports through the upgrade. The vault and config are not touched.

## Uninstall and purge

`sudo apt remove iron-vault` stops the service, stops and disables the listener instances, and removes the program. It
keeps `/etc/iron-vault`, `/var/lib/iron-vault`, `/var/log/iron-vault`, the listener drop-ins and the `iron-vault` account,
so a later install opens the same vault and starts Locked. Enable each listener socket unit again after reinstalling.

`sudo apt purge iron-vault` deletes `/etc/iron-vault` (the published config and signature, and any TLS files you put
there), `/var/log/iron-vault` and the listener drop-ins under `/etc/systemd/system/iron-vault-listener@*.socket.d`. It then
asks, at high priority and defaulting to no: "Delete the vault and every stored credential?" Answer yes to delete
`/var/lib/iron-vault`. Under a non-interactive frontend, with no answer preseeded, the vault is kept and the purge prints
the command to delete it.

Deleted credential records cannot be recovered, not even with the recovery key. To delete a kept vault by hand:

```sh
sudo rm -rf /var/lib/iron-vault
```

A kept vault whose config went with the purge unlocks into an Unavailable service with an invalid policy until you approve
a config again ([config-approval.md](config-approval.md#recovery-table)). The `iron-vault` account stays after purge, so a
later account cannot reuse its uid and gain a kept vault's files. To remove it too, after deleting the vault:
`sudo userdel iron-vault`.
