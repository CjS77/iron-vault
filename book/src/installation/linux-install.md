# Installing Iron Vault on Linux

This guide installs the protected Linux deployment ([§4](../../../design/iron-vault-specification.md#4-installation-and-ownership)): the
service runs as the `iron-vault` system account, its vault is in `/var/lib/iron-vault`, and no ordinary account can read
it. [linux-package.md](../../../design/linux-package.md) says what the package installs and why. For a worked example with several
accounts, see [multiuser-linux.md](multiuser-linux.md). To try Iron Vault as your own user instead, use
[development mode](development-mode.md), which gives no isolation from malware running as you.

The protection depends on the host, not only the package. Do the two checks under
[Before you install](#before-you-install) first.

## Before you install

### Harden `sudo`

Every admin command runs through `sudo` ([§5](../../../design/iron-vault-specification.md#5-service-and-cli-separation-of-concerns)): your login
account is never an admin principal, so malware running as you cannot reach the admin socket. That barrier is only as
strong as your `sudo` setup. After you enter your password, `sudo` remembers it for a timeout that depends on the
distribution: 5 minutes upstream, 15 on Ubuntu. Since sudo 1.8.21 the cache is per terminal (`timestamp_type=tty`) by
default, so anything running in that terminal, malware included, can run admin commands without a prompt until the timeout
ends.

- **Cache per terminal, or not at all.** Create `/etc/sudoers.d/iron-vault-sudo` with `sudo visudo -f` and put one of these
  in it. The first sets the per-terminal cache explicitly, so a distribution default cannot change it:

  ```
  Defaults timestamp_type=tty
  ```

  or, the stronger choice, to ask for the password every time:

  ```
  Defaults timestamp_timeout=0
  ```

- **Add a hardware key where you have one.** `pam_u2f` (Debian and Ubuntu package `libpam-u2f`) makes `sudo` ask for a
  touch on a FIDO2 key as well as the password.
  1. Before editing `/etc/pam.d/sudo`, open a spare terminal and run `sudo -i` in it, and keep that root shell open until
     the last step. (`su -` fails on Ubuntu, where root is locked.) Without the key file, every later `sudo` is refused.
  2. Register the key; `pamu2fcfg` prints to stdout, writes no file and needs a touch on the key, so redirect it:

     ```sh
     mkdir -p ~/.config/Yubico && pamu2fcfg > ~/.config/Yubico/u2f_keys
     ```

     Malware running as you can rewrite that file and register its own key. A central `authfile=` under `/etc`, owned by
     root (`auth required pam_u2f.so authfile=/etc/u2f_mappings`), keeps the registration out of its reach. Register with
     `pamu2fcfg -u "$USER" | sudo tee -a /etc/u2f_mappings` instead.
  3. In `/etc/pam.d/sudo`, add `auth required pam_u2f.so` after the `@include common-auth` line.
  4. From a second terminal, check that `sudo true` asks for the touch, and only then close the root shell.

Approving a config also needs the approval passphrase, and unlocking needs the vault passphrase, so a borrowed `sudo`
session alone can do neither. It is still a host administrator ([§2](../../../design/iron-vault-specification.md#2-security-promise-and-limits)):
it can read the unlocked service's memory, lock the service, and run as any caller account to use that account's routes.

### Encrypt swap and hibernation storage

Iron Vault locks its memory with `mlockall`, so the service's secrets are not paged out to swap. Locking does not stop
hibernation: the kernel writes all of RAM to the hibernation image, locked pages included
([§14](../../../design/iron-vault-specification.md#14-recipients-startup-and-memory)). Swap and hibernation storage must therefore be
encrypted whenever either is enabled, normally by full-disk encryption. Swap matters beyond the service too: the CLI
(`sudo iron-vault init`, `unlock`, `add`, `replace` and `config approve`) holds the passphrases and keys you type, and
does not call `mlockall`, so those pages can be swapped out.

Check what the machine uses:

```sh
swapon --show
lsblk -o NAME,TYPE,FSTYPE
```

In the `lsblk` tree, the partition should show `crypto_LUKS` in FSTYPE, with a `crypt` device (TYPE column) beneath it
and `swap` in FSTYPE on that `crypt` device. A swap partition directly on a plain disk partition is unencrypted.

`lsblk` lists no swap files, and Ubuntu's default swap is the file `/swap.img`. For a swap file, find the device that holds
it and check that device in the `lsblk` tree for `crypt`:

```sh
findmnt -no SOURCE -T /swap.img
```

A `zram` swap device without a writeback device is RAM-backed and never reaches disk, so it needs no encryption.
If `swapon --show` prints nothing and you never hibernate, there is no swap to protect.
If you hibernate, the resume device is the swap device: check it the same way.

## Install

Build the package from source, or use one you were given. Building needs `cargo-deb`:

```sh
cargo install cargo-deb --locked
cargo deb -p iron-vault --locked
sudo apt install ./target/debian/iron-vault_*.deb
```

`scripts/build-deb.sh` builds the package into a temporary directory and checks it, but leaves no `.deb` behind. It needs
`lintian` (`sudo apt install lintian`), or `IRON_VAULT_SKIP_LINTIAN=1` to skip that one check
([details](../../../design/linux-package.md#building-and-checking-the-package)).

The package creates the `iron-vault` account and its directories, and enables and starts `iron-vault.service`. The
service starts Locked with no vault, and the installer prints the next command.

```sh
sudo iron-vault init      # prompts for the vault and approval passphrases; shows the recovery key once
sudo iron-vault unlock    # prompts for the vault passphrase
sudo iron-vault status    # service: ready
```

`init` is described in [vault-initialization.md](../../../design/vault-initialization.md). Store the recovery key offline.

`unlock` is refused with `memory-unprotected` if the service could not lock its memory, and `status` names the cause. The
packaged unit sets `LimitMEMLOCK=infinity`, which is what allows the lock, so the usual cause is an edited unit or a drop-in
that lowers the limit. Fix the limit (after a hand edit of a unit or drop-in, run `sudo systemctl daemon-reload` first) and
`sudo systemctl restart iron-vault`; the service does not restart itself, because it has not failed.

Then add each credential the config names, write a config and approve it, as in [multiuser-linux.md](multiuser-linux.md#setting-it-up):

```sh
sudo iron-vault add github --origin api.github.com
sudo iron-vault config approve config.toml
```

The config can be anywhere `sudo` can read it. The service publishes the approved copy to `/etc/iron-vault/config.toml`.

## Send a request

A config with a Unix socket listener needs no listener socket unit: the service binds the socket itself in
`/run/iron-vault`. This example assumes the [multi-user config](multiuser-linux.md#4-write-the-config), which grants the
`gh` route to the `code` account by its peer account. Run it as `code`:

```sh
curl --unix-socket /run/iron-vault/proxy.sock http://localhost/gh/user
```

Your own login gets `401` unless the config names it as a caller. `sudo curl ...` is refused: the service never accepts
root as a caller ([§7](../../../design/iron-vault-specification.md#7-caller-authentication-and-listeners)).

## Add a TCP listener

In a protected install, systemd holds every TCP port, so the service never binds one itself
([§7](../../../design/iron-vault-specification.md#7-caller-authentication-and-listeners)). Each listener is an instance
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
2. Enable it, so it starts at every boot:

   ```sh
   sudo systemctl enable iron-vault-listener@loopback.socket
   ```

3. Start it with the service stopped, then start the service so it receives the socket, and unlock it again. systemd
   refuses to start a socket while its service is running (`Socket service iron-vault.service already active,
   refusing`), so `enable --now` or a plain `start` fails here:

   ```sh
   sudo systemctl stop iron-vault
   sudo systemctl start iron-vault-listener@loopback.socket
   sudo systemctl start iron-vault
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

Build the new package as under [Install](#install), then:

```sh
sudo apt install ./target/debian/iron-vault_*.deb
sudo iron-vault unlock
```

The upgrade restarts `iron-vault.service`, and it comes back Locked: requests get `503` with reason `locked` until you
unlock it ([§15](../../../design/iron-vault-specification.md#15-service-states-and-errors)). Listener socket units are not restarted, so
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
a config again ([config-approval.md](../../../design/config-approval.md#recovery-table)). The `iron-vault` account stays after purge, so a
later account cannot reuse its uid and gain a kept vault's files. To remove it too, after deleting the vault:
`sudo userdel iron-vault`.
