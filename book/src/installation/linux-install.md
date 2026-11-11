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

Build the package from source, or use one you were given. Building needs `cargo-deb`, `lintian`, and `libtss2-dev` and
`pkg-config` for the TPM signing helper:

```sh
sudo apt install libtss2-dev pkg-config lintian
cargo install cargo-deb --locked
scripts/build-deb.sh
sudo apt install ./target/debian/iron-vault_*.deb
```

`scripts/build-deb.sh` builds both the service and the helper (`cargo deb` alone builds only the service), checks the package, and
writes it to `target/debian/`. `IRON_VAULT_SKIP_LINTIAN=1` skips the `lintian` check
([details](../../../design/linux-package.md#building-and-checking-the-package)).

The package creates the `iron-vault` account and its directories, and enables and starts `iron-vault.service`. The
service starts Locked with no vault, and the installer prints the next command.

If an `iron-vault` account or group already exists, the install stops with "an iron-vault account or group already exists
and is not a locked system account", unless it is what the package would have created: a system uid, a `nologin` or
`false` shell, a locked password, home `/`, `/nonexistent` or `/var/lib/iron-vault`, no other groups, and a group with
no members, no administrators and no password in `/etc/gshadow` (or in `/etc/group` when `/etc/gshadow` has no entry
for it). The package would otherwise hand that account the vault and its group the audit log. The message lists each
problem. Correct the account, or delete it so the package creates its own, then finish the install:

```sh
sudo userdel iron-vault
sudo groupdel iron-vault             # only if the group is still there
sudo dpkg --configure iron-vault
```

The same check runs when you reinstall after a purge, which keeps the account. If you gave a
[log collector](../reference/log-operations.md#location-and-permissions) the `iron-vault` group, take it out of the
group first and add it back afterwards. If the install stops instead with "could not check the account files for an
existing iron-vault account", check that `/etc/passwd`, `/etc/group`, `/etc/shadow` and `/etc/gshadow` are readable,
then run `sudo dpkg --configure iron-vault`.

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

3. List the running listener sockets, then stop them together with the service, start each one the list shows plus the
   new one, then start the service and unlock it. systemd refuses to start a socket while its service is running
   (`Socket service iron-vault.service already active, refusing`), so `enable --now` or a plain `start` fails here.
   Stopping the service alone is not enough: a caller connecting to a listener socket that is still up starts it again,
   and the refusal returns. This frees every listener's port for a moment. Read [Stop the service](#stop-the-service)
   for what that means for callers and for port squatting, and stop your callers first.

   ```sh
   systemctl list-units 'iron-vault-listener@*.socket'
   sudo systemctl stop 'iron-vault-listener@*.socket' iron-vault.service
   sudo systemctl start iron-vault-listener@loopback.socket   # one line for each socket the list showed, the new one included
   sudo systemctl start iron-vault
   sudo iron-vault unlock
   ```

   List before you stop: a stopped instance may be unloaded, and a glob passed to `start` then matches nothing. A
   listener you leave out stays down, with its port free, until the next boot.

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

systemd keeps the port through service restarts and crash loops. A socket that fails to bind at boot, for example
because another process took the port first, leaves the port free, and a process holding it can collect the caller
tokens your callers send. Check `systemctl --failed` after each boot. If a listener socket was down while callers kept
sending, rotate their tokens as under [Stop the service](#stop-the-service).

## Stop the service

`sudo systemctl stop iron-vault` stops the service only until a caller connects. systemd keeps listening on each
listener socket and starts the service again on the next connection. It comes back Locked, so no credential is exposed,
but it is running. If you stop it during an incident, for example because you suspect a caller was compromised, stop
the listener sockets with it:

```sh
sudo systemctl stop 'iron-vault-listener@*.socket' iron-vault.service
```

It stays stopped until the next boot. Stopping the sockets releases their ports, and another local process can then
bind a TCP port and collect the caller tokens that callers keep sending to it. Stop your callers first. If any kept
sending while the ports were free, issue new caller tokens for the callers on TCP listeners with
[`iron-vault caller-token`](../reference/cli.md#iron-vault-caller-token) and approve a config with their new
`token_hash` lines.

To start it again, start each listener socket, then the service, and unlock it:

```sh
sudo systemctl start iron-vault-listener@loopback.socket
sudo systemctl start iron-vault
sudo iron-vault unlock
```

## TPM unlock

TPM unlock lets the service open the vault at boot with no one typing a passphrase. The vault passphrase and the offline
recovery key keep working: TPM unlock adds a way in and replaces none. It is optional, and **it has had no release check
on a real machine yet, so don't rely on it for real secrets.** For a walk-through that ends in a reboot that reaches Ready,
see the [recipe](../cookbook/tpm-unlock.md). The design is [tpm-unlock.md](../../../design/tpm-unlock.md).

**What it needs.** Ubuntu 24.04 LTS only (systemd 255): on any other release the provisioning helper stops, and the service
starts Locked and waits for `iron-vault unlock` as before. It also needs a TPM 2.0, Secure Boot on (the seal is bound to PCR 7,
which records the Secure Boot policy) and `age-keygen` (Ubuntu package `age`). **TPM unlock has no PIN in v0** (the [TPM approver](#tpm-approval-signer) has one). A laptop gets its second
secret from full-disk encryption instead, as below.

**How it works.** The host unlock identity is a key that `systemd-creds` seals to the TPM as the root-only file
`/etc/iron-vault-host/host-unlock.cred`. At each boot the package's handoff unit, `iron-vault-host-unlock.service`, unseals
it as root onto a ramfs at `/run/iron-vault-unlock` and hands it to the service, which uses it to open the vault. The service
never opens the TPM, and the identity is never written to disk in the clear. There is nothing to enable: the service pulls the
handoff unit in at every start, and the unit is skipped on a machine with no blob.

### Provision

Run the helper once, as root, with the choice of mode it asks for. There is no default, because the two modes accept
different risks ([§14](../../../design/iron-vault-specification.md#14-recipients-startup-and-memory)):

- **`--server`**: for a server or appliance. Anyone with physical access to the machine and a trusted boot image can start
  the vault. The helper says so and seals nothing until you type `yes`.
- **`--portable`**: for a laptop. The helper checks, once, that something you must supply at boot protects the disk that holds
  the blob: a LUKS passphrase typed at boot, or a LUKS TPM slot that needs a PIN (`systemd-cryptenroll --tpm2-with-pin=yes`).
  On a btrfs or bcachefs filesystem that spans several devices it checks every device. It warns when part of the disk is not
  encrypted, when a TPM or `clevis` slot needs no PIN, when `/etc/crypttab` or an initramfs holds a key file, when a crypttab
  `keyscript=` is not one known to ask you, and when it cannot tell. With a warning it seals nothing until you accept that anyone who steals the machine can start the vault.

```sh
sudo iron-vault-provision-host-unlock --server       # or --portable
```

It prints the identity's recipient key, `age1…`, and writes `/etc/iron-vault-host/host-unlock.cred`. It refuses to run when
the blob exists: move the old one aside first. With no terminal, `yes` is never read from a pipe; pass
`--accept-physical-access` (`--server`) or `--accept-no-second-secret` (`--portable`) to accept in a script. The choice is
recorded in the journal (`journalctl -t iron-vault-host-unlock`) and in `/etc/iron-vault-host/provisioning.txt`. The helper
never clears the TPM, sets a TPM password or changes its lockout settings.

**The `--portable` check runs once, at provisioning.** A PIN-less slot added later, for example with
`systemd-cryptenroll --tpm2-device=auto`, silently removes the second secret and the helper never sees it. Run the helper
again, as under [Replace the identity](#replace-the-identity), after any change to the disk's key slots. It cannot see a
passphrase written on the laptop either.

### Enrol

The handoff unit runs before the service only at boot. On a running install, start it by hand; the running service sees its
mount.

- **A new vault**: provision, start the handoff unit, then create the vault with the identity as a recipient.

  ```sh
  sudo systemctl start iron-vault-host-unlock.service
  sudo iron-vault init --host-unlock
  sudo iron-vault unlock
  ```

- **An existing vault**: provision, start the handoff unit, then enrol the recipient key the helper printed. It asks for the
  vault passphrase.

  ```sh
  sudo systemctl start iron-vault-host-unlock.service
  sudo iron-vault recipient add --host-unlock age1… --label "host unlock"
  ```

Then check that a restart needs no `unlock`:

```sh
sudo systemctl restart iron-vault
sudo iron-vault status        # service: ready, host unlock: unlocked
```

`lock` still wins: a service its owner locked stays Locked across a crash, a restart and a reboot until a passphrase
`unlock` ([lock, unlock and restart](../cookbook/lock-unlock-restart.md#a-lock-survives-a-restart)).

### Before a Secure Boot key or firmware update

These change PCR 7, and the blob no longer unseals: a change to the Secure Boot keys or databases (PK, KEK, `db`, `dbx`),
turning Secure Boot on or off, a change to the certificate that verifies the boot chain, shim's `MokSBState` or SBAT level,
and an option ROM the firmware verifies against a different `db` entry. Treat a firmware update as one unless the
vendor says it leaves the Secure Boot variables alone. `dbx` and KEK updates arrive routinely through `fwupd` and
distribution updates. **Unattended unlock does not survive them**, and a server that applies them unattended needs someone
to type the passphrase afterwards, or should hold them for a maintenance window. The vault is not stranded: the service
starts Locked and `unlock` and the recovery key work as before.

Before the update:

1. Run `sudo iron-vault recovery check` with the offline recovery key, to prove a way in that does not need the TPM.
2. Confirm that whoever holds the vault passphrase can reach the machine after the reboot.
3. Schedule it for a window in which callers can do without the vault until the passphrase is typed.

### After the update

After the reboot the service is Locked, `sudo iron-vault status` says `host unlock: unseal_failed`, and the audit log has
`vault.host-unlock` with `host_unlock_outcome` `unseal_failed`.

1. `sudo iron-vault unlock` with the vault passphrase.
2. Move the old blob aside and provision a new identity (see [Replace the identity](#replace-the-identity)). The helper
   prints a new recipient key.
3. `sudo systemctl restart iron-vault-host-unlock.service`
4. `sudo iron-vault recipient add --host-unlock <new age1…> --label "host unlock"`
5. `sudo systemctl restart iron-vault`, and check that `status` reaches Ready with no `unlock`.
6. `sudo iron-vault recipient remove <old age1…>` (it asks for the approval passphrase), and delete the old blob.

### Replace the identity

Provisioning a new identity is also what to do after a lost TPM or a change to the disk's key slots. The blob must be moved
aside first, because the helper will not overwrite it:

```sh
sudo mv /etc/iron-vault-host/host-unlock.cred /etc/iron-vault-host/host-unlock.cred.old
sudo iron-vault-provision-host-unlock --server       # or --portable
```

Then restart the handoff unit and enrol the new key as in steps 3 to 6 above. `recipient list` shows the old key as
`host-unlock` beside the new one until you remove it. `recipient remove` refuses the
recipient whose identity the handoff currently holds, so if it refuses, you named the new key.

### Retire TPM unlock

1. `sudo systemctl stop iron-vault-host-unlock.service`
2. `sudo rm /etc/iron-vault-host/host-unlock.cred`
3. `sudo iron-vault recipient remove <age1…>` for the `host-unlock` recipient.
4. `sudo systemctl restart iron-vault`: the service starts Locked, with `host unlock: absent`.

A copy of the blob in a backup still opens on this TPM at this PCR 7. To retire the whole machine, see
[Retire a machine](../cookbook/forget-machine.md).

### Other things to know

- **A distribution upgrade.** `systemd-creds` changes how it binds to the TPM between releases, and whether a blob sealed on
  one release unseals after an upgrade to the next has not been checked. Have the vault passphrase at hand: a failure reads
  `unseal_failed`, and the steps above replace the identity.
- **An owner password set by another OS.** `systemd-creds` seals under the TPM's owner hierarchy, whose password is empty on
  Linux by default. If another operating system set one, the helper fails with `systemd-creds`'s error. Iron Vault never sets,
  clears or reads it.
- **Hibernation.** The unsealed identity is in RAM, so hibernation writes it into the hibernation image. Swap and hibernation
  storage must be encrypted ([above](#encrypt-swap-and-hibernation-storage)); this matters most on a laptop.
- **Who can interfere.** A member of the `tss` group can open `/dev/tpmrm0` and clear the TPM or set an owner password. That
  ends unattended unlock until you provision again; the vault waits Locked, not stranded.
- **Uninstall and purge.** `apt remove` stops the handoff unit and keeps `/etc/iron-vault-host`. `apt purge` deletes it only
  when you also let it delete the vault, because that identity opens only that vault.

## TPM approval signer

The package can also use the machine's TPM as an approval signer: a key that never leaves the TPM approves your configs and the
changes that need you present, once you type its PIN. It is optional, adds an approver and replaces none, and **it has had no
release check on a real machine yet, so don't rely on it for real secrets.** For the commands, see the
[recipe](../cookbook/tpm-approval.md). The design is [tpm-approval-signer.md](../../../design/tpm-approval-signer.md).

**What it needs.** Ubuntu 24.04 LTS only, a TPM 2.0 at `/dev/tpmrm0` and the `tss` group with the udev rule that gives it that
device. Ubuntu's `tpm-udev` package provides both, and the TPM libraries the package depends on pull it in, so it is always installed;
the package creates no `tss` group itself. If the rule does not match your TPM's device, the kind is still offered, because the
socket exists, but `approver add --kind tpm` answers `approver-kind-unavailable`.

**What the package installs.** A helper, `/usr/libexec/iron-vault/iron-vault-tpm-signer`, run for one connection at a time by
`iron-vault-tpm-signer.socket` as its own account, `iron-vault-tpm`. The service account and root alone can connect to
`/run/iron-vault-tpm/signer.sock`. `iron-vault.service` is unchanged: it still has no access to any TPM device. Install enables
and starts the socket, and remove stops it; both accounts are kept, as `iron-vault` is.

**The PIN.** At least 6 characters, typed twice at enrollment. The TPM keeps no copy of it. The TPM counts every wrong try, and
shares one counter among everything on the machine that uses a PIN, such as a disk-encryption slot. The helper therefore spends
at most half of the TPM's tries, never more than 16 at a time, and refuses to work at all when the TPM's lockout recovery
interval is under 600 seconds (one forgotten try is forgiven per interval). A wrong try is also counted after a power cut that
follows a use of the key.

**Recovery advice.**

- Keep a software approver beside the TPM one. A forgotten PIN, a firmware reset that cleared the TPM, or a replaced board are
  all recovered by enrolling another approver and removing the TPM one; both approval counters carry over.
- If the TPM approver is the only one and it is lost, only [`reset`](../cookbook/reset-vault.md) remains.
- The recovery key and the vault passphrase are not approvers and cannot enroll or remove one.
- The key works on this machine only, and does not move in a migration bundle.
- To retire the TPM approver, `approver remove` it; that deletes its blob. Nothing of Iron Vault's stays in the TPM.

## Upgrade

Build the new package as under [Install](#install), then:

```sh
sudo apt install ./target/debian/iron-vault_*.deb
sudo iron-vault unlock
```

The upgrade restarts `iron-vault.service`, and it comes back Locked unless TPM unlock is set up: requests get `503` with
reason `locked` until you unlock it ([§15](../../../design/iron-vault-specification.md#15-service-states-and-errors)). Listener socket units are not restarted, so
they keep their ports through the upgrade. The vault and config are not touched.

## Uninstall and purge

`sudo apt remove iron-vault` stops the service, stops and disables the listener instances, and removes the program. It
keeps `/etc/iron-vault`, `/var/lib/iron-vault`, `/var/log/iron-vault`, the listener drop-ins and the `iron-vault` account,
so a later install opens the same vault and starts Locked. Enable each listener socket unit again after reinstalling.

Removing the package releases the listener ports, and the caller tokens stay valid for the reinstall. Stop your callers
before `apt remove`. If any kept sending to a TCP listener while the package was removed, rotate their tokens as under
[Stop the service](#stop-the-service).

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
a config again ([config-approval.md](../../../design/config-approval.md#recovery-table)). The `iron-vault` account and the `iron-vault-tpm` account of the TPM signing helper stay after purge, so a
later account cannot reuse their uids and gain a kept vault's files. To remove them too, after deleting the vault:
`sudo userdel iron-vault` and `sudo userdel iron-vault-tpm`.
