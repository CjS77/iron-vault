# Protected Linux install

*Written against `main` at `378d57d`. **Not run:** this recipe needs root and a Debian or Ubuntu machine to install
on, and neither was available when it was checked, so no output is shown. Every command comes from the
[installation guide](../installation/linux-install.md).*

At the end of this recipe Iron Vault runs as the `iron-vault` system service from the `.deb` package, with its vault in
`/var/lib/iron-vault`, out of reach of ordinary accounts. Your own account calls it through a Unix socket and is
recognised by the kernel, with no token file to steal. You administer it with `sudo`.

**The package has not had a release check on a real machine yet, so don't rely on it to protect real secrets.**

This page is the order of work. The two install guides hold the detail, and each step links to its section:

- [Installing Iron Vault on Linux](../installation/linux-install.md): the host checks, the package, listeners,
  upgrade and uninstall.
- [A shared Linux workstation](../installation/multiuser-linux.md): a complete config with several accounts, each
  given only its own routes.

## Prerequisites

- Debian or Ubuntu, and an account that can use `sudo`.
- A Rust toolchain and `cargo-deb`, to build the package.
- An idea of which accounts need which credentials. The [multi-user guide](../installation/multiuser-linux.md#the-situation)
  works through one example.

## Steps

### 1. Harden the host

Do these before you install, because the protection rests on them:

- [Harden `sudo`](../installation/linux-install.md#harden-sudo): a per-terminal credential cache or none, and a
  hardware key where you have one. Every admin command runs through `sudo`, so a cached `sudo` session is as good as
  the admin socket.
- [Encrypt swap and hibernation storage](../installation/linux-install.md#encrypt-swap-and-hibernation-storage).

### 2. Build and install the package

```sh
sudo apt install libtss2-dev pkg-config lintian
cargo install cargo-deb --locked
scripts/build-deb.sh
sudo apt install ./target/debian/iron-vault_*.deb
```

The package creates the `iron-vault` account and its directories, and starts `iron-vault.service` Locked, with no
vault. See [Install](../installation/linux-install.md#install).

### 3. Create and unlock the vault

```sh
sudo iron-vault init
sudo iron-vault unlock
sudo iron-vault status
```

`init` works as in [getting started](getting-started.md#3-create-the-vault): two passphrases and the recovery key,
shown once. [Store and check the recovery key](recovery-key.md) now. `status` should show `service: ready`. If
`unlock` is refused with `memory-unprotected`, the
[install guide](../installation/linux-install.md#install) says how to fix the memory limit.

### 4. Add credentials and a peer-authenticated caller

Store each credential with `sudo iron-vault add`. Then write a config whose callers are recognised by their account
on a Unix socket listener, with no token. This is a fragment of the
[multi-user config](../installation/multiuser-linux.md#4-write-the-config), not a whole config: on its own it has no
`schema_version` and grants a `gh` route it doesn't define, so it would be refused.

```toml
[listeners.local]
unix_socket = "/run/iron-vault/proxy.sock"

[callers.code]
listener = "local"
auth = "peer"
user = "code"            # the account the calling process runs as
routes = ["gh"]
```

The [multi-user guide's config](../installation/multiuser-linux.md#4-write-the-config) is a complete one, with routes.
Approve it with `sudo iron-vault config approve config.toml`; the service publishes its own copy to
`/etc/iron-vault/config.toml`. Read the summary first, as in [widen or narrow a route](change-route.md).

### 5. Send a request

As the `code` account:

```sh
curl --unix-socket /run/iron-vault/proxy.sock http://localhost/gh/user
```

Another account gets `401` unless the config names it, and `sudo curl` is refused: root is never a caller. See
[Send a request](../installation/linux-install.md#send-a-request).

### 6. Add a TCP listener, if a caller needs one

systemd holds every TCP port, through an `iron-vault-listener@<name>.socket` instance named after the listener. Give
the instance its address, enable it, start it while the service is stopped, start and unlock the service, then approve
a config with a listener of the same name and address. The four steps are in
[Add a TCP listener](../installation/linux-install.md#add-a-tcp-listener). A non-loopback address also needs
`tls_certificate` and `tls_key`.

### 7. Upgrade

Build the new package, then:

```sh
sudo apt install ./target/debian/iron-vault_*.deb
sudo iron-vault unlock
```

The upgrade restarts the service, which comes back Locked: requests get `503` with reason `locked` until you unlock.
See [Upgrade](../installation/linux-install.md#upgrade), and [Uninstall and purge](../installation/linux-install.md#uninstall-and-purge)
for removing it.

## What can go wrong

- **An admin command run without `sudo` is refused.** Your login account is never an admin principal in a protected
  install, so malware running as you can't reach the admin socket.
- **`unlock` is refused with `memory-unprotected`.** An edited unit or drop-in lowered `LimitMEMLOCK`. Fix it and
  restart the service.
- **Every request gets `503` after an upgrade or reboot.** The service restarted Locked. Run `sudo iron-vault unlock`.

## Reference

- [Installing Iron Vault on Linux](../installation/linux-install.md) and
  [a shared Linux workstation](../installation/multiuser-linux.md).
- [CLI](../reference/cli.md#sudo-in-a-protected-installation): running commands with `sudo`.
- [§4](../../../design/iron-vault-specification.md#4-installation-and-ownership) of the specification, and the
  [package design](../../../design/linux-package.md).
- The rest of the cookbook applies with `sudo` in front of each `iron-vault` command, the log at
  `/var/log/iron-vault/iron-vault.log` and the published config at `/etc/iron-vault/config.toml`.
