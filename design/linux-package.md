# Linux package

This document decides how Iron Vault is packaged for a protected Linux installation
([§3.1](iron-vault-specification.md#31-installation-and-ownership)): the package format, who owns every path the
package installs or creates, the systemd units, and what install, upgrade, remove and purge do. The paths and modes
here are the ones the service's trusted-path checks accept (`trusted_path.rs`), so a fresh
install passes them without any manual step.

Terms used here:

- **Linux package**: the `.deb` that installs a protected Linux deployment.
- **Service unit**: `iron-vault.service`, the systemd unit that runs `iron-vault serve`.
- **Listener socket unit**: an instance `iron-vault-listener@<listener>.socket` of the package's template socket unit,
  which binds one request listener for the service ([socket activation](#listener-socket-units)).

Each has a [glossary](glossary.md) entry.

## Format

The Linux package is a `.deb`, built with [`cargo-deb`](https://github.com/kornelski/cargo-deb) from the
`[package.metadata.deb]` table in `crates/iron-vault/Cargo.toml`. It is built with the release profile and the
crate's default features, and never with `dev-mode`: the metadata names no features, and the release check runs the
packaged binary's `--version` and refuses a package whose feature list names `dev-mode`, as CI already does for the
release build.

A `.deb` alone is enough for v0:

- Debian and Ubuntu cover the desktops and servers that v0's users run
  ([§1.1](iron-vault-specification.md#11-intended-users)).
- `cargo-deb` builds from the Cargo workspace with no separate packaging tree. It installs systemd units, `sysusers.d`
  and `tmpfiles.d` files, and adds the maintainer-script snippets that enable, start, restart and stop the units.
- One format means one set of maintainer scripts to review and one release check on a real install.

The unit, `sysusers.d` and `tmpfiles.d` files are not specific to Debian, so another format can reuse them. An RPM,
an Arch package or a tarball would each be a later ticket. A tarball cannot create the service account or enable the
units by itself, so it would also need an install script.

The package depends on `systemd`, which must be the init system, and on `debconf` for the
[purge question](#purge). It recommends `logrotate`, which reads the rotation file it ships
([log-operations.md](log-operations.md#rotation)).

## Ownership

Every path the package installs, and every directory it creates, with the rule that checks it. "Package" in the
Created by column means a file in the `.deb`'s data archive, so dpkg owns it and removes it on remove.

| Path | Owner:group | Mode | Created by | Trusted-path rule |
|---|---|---|---|---|
| `/usr/bin/iron-vault` | `root:root` | `0755` | package | `Binary`: a regular file owned by root, writable by neither group nor others |
| `/usr/lib/systemd/system/iron-vault.service` | `root:root` | `0644` | package | not checked by the service; root-owned and unwritable by users ([§3.1](iron-vault-specification.md#31-installation-and-ownership)) |
| `/usr/lib/systemd/system/iron-vault-listener@.socket` | `root:root` | `0644` | package | as above |
| `/usr/lib/sysusers.d/iron-vault.conf` | `root:root` | `0644` | package | as above |
| `/usr/lib/tmpfiles.d/iron-vault.conf` | `root:root` | `0644` | package | as above |
| `/etc/logrotate.d/iron-vault` | `root:root` | `0644` | package, as a conffile | not checked by the service |
| `/etc/iron-vault` | `iron-vault:iron-vault` | `0700` | `tmpfiles.d` | `ConfigDir`: a directory owned by the service account, mode exactly `0700` |
| `/var/lib/iron-vault` | `iron-vault:iron-vault` | `0700` | `tmpfiles.d` | `StateDir`: a directory owned by the service account, mode exactly `0700` |
| `/run/iron-vault` | `iron-vault:iron-vault` | `0711` | `tmpfiles.d` | `RuntimeDir`: a directory owned by the service account, writable by neither group nor others |
| `/var/log/iron-vault` | `iron-vault:iron-vault` | `0750` | the service unit's `LogsDirectory=` | `LogDir`: a directory owned by the service account, no more open than `0750` |

`cargo-deb` may install the units and the `sysusers.d` and `tmpfiles.d` files under `/lib` rather than `/usr/lib`. On
the merged-`/usr` systems that current Debian and Ubuntu releases are, the two are the same directory.

Every ancestor passes the ancestor rule as these distributions ship it: `/`, `/usr`, `/usr/bin`, `/etc`, `/var`,
`/var/lib` and `/run` are owned by root and writable by neither group nor others. `/var/log` may be `root:syslog`
`0775`, as on Ubuntu; the `LogDir` rule allows a group-writable ancestor when root owns it.

The service writes everything inside these directories itself, with the modes the trusted-path rules require; the
package installs none of it. The service owns each file, with mode `0600` unless the list says otherwise:

- `/etc/iron-vault`: `config.toml`, `config.toml.sig`, `config.toml.lock`, and the approval transaction's pending and
  staged files ([config-approval.md](config-approval.md#where-the-files-live)).
- `/var/lib/iron-vault`: the vault's files and `lock` ([storage-formats.md](storage-formats.md)).
- `/run/iron-vault`: `admin.sock`, and any request socket the service binds itself, mode `0666`.
- `/var/log/iron-vault`: `iron-vault.log`, mode `0640`.

Because none of these is a dpkg conffile or in the data archive, dpkg never removes them, which is why
[purge](#purge) deletes them in `postrm`. TLS certificates, keys and pinned CA files are installed by the
administrator, not the package, and keep their own rules (`AdminCertificate`, `AdminPrivateKey`).

### Why the package does not ship the service's directories

The four service-owned directories are not in the `.deb`'s data archive. dpkg sets the owner and mode of every path
in the archive from the archive on each upgrade, and `cargo-deb` can only give a path root ownership. A shipped
`/etc/iron-vault` would be root-owned after every upgrade, and the `ConfigDir` rule would refuse it. dpkg would also try
to remove a shipped directory on remove, which must keep these.

systemd's per-unit directories do not fit three of them either:

- **`ConfigurationDirectory=`** leaves the directory owned by root. The service must create and rename files in
  `/etc/iron-vault`, so the `ConfigDir` rule requires the service account to own it.
- **`RuntimeDirectory=`** is deleted when the service stops. A request socket that a listener socket unit created in
  it would be unlinked on every restart, while systemd still held the listening socket, so callers could no longer
  reach it. The socket unit also starts before the service, so the directory must exist before the service first runs.
- **`StateDirectory=`** would work for `/var/lib/iron-vault`, but `tmpfiles.d` already creates the other two, and one
  mechanism for all three is simpler to review.

### Account and directories

`/usr/lib/sysusers.d/iron-vault.conf` creates the system account and its group:

```
u iron-vault - "Iron Vault credential proxy" - /usr/sbin/nologin
```

The account gets a system uid, no login shell, and `systemd-sysusers`'s default home `/`, so no home directory is
created.

`/usr/lib/tmpfiles.d/iron-vault.conf` creates the three directories:

```
d /etc/iron-vault     0700 iron-vault iron-vault -
d /var/lib/iron-vault 0700 iron-vault iron-vault -
d /run/iron-vault     0711 iron-vault iron-vault -
```

`postinst` runs `systemd-sysusers` and then `systemd-tmpfiles --create` before it starts any unit. At every boot
`systemd-tmpfiles-setup.service` recreates `/run/iron-vault` before `sockets.target`, so listener socket units can
bind in it. A `d` line also puts back the owner and mode of a directory that already exists, and its age field `-`
means it is never cleaned.

## Service unit

```ini
[Unit]
Description=Iron Vault credential proxy

[Service]
Type=exec
ExecStart=/usr/bin/iron-vault serve
ExecReload=/bin/kill -HUP $MAINPID
User=iron-vault
Group=iron-vault
Restart=on-failure
LimitCORE=0
LimitMEMLOCK=infinity
UMask=0077
LogsDirectory=iron-vault
LogsDirectoryMode=0750
ProtectSystem=strict
ReadWritePaths=/etc/iron-vault /var/lib/iron-vault /run/iron-vault
ProtectHome=yes
PrivateDevices=yes
PrivateTmp=yes
NoNewPrivileges=yes
CapabilityBoundingSet=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallFilter=@system-service
MemoryDenyWriteExecute=yes

[Install]
WantedBy=multi-user.target
```

| Directive | Why |
|---|---|
| `Type=exec` | The service sends no readiness notification. `exec` makes a start fail when the binary cannot be executed, rather than reporting success. |
| `ExecReload=` | The service reloads its published config on SIGHUP ([config-approval.md](config-approval.md#reload)), so `systemctl reload iron-vault` does that. |
| `User=iron-vault`, `Group=iron-vault` | The service runs under its own account ([§3.1](iron-vault-specification.md#31-installation-and-ownership)), which is the expected owner the trusted-path checks look for and an admin principal ([§3.2](iron-vault-specification.md#32-service-and-cli-boundary)). |
| `Restart=on-failure` | A crash restarts the service unattended ([§3.12](iron-vault-specification.md#312-service-states-and-errors)). A clean exit, and a service waiting Locked, are not failures, so neither is restarted. |
| `LimitCORE=0` | No core dump can hold service memory ([§3.11](iron-vault-specification.md#311-recipients-startup-and-memory)). The service also sets `RLIMIT_CORE` to 0 and clears `PR_SET_DUMPABLE` itself. |
| `LimitMEMLOCK=infinity` | `hardening.rs` calls `mlockall` only when the `RLIMIT_MEMLOCK` soft limit is unlimited, because locking future mappings under a finite limit makes allocations fail once the service grows past it. A protected install does not unlock without locked memory ([§3.11](iron-vault-specification.md#311-recipients-startup-and-memory)). Locking needs no capability once the limit allows it. |
| `UMask=0077` | Any file the service creates without an explicit mode is its own alone. Files that need another mode set it explicitly: the log file `0640`, request sockets `0666`. |
| `LogsDirectory=`, `LogsDirectoryMode=0750` | systemd creates `/var/log/iron-vault`, owned by the service account, before each start, and makes it writable under `ProtectSystem=strict` ([log-operations.md](log-operations.md)). Without `LogsDirectoryMode=` the mode would be `0755`, which the `LogDir` rule refuses. |
| No `Environment=`, `EnvironmentFile=` or `PassEnvironment=` | The service gets only the environment systemd builds for a unit, never the environment of the administrator who started it. The service does not depend on this: it ignores proxy, trust-root and log-level variables in code ([§3.7](iron-vault-specification.md#37-outbound-tls-and-environment)). |
| `ProtectSystem=strict`, `ReadWritePaths=` | The whole filesystem is read-only to the service except its config, state and runtime directories and its log directory. `/run` is read-only under `strict` too, so the runtime directory must be listed: the service binds `admin.sock` there. An approved config whose `[logging] destination` names another directory needs a drop-in adding that directory to `ReadWritePaths=`. |
| `ProtectHome=yes` | `/home`, `/root` and `/run/user` are invisible. The service has no reason to read a login account's files. |
| `PrivateDevices=yes` | Only pseudo-devices such as `/dev/null` and `/dev/urandom` are visible. v0 uses no device. |
| `PrivateTmp=yes` | The service gets its own `/tmp`, which no other account can use to plant files for it. |
| `NoNewPrivileges=yes` | No set-uid program or file capability can raise the service's privileges. |
| `CapabilityBoundingSet=` (empty) | The service needs no capability: it binds no privileged port itself, and memory locking is allowed by the limit. |
| `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` | The service uses Unix sockets and IP, and nothing else, such as netlink or packet sockets. |
| `SystemCallFilter=@system-service` | systemd's set for ordinary services. It includes `mlockall`, `setrlimit` and `prctl`, which process hardening calls. |
| `MemoryDenyWriteExecute=yes` | No memory is both writable and executable. The service generates no code at run time. |
| `WantedBy=multi-user.target` | Enabling the unit starts the service at boot. |

The TPM epics will add `DeviceAllow=/dev/tpmrm0 rw`. With `PrivateDevices=yes`, they must check that the systemd
versions the package supports make an allowed device node visible in the private `/dev`, or replace
`PrivateDevices=yes` with `DevicePolicy=closed`.

## Listener socket units

In a protected install every TCP listener comes from systemd socket activation: the service refuses to bind one
itself (`socket_activation::check_origin`), so that no other process can take the port while the service restarts
([§3.4](iron-vault-specification.md#34-caller-authentication-and-listeners), R-6). A Unix request socket may be
bound by the service or by a socket unit.

The package ships one template:

```ini
[Unit]
Description=Iron Vault request listener %i

[Socket]
FileDescriptorName=%i
Service=iron-vault.service

[Install]
WantedBy=sockets.target
```

The template names no address. Each listener gets an instance named after it, and the administrator gives that
instance its address in a drop-in:

```sh
sudo systemctl edit iron-vault-listener@loopback.socket
```

```ini
[Socket]
ListenStream=127.0.0.1:7878
```

`systemctl edit` writes the drop-in to `/etc/systemd/system/iron-vault-listener@loopback.socket.d/override.conf`. An
instance without a drop-in has no `ListenStream=` and fails to start, so a listener is never bound by accident.

- **`FileDescriptorName=%i`** passes the socket under the instance name, which must be the listener's name. Listener
  names are 1 to 64 characters of `[a-z0-9_-]`, starting with a letter, and `%i` keeps them unchanged.
- **`Service=iron-vault.service`** passes the socket to the service unit. A socket unit is ordered before the service
  it names, so the socket is listening when the service starts.
- **No `PartOf=`**. Restarting the service must leave the socket open, or the port would be free for the restart.
- **`WantedBy=sockets.target`** binds the socket at boot.
- **Unix sockets** use `ListenStream=/run/iron-vault/<name>.sock`. systemd's default `SocketMode=0666` and
  `SocketUser=root` are what the service accepts for an adopted socket file.
- **An address that appears after boot**, such as an isolated Docker network's bridge address, needs `FreeBind=yes`
  in the drop-in. Otherwise the socket cannot bind at `sockets.target`.

### Why a socket unit change needs no approval

A socket unit decides only whether an endpoint is held and passed, never what the service does with it. Before it
serves on a passed socket, the service checks it against the approved listener of the same name
(`socket_activation::verify`). It must be a listening stream socket bound exactly to the configured address, and a
Unix socket's file must be a socket owned by root or the service account, in a directory that passes the
`RuntimeDir` rule. A socket that fails the check is held unused and logged, and a socket that no approved listener
names is never served on. Caller authentication, routes and TLS all come from the approved config. A changed socket
unit can therefore only remove a listener, never widen one. Socket unit files and drop-ins live under
`/etc/systemd/system`, which only a host administrator can write.

### Adding and removing a TCP listener

A running service cannot take a socket that was started after it, so a new TCP listener needs a restart:

1. Write the drop-in, then `sudo systemctl enable --now iron-vault-listener@<name>.socket`.
2. `sudo systemctl restart iron-vault`, then `sudo iron-vault unlock`. The restarted service holds the new socket.
3. Approve a config that names the listener. The approval can come before step 2, and its summary then marks the
   listener as taking effect after restart ([config-approval.md](config-approval.md#open-questions), question 2).

To remove one, approve a config without it, then `sudo systemctl disable --now iron-vault-listener@<name>.socket`.
Otherwise systemd keeps the port and passes a socket that nothing serves on.

## Lifecycle

The maintainer scripts follow the dpkg contract
([Debian Policy §6.8](https://www.debian.org/doc/debian-policy/ch-maintainerscripts.html#details-of-removal-and-or-configuration-purging)).
`cargo-deb` generates the unit snippets in the same form as `dh_installsystemd`. The package's own scripts add the
rest.

### Install

`postinst configure` creates the account and the directories ([above](#account-and-directories)), loads the purge
question's debconf template by sourcing debconf's `confmodule`, then enables and starts `iron-vault.service`. It
enables no listener socket unit: the administrator creates those. The service starts Locked with no vault, and
`status` says to run `iron-vault init`. Nothing unlocks it.

### Upgrade

dpkg replaces the files, then `postinst configure` runs `systemd-sysusers` and `systemd-tmpfiles --create` again,
reloads systemd and restarts `iron-vault.service`. The old service keeps running until that restart. The service
comes back Locked, and an interactive-unlock profile waits for `sudo iron-vault unlock`. Listener socket units are
not restarted, so they keep their ports through the upgrade.

### Remove

`prerm remove` stops and disables `iron-vault.service` and every `iron-vault-listener@*.socket` instance. dpkg then
removes the binary, the units and the `sysusers.d` and `tmpfiles.d` files. Remove keeps:

- `/etc/iron-vault`, `/var/lib/iron-vault` and `/var/log/iron-vault`;
- the listener drop-ins under `/etc/systemd/system`;
- the `iron-vault` account.

A later install finds the vault and its config where they were and starts Locked. The administrator enables each
listener socket unit again. `/run/iron-vault` is on a tmpfs and goes at the next boot.

### Purge

dpkg removes the conffile `/etc/logrotate.d/iron-vault`, then `postrm purge`:

1. Deletes `/etc/iron-vault` and `/var/log/iron-vault`. The service wrote their contents, so none is a dpkg conffile,
   and dpkg would leave them behind. Debian Policy requires a package to delete configuration it manages outside
   conffiles on purge ([§10.7.3](https://www.debian.org/doc/debian-policy/ch-files.html#behavior)), and its log
   files ([§10.8](https://www.debian.org/doc/debian-policy/ch-files.html#log-files)). Any TLS files the administrator
   put under `/etc/iron-vault` go with it.
2. Deletes the drop-in directories `/etc/systemd/system/iron-vault-listener@*.socket.d`, which configure nothing but
   this package.
3. Asks whether to delete the vault, as below.
4. Purges the package's debconf entries.

The `iron-vault` account stays, as Debian packages' system accounts usually do. A kept vault is owned by it, and
deleting the account could let a later account reuse its uid and gain the vault's files.

#### The vault question

The vault is the one directory a purge does not delete without asking. `/var/lib/iron-vault` holds the only copies of
the encrypted credential records. The offline recovery key opens the vault's identity envelope, which lives in that
same directory, so it cannot bring back deleted records. Losing them means reissuing every provider credential, and
`apt purge` is easy to run by accident. Database packages handle this case the same way: `mariadb-server` asks
`mariadb-server/postrm_remove_databases` ("Remove all MariaDB databases?") in `postrm purge`
([template](https://salsa.debian.org/mariadb-team/mariadb-server/-/blob/debian/latest/debian/mariadb-server.templates)),
and `slapd` asks `slapd/purge_database` ("Do you want the database to be removed when slapd is purged?")
([template](https://salsa.debian.org/openldap-team/openldap/-/blob/master/debian/slapd.templates)). Both default to
no.

The template follows `mariadb-server`'s:

```
Template: iron-vault/purge_vault
Type: boolean
Default: false
_Description: Delete the vault and every stored credential?
 /var/lib/iron-vault holds the only copies of the encrypted credential
 records. The offline recovery key cannot bring back deleted records.
 .
 If you keep the vault, a later install of iron-vault opens it again.
```

When `/var/lib/iron-vault` exists, `postrm purge` asks the question at priority `high` and reads the answer:

- **Yes** deletes `/var/lib/iron-vault`.
- **No** keeps it. So does a purge with no answer, which takes the default: the `noninteractive` frontend, a
  priority threshold above `high`, or debconf no longer installed. `postrm` then prints the path and how to remove it:
  `sudo rm -rf /var/lib/iron-vault`.

An answer preseeded with `debconf-set-selections` counts as an answer, as it does for `mariadb-server`, so an
unattended purge deletes the vault only when an administrator said so in advance.

A kept vault opens with a later install, but its published config and signature went with `/etc/iron-vault`. After
`unlock` the service is Unavailable with an invalid policy, because the committed config is missing
([config-approval.md](config-approval.md#recovery-table), row 7), until the owner approves a config again.

## Admin access

Admin commands run only through `sudo` ([§3.2](iron-vault-specification.md#32-service-and-cli-boundary)). The admin
principals of a protected install are root and the service account, fixed by the deployment profile. `admin.sock` is
the service account's with mode `0600`, and the service checks each connection's peer account before reading
anything. The package creates no admin group. Adding a login account to the `iron-vault` group would grant nothing,
because the socket's group has no access and the peer check refuses the account anyway. The owner runs
`sudo iron-vault <command>`. The installation guide recommends per-terminal `sudo` credential caching or none, and a
hardware-key factor where the platform supports one.
