# Linux package

This document decides how Iron Vault is packaged for a protected Linux installation
([§4](iron-vault-specification.md#4-installation-and-ownership)): the package format, who owns every path the
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

A `.deb` alone is enough for v0, by the owner's decision. It installs on Debian, Ubuntu and their derivatives, and
it keeps the first package small:

- `cargo-deb` builds from the Cargo workspace with no separate packaging tree. It installs systemd units, `sysusers.d`
  and `tmpfiles.d` files, and adds the maintainer-script snippets that enable, start, restart and stop the units.
- One format means one set of maintainer scripts to review and one release check on a real install.

The unit, `sysusers.d` and `tmpfiles.d` files are not specific to Debian, so another format can reuse them. An RPM,
an Arch package or a tarball would each be a later ticket. A tarball cannot create the service account or enable the
units by itself, so it would also need an install script.

The package depends on `systemd`, which must be the init system, and on `debconf` for the
[purge question](#purge). It recommends `logrotate`, which reads the rotation file it ships
([log-operations.md](../book/src/reference/log-operations.md#rotation)).

## Ownership

Every path the package installs, and every directory it creates, with the rule that checks it. "Package" in the
Created by column means a file in the `.deb`'s data archive, which dpkg owns and removes.

| Path | Owner:group | Mode | Created by | Trusted-path rule |
|---|---|---|---|---|
| `/usr/bin/iron-vault` | `root:root` | `0755` | package | `Binary`: a regular file owned by root, writable by neither group nor others |
| `/usr/lib/systemd/system/iron-vault.service` | `root:root` | `0644` | package | not checked by the service; root-owned and unwritable by users ([§4](iron-vault-specification.md#4-installation-and-ownership)) |
| `/usr/lib/systemd/system/iron-vault-listener@.socket` | `root:root` | `0644` | package | as above |
| `/usr/lib/sysusers.d/iron-vault.conf` | `root:root` | `0644` | package | as above |
| `/usr/lib/tmpfiles.d/iron-vault.conf` | `root:root` | `0644` | package | as above |
| `/etc/logrotate.d/iron-vault` | `root:root` | `0644` | package, as a conffile | not checked by the service |
| `/usr/share/doc/iron-vault/copyright` | `root:root` | `0644` | package | not checked by the service |
| `/usr/share/doc/iron-vault/changelog.Debian.gz` | `root:root` | `0644` | package | not checked by the service |
| `/usr/share/man/man1/iron-vault.1.gz` | `root:root` | `0644` | package | not checked by the service |
| `/usr/share/man/man5/iron-vault-config.5.gz` | `root:root` | `0644` | package | not checked by the service |
| `/usr/share/lintian/overrides/iron-vault` | `root:root` | `0644` | package | not checked by the service |

The package also installs one man page per subcommand beside `iron-vault.1.gz`, such as `iron-vault-config-approve.1.gz`,
with the same owner and mode. `clap_mangen` names them in each parent page. They are generated from the CLI definition
into `packaging/linux/man/` by a test that fails when the committed pages are out of date, as the book's
[CLI reference](../book/src/reference/cli.md) is.

`iron-vault-config(5)` describes the config file, pairing with `iron-vault-config(1)` as `crontab(5)` pairs with
`crontab(1)`. It is hand-written, a summary of the [configuration reference](../book/src/reference/configuration.md)
without its refusal messages. A test in `iron-vault-policy` fails when the page does not name, in bold, every key and
enumerated value the parser accepts (read from the parser's own unknown-key refusals), or when its EXAMPLE section is
not a valid config.
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
- `/run/iron-vault`: `admin.sock`, and request sockets with mode `0666`. A request socket that a listener socket unit
  creates is owned by root instead, which the service also accepts.
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
- **`RuntimeDirectory=`** is created only when the service starts. A listener socket unit starts before the service
  it names and binds its Unix socket in `/run/iron-vault`, so the directory must exist before the service first runs.
  systemd also deletes the directory when the service stops, which would unlink the socket's file while systemd still
  held the listening socket, so callers could no longer reach it. `RuntimeDirectoryPreserve=yes` would keep the
  directory across a stop, but not create it before the socket unit at boot.
- **`StateDirectory=`** would work for `/var/lib/iron-vault`, but `tmpfiles.d` already creates the other two, and one
  mechanism for all three is simpler to review.

### Account and directories

`/usr/lib/sysusers.d/iron-vault.conf` creates the system account and its group:

```
u iron-vault - "Iron Vault credential proxy" - /usr/sbin/nologin
```

The account gets a system uid, no login shell, and `systemd-sysusers`'s default home `/`, so no home directory is
created.

`systemd-sysusers` leaves an existing account or group of that name as it is. A login account called `iron-vault` that
was there first would own the three directories below, so it could read the encrypted records and change the config
directory, and anyone in an existing `iron-vault` group could read the audit log. So on the first configure, and the
first after a purge, `postinst` checks an `iron-vault` account or group that already exists, before `systemd-sysusers`
runs. It fails `configure` unless the account is what `systemd-sysusers` would have made:

- a system uid, above 0 and at most `SYS_UID_MAX` from `/etc/login.defs` (999 when unset);
- the shell `nologin` or `false`, under `/usr/sbin`, `/sbin`, `/usr/bin` or `/bin`;
- a locked password (`!` or `*` first) or none, in `/etc/shadow` or `/etc/passwd`;
- the home `/`, `/nonexistent` or `/var/lib/iron-vault`, so no `~/.ssh` or other login file belongs to it;
- `iron-vault` as its primary group and no supplementary group;
- an `iron-vault` group with no members, which is no other account's primary group;
- no other account with its uid and no other group with its gid, because either would be the same identity under
  another name.

The refusal lists each problem and says to correct the account, or delete it (`userdel iron-vault`, and `groupdel
iron-vault` if the group remains) so the package creates its own, then run `dpkg --configure iron-vault`. Later
configures skip the check: the account is then the package's own, and its group may hold a log collector's account
([Admin access](#admin-access)). A purge keeps the account and group, so a collector's membership must be removed
before reinstalling and added back afterwards. When `postinst` cannot run the check, because a file is missing or
unreadable or `awk` fails, it says so and fails `configure` too, because an account it could not check may be one it
should refuse. The check reads only the files in `/etc`, not accounts that NSS takes from a directory service.

#### Why `serve` does not check the account again

A second check was considered: `iron-vault serve` would refuse to start when its own account is not a locked system
account. It is not built.

It would gain three things over the check in `postinst`:

- it runs at every start, not only on the first configure;
- it looks the account up through NSS, so it also sees an account, or a group membership, that a directory service
  provides;
- it catches a change made to the account after install, such as a login shell or a supplementary group added later.

It would cost three things:

- the service runs as `iron-vault` and cannot read `/etc/shadow`, so it cannot see whether the password is locked,
  which is what decides whether anyone can log in as the account;
- a failing check takes the service down, so a mistake in the check, or a harmless change to the account, stops every
  caller's routes;
- it must allow a log collector's account in the `iron-vault` group ([Admin access](#admin-access)), so it cannot refuse
  a group with members, the check that keeps the audit log private.

Against those costs the gains are small. After install, only root can change the account. Only root can change the
group's members too, unless the group existed before the package and names a group administrator or has a group
password (the second gap below). The threat model trusts root and the host's administrators
([§2](iron-vault-specification.md#2-security-promise-and-limits)). The case the threat model does cover, an account that
existed before the package and would be adopted by it, is closed at configure, where `postinst` runs as root and reads
`/etc/shadow`, apart from that second gap. [§5](iron-vault-specification.md#5-service-and-cli-separation-of-concerns)
requires that taking over the service account not give admin access; the `Protected` deployment profile still accepts
the service account's uid on the admin socket ([Admin access](#admin-access)) until that is brought in line with §5.

Two gaps are left open:

- an account from a directory service, which neither check would fully close, because `serve` still could not see its
  password state;
- an `iron-vault` group that existed before the package and names a group administrator in `/etc/gshadow`, or has a
  group password. A group administrator can add members with `gpasswd -a` without being root, and anyone who knows the
  group password can join with `newgrp iron-vault`; either gives read access to the audit log. The `postinst` check
  does not yet read `/etc/gshadow` or the password field of `/etc/group`.

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
| `User=iron-vault`, `Group=iron-vault` | The service runs under its own account ([§4](iron-vault-specification.md#4-installation-and-ownership)), which is the expected owner the trusted-path checks look for and an admin principal ([§5](iron-vault-specification.md#5-service-and-cli-separation-of-concerns)). |
| `Restart=on-failure` | A crash restarts the service unattended ([§15](iron-vault-specification.md#15-service-states-and-errors)). A clean exit, and a service waiting Locked, are not failures, so neither is restarted. |
| `LimitCORE=0` | No core dump can hold service memory ([§14](iron-vault-specification.md#14-recipients-startup-and-memory)). The service also sets `RLIMIT_CORE` to 0 and clears `PR_SET_DUMPABLE` itself. |
| `LimitMEMLOCK=infinity` | `hardening.rs` calls `mlockall` only when the `RLIMIT_MEMLOCK` soft limit is unlimited, because locking future mappings under a finite limit makes allocations fail once the service grows past it. A protected install does not unlock without locked memory ([§14](iron-vault-specification.md#14-recipients-startup-and-memory)). Locking needs no capability once the limit allows it. |
| `UMask=0077` | Any file the service creates without an explicit mode is its own alone. Files that need another mode set it explicitly: the log file `0640`, request sockets `0666`. |
| `LogsDirectory=`, `LogsDirectoryMode=0750` | systemd creates `/var/log/iron-vault`, owned by the service account, before each start, and makes it writable under `ProtectSystem=strict` ([log-operations.md](../book/src/reference/log-operations.md)). Without `LogsDirectoryMode=` the mode would be `0755`, which the `LogDir` rule refuses. |
| No `Environment=`, `EnvironmentFile=` or `PassEnvironment=` | The service gets only the environment systemd builds for a unit, never the environment of the administrator who started it. The service does not depend on this: it ignores proxy, trust-root and log-level variables in code ([§10](iron-vault-specification.md#10-outbound-tls-and-environment)). |
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
([§7](iron-vault-specification.md#7-caller-authentication-and-listeners)). A Unix request socket may be
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

A running service cannot take a socket that was started after it, and systemd refuses to start a socket unit whose
service is already active (`Socket service iron-vault.service already active, refusing`). A new TCP listener therefore
needs the service stopped while its socket starts:

1. Write the drop-in, then `sudo systemctl enable iron-vault-listener@<name>.socket`.
2. `sudo systemctl stop iron-vault`, `sudo systemctl start iron-vault-listener@<name>.socket`,
   `sudo systemctl start iron-vault`, then `sudo iron-vault unlock`. The started service holds the new socket.
3. Approve a config that names the listener. The approval can come before step 2, and its summary then marks the
   listener as taking effect after restart ([config-approval.md](config-approval.md#open-questions), question 2).

To remove one, approve a config without it, then `sudo systemctl disable --now iron-vault-listener@<name>.socket`.
Otherwise systemd keeps the port and passes a socket that nothing serves on.

### Stopping the service

`sudo systemctl stop iron-vault` does not keep the service down. Each listener socket names
`Service=iron-vault.service`, so systemd keeps listening and starts the service again on the next caller connection.
It comes back Locked, so no credential is exposed, but an owner who stops it during an incident expects it to stay
stopped. To stop it until the next boot, stop the sockets with it:

```sh
sudo systemctl stop 'iron-vault-listener@*.socket' iron-vault.service
```

This releases the listeners' ports. Another local process can then bind a TCP port and collect the caller tokens that
callers keep sending to it. Stop the callers first, or rotate the caller tokens of the callers on TCP listeners
afterwards. To bring the service back, start each `iron-vault-listener@<name>.socket`, then `iron-vault`, then unlock.

## Lifecycle

The maintainer scripts follow the dpkg contract
([Debian Policy §6.8](https://www.debian.org/doc/debian-policy/ch-maintainerscripts.html#details-of-removal-and-or-configuration-purging)).
`cargo-deb` generates the snippets for `iron-vault.service` in the same form as `dh_installsystemd`
([autoscripts](https://github.com/kornelski/cargo-deb/tree/main/autoscripts)). It generates none for the listener
template, because it skips every unit whose name contains `@`: a template cannot be enabled or stopped without an
instance name. The package's own scripts add the rest, including everything for the listener instances.

### Install

`postinst configure` loads the purge question's debconf template by sourcing debconf's `confmodule`, refuses an
existing `iron-vault` account or group that is not a locked system account, creates the account and the directories
([above](#account-and-directories)), then enables and starts `iron-vault.service`. It
enables no listener socket unit: the administrator creates those. The service starts Locked with no vault, and
`status` says to run `iron-vault init`. Nothing unlocks it.

### Upgrade

dpkg replaces the files, then `postinst configure` runs `systemd-sysusers` and `systemd-tmpfiles --create` again,
reloads systemd and restarts `iron-vault.service`. The old service keeps running until that restart. The service
comes back Locked, and an interactive-unlock profile waits for `sudo iron-vault unlock`. Listener socket units are
not restarted, so they keep their ports through the upgrade.

### Remove

The service unit and the listener instances are taken out of use in different ways.

- **`iron-vault.service`** is handled by the generated snippets. `prerm remove` stops it, and `postrm remove` masks
  it with `deb-systemd-helper mask`, so nothing can start it while the package is removed. Its enablement symlink
  and `deb-systemd-helper`'s record of it stay until purge, which runs `deb-systemd-helper purge` and then unmasks
  it. A reinstall before purge therefore unmasks and enables it again, as an install does.
- **Listener instances** are handled by the package's own `prerm remove`, in lines before its `#DEBHELPER#` token, so
  they run ahead of the generated stop. It stops every loaded `iron-vault-listener@*.socket` instance (`systemctl
  stop` matches the pattern against loaded units), so no connection can start the service again through socket
  activation once it has stopped. It then disables each enabled instance by name. `systemctl disable` does not
  expand patterns, so the script lists the instances from the `iron-vault-listener@*.socket` symlinks in
  any `/etc/systemd/system/*.wants` or `*.requires` directory, without duplicates, and passes each name. Disabling an
  instance removes its symlink, so the boot no longer asks for a socket unit whose template is gone.

dpkg then removes the binary, the units and the `sysusers.d` and `tmpfiles.d` files. Remove keeps:

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
   this package ([open question 1](#open-questions), decided).
3. Asks whether to delete the vault, as below.
4. Purges the package's debconf entries.

The `iron-vault` account stays, as Debian packages' system accounts usually do. A kept vault is owned by it, and
deleting the account could let a later account reuse its uid and gain the vault's files.

#### The vault question

The vault is the one directory a purge does not delete without asking. `/var/lib/iron-vault` holds the only copies of
the encrypted credential records. The offline recovery key opens the vault's identity envelope, which lives in that
same directory, so it cannot bring back deleted records. Losing them means reissuing every provider credential, and
`apt purge` is easy to run by accident. Database packages guard their data with a debconf question that defaults to
no, and they differ in when they ask:

- `slapd` asks `slapd/purge_database` ("Do you want the database to be removed when slapd is purged?") at priority
  `low` while it is first configured, in its `config` script
  ([source](https://salsa.debian.org/openldap-team/openldap/-/blob/master/debian/slapd.config)). Its `postrm purge`
  only reads the stored answer
  ([source](https://salsa.debian.org/openldap-team/openldap/-/blob/master/debian/slapd.postrm),
  [template](https://salsa.debian.org/openldap-team/openldap/-/blob/master/debian/slapd.templates)).
- `mariadb-server` asks `mariadb-server/postrm_remove_databases` ("Remove all MariaDB databases?") at priority `high`
  in `postrm purge` itself
  ([source](https://salsa.debian.org/mariadb-team/mariadb-server/-/blob/debian/latest/debian/mariadb-server.postrm),
  [template](https://salsa.debian.org/mariadb-team/mariadb-server/-/blob/debian/latest/debian/mariadb-server.templates)).

Iron Vault follows `mariadb-server` and asks at purge time, when the owner can see what is about to go. An answer
given at install time, possibly years earlier and at a priority most installs never show, is a poor guard for the
only copies of the credential records. The template also follows `mariadb-server`'s:

```
Template: iron-vault/purge_vault
Type: boolean
Default: false
Description: Delete the vault and every stored credential?
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

## Building and checking the package

`scripts/build-deb.sh` builds the `.deb` with `cargo deb -p iron-vault` and checks it. It needs `cargo-deb`
(`cargo install cargo-deb --locked`), `dpkg-deb` and `lintian` (`sudo apt install lintian`). Without `lintian` it exits non-zero;
`IRON_VAULT_SKIP_LINTIAN=1` is the explicit opt-out, and the script then ends with "package checks passed WITHOUT lintian". It fails when:

- the package `Version:` is not the crate version with its first `-` turned into `~` plus the revision `-1`, or still holds a
  `-` before the revision (see below);
- the newest entry of the changelog, `packaging/linux/debian/changelog`, is not that package version, so a version bump
  needs a changelog entry;
- the packaged binary's `--version` lists any feature, so a `dev-mode` package is refused;
- a file's owner or mode differs from the [ownership table](#ownership), a path is owned by anyone but root, or
  anything is shipped under `/etc/iron-vault`, `/var/lib/iron-vault`, `/var/log/iron-vault` or `/run/iron-vault`;
- the conffiles are anything but `/etc/logrotate.d/iron-vault`, or a maintainer script is missing or not executable;
- `lintian --fail-on error` reports an error.

The script passes `--deb-version` to `cargo deb`. cargo-deb would turn the crate version `0.2.0-alpha` into `0.2.0-alpha-1`,
which dpkg sorts above `0.2.0-1`, so the final release would not upgrade an alpha. Debian writes a pre-release with `~`:
`0.2.0-alpha` becomes `0.2.0~alpha-1`, which sorts below `0.2.0-1`.

The package's own scripts (`packaging/linux/debian/`) use `systemctl` rather than `deb-systemd-invoke` for the listener
instances, because `deb-systemd-invoke` neither disables a unit nor takes a pattern.

#### Accepted lintian tags

The package ships these overrides in `/usr/share/lintian/overrides/iron-vault` (source
`packaging/linux/lintian/iron-vault`). Any other error or warning is fixed, not overridden.

| Tag | Level | Why it is accepted |
|---|---|---|
| `no-debconf-config` | error | The only debconf question is the [vault question](#the-vault-question), which `postrm` asks at purge time, as `mariadb-server` does. Nothing is asked at configure time, so there is no `config` script. |
| `maintainer-script-calls-systemctl` (`prerm`) | warning | `prerm` stops and disables the listener socket instances, and `deb-systemd-invoke` neither disables a unit nor takes a pattern (above). |
| `initial-upload-closes-no-bugs` | warning | The package is built from this repository and never uploaded to Debian, so its first changelog entry has no ITP bug to close. |

### Checking a real install

`scripts/release/linux-install-check.sh` is the release check for an installed package. It runs as root on a disposable
VM, takes an ordinary test account, and prints a PASS or FAIL line per check. It reads the [ownership table](#ownership)
from this file, then checks the service's account, locked memory, core limit and dumpability, that the test account
cannot reach the admin socket, `/proc/<pid>/mem`, `/proc/<pid>/environ` or the vault, that a group-writable
`/etc/iron-vault` stops a restart, that a second `serve` fails on the state lock, and that a listener socket unit keeps
its port across a service restart. It refuses to run without `--i-know-this-is-a-disposable-vm`. The refusal of the
group-writable directory is read from the journal, because the service's startup error goes to stderr.

## Admin access

Admin commands run only through `sudo` ([§5](iron-vault-specification.md#5-service-and-cli-separation-of-concerns)). The admin
principals of a protected install are root and the service account, fixed by the deployment profile. `admin.sock` is
the service account's with mode `0600`, and the service checks each connection's peer account before reading
anything. The package creates no admin group. Membership of the `iron-vault` group grants no admin access: the
socket's group has no access, and the peer check refuses the account anyway. It does grant read access to the audit
log, because `/var/log/iron-vault` is `0750` and `iron-vault.log` is `0640`, both with the service's group, and
anyone who reads the log sees every route, caller and refusal. Only a log collector's own service account belongs in
the group; never add a login account ([log-operations.md](../book/src/reference/log-operations.md#location-and-permissions)).

The owner runs `sudo iron-vault <command>`. The installation guide recommends per-terminal `sudo` credential caching
or none, and a hardware-key factor where the platform supports one.

## Open questions

1. **Purge deletes the listener drop-ins.** *Decided: default accepted (2026-11-09).* [Purge](#purge) step 2 deletes
   `/etc/systemd/system/iron-vault-listener@*.socket.d`. The administrator wrote these files, not the package, and
   the purge contract the owner set names only `/etc/iron-vault`, `/var/log/iron-vault` and the vault. Deleting them
   is the default because they configure nothing once the template unit is gone; the owner should confirm it.
