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

The package depends on `systemd`, which must be the init system, on `debconf` for the
[purge question](#purge), and on the `libtss2` libraries the [TPM signing helper](#tpm-signing-helper) links, which `cargo-deb` adds to `$auto`
from that binary (`/usr/bin/iron-vault` links none). It recommends `logrotate`, which reads the rotation file it ships
([log-operations.md](../book/src/reference/log-operations.md#rotation)), and `tpm-udev`, for the
[TPM signing helper](#tpm-signing-helper) (the libtss2 packages depend on it anyway).

## Ownership

Every path the package installs, and every directory it creates, with the rule that checks it. "Package" in the
Created by column means a file in the `.deb`'s data archive, which dpkg owns and removes.

| Path | Owner:group | Mode | Created by | Trusted-path rule |
|---|---|---|---|---|
| `/usr/bin/iron-vault` | `root:root` | `0755` | package | `Binary`: a regular file owned by root, writable by neither group nor others |
| `/usr/lib/systemd/system/iron-vault.service` | `root:root` | `0644` | package | not checked by the service; root-owned and unwritable by users ([§4](iron-vault-specification.md#4-installation-and-ownership)) |
| `/usr/lib/systemd/system/iron-vault-listener@.socket` | `root:root` | `0644` | package | as above |
| `/usr/lib/systemd/system/iron-vault-host-unlock.service` | `root:root` | `0644` | package | as above |
| `/usr/lib/systemd/system/iron-vault-tpm-signer.socket` | `root:root` | `0644` | package | as above |
| `/usr/lib/systemd/system/iron-vault-tpm-signer@.service` | `root:root` | `0644` | package | as above |
| `/usr/libexec/iron-vault/iron-vault-tpm-signer` | `root:root` | `0755` | package | not checked by the service; run only by systemd as `iron-vault-tpm` |
| `/usr/sbin/iron-vault-provision-host-unlock` | `root:root` | `0755` | package | not checked by the service; run only by root |
| `/usr/lib/sysusers.d/iron-vault.conf` | `root:root` | `0644` | package | as above |
| `/usr/lib/tmpfiles.d/iron-vault.conf` | `root:root` | `0644` | package | as above |
| `/etc/logrotate.d/iron-vault` | `root:root` | `0644` | package, as a conffile | not checked by the service |
| `/usr/share/doc/iron-vault/copyright` | `root:root` | `0644` | package | not checked by the service |
| `/usr/share/doc/iron-vault/changelog.Debian.gz` | `root:root` | `0644` | package | not checked by the service |
| `/usr/share/man/man1/iron-vault.1.gz` | `root:root` | `0644` | package | not checked by the service |
| `/usr/share/man/man5/iron-vault-config.5.gz` | `root:root` | `0644` | package | not checked by the service |
| `/usr/share/man/man8/iron-vault-provision-host-unlock.8.gz` | `root:root` | `0644` | package | not checked by the service |
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
| `/run/iron-vault-tpm` | `root:root` | `0755` | the signer socket unit | none: the service connects to `signer.sock` in it, owned by `iron-vault` with mode `0600` |
| `/run/iron-vault-unlock` | `root:root` | `0711` | `tmpfiles.d` | none: the service only opens the unlock handoff and the unseal-failure file in it, by name ([tpm-unlock.md](tpm-unlock.md#at-boot)) |
| `/var/log/iron-vault` | `iron-vault:iron-vault` | `0750` | the service unit's `LogsDirectory=` | `LogDir`: a directory owned by the service account, no more open than `0750` |

`/run/iron-vault-unlock` is the [handoff unit](tpm-unlock.md#at-boot)'s mount point. While that unit is active, a ramfs
owned by root with the same mode, `0711`, is mounted over it, so the table's row holds before and after provisioning,
and `scripts/release/linux-install-check.sh` finds it either way. The two modes must match: every
`systemd-tmpfiles --create`, which `postinst` runs at each configure, re-applies the `d` line's mode through the mount
to the ramfs root, and anything wider would let any account list the ramfs. `/etc/iron-vault-host`, root `0700`, and
the blob in it, root `0600`, have no row: the [provisioning helper](tpm-unlock.md#provisioning) creates them, not the
package, and a machine never provisioned has neither. The helper also writes `provisioning.txt` there, root `0600`: the
[acceptance record](tpm-unlock.md#the-acceptance-record), replaced whole at each provisioning.

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
created. The same file creates the [TPM signing helper](#tpm-signing-helper)'s account the same way:

```
u iron-vault-tpm - "Iron Vault TPM signing helper" - /usr/sbin/nologin
```

`postinst`'s check below covers `iron-vault` only. An `iron-vault-tpm` account that was there first owns nothing
of the package's, and the helper's socket admits only the service account, so the check would protect nothing.

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
- in `/etc/gshadow`, a group with no administrators, no members and no usable password. A password is unusable when
  it is empty or starts with `!` or `*`, which `gshadow(5)` says is not a valid `crypt(3)` string, so `newgrp` cannot
  be passed with it. `systemd-sysusers` writes `iron-vault:!*::`; `adduser --system --group`'s `!::` and `*::` are also
  accepted. Every `iron-vault` line is read for these. A group administrator can add members with
  `gpasswd -a`, and anyone who knows a password can join with `newgrp`. Members are refused here as well as in
  `/etc/group`, because the two lists can differ. A missing `/etc/gshadow` means no group has an entry. An entry is
  the first `iron-vault` line that has exactly four colon-separated fields and follows no malformed line, because
  `newgrp` looks it up with shadow-utils' `getsgnam`: `sgetsgent` (`lib/gshadow.c`) rejects any other field count,
  and `getsgent` ends the scan at the first line it rejects. A blank line, a bare name or a five-field line therefore
  hides every later line, and `newgrp` then uses the `/etc/group` password. So does a line ending in `\`: `fgetsx`
  (`lib/fputsx.c`) joins it to the next line before `sgetsgent` counts fields, and the joined line is rejected. A NUL
  byte in the file can also make the parsers disagree; that is a known limit, as only root writes `/etc/gshadow`;
- when `/etc/gshadow` has no `iron-vault` entry, a usable password in the second field of the `/etc/group` entry, because
  `newgrp(1)` takes the group's password from `/etc/group` only then. The same rule applies: empty, `!…` and `*…` are
  unusable. So is `x`, which means "look in `/etc/gshadow`": with no entry there is nothing to match, and `crypt(3)`
  cannot produce a string that equals it. With a gshadow entry, that entry decides and the field is ignored;
- no other account with its uid and no other group with its gid, because either would be the same identity under
  another name.

The refusal lists each problem and says to correct the account, or delete it (`userdel iron-vault`, and `groupdel
iron-vault` if the group remains) so the package creates its own, then run `dpkg --configure iron-vault`. Later
configures skip the check: the account is then the package's own, and its group may hold a log collector's account
([Admin access](#admin-access)). A purge keeps the account and group, so a collector's membership must be removed
before reinstalling and added back afterwards. When `postinst` cannot run the check, because a file is missing or
unreadable or `awk` fails, it says so and fails `configure` too, because an account it could not check may be one it
should refuse; that includes an `/etc/gshadow` that exists but cannot be read. The check reads only the files in `/etc`,
not accounts that NSS takes from a directory service.

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
password, which `postinst` refuses. The threat model trusts root and the host's administrators
([§2](iron-vault-specification.md#2-security-promise-and-limits)). The case the threat model does cover, an account that
existed before the package and would be adopted by it, is closed at configure, where `postinst` runs as root and reads
`/etc/shadow` and `/etc/gshadow`. Taking over the service account gives no admin access either: the admin
socket refuses the service account's uid ([Admin access](#admin-access);
[§5](iron-vault-specification.md#5-service-and-cli-separation-of-concerns)).

One gap is left open: an account from a directory service, which neither check would fully close, because `serve`
still could not see its password state.

`/usr/lib/tmpfiles.d/iron-vault.conf` creates the three directories, and the handoff unit's mount point:

```
d /etc/iron-vault        0700 iron-vault iron-vault -
d /var/lib/iron-vault    0700 iron-vault iron-vault -
d /run/iron-vault        0711 iron-vault iron-vault -
d /run/iron-vault-unlock 0711 root       root       -
```

`postinst` runs `systemd-sysusers` and then `systemd-tmpfiles --create` before it starts any unit. At every boot
`systemd-tmpfiles-setup.service` recreates `/run/iron-vault` before `sockets.target`, so listener socket units can
bind in it. The age field `-` means the directories are never cleaned.

A `d` line also resets the owner and mode of a directory that already exists. That runs at every boot and every
`postinst configure`, before the service checks the directory. So a `/etc/iron-vault` or `/var/lib/iron-vault` that was
made group-writable or handed to another account is put right silently, and the service's `ConfigDir` or `StateDir`
refusal only fires between those runs, such as on `systemctl restart`. Files planted while the directory was open stay.
The service still does not trust them, with two exceptions. In `/etc/iron-vault`, the `Config` rule and the config
signature catch a planted `config.toml`. In `/var/lib/iron-vault`, the [MAC'd file
frame](storage-formats.md#macd-file-frame) on the manifest, the approval state and the recipient inventory rejects a
file written without the vault identity, and a record file is trusted only through the manifest that lists it. The `age`
envelopes are trusted only through the manifest MAC (`identity.age`, `operational.age`) or the pinned approver key
(`approver-<approver ID>.age`), so a planted one can only make unlock or approval fail. The first exception is
`init.unfinished`, which the service reads by name alone: its presence is its whole meaning ([unfinished initialization
file](storage-formats.md#unfinished-initialization-file)). A planted one makes `unlock` refuse the vault as an
unfinished or unrecognized initialization, and the owner's next `init` then offers to discard the vault's files. That is
loud and touches availability only, no worse than deleting the vault's files, and it never reaches a credential or the
config. The other exception is `recovery.toml`, the [recovery check record](storage-formats.md#recovery-check-record):
it is plaintext, with no MAC and no version, so the service reads a planted or edited one if it is valid. Its only guard
was that just the service account can write the state directory, which is the guard that failed here. A forged record
can only move or suppress the recovery reminder and what `status` reports as `recovery last checked` (it holds two
times, and `since` may not be later than `last_checked`); an invalid one is unusable and the reminder counts as due. It
cannot reach a credential or a config. So the repair hides the warning sign, and lets a planted `recovery.toml` through,
with that limited effect. One warning sign survives the repair: `unlock` logs a `vault.foreign-file` WARN for any file
in the state directory that init never writes. The package keeps the repair: an upgrade or reboot heals a mistaken
`chmod` without an administrator's help, and that is worth more than the earlier warning. An administrator who wants to
know that a directory was tampered with must look at the journal of an earlier restart or at the files in it, not at the
next boot.

## Service unit

```ini
[Unit]
Description=Iron Vault credential proxy
StartLimitIntervalSec=0
Wants=iron-vault-host-unlock.service
After=iron-vault-host-unlock.service

[Service]
Type=exec
ExecStart=/usr/bin/iron-vault serve
ExecReload=/bin/kill -HUP $MAINPID
User=iron-vault
Group=iron-vault
Restart=on-failure
RestartSec=1
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
| `StartLimitIntervalSec=0` (in `[Unit]`) | No start limit. When a socket-activated service hits its start limit, systemd fails every socket unit that names it (`service-start-limit-hit`), and a failed socket unit closes its port. Under the default limit, 5 starts in 10 s, a crash loop would free each TCP listener's port for another local process to bind and collect caller tokens ([§7](iron-vault-specification.md#7-caller-authentication-and-listeners)). A loop needs no crash bug: `serve` exits non-zero when an audit-log write fails, so an account that can fill the filesystem holding `/var/log` makes every start fail fast. With no limit, systemd keeps restarting the service and keeps the ports. |
| `Wants=iron-vault-host-unlock.service`, `After=iron-vault-host-unlock.service` (in `[Unit]`) | Every start of the service pulls in the [handoff unit](tpm-unlock.md#at-boot) and waits for it, so a host unlock handoff is on its ramfs, and inside the service's mount namespace, before `serve` runs. `Wants=`, not `Requires=`: a failed unseal fails only the handoff unit, and the service still starts and waits Locked. On a machine with no host unlock blob, the handoff unit's `ConditionPathExists=` skips it. |
| `Type=exec` | The service sends no readiness notification. `exec` makes a start fail when the binary cannot be executed, rather than reporting success. |
| `ExecReload=` | The service reloads its published config on SIGHUP ([config-approval.md](config-approval.md#reload)), so `systemctl reload iron-vault` does that. |
| `User=iron-vault`, `Group=iron-vault` | The service runs under its own account ([§4](iron-vault-specification.md#4-installation-and-ownership)), which is the expected owner the trusted-path checks look for. It is not an admin principal ([§5](iron-vault-specification.md#5-service-and-cli-separation-of-concerns)). |
| `Restart=on-failure` | A crash restarts the service unattended ([§15](iron-vault-specification.md#15-service-states-and-errors)). A clean exit, and a service waiting Locked, are not failures, so neither is restarted. |
| `RestartSec=1` | Paces a restart loop at about one start a second, since no start limit ends it; the default 100 ms would spin. A start that is refused, for example for an untrusted directory, repeats its journal line once a second until the cause is fixed, and the next start after the fix succeeds without an administrator, Locked. `RestartSteps=` and `RestartMaxDelaySec=` would back the loop off further, but they need systemd 254, newer than Debian 12's 252. |
| `LimitCORE=0` | No core dump can hold service memory ([§14](iron-vault-specification.md#14-recipients-startup-and-memory)). The service also sets `RLIMIT_CORE` to 0 and clears `PR_SET_DUMPABLE` itself. |
| `LimitMEMLOCK=infinity` | `hardening.rs` calls `mlockall` only when the `RLIMIT_MEMLOCK` soft limit is unlimited, because locking future mappings under a finite limit makes allocations fail once the service grows past it. A protected install does not unlock without locked memory ([§14](iron-vault-specification.md#14-recipients-startup-and-memory)). Locking needs no capability once the limit allows it. |
| `UMask=0077` | Any file the service creates without an explicit mode is its own alone. Files that need another mode set it explicitly: the log file `0640`, request sockets `0666`. |
| `LogsDirectory=`, `LogsDirectoryMode=0750` | systemd creates `/var/log/iron-vault`, owned by the service account, before each start, and makes it writable under `ProtectSystem=strict` ([log-operations.md](../book/src/reference/log-operations.md)). Without `LogsDirectoryMode=` the mode would be `0755`, which the `LogDir` rule refuses. |
| No `Environment=`, `EnvironmentFile=` or `PassEnvironment=` | The service gets only the environment systemd builds for a unit, never the environment of the administrator who started it. The service does not depend on this: it ignores proxy, trust-root and log-level variables in code ([§10](iron-vault-specification.md#10-outbound-tls-and-environment)). |
| `ProtectSystem=strict`, `ReadWritePaths=` | The whole filesystem is read-only to the service except its config, state and runtime directories and its log directory. `/run` is read-only under `strict` too, so the runtime directory must be listed: the service binds `admin.sock` there. An approved config whose `[logging] destination` names another directory needs a drop-in adding that directory to `ReadWritePaths=`. |
| `ProtectHome=yes` | `/home`, `/root` and `/run/user` are invisible. The service has no reason to read a login account's files. |
| `PrivateDevices=yes` | Only pseudo-devices such as `/dev/null` and `/dev/urandom` are visible. The service uses no device, the TPM included: there is no `DeviceAllow=`. |
| `PrivateTmp=yes` | The service gets its own `/tmp`, which no other account can use to plant files for it. |
| `NoNewPrivileges=yes` | No set-uid program or file capability can raise the service's privileges. |
| `CapabilityBoundingSet=` (empty) | The service needs no capability: it binds no privileged port itself, and memory locking is allowed by the limit. |
| `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` | The service uses Unix sockets and IP, and nothing else, such as netlink or packet sockets. |
| `SystemCallFilter=@system-service` | systemd's set for ordinary services. It includes `mlockall`, `setrlimit` and `prctl`, which process hardening calls. |
| `MemoryDenyWriteExecute=yes` | No memory is both writable and executable. The service generates no code at run time. |
| `WantedBy=multi-user.target` | Enabling the unit starts the service at boot. |

TPM unlock adds no device: the handoff unit unseals as root and the service reads the result from
`/run/iron-vault-unlock` ([tpm-unlock.md](tpm-unlock.md#at-boot)). `PrivateDevices=yes` stays, and `ReadWritePaths=`
does not name `/run/iron-vault-unlock`: the service only reads there.

The handoff unit, `iron-vault-host-unlock.service`, is listed in [tpm-unlock.md](tpm-unlock.md#at-boot). The package
installs it as a plain asset, and `systemd-units`' `unit-name = "iron-vault"` keeps `cargo-deb` from generating
snippets for it. With no `[Install]` section as well, no install or upgrade enables, starts or restarts it; `prerm`
stops it on remove only. It runs as root with no sandboxing directives, which would give it a private mount namespace
and hide its ramfs from the service.

## TPM signing helper

The helper is [the adapter for TPM approval signing](tpm-approval-signer.md#the-helper-process): a separate binary, so
`/usr/bin/iron-vault` never links `libtss2`. The package installs it as `/usr/libexec/iron-vault/iron-vault-tpm-signer`,
built with its `tpm` feature, and two units:

- **`iron-vault-tpm-signer.socket`** listens on `/run/iron-vault-tpm/signer.sock` with `Accept=yes`, `MaxConnections=1`,
  `SocketUser=iron-vault`, `SocketGroup=root` and `SocketMode=0600`: the service account and root, and no group. The
  connection limit is what serialises the helper's reads of the dictionary-attack counter.
- **`iron-vault-tpm-signer@.service`** is started once per connection. It runs as `iron-vault-tpm` with `tss` as a
  supplementary group of the process only, `DevicePolicy=closed` with `DeviceAllow=/dev/tpmrm0 rw`, `RuntimeMaxSec=30`,
  and the hardening list of the design. `StandardInput=socket` hands the helper its connection, and
  `StandardOutput=journal` with `StandardError=inherit` keeps its diagnostics off that connection.

`iron-vault.service` is unchanged: `PrivateDevices=yes` stays and it has no `DeviceAllow=`.

**`Recommends: tpm-udev` (decided).** The helper opens `/dev/tpmrm0` through the `tss` group, and the package does not
create that group ([tpm-approval-signer.md](tpm-approval-signer.md#open-questions), question 5). Ubuntu's `tpm-udev` owns both
the group and the rule that gives it the device (`tss:tss`, `0660`). The `libtss2-esys` and `libtss2-tctildr` packages that
`$auto` adds both `Depend:` on `tpm-udev`, so it is always installed with the package and cannot be declined, and the `tss` group
always exists. `Recommends: tpm-udev` stays so the package states its own need instead of leaning on the library packages'
dependencies. Where the rule does not match the machine's TPM device, the socket still listens, an instance cannot start, and
`approver add --kind tpm` answers `approver-kind-unavailable`.

`cargo-deb` generates snippets for `iron-vault.service` only, so the package's own scripts handle the socket in the form
`dh_installsystemd` uses ([Lifecycle](#lifecycle)). The socket listens on a machine with no TPM as well: its absence would
be a simpler check for the service, but the service already reads the helper's refusal, and one rule for the kind being
offered is easier to review than a second.

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
- **systemd's default trigger limit stays.** While the service is not running, more than 20 connections in 2 s fail
  the socket unit with `trigger-limit-hit`, which closes its port. On Debian 12 (systemd 252) the limit did not fire
  for a service that fails at every start, as in a crash or log-write failure loop: the service waits in
  auto-restart, and connections meanwhile do not count as triggers. It fired only for a service that exits 0 at once,
  because `Restart=on-failure` does not restart a clean exit, so each connection starts it again. `serve` exits 0 only
  on SIGTERM or SIGINT, and sending those over and over takes root or the service account. With
  `TriggerLimitIntervalSec=0` the port stayed held in that case, but systemd started the service 368 times in 10 s,
  and the loop never ends, because the connections stay in the backlog. The template keeps the default: an endless
  busy loop is a worse cost than a released port that only root or the service account can cause.
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
service is already active (`Socket service iron-vault.service already active, refusing`). Every listener socket names
`Service=iron-vault.service`, so stopping the service alone is not enough: a caller connecting to a listener socket that
is still up starts the service again. A new TCP listener therefore needs the existing sockets stopped with the service:

1. Write the drop-in, then `sudo systemctl enable iron-vault-listener@<name>.socket`.
2. `systemctl list-units 'iron-vault-listener@*.socket'` lists the running instances. The listing comes before the
   stop because a stopped instance may be unloaded, and a glob passed to `start` would then match nothing. A listener
   left out stays down, with its port free, until the next boot.
3. `sudo systemctl stop 'iron-vault-listener@*.socket' iron-vault.service`, then `sudo systemctl start` for every
   instance the listing showed, the new one included, then `sudo systemctl start iron-vault` and `sudo iron-vault
   unlock`. The started service holds all the sockets.
4. Approve a config that names the listener. The approval can come before step 3, and its summary then marks the
   listener as taking effect after restart ([config-approval.md](config-approval.md#open-questions), question 2).

The alternative was to keep the plain stop and start and tell the owner to repeat them if systemd refuses. That leaves
the race open and hides it behind a retry. Stopping the sockets is deterministic, at the cost of freeing the existing
ports for a moment, which is the same exposure as [Stopping the service](#stopping-the-service) and is documented there.
An owner can weigh and plan for a known, bounded gap; an intermittent failure gives no such choice.

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

### When systemd releases a port

systemd keeps a listener's port through service restarts and crash loops. It releases the port, so that another local
process can bind it and collect the caller tokens that callers keep sending, only when:

- **a socket unit fails to bind at boot**, for example because another process holds the port, or an address that
  appears after boot has no `FreeBind=yes`. The service never binds a TCP port itself, so the port stays free until
  someone notices;
- **the package is removed**: `prerm` stops the listener sockets ([Remove](#remove)). The vault and config are kept,
  so tokens collected in between stay valid after a reinstall;
- **an administrator stops a listener socket**, as in [Stopping the service](#stopping-the-service);
- **the trigger limit fires** while the service keeps exiting cleanly, which takes root or the service account
  ([above](#listener-socket-units)).

The owner checks `systemctl --failed` after each boot and stops the callers before `apt remove`. If callers kept
sending while a port was free, the owner rotates their tokens: new ones from `iron-vault caller-token`, and an approved
config with the new `token_hash` lines.

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
enables no listener socket unit: the administrator creates those. It does enable and start
`iron-vault-tpm-signer.socket`, unless the administrator disabled it earlier. The service starts Locked with no vault, and
`status` says to run `iron-vault init`. Nothing unlocks it: the service's `Wants=` pulls in the handoff unit, which
`ConditionPathExists=` skips until the administrator provisions a host unlock blob
([tpm-unlock.md](tpm-unlock.md#enrolment-and-retirement)).

### Upgrade

dpkg replaces the files, then `postinst configure` runs `systemd-sysusers` and `systemd-tmpfiles --create` again,
reloads systemd and restarts `iron-vault.service`. The old service keeps running until that restart. The service
comes back Locked, and an interactive-unlock profile waits for `sudo iron-vault unlock`. Listener socket units are
not restarted, so they keep their ports through the upgrade.

The handoff unit is not restarted either: no generated snippet names it, and `prerm` stops it on remove only. The
service's restart finds it active, by `RemainAfterExit=yes`, so the TPM is not used again and the service reads the same
handoff and reaches Ready with no `unlock`, unless the owner [locked it](tpm-unlock.md#lock-across-restarts). A handoff
unit that failed earlier in the boot is started again by the service's `Wants=`, which retries the unseal.

### Remove

The service unit, the listener instances and the handoff unit are taken out of use in different ways.

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

- **The handoff unit** is stopped by the package's own `prerm remove`, in lines after its `#DEBHELPER#` token, so
  after the generated stop of the service. Its `ExecStopPost=` lines remove the unlock handoff and unmount the ramfs,
  so the plaintext identity does not stay in memory once the package is gone. It has no `[Install]` section, so
  there is nothing to disable or mask.

- **The TPM signing socket** is stopped by the package's own `prerm remove`, ahead of the generated stop, and masked by
  `postrm remove`. Instances end within their `RuntimeMaxSec`. Purge runs `deb-systemd-helper purge` and unmasks it.

dpkg then removes the binary, the helpers, the units and the `sysusers.d` and `tmpfiles.d` files. Remove
keeps:

- `/etc/iron-vault`, `/var/lib/iron-vault` and `/var/log/iron-vault`;
- `/etc/iron-vault-host` and the host unlock blob in it, which a reinstall needs to unlock the kept vault again;
- the listener drop-ins under `/etc/systemd/system`;
- the `iron-vault` and `iron-vault-tpm` accounts.

A later install finds the vault and its config where they were and starts Locked, or, on a machine provisioned for TPM
unlock, unlocks it from the kept host unlock blob, as at boot. The administrator enables each
listener socket unit again. The listeners' ports are free in between, and the caller tokens stay valid
([When systemd releases a port](#when-systemd-releases-a-port)). `/run/iron-vault` is on a tmpfs and goes at the
next boot.

### Purge

dpkg removes the conffile `/etc/logrotate.d/iron-vault`, then `postrm purge`:

1. Deletes `/etc/iron-vault` and `/var/log/iron-vault`. The service wrote their contents, so none is a dpkg conffile,
   and dpkg would leave them behind. Debian Policy requires a package to delete configuration it manages outside
   conffiles on purge ([§10.7.3](https://www.debian.org/doc/debian-policy/ch-files.html#behavior)), and its log
   files ([§10.8](https://www.debian.org/doc/debian-policy/ch-files.html#log-files)). Any TLS files the administrator
   put under `/etc/iron-vault` go with it.
2. Deletes the drop-in directories `/etc/systemd/system/iron-vault-listener@*.socket.d`, which configure nothing but
   this package ([open question 1](#open-questions), decided).
3. Asks whether to delete the vault, as below. When the answer deletes `/var/lib/iron-vault`, it also deletes
   `/etc/iron-vault-host`: the host unlock identity sealed there opens only that vault. A kept vault keeps it, because
   a later install needs it to unlock that vault with no one present.
4. Purges the package's debconf entries.

The `iron-vault` and `iron-vault-tpm` accounts stay, as Debian packages' system accounts usually do. A kept vault is owned by it, and
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

## Threats

What this layout leaves to a process running as the service account. Besides the service, the package has root start
two short-lived programs as it: the reload command (`ExecReload=` has no `+` prefix) and logrotate's `gzip` (the rule
has `su iron-vault iron-vault` and `compress`). A compromised service can take either over at Yama `ptrace_scope` 0. In
practice, then, the attacker is code running in the service, a process the service started, or one of those two. §5
treats each of them as the service.

| Threat | Controls here | What remains |
|---|---|---|
| A process running as the service uid replaces `admin.sock` and collects the passphrases the owner types (§5) | None: `/run/iron-vault` is the service account's and listed in `ReadWritePaths=`, because the service binds there. Neither a root-owned admin socket nor a CLI check of the server's pid would stop it: a program `execve`d in place keeps the service's pid and its sockets | Accepted Low residual under §5, which treats anything running as the service uid as the service. A program the service starts, or one of the two above, can capture the passphrases at the local path or through an `ssh -L` forward. No control is built for it: the service already receives every owner input, so the replacement saves an attacker only the work of hooking the running service ([iron-vault-account.md](reviews/iron-vault-account.md), finding 3) |
| A process running as the service uid replaces a Unix request socket (§7) | Other accounts cannot write `/run/iron-vault` | The service uid can, whether the service or a listener socket unit bound the socket; callers would only send it what a compromised service already sees |

## Building and checking the package

`scripts/build-deb.sh` builds the `.deb` with `cargo deb -p iron-vault --no-build` and checks it. It builds `iron-vault` and, with
`--features tpm`, `iron-vault-tpm-signer` itself first, because `cargo-deb` cannot enable a feature of a second package; the
helper needs `libtss2-dev` and `pkg-config` on the build machine. It needs `cargo-deb`
(`cargo install cargo-deb --locked`), `dpkg-deb` and `lintian` (`sudo apt install lintian`). Without `lintian` it exits non-zero;
`IRON_VAULT_SKIP_LINTIAN=1` is the explicit opt-out, and the script then ends with "package checks passed WITHOUT lintian". It fails when:
- the package `Version:` is not the crate version with its first `-` turned into `~` plus the revision `-1`, or still holds a
  `-` before the revision (see below);
- the newest entry of the changelog, `packaging/linux/debian/changelog`, is not that package version, so a version bump
  needs a changelog entry;
- the packaged binary's `--version` lists any feature, so a `dev-mode` package is refused (`scripts/build-deb-test.sh`,
  run in CI, shows this check refusing `dev-mode`, `container` and both);
- a file's owner or mode differs from the [ownership table](#ownership), a path is owned by anyone but root, or
  anything is shipped under `/etc/iron-vault`, `/var/lib/iron-vault`, `/var/log/iron-vault` or `/run/iron-vault`;
- `/usr/bin/iron-vault` links `libtss2`, or the helper does not (it was built without its `tpm` feature);
- the signer socket unit lacks any of the settings above, or the instance unit lacks the account, the supplementary group,
  `StandardInput=socket`, `StandardOutput=journal`, `DevicePolicy=closed`, `RuntimeMaxSec=30` or the hardening list, or has a
  `DeviceAllow=` for anything but `/dev/tpmrm0`;
- `iron-vault.service` lacks the `Wants=` or `After=` line for the handoff unit, has a `DeviceAllow=` line, or has lost
  `PrivateDevices=yes`; or the handoff unit has an `[Install]` section;
- the conffiles are anything but `/etc/logrotate.d/iron-vault`, a maintainer script is missing or not executable, or
  `postinst` names the handoff unit, which would let an install or upgrade start it;
- `lintian --fail-on error` reports an error.

The release workflow (`.github/workflows/release.yml`) runs the script, without the opt-out, for every release and every release
tag: when a release is published, or a tag matching the pattern below is pushed. Pull requests do not run it; `ci.yml`'s
"Release build has no development mode" step is the per-pull-request guard against a packaged `dev-mode` or `container`
build. The workflow's first step, `scripts/check-release-tag.sh`, applies this rule and then checks that the tag without its
`v` equals the `iron-vault` crate version:

```
^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$
```

That is `v`, three numbers without leading zeros, and an optional non-empty pre-release of `[0-9A-Za-z.-]`.
`v0.3.0-alpha` and `v1.12.342-alpha.ubuntu` match; `v1.0`, `v01.2.3`, `v1.0.0-` and `v1.2.3-alpha_1` do not. Git refuses `~` in
a tag name, so the tag is `v0.3.0-alpha` and only the package version is `0.3.0~alpha-1`. The workflow's tag filters are globs
and cannot say all of this, so they only narrow the tags that start a run. `scripts/check-release-tag-test.sh` tests the rule.
The checked `.deb` is uploaded as a workflow artifact, and on a published release it is also attached to the GitHub release.

The script passes `--deb-version` to `cargo deb`. cargo-deb would turn the crate version `0.2.0-alpha` into `0.2.0-alpha-1`,
which dpkg sorts above `0.2.0-1`, so the final release would not upgrade an alpha. Debian writes a pre-release with `~`:
`0.2.0-alpha` becomes `0.2.0~alpha-1`, which sorts below `0.2.0-1`.

The package's own scripts (`packaging/linux/debian/`) use `systemctl` rather than `deb-systemd-invoke` for the listener
instances, because `deb-systemd-invoke` neither disables a unit nor takes a pattern. `prerm` stops the handoff unit
with `systemctl` as well, under the same check for a running systemd.

`scripts/provision-host-unlock-test.sh`, run in CI, tests the provisioning helper with stub tools and no root or TPM:
the release check, the mode argument, the terminal rule of `--server` and `--portable`, the refusal of an existing blob,
each `--portable` check on a fake sysfs, crypttab, `/boot` and `luksDump` output (a check that cannot run must warn), and
the acceptance record.

#### Accepted lintian tags

Lintian 2.117.0ubuntu1.5, run locally on Ubuntu 24.04.5 LTS (2026-11-10), reports no error or warning beyond the three tags
below, which the package overrides. CI's lintian version may differ, since tags change between releases; a new tag it
reports is fixed or added here with its reason. Lintian also prints information-level notes (`hardening-no-fortify-functions`,
`no-md5sums-control-file`, `spelling-error-in-binary` from dependency strings, `systemd-service-file-missing-documentation-key`)
that do not fail the check and are not accepted warnings. `no-manual-page` does not occur: the man pages are packaged.

The package ships these overrides in `/usr/share/lintian/overrides/iron-vault` (source
`packaging/linux/lintian/iron-vault`). Any other error or warning is fixed, not overridden.

| Tag | Level | Why it is accepted |
|---|---|---|
| `no-debconf-config` | error | The only debconf question is the [vault question](#the-vault-question), which `postrm` asks at purge time, as `mariadb-server` does. Nothing is asked at configure time, so there is no `config` script. |
| `maintainer-script-calls-systemctl` (`prerm`) | warning | `prerm` stops and disables the listener socket instances, and `deb-systemd-invoke` neither disables a unit nor takes a pattern (above). On remove it also stops the handoff unit, which has no generated snippets. |
| `initial-upload-closes-no-bugs` | warning | The package is built from this repository and never uploaded to Debian, so its first changelog entry has no ITP bug to close. |

### Checking a real install

`scripts/release/linux-install-check.sh` is the release check for an installed package. It runs as root on a disposable
VM, takes an ordinary test account, and prints a PASS or FAIL line per check. It reads the [ownership table](#ownership)
from this file, then checks the service's account, locked memory, core limit and dumpability, that neither the test
account nor the service account can use the admin socket, that the test account cannot reach `/proc/<pid>/mem`,
`/proc/<pid>/environ` or the vault, that a group-writable `/etc/iron-vault` stops a `systemctl restart` (a reboot would
repair it), that a second `serve` fails on the state lock, and that a listener socket unit keeps its port across a
service restart and stays active through seven crashes, past systemd's default start limit. It refuses to run
without `--i-know-this-is-a-disposable-vm`. The refusal of the group-writable directory is read from the journal,
because the service's startup error goes to stderr.

The script does not run the [account check](#account-and-directories) against `/etc/gshadow`; the fixture tests in
`crates/iron-vault/tests/service/package_account_check.rs` do. To check a real host by hand, read the `iron-vault` line of
`/etc/gshadow`, which should be `iron-vault:!*::` on a package install.

## Admin access

Admin commands run only through `sudo` ([§5](iron-vault-specification.md#5-service-and-cli-separation-of-concerns)). The admin
principal of a protected install is root alone, fixed by the deployment profile. No administrator acts as the service
account, and accepting it would let anything that took over the service lock the vault or spend the owner's passphrase
attempts. `admin.sock` is the service account's with mode `0600`, and the service checks each connection's peer account
before reading anything. The package creates no admin group. Membership of the `iron-vault` group grants no admin
access: the socket's group has no access, and the peer check refuses the account anyway, as it refuses the service
account itself. It does grant read access to the audit log, because `/var/log/iron-vault` is `0750` and
`iron-vault.log` is `0640`, both with the service's group, and anyone who reads the log sees every route, caller and
refusal. Only a log collector's own service account belongs in the group; never add a login account
([log-operations.md](../book/src/reference/log-operations.md#location-and-permissions)).

The owner runs `sudo iron-vault <command>`. The installation guide recommends per-terminal `sudo` credential caching
or none, and a hardware-key factor where the platform supports one.

## Open questions

1. **Purge deletes the listener drop-ins.** *Decided: default accepted (2026-11-09).* [Purge](#purge) step 2 deletes
   `/etc/systemd/system/iron-vault-listener@*.socket.d`. The administrator wrote these files, not the package, and
   the purge contract the owner set names only `/etc/iron-vault`, `/var/log/iron-vault` and the vault. Deleting them
   is the default because they configure nothing once the template unit is gone; the owner should confirm it.
