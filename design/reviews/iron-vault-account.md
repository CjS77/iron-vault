---
title: Admin access for the iron-vault service account in protected and container installations
date: 2026-11-09 11:17
source: 0eb3acc
---

## Investigation Scope

Why does a protected installation accept the service account `iron-vault` as an admin principal, while a container
(Docker Compose) installation refuses it? Does refusing it improve security? Should the two profiles match, and if so,
which way?

## Source scope

Design and code, read only. The source is `0eb3acc`, plus uncommitted edits to §3.2 of
`design/iron-vault-specification.md` made during this review.

- `design/iron-vault-specification.md` §3.2
- `design/docker-compose.md`: Container profile, Service identity, Admin access
- `design/linux-package.md`: Admin access
- `crates/iron-vault/src/admin/principal.rs` and `principal/tests.rs`
- `crates/iron-vault/src/admin/dispatch.rs`, and the admin handlers' use of `require_owner_presence`
- `crates/iron-vault/src/cli/client.rs`
- `packaging/linux/sysusers.d/iron-vault.conf`, `packaging/linux/iron-vault.service`
- `packaging/compose/compose.yaml`, `packaging/compose/Dockerfile`
- `book/src/reference/cli.md`
- Commit history: `70c6520` (the admin principal rule), `4d7c1af` (owner terms), `48ef981` (container profile),
  `251c51b` (spec §3.2 and §3.4 amendments)

## Key findings

### 1. The two profiles' admin principal rules differ for a reason that applies to both (Low)

**Description.** `AdminPrincipals::accepts` accepts uid 0 or the service uid in `Protected`, and only uid 0 in
`Container`. The container's reason is in `docker-compose.md` and in the doc comment on `accepts`. Only the service
runs as that uid, and the account "holds no host login to administer from", so accepting it would grant an
administrator nothing and would admit anything that took over the service.

That reason applies equally to a protected installation:

- `sysusers.d/iron-vault.conf` creates the account with `/usr/sbin/nologin`.
- `iron-vault.service` is the only thing that runs as it.
- Every guide tells administrators to use `sudo`, which arrives as root.
- No script, unit or guide sends an admin command as `iron-vault`. The release checks use `runuser -u iron-vault` only
  to start `serve`.

The protected rule was introduced in `70c6520` and `4d7c1af` with no recorded rationale. It most likely mirrors the
socket's permissions. A `0600` socket owned by the service account admits root and its owner, and the check admitted
the same two. That is consistency, not a security argument.

**Impact.** The service account is an admin principal in a protected installation, with nothing to show it is needed.
One profile's admin principal rule is weaker than the other's for no reason, and the spec has to explain both.

**Examples.** `principal.rs`, the `DeploymentProfile::Protected` arm of `accepts`. `linux-package.md` describes the
admin principals of a protected install as "root and the service account, fixed by the deployment profile" and gives
no reason.

**Recommendations.**

- Make root the only admin principal in a protected installation, matching `Container`. Update:
  - `accepts` and its tests;
  - spec §3.2;
  - the glossary's Admin principal entries;
  - `linux-package.md` (Admin access);
  - `book/src/reference/cli.md`;
  - the comment in `cli/client.rs`.
- Do not take the opposite route of accepting the service account in containers. No administrator can act as that uid
  there, so accepting it only widens access.

### 2. Refusing the service account is minor hardening, not a primary control (Informational)

**Description.** The refusal matters only to an attacker who can run code as the service uid but is not root, for
example through a bug in the request path. That attacker already holds the decrypted credentials in the service's
memory while the vault is unlocked, and owns the vault files and the runtime directory.

Commands that change credentials or policy already require a passphrase:

- `replace`, `rm` and `recipient remove` require owner presence;
- `config approve` requires the approval passphrase.

What the refusal does withhold are the commands that need no owner presence:

- `lock`, and repeated wrong `unlock` attempts. Five failures trip the shared cooldown, which locks the real owner out
  for up to 15 minutes.
- `add`, `list`, `status` and `recipient list`.

**Impact.** Refusing the account prevents a compromised service uid from denying service and from listing credential
and recipient names. It does not prevent credential theft.

**Recommendations.**

- Keep the refusal, and apply it in every protected profile (finding 1). It costs nothing.
- Do not describe it in the spec as protection against a compromised service. Describe it as the rule that no account
  but root administers a protected or container installation.

### 3. The service uid can replace the admin socket (Low, confirmed)

Investigated under K-273 at `0be0b0b`. Spec references here use the current numbering: §5 was §3.2, §7 was §3.4.

**Description.** In protected and container installations, a process running as the service account can unlink
`admin.sock` and bind its own socket at the same path. The CLI then sends that process the owner input for the next
admin command.

*How the CLI reaches the service.* Every client command goes through `run_on` and `exchange` in `cli/client.rs`:

- Without `--admin-socket`, `installation_socket` joins `admin.sock` to the deployment profile's runtime directory.
  That is `/run/iron-vault` in Protected and Container, and `$XDG_RUNTIME_DIR/iron-vault-dev` in Development
  (`deployment.rs`, `protected_paths` and `development_paths`).
- With `--admin-socket PATH`, the CLI uses the path as given.
- `connect` is a plain `UnixStream::connect`. `converse` then sends the admin request and answers each prompt frame
  from the owner console.

The CLI reads no peer credentials, checks no owner or mode on the path, and authenticates nothing. Prompts are the
server's to choose, so a stand-in can ask for any value on any command: the vault passphrase, the approval
passphrase or the recovery key.

*What the service checks.* At bind (`socket_file.rs`), `remove_stale` removes a leftover only when it is a socket the
service account owns. `verify` then requires a socket owned by the service account with mode `0600`. On each of its
own connections, the server checks the peer's uid against the admin principals (`admin/server.rs`,
`admin/principal.rs`). All of these run in the real service, at bind or on connections that reach it. Nothing
watches the path afterwards, and a stand-in has the same owner and mode, so `lstat` cannot tell the two apart.

*Can the service uid unlink and rebind `admin.sock`?*

- **Protected: yes.** `tmpfiles.d/iron-vault.conf` creates `/run/iron-vault` as `iron-vault:iron-vault` `0711`.
  - The owner has write and search permission on the directory, so it may unlink any entry. The directory has no
    sticky bit, and one would not help: the socket's owner is the same account.
  - `ProtectSystem=strict` makes `/run` read-only, but `ReadWritePaths=` lists `/run/iron-vault`. It has to: the
    service removes a stale `admin.sock` and binds there.
  - `SystemCallFilter=@system-service` and `RestrictAddressFamilies=AF_UNIX …` allow `unlink`, `bind` and `listen`,
    because the service makes those same calls.
  - Clearing the directory's write bit would not help either: its owner can `chmod` it back.
- **Container: yes.** The host's `/run/iron-vault` (`iron-vault`, `0711`, from the host `tmpfiles.d`) is bind-mounted
  read-write.
  - `read_only: true` covers only the image's root filesystem, not volumes or bind mounts.
  - `cap_drop: [ALL]` removes nothing the attack needs, because the uid owns the directory. Docker's default seccomp
    profile allows the calls.
  - The host's `sudo iron-vault` connects to the same directory, so it reaches whichever socket was bound there last.
- **Development: yes**, by design: the service runs as the owner, and development mode promises no isolation from the
  owner's own processes (§4).

*Reproduced* unprivileged, in development mode under a temporary directory:

1. `serve` ran and `ping` answered.
2. A Python process running as the same uid unlinked `admin.sock` and bound its own socket there with mode `0600`.
   `ls -li` showed the same owner and mode and a new inode.
3. The stand-in answered the request with one prompt frame, "Vault passphrase".
4. `printf '<passphrase>\n' | iron-vault unlock` sent it the passphrase, which the stand-in recorded. The CLI reported
   only "the service closed the connection without answering".
5. The real service kept running, unreachable at its path.

The same client and bind code runs in every profile. Only the directory's owner differs, and in each profile it is
the account the attacker runs as.

*Who can run as the service uid?*

- **Protected:** the service, and two short-lived programs the package has root start as the uid. The account has no
  login shell or password (`sysusers.d`). Only root can start a process as it (`runuser`, `systemd-run --uid`), and
  root is trusted. The package does so twice:
  - **The reload command.** The unit's `ExecReload=/bin/kill -HUP $MAINPID` has no `+` prefix, so each
    `systemctl reload iron-vault` runs `/bin/kill` as `User=iron-vault`, in the unit's sandbox.
  - **logrotate's compressor.** `/etc/logrotate.d/iron-vault` has `su iron-vault iron-vault` and `compress`. logrotate
    3.21 (Debian 12, Ubuntu 24.04) sets the real and effective ids of its compressor child to the `su` account before it
    execs `gzip` (`switch_user_permanently`, called from `compressLogFile` in `logrotate.c`). That `gzip` runs once a
    day, outside the unit's sandbox and cgroup.

  Neither is the service or a process it started. Apart from them, the attacker is code running in the service, or a
  process it started, which stays in the unit's sandbox and cgroup and is killed when the unit stops.
- **Container:** the service, plus:
  - `docker exec`, plain or with `-u` and the service uid. A shell or `iron-vault` command started that way runs as the
    service uid, and it is not the service or its descendant. Administration needs no such process: the owner runs
    `sudo iron-vault` on the host (`compose-install.md`, Remote administration), and the admin socket refuses a plain
    `docker exec` anyway. A `docker exec` is runtime administration and outside the threat model, but such a process
    is still one the service can take over (below).
  - another container that runs as the uid and mounts the host's `/run/iron-vault`, which the hardening checklist
    forbids.

*Can the service take over such a process?* It shares the uid but is not the service's descendant. `ptrace` attach,
`process_vm_writev` and a write to `/proc/<pid>/mem` all need ptrace access to it. The uid matches, the target is
dumpable, and it holds no capability the service lacks, so Yama's `ptrace_scope` decides:

- At 0, access is allowed. A service taken over can rewrite the process's memory and make it `execve` any program.
- At 1 or more, it is refused, because the process is not the service's descendant.
- Ubuntu sets 1 in `/etc/sysctl.d/10-ptrace.conf` (shipped by `procps`; read on an Ubuntu 24.04 host). Debian's kernel
  is believed to leave Yama at 0 unless an administrator raises it; this was not checked on a Debian machine. The value
  is the host's, so it applies inside containers too.
- System call filters close only part of this. In Protected, `SystemCallFilter=@system-service` denies `ptrace` (in
  `@debug`) but allows `process_vm_readv` and `process_vm_writev` (in `@ipc`; read with `systemd-analyze syscall-filter`,
  systemd 255). Docker's default profile allows all three on kernels from 4.8. No filter can tell a write to
  `/proc/<pid>/mem` from any other `openat` and `pwrite64`.

The window is as long as the process runs: a moment for `kill`, a few seconds for `gzip`. A service taken over can
poll `/proc` for it.

**Impact.** Smaller than the investigation assumed. A compromised service already receives every owner input sent to
the real admin socket, and can send any prompt itself. Passphrases typed while it is compromised are lost with or
without the replacement. The replacement adds two things:

- **Capture from a separate process.** The service clears `PR_SET_DUMPABLE`, so a process it starts cannot read its
  memory. Replacing the socket gets that process the passphrases anyway. Under `MemoryDenyWriteExecute=yes`, starting
  such a process with one `execve` is a much simpler payload than hooking the running service. An `execve` in place,
  with no fork, also keeps the service's pid (the unit's `MainPID` in Protected, PID 1 in Container) and inherits every
  file descriptor not marked close-on-exec, which code in the service can clear on its listening sockets. To every
  check by pid, and on every socket the service holds, the new program is the service.
- **Every owner command goes to the stand-in**, `lock` included, which it can acknowledge without locking anything.
  A compromised service can lie the same way.

The code did not meet §5, which then said: "The CLI must send owner input only to the service. No other process,
including one running as the service account, may serve at the admin socket's path or otherwise stand in for the
service."

*Other paths in `/run/iron-vault`.* The runtime directory holds only `admin.sock` and Unix request sockets
(`serve.rs`, `request_listeners.rs`). The service uid can replace a request socket the same way, whether the service
bound it or a listener socket unit did. systemd keeps its socket open, but the path then names the stand-in. Callers
would send it their caller tokens and request bodies. A compromised service sees those anyway, and a caller has no
way to authenticate the server of a Unix socket, so this needs no action. TCP listeners have no path to replace. In
Protected, systemd holds each port. In Container, the service binds its listeners in its own network namespace.

*Fixes compared.* Each fix is judged against the payload the Impact names: code in the service that starts a program,
either with an in-place `execve` or as a child it hands a socket to.

| Fix | Protected | Container | `ssh -L` forward | Cost |
|---|---|---|---|---|
| A. A socket unit binds `admin.sock` in a root-owned directory and passes it to the service | Not closed. The service uid can no longer unlink the path, but the service holds the listening socket systemd passed it. Code in the service clears `FD_CLOEXEC` on it and `execve`s a program in place, or passes it to a process it starts; that program accepts the owner's connections on the real socket | Not possible: Docker cannot pass a socket into a container, and without `CAP_DAC_OVERRIDE` the service cannot bind in a root-owned directory | Not closed, for the same reason: `sshd` reaches the root-owned path, and whatever holds the socket answers | A new socket unit and admin socket path; the service adopts its admin socket. A connection to it starts a stopped service, as a listener socket unit already does |
| B. The CLI checks the listening process from `SO_PEERCRED` before it sends anything | Not closed. On the client end `SO_PEERCRED` gives the server's credentials as they were at `listen` (unix(7)), and a pid survives `execve`. A program `execve`d in place keeps `MainPID`, then unlinks `admin.sock`, binds and listens there, and passes. So does a socket the service itself binds at the path and hands to a child: the CLI sees the service's pid. Reading `MainPID` from systemd and the peer from `SO_PEERPIDFD` would not change this | Not closed, the same way: the program `execve`d in place stays PID 1 of the container | Not covered: the CLI's peer is the local `ssh`, and `sshd` on the server connects without checking | Client only, at one choke point (`exchange`). Conflicts with A: on a socket systemd bound, the listener is systemd (pid 1, uid 0), so B as described would refuse the real service |
| C. Once started, the service denies itself `execve` and `execveat` with a seccomp filter | Closed once the reload command runs as root (`ExecReload=+…`) and logrotate starts no compressor as the uid. The service then starts no program, and no process with its uid is anything but the service or a fork of it, which runs the service's own code with a copy of its memory and already receives every owner input. Until both changes, it holds only at Yama `ptrace_scope` 1 or more | Closed while nobody `docker exec`s into the container as the service uid, or at `ptrace_scope` 1 or more | Covered as far as the profile it forwards to: whatever answers at the path is the service or a fork of it | A dependency and a small filter at startup; `ExecReload=+` and no log compression in the package; hardware adapters may not be child processes. See below |
| A key pinned at `init` | No help: the key must work while the service is Locked, so it would sit in the state directory, which the service uid reads | Same | — | Ruled out |
| A check of `/proc/<pid>/exe` and the uid | No help: a process the service started can `execve` `/usr/bin/iron-vault` with `LD_PRELOAD` | Same | — | Ruled out |
| A separate admin socket directory | Becomes A: the service creates the socket, so a directory it cannot write needs a socket unit | Same as A | — | Not a separate fix |

The two bypasses of A and B were reproduced unprivileged, with a temporary directory. A process listened on one socket,
left it inheritable and `execve`d a second program in place, which bound and listened on another path. The second
program reported the first one's pid. A client connecting to either socket read that pid from `SO_PEERCRED`, and the
second program accepted on both.

*Fix C in detail.* The service starts no process: no non-test code uses `std::process::Command`, `tokio::process` or
an exec call. So it can give up `execve` and `execveat` once it is running, and nothing it does today is lost.

- **systemd cannot apply it.** systemd loads a unit's `SystemCallFilter=` in the process that is about to exec the
  service binary, just before it does. systemd.exec(5) (systemd 255) says `execve` is implicitly allow-listed, and
  "access to the execve() system call is required for the execution of the service binary — if it is blocked service
  invocation will necessarily fail". Checked with systemd 255: under
  `systemd-run --user -p SystemCallFilter=~execve /bin/true`, systemd's executor is killed by `SIGSYS` before
  `/bin/true` runs. `~execveat` starts it, but denying `execveat` alone leaves `execve` open. Docker's seccomp profile
  has the same limit, because the runtime loads it just before it execs the entrypoint.
- **So the filter is in-process,** called from `harden_process` (`hardening.rs`), implemented in `hardening/linux.rs`.
  - The workspace forbids `unsafe` code. rustix 1.1 exposes only seccomp's strict mode, not filter mode, and calling
    `prctl` or `seccomp` through `libc` needs `unsafe`. A crate is therefore needed. `seccompiler` 0.5 (rust-vmm,
    Apache-2.0 OR BSD-3-Clause) builds and installs the BPF program, and its only required dependency is `libc`, which
    is already in the lock tree. The `libseccomp` crate would link the C library instead.
  - Seccomp filter mode needs `no_new_privs` or `CAP_SYS_ADMIN`. Both profiles already set `no_new_privs`
    (`NoNewPrivileges=yes`, `no-new-privileges:true`), and Development can set it without privilege.
  - A filter applies to the thread that installs it and to threads started afterwards. `harden_process` runs on the
    main thread before any other thread starts, before the logger and before `serve::run` builds the tokio runtime,
    whose blocking pool starts threads on demand. Installed there, every later thread inherits it. Installed any later,
    it needs `SECCOMP_FILTER_FLAG_TSYNC` to cover threads already running.
  - The filter must also refuse other system call ABIs. On x86_64, the i386 `execve` has another number, and x32
    numbers carry bit `0x40000000`. The unit does not set `SystemCallArchitectures=native`, and Docker's default
    profile admits the x86 and x32 ABIs.
  - A denied call kills the process (`SECCOMP_RET_KILL_PROCESS`) rather than failing with `EPERM`. The service never
    makes these calls, so one means its code is compromised. Killing it ends the compromise and drops the vault
    identity from memory. The unit (`Restart=on-failure`) or Compose (`restart: unless-stopped`) restarts it Locked,
    and the `SIGSYS` exit is in the journal or the container's state.
  - The filter should also deny `ptrace`, `process_vm_readv` and `process_vm_writev`. The service never uses them, and
    in Container and Development nothing else denies them; in Protected `process_vm_*` are allowed (above). They are
    three more numbers in the same filter. They do not close `/proc/<pid>/mem`, so fix C still needs the package
    changes below in Protected, and no `docker exec` as the uid in Container.
  - If the filter fails to install, the gap is open. That is reported in the hardening report, `status` and the
    startup audit record, as the core-dump result is, and the service still serves. Refusing the admin socket would
    lock the owner out over a Low gap. A failure also means a bug rather than a platform: `SystemCallFilter=` and
    Docker's default profile already need seccomp filter mode on every host the two profiles support.
- **What it needs from the package.** In Protected, two programs started as the uid must go:
  - `ExecReload=+/bin/kill -HUP $MAINPID`. The `+` prefix runs the reload command as root, outside the sandbox, so it
    no longer runs as the uid. The unit file, and the unit listing and directive table in `linux-package.md`
    (Service unit), change with it.
  - The logrotate rule stops compressing: `compress` and `delaycompress` come out, so logrotate only renames, under
    `su`, and starts no child. Thirty daily files stay uncompressed. The rule appears in `audit-logging.md` (The
    shipped rule) and `log-operations.md`. An owner who keeps compression relies on `ptrace_scope` 1 or more.
- **What it rules out.** Planned work needs no exec in the service, except one adapter that is still only a lead:
  - The host-side signing helper (K-255) runs on the host. The service reaches it over a Unix socket.
  - The host unlock runs `systemd-creds` on the host, not in the container.
  - EP-32 (TPM recipient) and EP-33 (TPM approval signer) name `tss-esapi`/`tpm2-tss` (spec, platform table), a
    library that talks to `/dev/tpmrm0` from inside the process.
  - EP-32 and `implementation-specification.md` also name `age-plugin-tpm` as a lead. An `age` plugin is a separate
    program that `age` runs as a child process, so fix C rules that adapter out. The same holds for
    `age-plugin-yubikey` (`future-specifications.md` §2.1). Hardware adapters would run in the service, or as host-side
    helpers reached over a socket, never as child processes of the service.
- **What it leaves.**
  - Code inside the service can unlink `admin.sock` and bind its own listener there, with no exec at all. That is the
    service itself, which already receives every owner input.
  - Root can still start a process as the uid, and a `docker exec` as the uid is such a process (above). The service
    can take it over at `ptrace_scope` 0.
  - A fork of the service can still serve at the path. It is the service's own code with a copy of the service's
    memory, so it gains nothing the service lacks. Denying process creation too (`fork`, `vfork`, `clone` without
    `CLONE_THREAD`, and `clone3`, which must fail with `ENOSYS` so the C library falls back to `clone` for threads)
    would stop the service starting any process at all, at the price of a larger filter.

**Recommendations.**

- Do not build fix A or fix B. Neither closes the gap: an in-place `execve` keeps the service's pid and its sockets.
  They also conflict with each other.
- Fix C is the review's recommendation, for the owner to decide. It is the only fix compared that closes the gap, and
  it covers Protected, Container and the `ssh -L` forward. In Container it holds while nobody `docker exec`s in as the
  service uid. It needs no change to the CLI or the Compose file. Its costs:
  - one dependency (`seccompiler`) and a small filter at startup;
  - in the package, `ExecReload=+/bin/kill -HUP $MAINPID` and a logrotate rule without compression, with the matching
    text in `linux-package.md` (Service unit), `audit-logging.md` and `log-operations.md`;
  - a design rule that the service never starts a program, which rules out `age` plugins as hardware adapters.
- The alternative is no product fix. The gap stays Low: a compromised service already receives every passphrase typed
  while it runs. What the attacker saves is the work of hooking the running service.
- **Owner decision.** §5 then said no other process, "including one running as the service account", may serve at the
  admin socket's path or stand in for the service. Can anything short of stopping the service from starting processes
  meet that? The review finds nothing. Whatever owns the path or the socket, and whatever the CLI checks, a program the
  service starts inherits the service's pid or its sockets. So either:
  - build fix C with its package changes, and §5 holds in outcome, in Container while nobody `docker exec`s in as the
    service uid. A fork of the service can still serve at the path, so it holds literally only if the filter also
    denies process creation; or
  - build nothing, and reword §5 to what holds: no account but the service account can serve at the admin socket's
    path, and anything running as the service account is treated as the service, because the service already
    receives every owner input.
- No action for request sockets.

### 4. Spec §3.2's container text described mechanism, not outcomes (Low)

**Description.** The container sentence in §3.2 ("the forwarding process's uid as the container's user namespace
maps it…") stated a mechanism and left the requirement implicit. "Forwarding process" meant `sshd`, which the text
did not say. During this review it was rewritten as an outcome first: only root on the host may administer a container
installation, and taking over the service or a shell in its container gives no administrative access. A list of what
is accepted and refused follows. The mechanism (`sshd` connecting as the login account, `CAP_DAC_OVERRIDE` being
dropped) stays in `docker-compose.md`.

The rewritten bullet says the requirement holds "with or without user-namespace remapping". `docker-compose.md`,
however, lists `userns-remap` and rootless Docker as unsupported, because under remapping host root arrives as uid
65534 and admin access is impossible.

**Impact.** The old text could not be checked against an implementation. The new remapping clause contradicts the
compose design.

**Recommendations.**

- Replace "This holds with or without user-namespace remapping" with a statement that user-namespace remapping and
  rootless runtimes are unsupported, citing `docker-compose.md`.
- Once finding 1 is resolved, replace the parenthetical "(A protected installation does accept the service account.)"
  with the unified rule.

### Background: what `CAP_DAC_OVERRIDE` is

Every Linux file carries permissions saying who may read and write it, such as "only `iron-vault` may open this". These
are discretionary access control (DAC). Linux splits root's powers into separate capabilities, and `CAP_DAC_OVERRIDE`
is the one that lets a process ignore those file permissions. It is how `sudo iron-vault unlock` on the host opens
`admin.sock`, although the socket is `0600` and owned by `iron-vault`. The Compose file drops every capability
(`cap_drop: [ALL]`). Root inside the container (`docker exec -u 0`) therefore lacks it, and the socket's permissions
refuse root as they would refuse any other account.

## Actions taken

- **Finding 1:** ticket K-272 (EP-35). A protected installation will refuse the service account, so root is the only
  admin principal in both protected and container installations. The ticket covers `AdminPrincipals::accepts`, its
  tests, spec §3.2, the glossary, `linux-package.md`, `docker-compose.md`, the manual, a release check, and the macOS
  epic's scope (EP-36). The Windows epic's admin rule (EP-37) is flagged for the owner.
- **Finding 2:** no separate action. K-272 applies the refusal to every protected profile, and its spec wording will
  state the rule as an outcome rather than as protection against a compromised service.
- **Finding 3:** confirmed by the K-273 investigation, which also lowered it from Medium to Low.
  - The replacement works in Protected and Container, and was reproduced unprivileged in Development.
  - The threat tables in `linux-package.md` and `docker-compose.md` list it as an accepted Low residual.
  - Owner decision, 2026-11-10: no product fix. Fixes A, B and C are not built. Ticket K-286 (EP-35) reworded §5 to
    what holds: no account but the service account may serve at the admin socket's path, and anything running as the
    service account is treated as the service.
- **Finding 4:** open. The remapping clause in §3.2 (line 118) still contradicts `docker-compose.md`. The service
  account parenthetical will be replaced under K-272.
