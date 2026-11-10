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

- **Protected:** nothing but the service. The account has no login shell or password (`sysusers.d`). Only root can
  start a process as it (`runuser`, `systemd-run --uid`), and root is trusted. The attacker is therefore code running
  in the service, or a process it started, which stays in the unit's sandbox and cgroup and is killed when the unit
  stops.
- **Container:** the same, plus:
  - `docker exec`, which is runtime administration and outside the threat model;
  - another container that runs as the uid and mounts the host's `/run/iron-vault`, which the hardening checklist
    forbids.

**Impact.** Smaller than the investigation assumed. A compromised service already receives every owner input sent to
the real admin socket, and can send any prompt itself. Passphrases typed while it is compromised are lost with or
without the replacement. The replacement adds two things:

- **Capture from a separate process.** The service clears `PR_SET_DUMPABLE`, so a process it starts cannot read its
  memory. Replacing the socket gets that process the passphrases anyway. Under `MemoryDenyWriteExecute=yes`, starting
  such a process with one `execve` is a much simpler payload than hooking the running service.
- **Every owner command goes to the stand-in**, `lock` included, which it can acknowledge without locking anything.
  A compromised service can lie the same way.

The code does not meet §5, which says: "The CLI must send owner input only to the service. No other process,
including one running as the service account, may serve at the admin socket's path or otherwise stand in for the
service."

*Other paths in `/run/iron-vault`.* The runtime directory holds only `admin.sock` and Unix request sockets
(`serve.rs`, `request_listeners.rs`). The service uid can replace a request socket the same way, whether the service
bound it or a listener socket unit did. systemd keeps its socket open, but the path then names the stand-in. Callers
would send it their caller tokens and request bodies. A compromised service sees those anyway, and a caller has no
way to authenticate the server of a Unix socket, so this needs no action. TCP listeners have no path to replace. In
Protected, systemd holds each port. In Container, the service binds its listeners in its own network namespace.

*Fixes compared.*

| Fix | Protected | Container | `ssh -L` forward | Cost |
|---|---|---|---|---|
| A. A socket unit binds `admin.sock` in a root-owned directory and passes it to the service | Closed: neither file permissions nor `ProtectSystem=strict` let the service uid unlink there | Not possible: Docker cannot pass a socket into a container, and without `CAP_DAC_OVERRIDE` the service cannot bind in a root-owned directory | Covered: `sshd` connects to the root-owned path | A new socket unit and admin socket path; the service adopts its admin socket. A connection to it starts a stopped service, as a listener socket unit already does |
| B. The CLI checks the listening process from `SO_PEERCRED` before it sends anything | Closed: the server's pid must be `iron-vault.service`'s `MainPID`, and a process the service started has another pid | Closed: the server must be PID 1 of its own PID namespace, with its parent in the CLI's namespace, and no other process in the container is | Not covered: the CLI's peer is the local `ssh`, and `sshd` on the server connects without checking | Client only, at one choke point (`exchange`); no service or packaging change |
| A key pinned at `init` | No help: the key must work while the service is Locked, so it would sit in the state directory, which the service uid reads | Same | — | Ruled out |
| A check of `/proc/<pid>/exe` and the uid | No help: a process the service started can `execve` `/usr/bin/iron-vault` with `LD_PRELOAD` | Same | — | Ruled out |
| A separate admin socket directory | Becomes A: the service creates the socket, so a directory it cannot write needs a socket unit | Same as A | — | Not a separate fix |

**Recommendations.**

- Build fix B. It closes the gap in both profiles at one point in the CLI and needs no change to the service, the
  package or the Compose file.
  - The `ssh -L` forward stays exposed. The default remote form, `ssh -t … sudo iron-vault`, runs the CLI on the
    server and is covered.
  - Fix A could be added later for Protected, if the forward must be covered too.
- **Owner decision.** Fix B meets §5's first sentence and its "or otherwise stand in for the service": the CLI no
  longer treats a stand-in as the service. It does not stop another process from serving at the path, as the second
  sentence literally requires. Only fix A does that, and only in Protected. Either reword §5 to the outcome, or treat
  fix A as required for Protected.
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
  - The threat tables in `linux-package.md` and `docker-compose.md` now list it.
  - Ticket K-286 (EP-35) builds fix B: the CLI refuses a server that is not the service's own process.
  - Open for the owner: whether §5's "may serve at the admin socket's path" needs rewording, or fix A in Protected.
- **Finding 4:** open. The remapping clause in §3.2 (line 118) still contradicts `docker-compose.md`. The service
  account parenthetical will be replaced under K-272.
