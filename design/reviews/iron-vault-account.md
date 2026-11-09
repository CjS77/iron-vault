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

### 3. The service uid may be able to replace the admin socket (Medium, unconfirmed)

**Description.** The service account owns `/run/iron-vault` (`0711`) in both profiles, so a process running as that
uid can unlink `admin.sock` and bind its own. A fake socket would be owned by the service account, so ownership alone
cannot tell it from the real one. The server checks its own socket with `lstat` at bind (`admin-protocol.md`, Binding).
This review found no check in `cli/client.rs` that authenticates the server to the CLI, but did not trace the CLI's
whole connect path.

**Impact.** If confirmed, an attacker running as the service uid could put up a fake admin socket. They could then
collect the vault passphrase and approval passphrase the next time root runs `unlock`, `config approve`, `replace` or
`rm`. That is a larger gain than anything finding 2 withholds, and refusing the service account on the admin socket
does not prevent it.

**Recommendations.**

- Confirm or rule out the gap by tracing how the CLI finds and checks `admin.sock`.
- If confirmed, open a ticket so that the service uid cannot replace its own admin socket. Options include:
  - a root-owned runtime directory or socket, created by `tmpfiles.d` or systemd socket activation;
  - having the CLI authenticate the server before it sends owner input.

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
- **Finding 3:** ticket K-273 (EP-35), an investigation. Writing it found that `cli/client.rs` `connect` is a plain
  `UnixStream::connect` with no check of the server, which strengthens the finding but does not yet confirm it. K-273
  is to confirm or rule out the replacement in each profile, recommend a fix, and record the outcome here.
- **Finding 4:** open. The remapping clause in §3.2 (line 118) still contradicts `docker-compose.md`. The service
  account parenthetical will be replaced under K-272.
