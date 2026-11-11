# Reset

How `iron-vault reset` deliberately discards a vault, so the owner can build a new one with `iron-vault init` and
re-add credentials reissued by their providers
([§16](iron-vault-specification.md#16-administration-recovery-and-migration)). It is the way out when every owner
way in is lost: no vault passphrase or recovery key opens the vault, no approver can
[answer](approval-signers.md#when-no-approver-can-answer), or the service is Unavailable in a
[recovery row](config-approval.md#open-questions) that nothing else repairs. Terms follow the
[glossary](glossary.md); the initialization state it reads and the files it removes are those of
[vault-initialization.md](vault-initialization.md#initialization-state).

Two failures matter most. A reset that runs by mistake destroys the only copy of the owner's credentials, and a reset
that half-runs must never leave something that opens. A gate too weak would turn `reset` into a way to deny the owner
service; a gate too strong would lock out the owner who needs it, because the people who run `reset` have lost the
factors a strong gate would ask for. Five rules follow:

- **Only an admin principal can reset, and only after typing a confirmation at a terminal.** The confirmation is the
  vault ID, or the state directory's path when there is no Initialized vault. No owner factor is asked: see
  [Authorization](#authorization).
- **The vault stops serving before any file goes.** Reset uses `lock`'s withdrawal: requests are refused and in-flight
  ones cancelled before the first removal.
- **One durable write is the commit point.** The unfinished-reset file `reset.unfinished` is durable before the first
  removal and removed last, so a crash anywhere in between leaves a state that every command refuses except `reset`
  itself.
- **Reset removes only store-owned files, and all of them.** The active config goes with its signatures: reset is a
  clean start, and the owner rebuilds from their own copy. Reset never removes a foreign file, the lock files, the
  audit log, an administrator's TLS files or anything outside the state and config directories.
- **Reset adds no service state and no edge.** It runs in Locked, Ready and Unavailable, and leaves the service Locked
  over an Uninitialized directory, where `init` runs as on a fresh install.

The store already has the pieces: the [initialization state](vault-initialization.md#initialization-state) and its
`classify` and `survey`, `durable_remove`, `durable_replace`, the stale-temp sweep, and the discard of an unfinished
initialization. The binary owns the confirmation, the service state gate, the withdrawal and the service-wide lock, as
it does for `lock` and `init`. The owner's decisions on the points the specification left open are under
[Owner decisions](#owner-decisions).

## What reset is not

- **Not secure erasure.** Removal unlinks files; the filesystem, an SSD or a snapshot may keep their blocks. The
  files are encrypted, but under recipients the old owner held: a disk image plus the old vault passphrase or recovery
  key opens them.
- **Not revocation.** Copies of the old vault in backups still open with the old recovery key and vault passphrase.
  If any copy, key or passphrase may have leaked, the owner rotates the credentials at their providers, as
  [§16](iron-vault-specification.md#16-administration-recovery-and-migration) says of a lost machine.
- **Not a recovery path.** Nothing the old vault held can be recovered through `reset`. While any way in still works,
  `recovery check`, `recipient add --recovery`, `approver add` or `export` keep the vault; reset discards it.
- **Not TPM clearing.** Reset touches only files in the state and config directories. Clearing a retired TPM is
  `forget-machine`'s guidance ([§16](iron-vault-specification.md#16-administration-recovery-and-migration)).

## Authorization

Reset needs an admin principal on the admin socket
([§5](iron-vault-specification.md#5-service-and-cli-separation-of-concerns)) and a **reset confirmation**: the owner
types, at a terminal, the confirmation text shown in the reset summary. No vault passphrase, recovery key or approval
passphrase is asked, even when one would still answer. §5 makes `reset` the one destructive operation that needs no
owner approval, under §16's "explicit owner or administrator action" ([decision 1](#owner-decisions)).

Why no owner factor:

- **The factors are what is lost.** Reset exists for an owner who can no longer give the vault passphrase, the
  recovery key or an approval passphrase. A gate that asked for any of them would be closed exactly when it is needed;
  a gate that asked for one "when available" adds nothing, since the person running it decides what is available.
- **The admin principal can already delete the files.** root in a protected or container install, and the service's
  own user in development, can remove the state directory with `rm`, as a package [purge](linux-package.md#purge) that
  is told to delete the vault does. Reset gives an admin principal no power it lacks, so it is not a new way to deny
  service: it is the same deletion, done in the right order, with the vault withdrawn first, the audit log told and a
  crash recoverable.
- **A vault passphrase prompt would feed the attempt limit.** An owner who no longer knows the passphrase would be
  locked out of `unlock` for longer by each guess, for nothing.

What the confirmation guards against is a mistake: a reset typed on the wrong machine, in the wrong terminal, or run
by a script that pipes `yes` into whatever asks. Typing the confirmation text back at a terminal proves a person read
the summary for this vault.

### The confirmation text

The confirmation text depends on the [initialization state](#states) read at step 1:

- **Initialized:** the vault ID, hyphenated (`8-4-4-4-12` hex digits), compared ASCII case-insensitively, since hex
  digits have no case.
- **Every other state reset proceeds on** (Unfinished, Unfinished reset, Unrecognized with a vault file): the state
  directory's absolute path, compared exactly, byte for byte, since Linux paths are case-sensitive.

The CLI strips only the line ending, and the service trims nothing. A vault ID names one vault and changes when a new
one is made; a path names a directory, whatever is in it. So the vault ID is used only where it names what will be
discarded, and [step 4](#the-exchange) checks that the initialization state is still the one the summary described.

The vault ID comes from the [MAC'd file frame](storage-formats.md#macd-file-frame) header of `manifest.age`, which
holds it in clear at bytes 5 to 21, so it is known while the vault is locked. It is **unverified** unless the vault
is open: nothing checks the MAC without the vault identity. That is enough for a confirmation, which only has to name
which vault the owner meant. In Ready the service takes the vault ID from the open vault and calls it verified.

### Typed at a terminal

The confirmation is accepted only when typed at a terminal ([decision 5](#owner-decisions)). Before it sends the
request, the CLI checks that stdin is a terminal and that it can open `/dev/tty`. If either fails, it reports on stderr
that reset's confirmation must be typed at a terminal, naming which check failed, and exits with code 3 without
connecting, so the service takes no lock, writes nothing and records nothing. `yes | iron-vault reset`,
`echo <vault ID> | iron-vault reset`, a heredoc, `< /dev/null` and a cron job are all refused this way. With stdin a
terminal, the CLI reads the confirmation from `/dev/tty` with echo on, as any non-secret prompt is read under the
[owner input](admin-protocol.md#owner-input) rules.

The service cannot see where an answer came from, so this is the CLI's rule, as `init`'s terminal check is
([admin-protocol.md](admin-protocol.md#init-1)). It stops the shipped CLI being driven by a pipe. A program that speaks
the admin protocol itself runs as an admin principal, which could delete the files anyway.

## States

Reset is allowed in Locked, Ready and Unavailable, with either reason. In Starting, Checking and Stopped the exchange
ends with `wrong-state` before any prompt. A new admin operation, `AdminOperation::Reset`, maps the command onto the
service state gate, and `admin_allows` offers it in those three states.

- **From Ready and Unavailable** reset fires the existing explicit lock event, `ServiceEvent::Lock`, which
  [§15](iron-vault-specification.md#15-service-states-and-errors) draws from both to Locked.
- **From Locked** there is no transition; reset runs under the same locks.
- **It ends Locked**, as `lock` and `init` do, over an Uninitialized directory, or Unrecognized when a foreign file
  stays. The owner then runs `init`, or `import`.

[§15](iron-vault-specification.md#15-service-states-and-errors) needs no new state or edge.

Reset also reads the initialization state, without the vault identity. A **vault file** here is a store-owned file in
the state directory other than the recovery check record, the owner-lock file and stale temp files. None of them alone
is a vault: `recovery.toml` is the record of a vault already gone, and `init` removes it
([recovery.md](recovery.md#initialization)); the owner-lock file says only that the owner locked; and a temp file is a
write that never landed, which check 3 already lets an Uninitialized directory hold. Reset proceeds on:

| Initialization state | What reset does | Confirmation text |
|---|---|---|
| Initialized | discards the vault | the vault ID |
| Unfinished, by an initialization | discards the unfinished initialization, its initial config included | the state directory's path |
| Unfinished, by an [import](#interactions) | discards the unfinished import, its record files and its copy of `config.toml` included | the state directory's path |
| Unfinished reset | finishes the interrupted reset | the state directory's path |
| Unrecognized, with at least one vault file | discards every store-owned file and keeps the foreign ones; the summary names what stays | the state directory's path |
| Uninitialized | ends with `nothing-to-reset`; the message says to run `init` | none |
| Unrecognized, with no vault file | ends with `nothing-to-reset`; the message names the first file that is there and says to move it aside before `init` | none |

Every state reset proceeds on takes the same path: the [exchange](#the-exchange) below, with `reset.unfinished` as its
commit point and the one [removal order](#removal-order). In Unfinished it removes the same files `init`'s or
`import`'s discard would, and the config files with them whatever their bytes, so an unfinished initialization or
import needs no path of its own. A config file beside a state directory with no vault file is the owner's file waiting
for an `init`, not a vault, so reset leaves it.

### Unfinished reset

A new initialization state, checked before every other:

0. **`reset.unfinished` is present.** The state is Unfinished reset, whatever else the directories hold.

Checks 1 to 4 of [vault-initialization.md](vault-initialization.md#initialization-state) follow unchanged, and that
document lists check 0 with them. A new file, not `init.unfinished`, because the two mean opposite things: `init.unfinished` says files
are being added and lets `init` remove only what an init writes, while a vault being reset holds record files, the
staged inventory and several approver key envelopes. Beside `init.unfinished` they would read Unrecognized and strand
the owner. Checked first, `reset.unfinished` decides the state whatever `init.unfinished` or `import.unfinished` lies
beside it.

In Unfinished reset:

- `unlock` ends with `unlock-failed` before any prompt; the message says a reset was interrupted and to run
  `iron-vault reset` again. Host unlock at startup ([docker-compose.md](docker-compose.md)), and with K-319 the TPM
  unlock of a protected install, refuses it too, as it refuses anything but Initialized.
- `init` and `import` end with `already-initialized` before any prompt; the message says a reset was interrupted and
  to run `iron-vault reset` again. Until the manifest is gone the directory may hold an intact vault that has served,
  and only a confirmed reset removes such a vault; `init`'s and `import`'s discards are for vaults that never opened.
- `recovery check` ends with `recovery-check-unavailable`, naming the state.
- `status` reports, in tag 12 (initialization), a new value meaning "reset unfinished (run iron-vault reset again)";
  the value is 3 (command 21, error codes 49 `nothing-to-reset` and 50 `reset-failed`;
  see [admin-protocol.md](admin-protocol.md#reset)).
- **Startup does not finish it.** The service starts Locked, as always, and waits for an admin principal to run
  `reset` again ([decision 4](#owner-decisions)). A reset finished at startup would have no principal to record,
  and a service that deletes files on its own at boot is one wrong classification away from destroying a vault.

## The exchange

The CLI first checks for a [terminal](#typed-at-a-terminal) and sends nothing without one. After the admin request,
which carries no arguments, in order:

1. **Check.** The service checks its state (`wrong-state` otherwise), reads the initialization state
   (`nothing-to-reset` as in the [table](#states)) and computes the confirmation text. Nothing is locked.
2. **Summary.** A notice, line by line:
   - what will be discarded: "the vault `<vault ID>`" (marked unverified unless the vault is open), "the unfinished
     initialization", "the unfinished import and its `<n>` record files", "the files of an interrupted reset", or
     "vault files with no Initialized vault";
   - the service state, and that the service stops serving at once and stays Locked;
   - the credentials that go with it: in Ready, their names, as `list` shows them; otherwise the count of
     `record-*.age` files, marked unverified, since only the manifest says which records are live;
   - that the config files go too: `config.toml`, its signature and any pending config, each named when present;
   - each foreign file reset leaves, and that `init` will refuse until it is moved aside;
   - that nothing can be recovered afterwards, and that the owner rebuilds from their own copy of the config and of
     the `iron-vault list` output, with credentials reissued by their providers: keep both before going on;
   - that copies in backups still open with the old recovery key and vault passphrase, so rotate at the provider any
     credential that may have leaked, and that removal is not secure erasure.
3. **Confirmation.** The prompt `Type <the confirmation text> to discard this vault` (`to discard these files` when
   the text is the path), not secret. Any other answer ends with `declined`. Nothing is written before this point, and
   a prompt that gets no answer, a cancelled CLI or a closed connection ends the exchange with the directories exactly
   as they were.
4. **Withdraw.** The service announces a lock request, which cancels an approval or a vault change waiting at a prompt
   as `lock` does, and waits for the [service-wide lock](glossary.md). It then takes the service context's mutex and
   checks again:
   - the service state, which a concurrent `lock` or `unlock` may have changed (`wrong-state` if it is no longer one
     reset allows);
   - the initialization state: Uninitialized, which a concurrent reset leaves, ends with `nothing-to-reset`; any other
     state that is not the one step 1 read, or an Initialized vault whose vault ID is not the one step 1 read, ends
     with `declined`, naming the change. An `init` past its step 5, or an import, holds a manifest while it writes, and
     step 1 read it as Unfinished; if it finished in between, step 4 reads Initialized and removes nothing.

   From here the service-wide lock is held to the end, and every store writer takes it, so nothing changes the
   directories under reset. Then, from Ready or Unavailable, it fires `ServiceEvent::Lock`: the request gate closes,
   the serving snapshot is withdrawn (cancelling in-flight requests), the open vault, the approval state and the
   context's copy of the vault identity are dropped, and the [migration challenge](glossary.md) is retired, exactly as
   `lock`'s withdrawal does. From Locked there is nothing to withdraw. The service then releases the context's mutex,
   so `status` answers during the discard, and keeps the service-wide lock. The withdrawal is `lock`'s but for the
   [owner-lock file](#interactions): the write of `locked-by-owner` belongs to K-338, and until it lands reset does
   not write it (it removes the file in step 6 either way).
5. **Begin.** The service records `vault.reset-confirmed`, then writes `reset.unfinished` with `durable_replace`.
   That write is the commit point. A failed write ends with `reset-failed`, naming the step `begin`; a failed log
   write stops the service, as every failed audit write does. Either way the service is Locked and no file has been
   removed. A write that fails before its rename leaves the directories as they were. One whose rename lands but whose
   state directory fsync fails leaves `reset.unfinished` visible over the intact vault, which then reads Unfinished
   reset, refused by every command but `reset`, until the next `reset` finishes it; this fails closed.
6. **Discard.** With the mutex already released and the service-wide lock still held, it runs the
   [removal order](#removal-order), in one blocking call that also does the step 5 write, and ends with `reset-failed`, naming the step and file, on the first failure.
7. **Finish.** It removes `reset.unfinished` with `durable_remove`. If the unlink lands but the state directory's
   fsync fails, the run still succeeds, with a warning that `reset.unfinished` may come back after a power loss. It can
   only come back over a directory holding no vault file: `init`'s and `import`'s first write is their own unfinished
   file, with `durable_replace`, whose state directory fsync makes the earlier unlink durable before either writes a
   vault file. A `reset.unfinished` that comes back reads Unfinished reset over an empty vault, and the next reset
   removes it ([crash table](#crash-table)). The service then clears the
   [passphrase attempt limit](migration-authorization.md#passphrase-attempt-limit), since the passphrase it counted
   guesses against is gone, records `vault.reset`, and releases the service-wide lock.
8. **Drain and result.** It waits for the [lock drain](glossary.md), as `lock` does, and answers with the
   [result](#result).

Once the confirmation is in, no prompt remains, so a cancel or a lost connection no longer stops the service: steps 4
to 8 run to the end in a task the service owns, as an unlock's config check does.

**Locking.** The summary and the confirmation hold no lock, so `status` and requests run while the owner reads. Step 4
waits for the service-wide lock rather than failing with `busy`, as `lock` does: the announcement has cancelled
everything that holds it at a prompt, and the rest (a config check, a vault write past its prompts, an `init` or
`import` writing its vault) holds it for seconds. Every store writer takes the service-wide lock, so while reset holds
it no `add`, approval, recipient or approver change, `init`, `import` or recovery check record write interleaves. An
`unlock` waiting for the lock reads the initialization state under it, finds Uninitialized or Unfinished reset, and
ends with `unlock-failed`. Steps 5 to 7 take about as long as `init`'s writes: one durable write and up to a few dozen
durable removes, more on a vault with many records, well inside the CLI's 60-second timeout.

## Removal order

The **store-owned files** are the names the store writes:

- in the state directory: `identity.age`, `operational.age`, `manifest.age`, `approval.age`, `recipients.age`,
  `recipients.age.staged`, every approver key envelope `approver-<approver ID>.age`, every record file
  `record-<record ID>.age`, `init.unfinished`, `import.unfinished` (K-307), `reset.unfinished`, the owner-lock file
  `locked-by-owner` (K-338), the recovery check record `recovery.toml`, and the stale temp file `.<name>.tmp` of each;
- in the config directory: `config.toml`, `config.toml.sig`, `config.toml.pending`, `config.toml.sig.staged`, and
  the stale temp file of each.

The lock files (`lock`, `config.toml.lock`), `lost+found` and every other name are not store-owned. The store holds
this list in one place, which the initialization state, every discard (`init`'s and `import`'s) and reset share. A
later design that adds a state file adds it to the list, and reset removes it with no change of its own.

Under the service-wide lock, after `reset.unfinished` is durable:

1. **`manifest.age`**, with `durable_remove`. From here no binary opens the vault: without the manifest the
   initialization state is never Initialized. A release that predates reset reads `reset.unfinished` as a foreign
   file; before this step it reads Initialized ("whatever else is there") and can open the whole, intact vault, which
   is not a half-open one, and from this step on it reads Unrecognized.
2. **The rest of the state directory's store-owned files**, each with `durable_remove`, in this order:
   `identity.age`, `operational.age`, `recipients.age`, `recipients.age.staged`, the approver key envelopes, then
   `approval.age`, the record files, `recovery.toml` (as [recovery.md](recovery.md#initialization) asks of a discard),
   `init.unfinished`, `import.unfinished`, the owner-lock file `locked-by-owner`, and the stale temp files. The
   identity envelope goes first so a crash leaves no file that a recovery key opens.
3. **The config directory**, each with an unlink and then the config directory's fsync: `config.toml.sig` and
   `config.toml.sig.staged`, then `config.toml.pending` and `config.toml`, then the stale temp files. Signatures go
   before configs, as in `init`'s [discard](vault-initialization.md#discarding-an-unfinished-initialization).
4. **`reset.unfinished`**, at [step 7](#the-exchange).

Each removal tolerates a file that is already gone, so a rerun after a crash resumes wherever the last run stopped.
A file that cannot be removed (a permission change, an I/O error) stops the run with `reset-failed`;
`reset.unfinished` stays, and the next reset resumes. Reset never follows a symlink or descends into a directory: a
store-owned name that is not a regular file stops the run with `reset-failed`, naming it, for the administrator to
inspect.

**Why the config goes.** Reset is a clean start ([decision 2](#owner-decisions)). An approved config always comes
from an unsigned copy the owner keeps elsewhere, so a copy exists outside the config directory, and the summary tells
the owner to keep it. The signatures name the old vault ID and the old approver and could never verify again. Once
the credentials are reissued and added, the owner approves their copy with `config approve`. `init`'s discard removes
only an initial config, because its state test proves every config file there is its own; reset removes the config
files whatever their bytes, because the admin principal confirmed it.

**Counters.** Removing `approval.age` discards the approval counters.
[§12](iron-vault-specification.md#12-configuration-approval-and-reload) says never to reset a version "on restart or
signing-key replacement", and to initialize the highest reserved version to zero "only when creating a new vault"; it
also says `iron-vault reset` discards a vault with its approval state, and that the `init` after it creates a new
vault, which starts at zero ([decision 3](#owner-decisions)). No old approval can replay into the new vault: its
payload names the old vault ID and its signature is the old approver key's, and the new vault has a new ID and a new
approver.

## Crash table

What each command does after a crash, or any failure, in each step. A crash inside a step leaves the state of the row
before it or of its own row, because each durable write or remove is whole or absent.

| Last step durable | Initialization state | Service after restart | `unlock` | `reset` again | `init` and `import` |
|---|---|---|---|---|---|
| none (before `begin`) | as before the reset | Locked | as before the reset: Initialized opens | starts over from the summary | as before the reset |
| `begin`: `reset.unfinished` written | Unfinished reset | Locked | `unlock-failed`: reset interrupted | summary of an interrupted reset, then resumes | `already-initialized`: reset interrupted |
| any removal | Unfinished reset | Locked | as the row above | as the row above | as the row above |
| `finish`: `reset.unfinished` unlinked, the directory fsync failed, then a power loss before any `init` or `import` | Unfinished reset if it came back, over directories with no store-owned file; else Uninitialized, or Unrecognized with a foreign file | Locked | `unlock-failed`: reset interrupted, or not initialized | removes `reset.unfinished` again | `already-initialized`: reset interrupted, if it came back; else proceeds. Once `init` or `import` has begun it cannot come back: their first write's directory fsync makes the unlink durable |
| `finish`: `reset.unfinished` removed | Uninitialized, or Unrecognized with a foreign file | Locked | `unlock-failed`: not initialized | `nothing-to-reset` | proceeds, or refuses naming the foreign file |

A failure without a crash (`reset-failed`) leaves the same row with the service still running and Locked. A failure at
`begin` leaves the `none` row, unless the rename of `reset.unfinished` landed and only the state directory's fsync
failed: then the file is visible and the `begin` row applies, Unfinished reset over the intact vault, until the next
`reset` finishes it.

## Result

The success result carries the vault ID that was confirmed (empty when the confirmation was the state directory's
path), the number of files removed, the foreign files left, whether the lock drain cleared the vault identity (as
`lock`'s result does), and whether the removal of `reset.unfinished` is uncertain. The CLI prints them, then the next
step: `iron-vault init`. The command ID (21), the error codes (49 and 50) and the status value (3) are the next free numbers in
[admin-protocol.md](admin-protocol.md) after those [migration-bundle.md](migration-bundle.md) reserves (commands 19 and 20,
codes 45 to 48).

| Error | When |
|---|---|
| `wrong-state` (existing) | Starting, Checking or Stopped, at step 1 or step 4 |
| `declined` (existing) | the confirmation does not match, at step 3; or the initialization state, or the vault ID, changed by step 4 |
| `nothing-to-reset` (new) | no vault file is there, at step 1 or step 4; the message says what to run next |
| `reset-failed` (new) | writing `reset.unfinished` or a removal failed; the message names the step and the file, and says whether the vault is intact (`begin`) or the next reset resumes (every later step) |

The CLI's own refusal when there is no terminal is not a service error: it is reported on stderr with exit code 3, and
no request is sent.

## Logging

These are audit events in the [audit log](audit-logging.md#audit-events). The log directory is never inside the state
or config directory, and `lock` does not move it, so the log reaches every event a reset raises.

| Event | Level | When | Fields |
|---|---|---|---|
| `vault.reset-confirmed` | WARN | step 5, before `reset.unfinished` is written | the vault ID when the state was Initialized (`vault_id`), whether it is verified, the initialization state, the service state reset started from (`from_state`), whether this resumes an interrupted reset |
| `vault.reset` | WARN | step 7, `reset.unfinished` removed | `vault_id`, the store-owned file names removed (`files`), the foreign files kept, each escaped with `display::escaped` as `vault.foreign-file` escapes its `file`, whether the removal of `reset.unfinished` is uncertain |
| `vault.reset-failed` | WARN | any failure from step 5 on | the step (`begin`, `remove`, `finish`), the file name, the error's fixed kind label (`error_kind`), the names removed before it |

`vault.reset-confirmed` is written before `reset.unfinished` so that a log write failure, which stops the service,
stops it with the vault intact. A refusal before step 5 (`wrong-state`, `declined`, `nothing-to-reset`) records only
the admin server's `admin.command` event: the principal and the command. The CLI's terminal refusal sends no request,
so it records nothing. The lock event from Ready or Unavailable raises the existing `service.lock-transition`. No
event carries a secret, a typed confirmation or any file's contents.

## Interactions

- **Init** ([vault-initialization.md](vault-initialization.md)). Its initialization state gains check 0 and its
  list of names gains `reset.unfinished`. Its discard and reset share the store-owned list; init's discard still
  removes only what an init or an import writes.
- **Migration bundle** (K-307). `import` refuses an Initialized vault ("must not overwrite an initialized vault
  implicitly", [§16](iron-vault-specification.md#16-administration-recovery-and-migration)), so `reset` is the
  explicit clear before an import onto a used machine. Its unfinished-import file `import.unfinished` is store-owned,
  and `reset.unfinished` is checked before it. Reset discards an unfinished import like any Unfinished vault, record
  files and the bundle's `config.toml` included; the bundle and the source still hold both. Import refuses Unfinished
  reset with `already-initialized` and says to run `reset` again, as `init` does. An export waiting at its prompts is
  cancelled by reset's lock request, and its challenge retired. After a reset, `import` writes the bundle's
  `config.toml` without a signature, and the owner approves it as after any import; `import --host-unlock` enrols
  this machine's host unlock identity as `init --host-unlock` does. Bundles live outside the state and config
  directories and reset never touches them.
- **Host unlock and TPM unlock** ([docker-compose.md](docker-compose.md); K-319). On Linux, TPM unlock is host
  unlock, and none of it is in the state directory: the sealed credential is `/etc/iron-vault-host/host-unlock.cred`,
  the unlock handoff is on the ramfs at `/run/iron-vault-unlock/host-unlock`, a failed unseal leaves a root-owned file
  in `/run/iron-vault-unlock`, and the only persistent TPM handle is the storage root key that `systemd-creds` shares
  with every other credential on the machine. Reset leaves all of it alone. Startup over an Uninitialized directory
  with a handoff refuses the handoff and stays Locked, and a new `init --host-unlock` or `import --host-unlock` enrols
  the same host unlock identity again.
- **The owner-lock file `locked-by-owner`** (K-338). `lock` writes it in the state directory so that a crash or reboot
  does not undo an explicit lock: while it exists, host unlock at startup is skipped, and a passphrase `unlock` clears
  it. It is store-owned and reset removes it with the other state files, so a new vault starts without it. Reset's
  withdrawal is `lock`'s, so from Ready or Unavailable it writes the file as `lock` does, and a reset that fails at
  `begin` leaves the vault locked as `lock` would.
- **Linux package** ([linux-package.md](linux-package.md)). Purge still removes the directories by hand; reset is
  for keeping the installation and replacing the vault.

## Release checks

Added to the v0 release checks by K-318, each on a real service:

1. Reset from Ready, Locked, Unavailable(`PolicyInvalid`) and Unavailable(`RecoveryNeeded`) ends Locked over an
   Uninitialized directory with no config file; `init` then makes a vault with a new vault ID, and a copy of the old
   `config.toml` and `config.toml.sig`, saved aside before the reset and put back, is refused by the new vault.
2. A wrong confirmation, `yes`, an empty line, a vault ID typed for an Unfinished vault, a cancelled CLI and a closed
   connection each leave every file as it was.
3. With stdin a pipe, a file or `/dev/null`, and with no controlling terminal, the CLI exits with code 3 before
   connecting: the audit log has no `admin.command` for it and every file is as it was.
4. A vault whose every approver is unusable is reset and rebuilt from the owner's copy of the config and re-added
   credentials.
5. A crash injected before each removal leaves Unfinished reset; `unlock`, `init` and `import` refuse it, `status`
   reports the unfinished-reset value, and `reset` finishes it. A `reset.unfinished` put back over empty directories
   reads Unfinished reset, and the next reset removes it.
6. No request is admitted after step 4; requests in flight are cancelled as `lock` cancels them; and the result
   reports whether the vault identity was cleared.
7. A foreign file in the state directory survives and is named, escaped, in the summary, the result and `vault.reset`.
8. Uninitialized, and a config file alone, end with `nothing-to-reset`.
9. A pending migration challenge does not survive a reset, and the passphrase attempt limit is cleared.
10. Each of these makes the reset end with `declined` at step 4, removing nothing: an `init` that starts after the
    summary and finishes before step 4; an `init` past its step 5 (manifest written) at the summary that finishes
    before step 4; an import writing at the summary that finishes before step 4.
11. Reset of an Unfinished initialization and of an unfinished import, each confirmed with the state directory's
    path, leaves Uninitialized, record files and `config.toml` removed.
12. The three audit events reach the log, and none holds a secret or the typed confirmation.

## Owner decisions

The specification left each point below open, or its wording conflicted with this design. The owner decided each on
2026-11-11.

1. **No owner factor.** *Decided: the default stands.* An admin principal and the typed confirmation, with no vault
   passphrase, recovery key or approval passphrase, because the owner who resets has lost them and the admin principal
   can already delete the files. [§5](iron-vault-specification.md#5-service-and-cli-separation-of-concerns) said
   "Destructive and policy-changing operations require owner approval"; it now names `reset` as the exception, which
   [§16](iron-vault-specification.md#16-administration-recovery-and-migration) allows on "explicit owner or
   administrator action" alone.
2. **The active config is deleted.** *Decided.* Reset removes `config.toml` with its signatures and any pending
   config, and keeps no copy. In the owner's words: "Configs always come from unsigned copies somewhere else, so there
   will be a copy somewhere. Also sticks to the philosophy that a reset = clean start." The summary reminds the owner
   to keep their own copy of the config and of the `list` output.
3. **Counters are discarded.** *Decided: the default stands, and §12 now says so.*
   [§12](iron-vault-specification.md#12-configuration-approval-and-reload) forbade resetting a version "on restart or
   signing-key replacement" and starts at zero "only when creating a new vault", which assumed one vault's contiguous
   operation. It now also says that `iron-vault reset` discards a vault with its approval state, and that the `init`
   after it creates a new vault, which starts at zero. This is the reading `init`'s discard already takes
   ([vault-initialization.md open question 2](vault-initialization.md#open-questions)).
4. **Startup does not finish an interrupted reset.** *Decided: the default stands.* The service starts Locked in
   Unfinished reset and waits for an admin principal to run `reset` again; only `reset` finishes it.
5. **The confirmation is typed at a terminal.** *Decided.* The CLI refuses before connecting when stdin is not a
   terminal or there is no controlling terminal, so reset cannot be scripted through the CLI
   ([Typed at a terminal](#typed-at-a-terminal)).

## Implementation tickets

Each ticket updates the design documents and glossary entries it changes, in the same branch as its code.

| Order | Ticket | What | Depends on | Updates |
|---|---|---|---|---|
| 1 | K-316 | Store: `reset.unfinished` and the Unfinished reset initialization state (check 0 in `classify` and `survey`, refusals in `ensure_unlockable` and `begin_initialization`); the one store-owned file list, shared with init's discard and, when it lands, K-307's ticket 5; an unverified read of the vault ID from the manifest header and a count of record files; `discard_vault` in the [removal order](#removal-order), with fault-injection tests at every unlink and directory fsync | K-315 | vault-initialization.md "Initialization state" (check 0) and its list of names; storage-formats.md, an "Unfinished reset file" section; glossary "Initialization state", "Store-owned file" and "Unfinished reset" (Rust types) |
| 2 | K-317 | `iron-vault reset`: the CLI's terminal check, `AdminOperation::Reset`, the summary and confirmation, the step-4 re-check, the lock-first withdrawal, the task the service owns after the confirmation, the attempt-limit clear, error codes `nothing-to-reset` and `reset-failed`, the status value and the three audit events | K-316 | admin-protocol.md (command, error codes, status tag 12 value, the CLI's `reset`); audit-logging.md (`vault.reset-confirmed`, `vault.reset`, `vault.reset-failed`); glossary "Reset" and "Reset confirmation" (Rust types); the manual's CLI, errors, states and audit log references |
| 3 | K-318 | Reset release checks 1 to 12 in `crates/iron-vault/tests/reset_linux.rs`, and the manual: a reset recipe (what to keep first: a copy of the config and the `list` output), `start-over.md`, `approval-signers.md`, `security-model.md` | K-317 | README features; the manual's roadmap index and `SUMMARY.md` |
| 4 | K-327 | `iron-vault forget-machine`, with its own design section | K-319, K-321, K-318 | its own design section |
