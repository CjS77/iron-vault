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

- **Only an admin principal can reset, and only after typing the vault ID back.** No owner factor is asked: see
  [Authorization](#authorization).
- **The vault stops serving before any file goes.** Reset uses `lock`'s withdrawal: requests are refused and in-flight
  ones cancelled before the first removal.
- **One durable write is the commit point.** The marker `reset.unfinished` is durable before the first removal and
  removed last, so a crash anywhere in between leaves a state that every command refuses except `reset` itself.
- **Reset removes only store-owned files.** It never removes a foreign file, the lock files, the audit log, an
  administrator's TLS files or anything outside the state and config directories. It keeps the active config, renamed,
  as the list to rebuild from.
- **Reset adds no service state and no edge.** It runs in Locked, Ready and Unavailable, and leaves the service Locked
  over an Uninitialized directory, where `init` runs as on a fresh install.

The store already has the pieces: the [initialization state](vault-initialization.md#initialization-state) and its
`classify` and `survey`, `durable_remove`, the config directory's durable rename (`rename_staged`, which publishing
uses), the stale-temp sweep, and the discard of an unfinished initialization. The binary owns the confirmation, the
service state gate, the withdrawal and the service-wide lock, as it does for `lock` and `init`. Every default this
design picks where the specification is silent, or where it departs from the specification's wording, is listed under
[Open questions](#open-questions).

## What reset is not

- **Not secure erasure.** Removal unlinks files; the filesystem, an SSD or a snapshot may keep their blocks. The
  files are encrypted, but under recipients the old owner held: a disk image plus the old vault passphrase or recovery
  key opens them.
- **Not revocation.** Copies of the old vault in backups still open with the old recovery key and vault passphrase.
  If any copy, key or passphrase may have leaked, the owner rotates the credentials at their providers, as
  [§16](iron-vault-specification.md#16-administration-recovery-and-migration) says of a lost machine.
- **Not a recovery path.** Nothing the old vault held can be recovered through `reset`. While any way in still works,
  `recovery check`, `recipient add --recovery`, `approver add` or `export` keep the vault; reset discards it.
- **Not TPM clearing.** Reset touches only files. Clearing a retired TPM is `forget-machine`'s guidance
  ([§16](iron-vault-specification.md#16-administration-recovery-and-migration)).

## Authorization

Reset needs an admin principal on the admin socket
([§5](iron-vault-specification.md#5-service-and-cli-separation-of-concerns)) and a **reset confirmation**: the owner
types the vault ID shown in the reset summary. No vault passphrase, recovery key or approval passphrase is asked,
even when one would still answer.

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

What the confirmation guards against is a mistake: a reset typed on the wrong machine, in the wrong terminal, or by a
script that pipes `yes` into whatever asks. Typing the vault ID back proves the owner read the summary for this
vault. [§5](iron-vault-specification.md#5-service-and-cli-separation-of-concerns) says destructive operations require
owner approval, and [§16](iron-vault-specification.md#16-administration-recovery-and-migration) asks reset for
"explicit owner or administrator action"; this design reads reset under §16's wording
([open question 1](#open-questions)).

### The confirmation text

The confirmation text is the vault ID, hyphenated (`8-4-4-4-12` hex digits), when the state directory holds
`manifest.age` and its header reads. Otherwise, when no manifest is there or its header does not read, it is the state
directory's absolute path. The comparison is ASCII case-insensitive; the CLI strips only the line ending, and the
service trims nothing.

The vault ID comes from the [MAC'd file frame](storage-formats.md#macd-file-frame) header of `manifest.age`, which
holds it in clear at bytes 5 to 21, so it is known while the vault is locked. It is **unverified** unless the vault
is open: nothing checks the MAC without the vault identity. That is enough for a confirmation, which only has to name
which directory the owner meant. In Ready the service takes the vault ID from the open vault and calls it verified.

The confirmation is read like any other [owner input](admin-protocol.md#owner-input-kind-3): from the terminal, or the
next line of stdin when stdin is not a terminal ([open question 5](#open-questions)). A script that knows the vault ID
can reset; one that only answers `yes` cannot.

## States

Reset is allowed in Locked, Ready and Unavailable, with either reason. In Starting, Checking and Stopped the exchange
ends with `wrong-state` before any prompt. A new admin operation, `AdminOperation::Reset`, maps the command onto the
service state gate, and `admin_allows` offers it in those three states.

- **From Ready and Unavailable** reset fires the existing explicit lock event, `ServiceEvent::Lock`, which
  [§15](iron-vault-specification.md#15-service-states-and-errors) draws from both to Locked.
- **From Locked** there is no transition; reset runs under the same locks.
- **It ends Locked**, as `lock` and `init` do, over an Uninitialized directory (or Unrecognized, when a foreign file
  stayed). The owner then runs `init`.

[§15](iron-vault-specification.md#15-service-states-and-errors) needs no new state or edge.

Reset also reads the initialization state, without the vault identity. It proceeds on:

| Initialization state | What reset does |
|---|---|
| Initialized | discards the vault |
| Unfinished | discards the unfinished initialization, as `init` would, and leaves Uninitialized |
| Unfinished reset | finishes the interrupted reset |
| Unrecognized, with at least one vault file | discards the vault files and keeps the rest; the summary names what stays |
| Uninitialized | ends with `nothing-to-reset`; the message says to run `init` |
| Unrecognized, with no vault file | ends with `nothing-to-reset`; the message names the first file that is there and says to move it aside before `init` |

A **vault file** here is a store-owned file other than the recovery check record: `recovery.toml` alone is the record
of a vault already gone, and `init` removes it ([recovery.md](recovery.md#initialization)). A config file beside an
empty state directory is the owner's file waiting for an `init`, not a vault, so reset leaves it.

### Unfinished reset

A new initialization state, checked before every other:

0. **`reset.unfinished` is present.** The state is Unfinished reset, whatever else the directories hold.

Checks 1 to 4 of [vault-initialization.md](vault-initialization.md#initialization-state) follow unchanged. A new
marker, not `init.unfinished`, because the two mean opposite things: `init.unfinished` says files are being added and
lets `init` remove only what an init writes, while a vault being reset holds record files, the staged inventory and
several approver key envelopes, which `init` must never sweep up. Beside `init.unfinished` they would read
Unrecognized and strand the owner.

In Unfinished reset:

- `unlock` ends with `unlock-failed` before any prompt; the message says a reset was interrupted and to run
  `iron-vault reset` again. Every other way from Locked into Checking, such as host unlock
  ([docker-compose.md](docker-compose.md)) or a later TPM unlock, refuses it too, as they refuse anything but
  Initialized.
- `init` ends with `already-initialized` before any prompt; the message says a reset was interrupted and to run
  `iron-vault reset` again. Init keeps its rule that it never removes what it did not write.
- `recovery check` ends with `recovery-check-unavailable`, naming the state.
- `status` reports tag 12 (initialization) as `3`, "reset unfinished (run iron-vault reset again)".
- **Startup does not finish it.** The service starts Locked, as always, and waits for an admin principal to run
  `reset` again ([open question 4](#open-questions)). A reset finished at startup would have no principal to record,
  and a service that deletes files on its own at boot is one wrong classification away from destroying a vault.

## The exchange

After the admin request, which carries no arguments, in order:

1. **Check.** The service checks its state (`wrong-state` otherwise) and reads the initialization state
   (`nothing-to-reset` as in the [table](#states)). Nothing is locked.
2. **Summary.** A notice, line by line:
   - what will be discarded: "the vault `<vault ID>`" (marked unverified unless the vault is open), or "the unfinished
     initialization", or "the files of an interrupted reset", or "vault files with no manifest";
   - the service state, and that the service stops serving at once and stays Locked;
   - the credentials that go with it: in Ready, their names, as `list` shows them; otherwise the count of
     `record-*.age` files, marked unverified, since only the manifest says which records are live;
   - the config files that go, and that `config.toml`, when there is one, is kept as `config.toml.before-reset`;
   - each foreign file reset leaves, and that `init` will refuse until it is moved aside;
   - that nothing can be recovered afterwards; that the owner rebuilds from their copy of the approved config and
     `iron-vault list`, with credentials reissued by their providers;
   - that copies in backups still open with the old recovery key and vault passphrase, so rotate at the provider any
     credential that may have leaked, and that removal is not secure erasure.
3. **Confirmation.** The prompt `Type <the confirmation text> to discard this vault`, not secret. Any other answer
   ends with `declined`. Nothing is written before this point, and a prompt that gets no answer, a cancelled CLI or a
   closed connection ends the exchange with the directories exactly as they were.
4. **Withdraw.** The service announces a lock request, which cancels an approval or a vault change waiting at a prompt
   as `lock` does, and waits for the [service-wide lock](glossary.md). It then takes the service context's mutex and
   checks again:
   - the service state, which a concurrent `lock` or `unlock` may have changed (`wrong-state` if it is no longer one
     reset allows);
   - the initialization state (`nothing-to-reset` if a concurrent reset finished first);
   - the confirmation, against the text computed again now. A concurrent `init` that finished a new vault has a new
     vault ID, so the typed one no longer matches and the exchange ends with `declined`, naming the change.

   Then, from Ready or Unavailable, it fires `ServiceEvent::Lock`: the request gate closes, the serving snapshot is
   withdrawn (cancelling in-flight requests), the open vault, the approval state and the context's copy of the vault
   identity are dropped, and the [migration challenge](glossary.md) is retired, exactly as `lock`'s withdrawal does.
   From Locked there is nothing to withdraw.
5. **Commit.** The service records `vault.reset-confirmed`, then writes `reset.unfinished` with a durable replace.
   That write is the commit point. A failed marker write ends with `reset-failed`, naming the step `marker`; a failed
   log write stops the service, as every failed audit write does. Either way the directories are as they were before
   the reset, and the service is Locked.
6. **Discard.** It releases the context's mutex, so `status` can answer, and keeps the service-wide lock. It runs the
   [removal order](#removal-order) and ends with `reset-failed`, naming the step and file, on the first failure.
7. **Finish.** It durably removes `reset.unfinished`. A failure of the directory fsync after the unlink is reported as
   success with a warning that the marker may come back after a power failure; a marker that comes back reads
   Unfinished reset, and the next reset removes it again. It then clears the
   [passphrase attempt limit](migration-authorization.md#passphrase-attempt-limit), since the passphrase it counted
   guesses against is gone, records `vault.reset`, and releases the service-wide lock.
8. **Drain and result.** It waits for the [lock drain](glossary.md), as `lock` does, and answers with the
   [result](#result).

Once the confirmation is in, no prompt remains, so a cancel or a lost connection no longer stops the service: steps 4
to 8 run to the end in a task the service owns, as an unlock's config check does.

**Locking.** The summary and the confirmation hold no lock, so `status` and requests run while the owner reads. Step 4
waits for the service-wide lock rather than failing with `busy`, as `lock` does: the announcement has cancelled
everything that holds it at a prompt, and the rest (a config check, a vault write past its prompts, an `init` writing
its vault) holds it for seconds. Every store writer takes the service-wide lock, so while reset holds it no `add`,
approval, recipient or approver change, `init` or recovery check record write interleaves. An `unlock` waiting for the
lock reads the initialization state under it, finds Uninitialized or Unfinished reset, and ends with `unlock-failed`.
Steps 5 to 7 take about as long as `init`'s writes: one durable write and up to a few dozen durable removes, well
inside the CLI's 60-second timeout.

## Removal order

The **store-owned files** are the names the store writes:

- in the state directory: `identity.age`, `operational.age`, `manifest.age`, `approval.age`, `recipients.age`,
  `recipients.age.staged`, every approver key envelope `approver-<approver ID>.age`, every record file
  `record-<record ID>.age`, `init.unfinished`, `reset.unfinished`, the recovery check record `recovery.toml`, and the
  stale temp file `.<name>.tmp` of each;
- in the config directory: `config.toml`, `config.toml.sig`, `config.toml.pending`, `config.toml.sig.staged`, and
  the stale temp file of each.

The lock files (`lock`, `config.toml.lock`), `lost+found`, `config.toml.before-reset` and every other name are not
store-owned. The store holds this list in one place, which the initialization state, `init`'s discard and reset share.
A later design that adds a state file (an import marker, a TPM-sealed blob) adds it to the list, and reset removes it
with no change of its own.

Under the service-wide lock, after the marker is durable:

1. **`manifest.age`**, with `durable_remove`. From here no binary opens the vault: without the manifest the
   initialization state is never Initialized, and a release that predates reset reads `reset.unfinished` as a foreign
   file in a directory with no manifest, which is Unrecognized.
2. **The rest of the state directory's store-owned files**, each with `durable_remove`, in this order:
   `identity.age`, `operational.age`, `recipients.age`, `recipients.age.staged`, the approver key envelopes, then
   `approval.age`, the record files, `recovery.toml` (as [recovery.md](recovery.md#initialization) asks of a discard),
   `init.unfinished`, and the stale temp files. The identity envelope goes first so a crash leaves no file that a
   recovery key opens.
3. **The config directory**, each durably: `config.toml.sig`, `config.toml.sig.staged`, then `config.toml.pending`,
   then `config.toml` renamed to `config.toml.before-reset` with a durable rename, replacing one an earlier reset left.
   Signatures go first, as in `init`'s [discard](vault-initialization.md#discarding-an-unfinished-initialization).
4. **`reset.unfinished`**, at [step 7](#the-exchange).

Each removal tolerates a file that is already gone, so a rerun after a crash resumes wherever the last run stopped.
A file that cannot be removed (a permission change, an I/O error) stops the run with `reset-failed`; the marker stays,
and the next reset resumes. Reset never follows a symlink or descends into a directory: a store-owned name that is
not a regular file stops the run with `reset-failed`, naming it, for the administrator to inspect.

**Why the active config is kept.** The approved config names every routed credential, its upstream and its callers,
and [§16](iron-vault-specification.md#16-administration-recovery-and-migration) makes the owner's copy of it the list
to rebuild from. The copy in the config directory may be the only one left, and it holds no secret: caller tokens are
held as hashes. Renamed, it no longer counts as a config file, so `init` runs, and the owner approves it again with
`config approve /etc/iron-vault/config.toml.before-reset` once the credentials are back. Its signature is removed: it
names the old vault ID and the old approver, so it could never verify again. The pending config and the staged
signature belong to an approval the old vault never finished; the owner holds the file they were approving
([open question 2](#open-questions)).

**Counters.** Removing `approval.age` discards the approval counters that
[§12](iron-vault-specification.md#12-configuration-approval-and-reload) says are never reset. This design reads reset
as discarding a vault and `init` as creating a new one, where the counters start at zero by §12's own rule
([open question 3](#open-questions)). No old approval can replay into the new vault: its payload names the old vault
ID and its signature is the old approver key's, and the new vault has a new ID and a new approver.

## Crash table

What each command does after a crash, or any failure, in each step. A crash inside a step leaves the state of the row
before it or of its own row, because each durable write or remove is whole or absent.

| Last step durable | Initialization state | Service after restart | `unlock` | `reset` again | `init` |
|---|---|---|---|---|---|
| none (before the marker) | as before the reset | Locked | as before the reset: Initialized opens | starts over from the summary | as before the reset |
| marker | Unfinished reset | Locked | `unlock-failed`: reset interrupted | summary of an interrupted reset, then resumes | `already-initialized`: reset interrupted |
| any removal | Unfinished reset | Locked | as the row above | as the row above | as the row above |
| `config.toml` renamed | Unfinished reset | Locked | as the row above | as the row above | as the row above |
| marker removed | Uninitialized, or Unrecognized with a foreign file | Locked | `unlock-failed`: not initialized | `nothing-to-reset` | proceeds, or refuses naming the foreign file |

A failure without a crash (`reset-failed`) leaves the same row with the service still running and Locked.

## Result

The success result carries the vault ID that was confirmed (empty when the confirmation was the state directory's
path), the number of files removed, whether the config was kept as `config.toml.before-reset`, the foreign files left,
whether the lock drain cleared the vault identity (as `lock`'s result does), and whether the marker's removal is
uncertain. The CLI prints them, then the next step: `iron-vault init`. The command ID, tags and error codes are the
next free numbers in [admin-protocol.md](admin-protocol.md) when the command is built.

| Error | When |
|---|---|
| `wrong-state` (existing) | Starting, Checking or Stopped, at step 1 or step 4 |
| `declined` (existing) | the confirmation does not match, at step 3 or step 4 |
| `nothing-to-reset` (new) | no vault file is there, at step 1 or step 4; the message says what to run next |
| `reset-failed` (new) | the marker, a removal or the rename failed; the message names the step and the file, and says whether the vault is intact (`marker`) or the next reset resumes (every later step) |

## Logging

These are audit events in the [audit log](audit-logging.md#audit-events). The log directory is never inside the state
or config directory, and `lock` does not move it, so the log reaches every event a reset raises.

| Event | Level | When | Fields |
|---|---|---|---|
| `vault.reset-confirmed` | WARN | step 5, before the marker | the vault ID when one was read (`vault_id`), whether it is verified, the service state reset started from (`from_state`), whether this resumes an interrupted reset |
| `vault.reset` | WARN | step 7, the marker removed | `vault_id`, the store-owned file names removed (`files`), the foreign files kept, whether the config was kept, whether the marker's removal is uncertain |
| `vault.reset-failed` | WARN | any failure from step 5 on | the step (`marker`, `remove`, `rename`, `finish`), the file name, the error's fixed kind label (`error_kind`), the names removed before it |

`vault.reset-confirmed` is written before the marker so that a log write failure, which stops the service, stops it
with the vault intact. A refusal before step 5 (`wrong-state`, `declined`, `nothing-to-reset`) records only the admin
server's `admin.command` event: the principal and the command. The lock event from Ready or Unavailable raises the
existing `service.lock-transition`. No event carries a secret, a typed confirmation or any file's contents.

## Interactions

- **Init** ([vault-initialization.md](vault-initialization.md)). Its initialization state gains check 0 and its
  foreign-file list gains `reset.unfinished`. Its discard and reset share the store-owned list; `init` still removes
  only what an init writes.
- **Migration bundle** (K-307). `import` refuses an Initialized vault ("must not overwrite an initialized vault
  implicitly", [§16](iron-vault-specification.md#16-administration-recovery-and-migration)), so `reset` is the
  explicit clear before an import onto a used machine. An import marker joins the store-owned list, and reset removes
  it; `reset.unfinished` takes precedence over it, as over `init.unfinished`. Import treats Unfinished reset as `init`
  does: it refuses and says to run `reset` again. An export waiting at its prompts is cancelled by reset's lock request,
  and its challenge retired. Bundles live outside the state and config directories and reset never touches them.
- **TPM unlock** (K-319). A TPM-sealed blob kept in the state directory joins the store-owned list. Reset cannot
  remove persistent TPM handles or NV indexes, so the TPM design should keep none, or leave their clearing to
  `forget-machine`. The TPM unlock path at startup reads the initialization state, Unfinished reset included, and
  refuses anything but Initialized.
- **Host unlock** ([docker-compose.md](docker-compose.md)). The unlock handoff and the host's sealed credential are
  outside the state directory and stay; a new `init --host-unlock` enrols the same host unlock identity again.
- **Linux package** ([linux-package.md](linux-package.md)). Purge still removes the directories by hand; reset is
  for keeping the installation and replacing the vault.

## Release checks

Added to the v0 release checks by K-318, each on a real service:

1. Reset from Ready, Locked, Unavailable(`PolicyInvalid`) and Unavailable(`RecoveryNeeded`) ends Locked over an
   Uninitialized directory; `init` then makes a vault with a new vault ID, and the old `config.toml.sig` paired with
   `config.toml.before-reset` is refused by the new vault.
2. A wrong confirmation, `yes`, an empty line, a cancelled CLI and a closed connection each leave every file as it
   was.
3. A vault whose every approver is unusable is reset and rebuilt from `config.toml.before-reset` and re-added
   credentials.
4. A crash injected before each removal leaves Unfinished reset; `unlock` and `init` refuse it, `status` reports
   `3`, and `reset` finishes it.
5. No request is served, and no in-flight request completes with a credential, after step 4.
6. A foreign file in the state directory survives and is named in the summary and the result.
7. Uninitialized, and a config file alone, end with `nothing-to-reset`.
8. A pending migration challenge does not survive a reset, and the passphrase attempt limit is cleared.
9. An `init` that finishes between the summary and step 4 makes the reset end with `declined`, removing nothing.
10. The three audit events reach the log, and none holds a secret or the typed confirmation.

## Open questions

The specification leaves each point below open, or this design departs from its wording. Each takes its default until
the owner decides.

1. **No owner factor.** [§5](iron-vault-specification.md#5-service-and-cli-separation-of-concerns) says "Destructive
   and policy-changing operations require owner approval";
   [§16](iron-vault-specification.md#16-administration-recovery-and-migration) asks reset for "explicit owner or
   administrator action". *Default:* an admin principal and the typed vault ID, with no vault passphrase, recovery key
   or approval passphrase, because the owner who resets has lost them and the admin principal can already delete the
   files. The alternative asks an approver for presence when one answers, which
   stops nothing a root shell cannot do with `rm`.
2. **Keeping the active config.** *Default:* `config.toml` is renamed to `config.toml.before-reset`, replacing an older
   one, and the signatures and the pending config are removed. It holds no secret and may be the only rebuild list
   left. The alternative removes it with the others, so a reset leaves nothing of the old vault behind.
3. **Discarding counters.** [§12](iron-vault-specification.md#12-configuration-approval-and-reload) says never to
   reset a version and to start at zero "only when creating a new vault". *Default:* reset discards the vault and its
   counters, and the following `init` creates a new vault, with a new vault ID and approver, so no old approval
   verifies. This is the reading `init`'s discard already takes
   ([vault-initialization.md open question 2](vault-initialization.md#open-questions)).
4. **Startup does not finish an interrupted reset.** *Default:* the service starts Locked in Unfinished reset and
   waits for an admin principal to run `reset` again. The alternative finishes the removal at startup, with no
   principal to record.
5. **A piped confirmation.** *Default:* the confirmation is read like any owner input, so a script that supplies the
   vault ID on stdin can reset. The alternative reads it from the controlling terminal only, as `init`'s reveal is
   shown, which makes reset impossible to script.
