# Recovery check and reminders

How `iron-vault recovery check` proves that the owner's offline recovery key still opens the vault, and how the
service reminds the owner to run it (specification
[§3.13](iron-vault-specification.md#313-administration-recovery-and-migration),
[§3.15](iron-vault-specification.md#315-logging-and-v0-acceptance),
[§3.10](iron-vault-specification.md#310-vault-structure-and-durable-writes)). The recovery key is generated once, at
`init` ([vault-initialization.md](vault-initialization.md#recovery-key-presentation)), and the owner keeps it outside
the service. It is used rarely, so it can be lost, mistyped when it was saved, or kept for a vault that no longer
stands, and the owner finds out only when it is needed. The check finds that out early, and reminders make the owner
run it. Terms follow the [glossary](glossary.md). The frames, prompts and error codes are in
[admin-protocol.md](admin-protocol.md#recovery-check), and the audit events' fields are in
[audit-logging.md](audit-logging.md#audit-events).

Three rules drive the design:

- **The check proves the key against the vault as it is on disk.** It opens the current identity envelope and then
  the manifest, whose MAC only the real vault identity can produce, so a forged envelope cannot pass.
- **The check changes nothing but its own record.** Recipients, the approval state, the service state and every
  vault file stay as they were. The only file it writes is the recovery check record.
- **Reminders keep working while the vault is locked.** A service that has been locked for months is exactly the one
  whose owner most needs reminding, so the reminder schedule reads nothing sealed behind the vault identity.

The owner decided three points on 2026-11-06, and this design rests on them:

- **No reissue inventory.** The service keeps no file of names, kinds, hosts or reissue instructions, and there are
  no reissue notes and no `--reissue` option. The approved config names every routed credential and its upstream,
  and `iron-vault list` names every credential with its kind and origins while the vault is open; the owner's copies
  of both are what to rebuild from after complete loss. The [reminder](#reminders) tells the owner to keep them.
- **The recovery check record is plaintext with no MAC**, so reminders still fire while the vault is locked
  ([The recovery check record](#the-recovery-check-record) says why that is safe).
- **`status` shows the time since the last recovery check** ([Status](#status)).

Every other default this design picks where the ticket or the specification leaves a choice is listed under
[Open questions](#open-questions), with its alternatives.

## What the check proves

A recovery check succeeds only when all of these hold, in this order:

1. **The text is a recovery key.** `RecoveryKeySecret::parse` reads it as an `AGE-SECRET-KEY-1…` X25519 identity,
   ignoring surrounding whitespace. Anything else is `recovery-key-invalid`, before any file is read.
2. **It unwraps the current identity envelope.** The service reads `identity.age` and calls `unwrap_identity` with
   the parsed recipient identity. `EnvelopeError::NotARecipient` means the key is not listed in the envelope, or its
   stanza is damaged, which `age` cannot tell apart: the check fails with `recovery-check-failed`.
3. **What it unwraps is this vault's identity.** The service reads `manifest.age` and opens it with
   `open_manifest` and the unwrapped identity. The manifest's MAC is keyed from the vault identity
   ([storage-formats.md](storage-formats.md#mac)), so an envelope someone wrapped around an identity of their own,
   for the recovery key's recipient, unwraps cleanly and then fails here with `ManifestError::Damaged`: the check
   fails with `recovery-check-failed`. The check passes when `open_manifest` returns the manifest, and the vault ID it
   reports is the manifest's.

A damaged manifest also fails its MAC, and the service cannot tell that from a forged envelope, so both read as
`recovery-check-failed`. That is the safe reading: a key that cannot be shown to open the vault is not confirmed.
`unlock` and `status` report a damaged manifest on their own.

Every other failure means the check could not be run, not that the key is bad, and ends with
`recovery-check-unavailable`, whose message names the file and the error's kind: `identity.age` or `manifest.age`
missing or unreadable, an envelope that is too large, malformed or holds an unexpected stanza, and a manifest that is
too large, truncated, of an unknown version or fails after its MAC verified. Telling the owner that a good key is dead
because a read failed would send them to replace a recovery path that works.

Nothing is written except the [recovery check record](#the-recovery-check-record). The check never rewraps the
envelope, never touches `operational.age`, `approver.age` or `approval.age`, and never changes the recipient set or
the approval counters ([§3.13](iron-vault-specification.md#313-administration-recovery-and-migration)). The unwrapped
vault identity and the recipient identity are dropped, and cleared, before the service answers. They are never stored
in the service context: in Ready the vault identity the service already holds is neither used nor replaced, and in
Locked no vault identity is held once the check ends.

There is no attempt limit. The recovery key carries 256 bits, so guessing it through the check is no easier than
guessing it against a copy of `identity.age`, and only an admin principal can run the check.

## States and the service-wide lock

`recovery check` is allowed in Locked and Ready. A new admin operation, `AdminOperation::RecoveryCheck`, maps the
command onto the service state gate, and `admin_allows` offers it in those two states. In Starting, Checking,
Unavailable and Stopped the exchange ends with `wrong-state` before any prompt. Locked is where the check is most
useful, because a key can be checked without unlocking the vault; Ready is allowed because the check never touches
what Ready holds. Unavailable is not: there the owner's next step is to make the service Ready again, and a check
then would read files a failed config check has just distrusted.

The check never changes the service state. It never enters Checking, runs no config check and leaves the snapshot
holder alone, so requests are served throughout in Ready and refused with `locked` throughout in Locked.

The checks before the prompt run in this order, as `unlock`'s do:

1. **State:** Locked or Ready, else `wrong-state`.
2. **Initialization state:** Initialized, else `recovery-check-unavailable`, whose message names the
   [initialization state](vault-initialization.md#initialization-state) and says to run `iron-vault init`.
3. **Memory:** in a protected install whose memory is not locked, `memory-unprotected`. The check unwraps the vault
   identity into memory, so it is held to the same rule as `unlock`
   ([§3.11](iron-vault-specification.md#311-recipients-startup-and-memory)): the refusal comes before the owner
   types the key.

After the prompt, and once the text has parsed as a recovery key, the service **tries** the service-wide lock and
answers `busy` at once if it is taken, as `init` step 5 and `replace` do. It does not wait: a `config approve` holds
the lock across its prompts, for up to ten minutes, which would outlast the CLI's 60-second timeout. Under the lock it
reads the service state and the initialization state again, since an `init`, an `unlock` or a `lock` may have run
during the prompt. Locked and Ready both go on; any other state ends with `wrong-state`, and a vault no longer
Initialized ends with `recovery-check-unavailable`, both before any file is read. It holds the lock while it reads
`identity.age` and `manifest.age`, so both come from the same vault state and no vault write lands between them, and
while it writes the record, so the write never races a reminder evaluation. The work under the lock is two small
reads, an X25519 unwrap, a MAC and one durable write: milliseconds, with no scrypt.

## The exchange

`recovery check` is command 12. It takes no arguments.

1. The service runs the three checks above.
2. **Recovery key.** A prompt, secret: `Recovery key`. When stdin is not a terminal, the key is its next line, so
   `pass show iron-vault-recovery | sudo iron-vault recovery check` works. Empty, non-UTF-8 or unparsable input ends
   the exchange with `recovery-key-invalid`, whose message says the text is not an `AGE-SECRET-KEY-1…` recovery key
   and never repeats it. There is no second try in the same exchange.
3. The service takes the service-wide lock and runs the [check](#what-the-check-proves). A key that does not open
   the vault ends the exchange with `recovery-check-failed`, whose message is fixed: `the recovery key does not open
   this vault`. A check that could not run ends it with `recovery-check-unavailable`.
4. On success the service writes the recovery check record and answers with the vault ID, the check time and whether
   the record was written ([admin-protocol.md](admin-protocol.md#recovery-check)).

A failed record write does not fail the check: the key was proved, and saying otherwise would be false. The result
carries `recorded` false, the CLI warns on stderr that reminders still count from the last recorded check, and the
audit event names the write's error kind. A `SyncDir` failure means the record already holds the new bytes but may
not survive power loss; that counts as recorded, as `durable_replace` documents.

## The recovery check record

The **recovery check record** is the state-directory file `recovery.toml`. It holds two UTC times, to the second:

- `since`: when the schedule started counting, which is when the service first found the vault Initialized without a
  record, or the time of a check that replaced an unusable record;
- `last_checked`: the time of the last successful recovery check, absent when there has been none.

The byte format is in [storage-formats.md](storage-formats.md#recovery-check-record). The store owns it: the type
`RecoveryCheckRecord`, `StateFileName::recovery_check_record()`, and a read and a write built on `read_state_file`
and `durable_replace`. Its functions take the current time as an argument, so the store reads no clock.

**Writers.** Two things write the record, both under the service-wide lock, and nothing else:

- a successful recovery check writes `last_checked` as the check time. It keeps `since` from a readable record, and
  sets `since` to the check time when the record is missing or unusable;
- a [reminder evaluation](#reminders) that finds the vault Initialized and no record writes one with `since` as the
  current time and no `last_checked`. It never rewrites an existing record, readable or not.

A failed check, a refused check and a check that could not run leave the record as it was. `init` writes no record,
so its write order is untouched; [Initialization](#initialization) says what it removes.

**No MAC.** The record is not sealed or MAC'd, so it can be read while the vault is locked, which a reminder needs.
That is safe, because of what forging it can do:

- it can only move a reminder: a forged `last_checked` delays one, and a deleted or damaged record brings one
  forward. It cannot make the service open, unwrap or trust anything, and no decision but the reminder reads it;
- only the service account can write the state directory, and anyone who can has already defeated the vault: they
  can delete `identity.age` or every record outright.

`status` shows the record's times as recorded, never as proof: a recovery check is the only proof that the key works.

**Unusable records.** A record that cannot be read, is too large or is malformed is **unusable**. It is left in place
for the owner to inspect, a reminder counts as due, and the next successful check replaces it. A missing record is not
unusable: the next reminder evaluation creates it. The record is not in the manifest, so a vault restored without it
opens as before and starts counting again.

**Clock.** Times come from the wall clock. A record time in the future, as after the clock was set back, counts as
zero days, so a clock fault delays a reminder by at most the size of the jump and never makes the service fail.

## Reminders

A **recovery reminder** is the audit event `recovery.reminder`, which tells the owner to run a recovery check. v0
reminds through the log only ([§3.13](iron-vault-specification.md#313-administration-recovery-and-migration)); from
v1, EP-40's owner notifications carry it as the topic `recovery_reminder`
([owner-notifications.md](owner-notifications.md#which-events-notify)).

**The interval.** The approved config sets it:

```toml
[recovery]
reminder_days = 90
```

`reminder_days` is a whole number of days from 7 to 365, and 90 when absent, which meets the specification's "every
few months". The policy crate holds it as the value object `ReminderInterval`, valid on construction; a value outside
the range makes the config invalid, naming the key and the range. The approval summary shows a change to it
([config-approval.md](config-approval.md#approval-summary)).

The interval in force is the one in the active approved config, or, while no config is active, the one in the last
config that was. A `lock` keeps it, as it keeps the log destination. From startup until the first activation it is
90. It is never read from the unverified `config.toml`, for the reason the log destination is not
([audit-logging.md](audit-logging.md#before-an-approved-config-is-active)): an unverified file could otherwise silence
the reminders. A service that restarts and stays locked therefore reminds at the default interval until the owner
unlocks.

**When a reminder is due.** The reference time is `last_checked`, or `since` when there has been no check. A reminder
is due once the whole days elapsed since the reference time reach `reminder_days`. It is also due while the record
is unusable. While the vault is not Initialized nothing is due, because there is no key to check.

**Evaluation.** The service evaluates the schedule once at startup, after the startup sweep of stale temp files and
before the admin socket opens; after each `unlock` that opens the vault; and every 24 hours of the monotonic clock
from startup, in every state. An evaluation:

1. reads the initialization state, and stops unless it is Initialized;
2. reads the record. When it is missing, it waits for the service-wide lock, reads the record again under it, and if
   it is still missing writes one with `since` as the current time. If that write fails, this evaluation treats the
   record as unusable, and the next one tries the write again;
3. decides whether a reminder is due, and if so writes `recovery.reminder`, unless one was written less than 7 days
   ago.

The 7-day spacing is kept in memory, on the monotonic clock, as the time of the last reminder written. A restart
forgets it, so a service that restarts often may repeat a reminder sooner; that costs a log line, and a file to track
it would be one more file to keep consistent. A successful recovery check clears it, so a later reminder for the next
interval is never held back by one for the last.

**What the reminder says.** Beside the record's times and the interval, `recovery.reminder` carries a fixed
`remediation`:

> Run `sudo iron-vault recovery check` with your offline recovery key. Keep a copy of the approved config and of the
> output of `sudo iron-vault list` with the recovery key: the config names each routed credential and its upstream,
> and the list adds unrouted credentials and each one's kind and origins.

The second sentence is the owner's rebuild list after complete loss
([§3.13](iron-vault-specification.md#313-administration-recovery-and-migration)): with the vault gone, the owner
reissues each credential named there from its provider.

## Status

`status` reports the recovery check in every state, as part of the [status report](glossary.md): which form the
record is in, its reference time, the whole days elapsed, whether a reminder is due, and why the time is unknown when
it is ([admin-protocol.md](admin-protocol.md#status)). The service computes the days and the due flag with its own
clock and the interval in force, so the CLI's output does not depend on the CLI's clock or know the interval. The
service reads `recovery.toml` on each `status`, bounded, without the service-wide lock: the record is replaced by
rename, so a read sees either the old record or the new one whole.

The CLI prints one line, after `memory protection` and before the credentials:

| Record | Line |
|---|---|
| checked | `recovery last checked: 2027-02-01 (37 days ago)` |
| never checked | `recovery last checked: never (reminders counting since 2026-11-06)` |
| checked or never checked, reminder due | the same line with `, overdue` before the closing parenthesis, such as `recovery last checked: 2027-02-01 (97 days ago, overdue)` |
| unknown | `recovery last checked: unknown (<reason>)`, with `, overdue` when a reminder is due |

The date is the UTC date of the reference time. Zero days prints `today` and one day `1 day ago`. The reasons are
fixed phrases: `the vault is not initialized`, `no check record yet`, and `the check record is unusable
(<error kind>)`. A missing or unreadable record never fails `status`: it is a reported fact like any other.

## Initialization

`recovery.toml` is a known state file. The [initialization state](vault-initialization.md#initialization-state) and
the store's `classify` give it a class of its own, the recovery check record, which is not a foreign file:

- **beside a manifest** it is part of the vault, and `unlock` logs nothing about it;
- **beside `init.unfinished`** it does not make the state Unrecognized, and the
  [discard](vault-initialization.md#discarding-an-unfinished-initialization) removes it with the vault's other files;
- **with no manifest and no `init.unfinished`** it does not make Uninitialized impossible: it is a record of a vault
  that is no longer there, left when the owner removed a vault's files by hand or restored part of a backup. `init`
  removes it durably, under the service-wide lock and before step 1, so a new vault never starts with an old vault's
  `last_checked`, which would show a key as checked that never was.

`init`'s rule that it never removes what it did not write still holds, because the service wrote the record. Later
designs that discard or replace a vault, such as `reset` and `import`, must remove it the same way.

## Logging

These are audit events in the audit log; [audit-logging.md](audit-logging.md#audit-events) gives each field's name and
type. No event carries the recovery key's text, any key material or the record's bytes.

| Event | Level | When | Fields |
|---|---|---|---|
| `recovery.checked` | INFO when opened, WARN otherwise | a recovery check ended with `invalid` at its prompt, or with any other outcome after the key parsed and the lock was taken | `recovery_outcome`, and by outcome: `opened` adds `vault_id` and `recorded`, with `error_kind` when the record was not written; `failed` adds `recovery_failure` (`not_a_recipient` or `identity_unverified`); `invalid` adds nothing; `unavailable` adds `file` and `error_kind` |
| `recovery.reminder` | INFO | a reminder evaluation found a reminder due | `recovery_record` (`checked`, `never_checked` or `unusable`); `last_checked` when checked; `reminders_since` when never checked; `error_kind` when unusable; `reminder_days`; `remediation` |

`recovery_outcome` is `opened`, `failed` (the text is a recovery key and does not open this vault), `invalid` (the text
is not a recovery key) or `unavailable` (the check could not run). Only `failed` says the key is bad, so only it
raises the v1 `recovery_check_failed` notification. `recovery.checked` is raised for `invalid` when the text does not
parse, and otherwise only when the check ended after the key parsed and the lock was taken: `opened`, `failed`, or
`unavailable` for a file the check read. Every other end records only the admin server's `admin.command` event, whose
`command` is `recovery_check`:

- a refusal before the prompt: `wrong-state`, `memory-unprotected`, or `recovery-check-unavailable` for a vault that
  is not Initialized;
- `busy`, when another operation held the lock;
- the re-check under the lock: `wrong-state`, or `recovery-check-unavailable` for a vault no longer Initialized.

The record write's failure on a successful check is in `recovery.checked` (`recorded` false, `error_kind`). A failed
write of a new record by a reminder evaluation makes the record unusable for that evaluation, so its
`recovery.reminder` reports `unusable` with the write's `error_kind`, unless a reminder was written in the last 7
days.

## Where the code lives

- **`iron-vault-store`:** `RecoveryCheckRecord`, its file name, read and write; the check itself, as one function,
  `check_recovery_key`, that takes the state directory lock, the recipient identity and nothing else, reads both
  files, and returns the vault ID or a typed error (`RecoveryCheckError`) whose variants map onto `failed` and
  `unavailable` with their labels. It holds the unwrapped identity only inside that function. The `Entry` class for
  `recovery.toml` and the discard.
- **`iron-vault-policy`:** `ReminderInterval` and the `[recovery]` table, carried in the validated config, and its
  approval summary section.
- **`iron-vault`:** `AdminOperation::RecoveryCheck`, the handler and its prompt, the reminder schedule and its
  in-memory spacing, the status fields, the audit events and the CLI.

## Open questions

The ticket sets the defaults for questions 1 to 3, and this design takes them; the rest are defaults this design
picked. Each takes its default until the owner decides.

1. **States.** *Default:* Locked and Ready, as `AdminOperation::RecoveryCheck`; `wrong-state` otherwise. The
   alternatives allow Unavailable as well, so a key can be checked while the owner is repairing a config, or allow
   Ready only, so the check never unwraps the vault identity while the service is otherwise holding no secrets.
2. **Error codes.** *Default:* `recovery-key-invalid` for text that is not a recovery key and
   `recovery-check-failed`, with a fixed message, for a key that does not open this vault, as the ticket sets, plus
   a third, `recovery-check-unavailable`, for a check that could not run (a vault that is not Initialized, an
   unreadable or malformed envelope or manifest). The alternative reports those as `recovery-check-failed`, which
   would tell the owner a working key is dead when a read fails.
3. **Reminder interval.** *Default:* `[recovery] reminder_days` in the approved config, 7 to 365, default 90. The
   alternatives fix 90 days in the binary, or let the owner turn reminders off.
4. **`busy` rather than waiting.** The ticket asks for `busy` "like unlock", but `unlock` waits for the service-wide
   lock. *Default:* the check tries the lock and answers `busy` at once, as `init` step 5, `replace` and `rm` do,
   because a `config approve` can hold the lock for minutes, past the CLI's 60-second timeout. The alternative waits,
   as `unlock` does.
5. **`memory-unprotected` before the prompt.** *Default:* in a protected install whose memory is not locked, the check
   is refused like `unlock`, because it unwraps the vault identity. The alternative allows it, since the identity is
   held for milliseconds and is never kept.
6. **A failed record write.** *Default:* the check still succeeds, with `recorded` false in the result and the
   event. The alternative fails the command with a new error code, which would tell the owner the check failed when
   only its record did.
7. **The interval while no config is active.** *Default:* the last activated config's interval, or 90 from startup
   until the first activation; never the unverified `config.toml`. The alternative reads `reminder_days` from the
   unverified file while locked, so a restarted, locked service uses the owner's interval, at the cost of letting a
   writer of that file delay reminders.
8. **A leftover record on Uninitialized.** *Default:* a `recovery.toml` with no other vault file does not stop
   `init`, which removes it before step 1. The alternative makes the state Unrecognized, so `init` refuses until the
   owner removes the file.
9. **The record has no format version.** *Default:* like `init.unfinished`, `recovery.toml` carries no version, and
   a key a later release adds makes the record unusable to an older one, which then counts a reminder as due until the
   next check rewrites it. The alternative adds `version = 1`.
10. **The vault a check opens in Ready.** In Ready the check proves the key against the files on disk and never
    compares the vault ID it opened with the vault ID of the vault the service holds, as migration's `not_this_vault`
    does ([migration-authorization.md](migration-authorization.md#error-codes)). A writer of the state directory could
    plant an `identity.age` wrapped for the recovery key's recipient and a `manifest.age` MAC'd by the identity inside
    it, and the check would pass against that pair. *Default:* no comparison: such a writer has already defeated the
    vault, as [The recovery check record](#the-recovery-check-record) and the README's
    [security boundary](../README.md#security-boundary) say. The alternative ends a check in Ready with
    `recovery-check-failed` when the vault ID it opened is not the one the service holds, which catches a pair swapped
    in while the service runs; in Locked no vault ID is held, so there is nothing to compare.
