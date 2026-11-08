# Vault initialization

How `iron-vault init` creates a vault: its two independent recovery paths
([§3.11](iron-vault-specification.md#311-recipients-startup-and-memory)), the recovery key shown exactly once
([§3.13](iron-vault-specification.md#313-administration-recovery-and-migration)), the approval counters starting at zero
and the first committed approval ([§3.9](iron-vault-specification.md#39-configuration-approval-and-reload)). It also
covers what a crash part-way through leaves behind, and what each command does with it. Terms follow the
[glossary](glossary.md); byte formats are in [storage-formats.md](storage-formats.md), and the `init` command's frames
are in [admin-protocol.md](admin-protocol.md#init).

The store already has every piece: `Vault::create` and `Vault::create_approval_state`; `wrap_identity`,
`seal_passphrase_envelope` and `seal_signer_key`; `RecoveryKey::generate`, `OperationalIdentity::generate` and
`SoftwareSigner::generate`; and the approval transaction (`PendingConfig`, `PreparedApproval`). This document puts
them in order. The store owns the durable steps and their order. The binary owns the prompts, the reveal, the service
state check and the service-wide lock, as it does for the
[approval transaction](config-approval.md#the-transaction).

Three rules drive the design:

- **Nothing is written until the owner has saved the recovery key.** A crash or a refusal before then leaves the
  state directory as it was.
- **Every step is durable before the next one starts**, and one durable remove is the commit point
  ([§3.10](iron-vault-specification.md#310-vault-structure-and-durable-writes)).
- **Init never overwrites or removes what it did not write.** It removes only the files an unfinished initialization
  can have written (a config file only when its bytes are the initial config) and a leftover
  [recovery check record](recovery.md#initialization), and refuses anything else.

Every default this design picks where the specification is silent, or where it departs from the specification's
wording, is listed under [Open questions](#open-questions); the owner has accepted all but the last.

## State before and after

A fresh service starts Locked (`ServiceContext::start`): v0 keeps the vault identity behind a passphrase only, so
startup always waits for an interactive unlock. Before init the request interface answers `503` `locked`, as in any
Locked service, and the provisional listener set is empty, because there is no `config.toml` to name listeners.

[§3.12](iron-vault-specification.md#312-service-states-and-errors) has no "uninitialized" state, and this design adds
none, nor any edge ([open question 1](#open-questions)):

- **Init is allowed only in Locked.** In any other state it ends with `wrong-state` before any prompt. A new
  admin operation, `AdminOperation::Initialize`, maps the `init` command onto the service state gate, and
  `admin_allows` offers it only in Locked.
- **Init leaves the service Locked.** It writes the vault but never enters Checking: it unwraps nothing it keeps,
  and it runs no config check. The owner then runs `unlock`, which moves the service through Checking to Ready on
  the initial config.
- **Unlock needs an initialized vault.** Without one, a passphrase cannot open anything useful, and an unfinished
  vault could pass the passphrase and fail its config check, leaving the service Unavailable with
  `RecoveryNeeded`, where `init` is refused and the only way out is a restart. So `unlock` reads the
  [initialization state](#initialization-state) before its passphrase prompt, and again under the service
  context's mutex, and anything but Initialized ends the exchange with `unlock-failed`. The message names the
  initialization state and says what to run; for Unfinished it adds that an init may be in progress, since an
  `unlock` that reads the state while step 5 runs also sees `init.unfinished`. The service stays Locked. Every other
  way from Locked into Checking, such as a later host unlock (EP-32), checks the same.

## Initialization state

The **initialization state** is read from the names in the state directory and the config directory without the
vault identity, so it is known while the vault is locked. The one exception is the config directory's own files, whose
bytes are compared with the initial config (below). The checks run in this order, and the first that matches decides:

1. **`init.unfinished` is present.** The state is Unfinished if the state directory holds no file but the lock file
   (`lock`), a `lost+found` directory, stale temp files (`.<name>.tmp`), the files an initialization writes
   (`init.unfinished`, `identity.age`, `recipients.age`, `operational.age`, `approver.age`, `manifest.age`, `approval.age`) and the
   recovery check record (`recovery.toml`), and the config directory passes the [config test](#the-config-test).
   Otherwise it is Unrecognized.
2. **`manifest.age` is present.** The state is Initialized, whatever else the directories hold: an Initialized vault
   never depends on the absence of other files.
3. **The state directory holds only the lock file, a `lost+found` directory, stale temp files and the recovery check
   record**, and none of `config.toml`, `config.toml.sig`, `config.toml.pending` and `config.toml.sig.staged` is in
   the config directory. The state is Uninitialized.
4. **Otherwise** the state is Unrecognized.

| State | Meaning |
|---|---|
| Uninitialized | Check 3 matched: nothing of a vault or its config is there. |
| Unfinished | Check 1 matched: an initialization started and has not reached its commit point. |
| Initialized | Check 2 matched: a manifest and no `init.unfinished`. |
| Unrecognized | No check matched: a foreign file or a config file that is not init's own beside `init.unfinished`, or files of a vault without its manifest, or anything else in a directory with no manifest. |

A **foreign file** is a file in the state directory that is not on the lists above: the lock file, `lost+found`, temp
files, the vault's own files (`identity.age`, `recipients.age`, `recipients.age.staged`, `operational.age`,
`approver.age`, `manifest.age`, `approval.age`, `init.unfinished`), record files (`record-*.age`) and the recovery check
record (`recovery.toml`), which [recovery.md](recovery.md#initialization) describes. The staged inventory
(`recipients.age.staged`) is a vault file only beside a manifest: `init` never writes it, so beside `init.unfinished` it
is foreign ([recipients.md](recipients.md#initialization)). It matters only beside `init.unfinished`, where it makes the state
Unrecognized so the discard never sweeps it into the new vault, and in a state directory with no manifest, where it
makes Uninitialized impossible. Beside a manifest it changes nothing: `unlock` logs its name at WARN
(`vault.foreign-file`) and goes on, because `Vault::open` already ignores names it does not know and the manifest alone
decides which records exist ([§3.10](iron-vault-specification.md#310-vault-structure-and-durable-writes)). A stray
`lost+found` on a state volume, an editor's backup or a file a later release writes, left after a downgrade, must not
lock the owner out of a working vault. `lost+found` is the directory a filesystem check creates on a fresh volume, so
`init` ignores it like the lock file and temp files ([open question 9](#open-questions)).

Init proceeds only on Uninitialized and Unfinished. Examples of Unrecognized:

- envelope files (`identity.age`, `recipients.age`, `operational.age`, `approver.age`) without `init.unfinished` or a manifest: a
  crash cannot leave them, because `init.unfinished` is durable before the first of them is written;
- record files or `approval.age` without a manifest: what `Vault::open` already reports as damaged shared state;
- `init.unfinished` beside a record file: only `add` writes a record file, and only an initialized vault adds;
- `config.toml` or `config.toml.sig` beside an empty state directory. Init refuses rather than overwrite the owner's
  config file. The owner moves it aside, runs init, then approves it with `config approve`;
- `init.unfinished` beside a config file that is not init's own, by the config test below;
- `init.unfinished` beside a foreign file, or any foreign file in a state directory with no manifest.

### The config test

In an Unfinished directory the config directory may hold files an interrupted init wrote, and only those. They pass
when every one of the following holds:

- `config.toml` and `config.toml.pending`, each only if present, hold exactly the [initial config](#initial-config),
  `schema_version = 1\n`. Step 8 writes nothing else to either, so a crash cannot leave other bytes there;
- `config.toml.sig` and `config.toml.sig.staged`, each only if present, sit beside `config.toml` or
  `config.toml.pending`. A signature file is opaque, so it is judged by the config it belongs to; publishing renames the
  pending config before the signature, so a signature alone is never a crash state.

A config file with other bytes is the owner's: it makes the state Unrecognized, for the same reason `config.toml`
beside an empty state directory does. The test reads at most one byte more than the initial config.

The config directory holds other files too, such as administrator-installed TLS files, and only the four config file
names above count. Stale temp files are swept at startup, before any admin command runs, and do not count either.

An Initialized vault may still be damaged: its approval state missing, a partial restore, a damaged record. That is
for `unlock`'s config check to find and report, as it does today; the initialization state only says whether init has
anything to do.

The state is read twice: once when the request arrives, to refuse early, and again under the service-wide lock
before the first write, because another init may have run during the prompts.

## The exchange

After the admin request, in order:

1. **Check.** The service checks that it is Locked (`wrong-state` otherwise) and reads the initialization state:
   Initialized or Unrecognized ends with `already-initialized`, whose message names which, and for Unrecognized the
   first offending file names. On Unfinished, the service sends a notice that an unfinished initialization is here,
   or that another init is writing its vault right now: the prompts take no lock (see **Locking** below), so the
   service cannot tell the two apart. Once the owner confirms the new recovery key, an unfinished initialization is
   discarded, and any recovery key it showed opens nothing. A run still writing holds the service-wide lock, so it is
   never discarded: this init then writes nothing and ends with `busy`, or with `already-initialized` once that run
   has finished.
2. **Passphrases.** Four prompts, all secret: `Vault passphrase`, `Repeat the vault passphrase`,
   `Approval passphrase`, `Repeat the approval passphrase`. The [rules](#passphrase-rules) are checked once both
   entries of a passphrase are in; a broken rule ends with `passphrase-rejected`. There is no second try in the same
   exchange.
3. **Keys.** The service generates every key: the vault identity (`VaultIdentity::generate`), the vault ID (`VaultId::new_random`), the operational
   identity (`OperationalIdentity::generate`), the recovery key (`RecoveryKey::generate`) and the software signer
   key (`SoftwareSigner::generate`, which also returns the pinned approver).
4. **Recovery key.** The [presentation](#recovery-key-presentation): a notice, the reveal frame, then the prompt
   `Type yes once you have saved the recovery key`. Any answer but exactly `yes` ends with `declined`.
5. **Writes.** The service tries the service-wide lock and fails at once with `busy` if it is taken; it never waits.
   It then checks again that it is Locked (`wrong-state` otherwise) and that the initialization state is
   Uninitialized or Unfinished (`already-initialized` otherwise), discards an unfinished initialization, then runs the
   [write order](#write-order). A failure ends with `init-failed`, which names the failed step by its number, or
   `discard` for a failure of the discard.
6. The success result: the vault ID and the committed version, 1.

Nothing is written before step 5. A prompt that gets no owner input, a refusal or a cancelled CLI, up to the owner's
`yes`, ends the exchange with the directories exactly as they were, and every generated key is dropped and cleared.
Once the CLI has sent `yes` no prompt remains, so a cancel or a lost connection no longer stops the service: step 5
runs to its end whatever the CLI does.

Step 4's reveal puts the recovery key on the owner's screen, and steps 4 and 5 can still end without a vault. Every
ending after the reveal other than success therefore tells the owner what to do with
[the recovery key](#failing-after-the-reveal).

**Locking.** The prompts are not under any lock: holding the service context's mutex across up to five prompts of up
to 5 minutes each would block `status`. Step 5 takes the service-wide lock without waiting, as [`config approve`'s
concurrent writes](config-approval.md#the-service-wide-lock) do: another approval, vault write, reload, config check
or init holding it ends step 5 with `busy`. Waiting could outlast the CLI's 60-second timeout, since an approval can
hold the lock for about 10 minutes. Step 5 then holds the lock and the service context's mutex from the second state
check to the response. An `unlock` whose first read comes before step 9 sees Unfinished and ends with `unlock-failed`,
whose message says an init may be in progress. An `unlock` whose first read comes after step 9 sees Initialized
at once; its read under the context's mutex waits for step 5 to finish and sees Initialized too. A second init that passed its
own first check ends with `busy` if the first still holds the lock, or finds Initialized under the lock and ends
with `already-initialized` once it has finished. The service wrote nothing for the second init, but its owner has
already saved a recovery key, so both messages say to discard it. Step 5 takes a few seconds: two scrypt seals and one
scrypt open at `PASSPHRASE_WORK_FACTOR`, and about a dozen durable writes, inside the CLI's 60-second timeout.

## Passphrase rules

Both the vault-unlock passphrase and the approval passphrase:

- are entered twice, and the two entries must be equal;
- are valid UTF-8 and at least 12 characters long, counted as Unicode scalar values, with nothing trimmed or
  normalized;
- differ from each other. The comparison runs over the bytes in constant time (`subtle`'s `ConstantTimeEq`), as does
  the comparison of each passphrase with its repeat, so the time taken says nothing about how much of one matches the
  other.

A broken rule ends the exchange with `passphrase-rejected`, whose message names the rule (`the two entries differ`,
`shorter than 12 characters`, `not valid UTF-8`, `the vault and approval passphrases must differ`) and nothing the
owner typed. The errors carry no text of the input, not even its length. Only after every rule passes are the values
turned into `Passphrase` and `ApprovalPassphrase`; every `OwnerInput` and repeat is dropped, and cleared, as soon as
it has been compared.

`Passphrase::new` and `ApprovalPassphrase::new` refuse only an empty value, and `unlock` and `config approve` keep
that: the length rule applies when a passphrase is chosen, not when it is typed to open something, so a vault created
before the rule still opens. A later passphrase change applies the same rules ([open question 7](#open-questions)).

## Recovery key presentation

[§3.13](iron-vault-specification.md#313-administration-recovery-and-migration) requires the service to present the
recovery identity once, through the owner-only session, and to have the owner confirm they saved it. In order:

1. **Generate all keys first** (the exchange's step 3), so the key shown is the key that will be enrolled, and no
   prompt comes between the reveal and the confirmation except the confirmation itself.
2. **Notice.** One or more notice frames saying: this recovery key is shown once and the service keeps no copy; it is
   the second way into the vault if the passphrase or this machine is lost; store it in an independent password
   manager or on paper, never beside the vault; the owner may protect it in a passphrase-encrypted file of their own.
3. **Reveal.** One [reveal frame](admin-protocol.md#reveal-kind-7) whose body is the `AGE-SECRET-KEY-1…` text, 74
   bytes. The service builds the frame in a clearing buffer straight from `RecoveryKeySecret`'s text, writes it, and
   drops both the buffer and the `RecoveryKeySecret` as soon as the write returns.
4. **Confirmation.** A prompt, not secret: `Type yes once you have saved the recovery key`. Any other answer ends with
   `declined`, and nothing is written. The message says the recovery key shown opens nothing and is to be discarded.
5. **Only then** does the service write anything.

After the reveal the service keeps only the recovery key's parsed `RecipientIdentity`, for
[step 2's unwrap check](#write-order), and drops it once that check passes. It never writes the secret text or the
identity to disk, to a log or to an error, so the service holds no automatically usable recovery path, as
[§3.13](iron-vault-specification.md#313-administration-recovery-and-migration) requires. `RecoveryKey::generate`
returns only the text, so the binary parses that text back with `RecoveryKeySecret::parse` before dropping it, or the
store adds a way to keep the identity it generated; either keeps the parse inside a clearing buffer.

The CLI writes the reveal value to the controlling terminal only, never to stdout or a pipe
([open question 5](#open-questions)). It checks for that terminal before it sends the `init` request, so the secret
never reaches a CLI that will refuse to show it.
[§3.13](iron-vault-specification.md#313-administration-recovery-and-migration) also asks for a QR code; until K-160 the
CLI shows text only ([open question 4](#open-questions)).

### Failing after the reveal

From the reveal on, the owner holds a recovery key that opens a vault only if init succeeds. Two kinds of ending leave
no vault with that key, or leave it unknown, and the owner is told which.

**The key is dead.** No vault was written for it, or the vault that was written is not the one it opens. A key kept as
"the vault's recovery key" would be a dead key kept in good faith, so the ending says *the recovery key shown opens
nothing: discard it*:

| Ending | Who says it |
|---|---|
| `declined`: any answer but `yes` | the service, in the error message |
| `busy`: another operation, such as a second init, holds the service-wide lock at step 5 | the service |
| `already-initialized`: the re-check under the lock finds Initialized or Unrecognized, as when a second init finished first | the service |
| `wrong-state`: the re-check under the lock finds the service has left Locked | the service |
| `init-failed`: the service clock could not be read, before any write | the service |
| `init-failed` at the discard or at any step before 9: a write failed | the service |
| the command cancelled or lost before the CLI sent `yes`: Ctrl-C or a closed terminal, a signal, a dropped or timed-out connection | the CLI, on stderr before it exits, and after SIGHUP also in the system log; the service cannot answer a closed connection |

**The outcome is unknown.** The owner's `yes` has been sent, or the vault may already stand, so step 5 may have
finished, may still be running or may have failed, and the CLI cannot tell which. The advice is stated once, here:
*keep the recovery key and run `iron-vault init` again. If it starts over, with a new recovery key, the old key is
dead: discard it. If it answers `busy`, the first run is still writing: wait a few seconds and run it again. If it
answers `already-initialized` and the message says the vault is Initialized, a vault stands, but it may not be the
one this key opens, so do not rely on the key yet: confirm it with `iron-vault recovery check`, which runs while the
vault is locked ([§3.13](iron-vault-specification.md#313-administration-recovery-and-migration)), and keep the key
only if that passes. If the message says Unrecognized, files init did not write are present and the key is
not confirmed either.* The case the check guards against is a concurrent init: a second init finished first, so the
owner's own run was refused and its key is dead, yet the re-run answers `already-initialized` for the other run's
vault. [recovery.md](recovery.md) designs `recovery check`. The endings are:

| Ending | Who says it |
|---|---|
| `init-failed` at step 9: the unlink landed but the directory fsync failed, so a power loss may bring `init.unfinished` back | the service |
| the command cancelled or lost after the CLI sent `yes`, including a timeout waiting for the result | the CLI, on stderr before it exits, and after SIGHUP also in the system log |

The same errors raised before the reveal do not carry either sentence, because no key was shown. The service tracks
whether it has sent the reveal, and the CLI whether it has shown one and whether it has sent `yes`, so each says only
what is true.

## Write order

Each step is durable before the next starts. The state directory's files are written with `durable_replace` or a
store function built on it, so each is whole or absent after a crash.

| Step | What the service does | Durable change |
|---|---|---|
| 1 | Writes the empty file `init.unfinished` in the state directory. From here on the state directory reads Unfinished until step 9. | `init.unfinished` |
| 2 | Wraps the vault identity for the recipient set {operational recipient key, recovery recipient key} with `wrap_identity` and writes it. Then reads `identity.age` back and unwraps it with `unwrap_identity` twice, once with the operational identity and once with the recovery key's identity, and requires both to give the generated vault identity (same public key). Then writes the [recipient inventory](recipients.md#initialization) with `write_recipient_inventory`: the `operational` and `recovery` entries, labelled `vault passphrase` and `recovery key`, the init time, the vault ID generated with the keys and the digest of the envelope as read back. Reads it back and requires that it opens with the vault identity and equals what was written. The recovery identity is dropped. | `identity.age`, then `recipients.age` |
| 3 | Seals the operational identity to the vault passphrase with `seal_passphrase_envelope` and writes it. The operational identity is dropped. | `operational.age` |
| 4 | Seals the software signer key to the approval passphrase with `seal_signer_key` and writes it with `write_signer_key`. The signer key is dropped. | `approver.age` |
| 5 | Creates the vault with `Vault::create_with_id`, using the vault ID generated with the keys in step 3, and an empty manifest at state generation 1. | `manifest.age` |
| 6 | Creates the approval state with `Vault::create_approval_state`, pinning the approver from step 4, with nothing reserved and nothing committed, then the manifest write that records it. | `approval.age`, then `manifest.age` |
| 7 | Reads `approver.age` back and opens it with the approval passphrase (`open_signer_key`, checked against the pinned approver), which proves the file on disk opens. The approval passphrase is dropped. | none |
| 8 | Runs the approval transaction on the [initial config](#initial-config): `PendingConfig::write`, then `prepare` with the signer from step 7 (reserving version 1), then `commit` (committing version 1, publishing, and verifying the published pair as read back). | `config.toml.pending`, `approval.age` (reserve), `config.toml.sig.staged`, `approval.age` (commit), `config.toml`, `config.toml.sig` |
| 9 | Removes `init.unfinished` with `durable_remove`. **This is init's commit point.** | `init.unfinished` removed |

Notes on the steps:

- **Step 2's check** comes before anything else depends on the envelope, so a bad envelope is caught while the
  recovery key the owner just saved still means nothing. Both recipient paths are proved, not only the one `unlock`
  will use.
- **Step 5** consumes the `VaultIdentity`. Step 8's `ApprovalStorage` needs a borrow of it, so the store lends it from
  the `Vault` (a crate-level accessor), or `Vault::create` hands it back beside the vault. That is a store change the
  code ticket makes.
- **Step 6** is two writes. A crash between them leaves `approval.age` beside a manifest that does not record it; that
  is still Unfinished, and a re-run discards both.
- **Step 8's commit** takes proof that admission is paused (`AdmissionPaused`). The service passes the guard from
  `SnapshotHolder::pause`, which, in Locked, keeps the holder refusing with `locked` and changes nothing for
  requests. The guard is dropped after the commit, without `resume` or `fail`, so the holder keeps refusing with
  `locked`. No config check runs: the commit's read-back verification of the published pair is the check, and the
  first config check runs at `unlock`.
- **Step 9** is the only durable change that turns Unfinished into Initialized. A failure before it leaves the vault
  Unfinished, so a re-run discards it. If the unlink lands but the state directory's fsync fails, the vault reads
  Initialized now and may read Unfinished after a power loss; the service answers `init-failed` naming step 9, and the
  message gives the [unknown-outcome advice](#failing-after-the-reveal): keep the key until the re-run decides. Either
  way nothing is lost: the vault holds no credential until `add`, and `add`'s
  own directory fsync makes the earlier unlink durable.

## Discarding an unfinished initialization

On Unfinished, under the service-wide lock and before step 1, init removes exactly the files an initialization
writes, each durably, and only those present:

- in the config directory: first `config.toml.sig` and `config.toml.sig.staged`, then `config.toml` and
  `config.toml.pending`, each removed durably (unlink, then directory fsync). All signatures go before any config,
  because a signature with no config beside it makes the state Unrecognized and `publish` can leave `config.toml`
  beside `config.toml.sig.staged`;
- in the state directory: `recovery.toml`, `approval.age`, `manifest.age`, `approver.age`, `operational.age`,
  `recipients.age` and `identity.age`, each with `durable_remove`.

`init.unfinished` stays, and step 1 then rewrites it, so a crash during the discard leaves the state Unfinished and
the next init discards again. Nothing else is left to touch: the state is Unfinished only if the state directory holds
nothing but the lock file, temp files, `init.unfinished` and files removed here, and only if the config files pass the
[config test](#the-config-test). So the discard removes a config file only when its bytes are the initial
config (or it is a signature beside one), and a config file with any other bytes is never deleted: it makes the
state Unrecognized, and init refuses before any prompt.

The config test is why the discard can delete config files at all. Init starts only from Uninitialized, where the
config directory holds none of the four, or from Unfinished, where each is init's own, because step 8 is the only
writer and writes the initial config alone.

**Counters.** Discarding `approval.age` discards approval counters, which
[§3.9](iron-vault-specification.md#39-configuration-approval-and-reload) says start at zero "only when creating a new
vault". This design reads a re-run as creating a new vault, not resetting an old one
([open question 2](#open-questions)):

- the discarded counters never protected anything served. An Unfinished vault is never unlocked, so no config under
  its approval was ever activated;
- the new vault has a new vault ID and a new pinned approver, so a version-1 `config.toml.sig` from the discarded
  vault cannot verify: its payload names the old vault ID, and its signature is the old approver key's.

Discarding is logged; see [Logging](#logging).

**A leftover recovery check record.** On Uninitialized the state directory may still hold `recovery.toml`, the record
of a vault whose files are gone. Init removes it with `durable_remove`, under the service-wide lock and before step 1,
so the new vault never starts with the old one's `last_checked` ([recovery.md](recovery.md#initialization)). It is
the one file init removes from an Uninitialized directory, and the removal is not an audit event: the record holds
no secret and decides nothing but a reminder. A failed removal is handled as a failed discard of an unfinished
initialization: init ends with `init-failed` naming `discard` and raises `vault.init-failed` with the step `discard`.
Nothing else has been written, so the state is still Uninitialized and the next init tries the removal again.

## Crash table

What each command does after a crash, or any failure, following each step. A crash inside a step leaves the state of
the row before it or of its own row, because each durable write is whole or absent. `status` is the same in every row:
it answers in Locked, and the vault ID, approval versions and credentials print as unknown while the vault is locked.
It does not report the initialization state until K-161 ([open question 6](#open-questions)).

| Last step durable | Initialization state | `unlock` | `init` again |
|---|---|---|---|
| none | Uninitialized | `unlock-failed`: not initialized, run `iron-vault init` | removes a leftover `recovery.toml`, then proceeds from step 1 |
| 1 `init.unfinished` | Unfinished | `unlock-failed`: initialization unfinished, an init may be in progress; run `iron-vault init` again if none is | notice, discards (nothing yet), proceeds |
| 2 `identity.age`, then `recipients.age` | Unfinished | as row 1 | discards whichever of the two exist, proceeds |
| 3 `operational.age` | Unfinished | as row 1; the passphrase is never asked for, so the vault never reaches Checking | discards both envelopes, proceeds |
| 4 `approver.age` | Unfinished | as row 1 | discards the three envelopes, proceeds |
| 5 manifest | Unfinished | as row 1 | discards envelopes and manifest, proceeds |
| 6 approval state (recorded or not) | Unfinished | as row 1 | discards envelopes, manifest and `approval.age`, proceeds |
| 7 (no write) | Unfinished | as row 1 | as row 6 |
| 8, any part: pending, reserved, staged, committed or published | Unfinished | as row 1 | as row 6, and discards whichever of the four config files exist; each holds the initial config, or is a signature beside one |
| 9 `init.unfinished` removed | Initialized | prompts for the passphrase; the config check publishes nothing new, verifies version 1 and enters Ready with no listeners and no routes | `already-initialized` |
| any step, with a config file whose bytes are not the initial config (the owner's), or a signature file alone | Unrecognized | `unlock-failed`: files init did not write, names the first | `already-initialized`: names the first; nothing is changed, and the owner moves the file aside |
| any step, with a foreign file in the state directory | Unrecognized | as the row above | as the row above |
| 9 or later, with a foreign file in the state directory | Initialized | as row 9, and logs the file's name at WARN | `already-initialized` |

Each discard's notice also tells the owner that, once discarded, the recovery key from the unfinished run opens
nothing. That settles an [unknown outcome](#failing-after-the-reveal): a run that starts over has discarded the vault
the old key opened. The notice also covers a run still writing, which is never discarded (step 1 of
[the exchange](#the-exchange)).

## Initial config

Init approves exactly the 19 bytes `schema_version = 1\n`. It names no listener, caller or route: the vault holds no
credential yet, and a route naming one would fail activation at the first `unlock`, leaving the service Unavailable.
Every section the config parser defaults is left to its default. The owner adds credentials with `add`, then approves
a real config with `config approve`, which commits version 2.

Committing version 1 is what lets the owner reach Ready. `add` needs Ready (`AdminOperation::VaultChange`), and a vault
with nothing committed opens as Unavailable with `PolicyInvalid`, where only `config approve` runs. Without a first
approval the owner would have to approve before adding anything, against a credential catalog that is empty.

Init runs the store's approval transaction directly, without the approval summary and the confirmation prompt that
`config approve` adds: the owner authorizes init as a whole, and the summary of the empty config is empty. The approval
passphrase prompt is init's own step 2 prompt; step 7 opens the signer with it.
[§3.9](iron-vault-specification.md#39-configuration-approval-and-reload) step 2 says "authenticate the owner, show the
service-generated summary", so this departs from its wording ([open question 3](#open-questions)).

## Logging

These are audit events in the audit log; [audit-logging.md](audit-logging.md#audit-events) gives each one's exact
field names and types, and the record shape they share. The binary emits them from what the store's init returns
(`InitializedVault`, `InitError`); the failed step is logged as its number, or `discard`, and the cause as the variant's
`error_kind` label.

| Event | Level | When | Fields |
|---|---|---|---|
| `vault.init-discarded` | WARN | an unfinished initialization was discarded | the file names removed |
| `config.version-reserved` | INFO | step 8's reservation of version 1 is durable | version, config digest |
| `config.approval-completed` | INFO | step 8's commit of version 1 is durable | version, config digest; the summary field reads `initial config` |
| `vault.initialized` | INFO | step 9 is durable | the vault ID only |
| `vault.init-failed` | WARN | a step failed | the step and the error's fixed kind label, never a path or file contents |
| `vault.foreign-file` | WARN | `unlock` read an Initialized state directory holding a file not on the [lists](#initialization-state) | the file's name |

The two `config.` events are the [audit events](config-approval.md#audit-events) every approval raises (K-118), so
version 1 is audited like any other. No event carries a passphrase, the recovery key's text, any key material or the
config bytes. A refusal before any write (`wrong-state`, `already-initialized`, `passphrase-rejected`, `declined`)
records only the admin server's `admin.command` event: the principal and the command.

## Open questions

The specification leaves each point below open, or this design departs from its wording. The owner has decided
questions 1 to 8 by accepting their defaults, and the design stands on them; only question 9 is open, and takes its
default until the owner decides.

1. **No uninitialized service state.** *Decided: default accepted (2026-11-04).*
   [§3.12](iron-vault-specification.md#312-service-states-and-errors) draws no state for a service without a vault.
   *Default:* the service starts Locked as it does today; `init` runs only in Locked and leaves the service Locked;
   `unlock` refuses with `unlock-failed` unless the vault is Initialized. No state or edge is added. The alternative
   adds an Uninitialized state with an edge to Locked on init.
2. **Discarding counters on a re-run.** *Decided: default accepted (2026-11-04).*
   [§3.9](iron-vault-specification.md#39-configuration-approval-and-reload) initializes the highest reserved version
   to zero "only when creating a new vault". *Default:* a re-run on Unfinished discards the unfinished vault's
   `approval.age`, counters included, and creates a new vault with a new vault ID and a new approver, so no old
   signature can verify and the discarded counters never protected anything served. The alternative keeps an
   unfinished vault's counters, which would mean resuming rather than restarting.
3. **Version 1 without a summary or confirmation.** *Decided: default accepted (2026-11-04).*
   [§3.9](iron-vault-specification.md#39-configuration-approval-and-reload) step 2 says "authenticate the owner, show
   the service-generated summary". *Default:* init commits the fixed initial config without either, because the owner
   authorizes init as a whole and the config is fixed and empty. The alternative shows the empty summary and asks for
   a second confirmation.
4. **The QR code.** *Decided: default accepted (2026-11-04).*
   [§3.13](iron-vault-specification.md#313-administration-recovery-and-migration) asks for the recovery identity "as
   text and a QR code". *Default:* text only until K-160. A QR code needs no protocol change, since the CLI can render
   one from the reveal value on the terminal; K-160 adds it.
5. **Where the reveal is shown.** *Decided: default accepted (2026-11-04).* *Default:* the CLI writes the recovery key
   to the controlling terminal (`/dev/tty`) only, even when stdin is a pipe; with no controlling terminal it cancels
   the command before sending the request, so the service generates nothing and writes nothing. A scripted init
   therefore needs a terminal. The alternative writes it to stderr when there is no terminal, as notices are, which
   puts the key into whatever captures stderr.
6. **`status` and the initialization state.** *Decided: default accepted (2026-11-04).* *Default:* this design leaves
   the status report unchanged, so before init `status` says Locked, as after it, and `unlock`'s and `init`'s messages
   say which initialization state the directories are in. K-161 plans to add a status field for it.
7. **Passphrase rules.** *Decided: default accepted (2026-11-04).* The specification sets no strength rule. *Default:*
   the [rules above](#passphrase-rules): entered twice, at least 12 Unicode scalar values, the two passphrases
   different, no strength estimate or blocklist; applied when a passphrase is chosen (init, and later a passphrase
   change), never when one is typed to unlock or approve.
8. **Refusing Unrecognized with `already-initialized`.** *Decided: default accepted (2026-11-04).* *Default:*
   Initialized and Unrecognized both end with `already-initialized`, whose message says which, and for Unrecognized
   names the first offending files. Both mean "init will not write here". The alternative gives Unrecognized its own
   error code.
9. **`lost+found` on a fresh state volume.** A filesystem check creates a `lost+found` directory in the root of a
   freshly formatted volume, and a Compose deployment mounts such a volume as the state directory. *Default:* a
   `lost+found` directory is ignored like the lock file and temp files, so it does not make the state Unrecognized and
   `init` proceeds. The alternative treats it as a foreign file, so `init` refuses until the owner removes it.
