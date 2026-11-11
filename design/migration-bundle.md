# Migration bundle

How `iron-vault export` writes a migration bundle and `iron-vault import` makes a new vault from one on another
machine (specification [§16](iron-vault-specification.md#16-administration-recovery-and-migration),
[§19](iron-vault-specification.md#19-v0-user-acceptance)). It covers what the bundle holds and what it never holds,
how it travels between the service and the CLI, which states allow each command, the order of the import's writes and
what a crash leaves, each command's admin exchange, error codes and audit events, and the release checks. Terms follow
the [glossary](glossary.md); the bundle's bytes are in
[storage-formats.md](storage-formats.md#migration-bundle-v1). `export` consumes a
[migration authorization](migration-authorization.md), which is designed on its own.

Four rules drive the design:

- **Nothing in the bundle is plaintext secret.** Every file the bundle carries from the vault is already encrypted on
  disk and is copied byte for byte. The one new secret-bearing entry is the vault identity, sealed under the export
  passphrase. Neither the CLI nor any file ever holds a plaintext secret
  ([§16](iron-vault-specification.md#16-administration-recovery-and-migration) step 2).
- **The counters move unchanged.** The approval state is copied as it is, so the destination's highest reserved
  version and committed approval are the source's, and the destination's first approval is above every version the
  source ever reserved ([§12](iron-vault-specification.md#12-configuration-approval-and-reload)).
- **The destination makes its own ways in.** The bundle carries no recipient of the source. Import wraps the vault
  identity for a new vault passphrase and a new recovery key, as `init` does
  ([§14](iron-vault-specification.md#14-recipients-startup-and-memory)).
- **Import makes a vault only where none is.** It runs only where `init` could, and like `init` it has one commit
  point, so a crash leaves a state the next run discards.

Every default this design picks where the specification is silent, or where it reads the specification one way of two,
is listed under [Open questions](#open-questions).

## What the bundle holds

The vault is the set of state-directory files that the vault identity decrypts or authenticates. The bundle carries the
files that make up its credentials, its counters and its approvers, plus the vault identity sealed for the transfer:

| Bundle entry | From | Why it is safe to copy | Why it is carried |
|---|---|---|---|
| `bundle-header` | built by `export` | holds only the vault ID and two counts | names the bundle format version, and lets import refuse a foreign file before any prompt |
| `exported-identity.age` | built by `export` | the vault identity's secret text sealed to the export passphrase | the destination needs the vault identity to open everything else |
| `manifest.age` | `manifest.age` | encrypted to the vault public key, MAC'd with the manifest key | the record IDs, names and file digests; preserves record identities ([§16](iron-vault-specification.md#16-administration-recovery-and-migration) step 5) |
| `approval.age` | `approval.age` | encrypted, MAC'd with the approval key | the pinned approvers, the highest reserved version and the committed approval |
| `approver-<approver ID>.age` | the same file | sealed to that approver's approval passphrase | the destination's first approval is signed by an approver the source already pinned |
| `record-<record ID>.age` | the same file | encrypted to the vault public key; its digest is in the manifest | the credentials |

**Never carried**, and why:

| File | Why not |
|---|---|
| `identity.age` | It is wrapped for the source's recipients. The destination wraps the identity for its own. |
| `operational.age` | It opens with the source's vault passphrase; the destination's owner chooses a new one. |
| `recipients.age` | It describes the source's `identity.age`. The destination writes the inventory of the envelope it writes ([recipients.md](recipients.md#how-other-commands-see-recipients)). |
| `recovery.toml` | It records checks of the source's recovery key, which the destination is not wrapped for. |
| `recipients.age.staged`, `init.unfinished`, temp files | Transient state of a change that never finished, on the source. |
| Unindexed record files and orphan approver key files | The manifest and the approval state do not name them, so they are not part of the vault ([orphan key files](approval-signers.md#orphan-key-files)). |
| `config.toml`, `config.toml.sig` and their pending and staged files | The destination must approve a config of its own before it routes ([Counters and routing](#counters-and-routing)). |
| Host unlock handoff, TPM-sealed material, listener TLS keys | Bound to the source host; [§16](iron-vault-specification.md#16-administration-recovery-and-migration) moves no non-exportable key. |

**The exported identity envelope is not `identity.age`.** [§14](iron-vault-specification.md#14-recipients-startup-and-memory)
forbids an scrypt stanza in `identity.age` beside other recipients, and
[storage-formats.md](storage-formats.md#identity-envelope) holds `identity.age` to X25519 stanzas only. The exported
identity envelope is a separate file with exactly one scrypt stanza, in the format of a
[passphrase envelope](storage-formats.md#passphrase-envelope). It exists only inside a bundle: export builds it in
memory and streams it, and import opens it in memory and never writes it to disk.

**Record files are copied, never decrypted.** [§16](iron-vault-specification.md#16-administration-recovery-and-migration)
step 2 allows copying "already encrypted record files". Export checks each file's BLAKE2b-256 against its manifest
entry and does not decrypt it, so no credential is ever in plaintext for an export. A record file that is missing or
does not match its entry is damage; export refuses it, naming the record, rather than carry a vault that would fail
its own check on the destination. The owner removes or replaces the damaged credential first.

**Every pinned approver's key file is carried.** v0 pins only software approvers, each with its key file. A pinned
approver whose key file is missing or larger than `MAX_PASSPHRASE_ENVELOPE_LEN` is refused by export, naming the
approver ID. TPM and hardware approvers (signer kinds `tpm` and `hardware`, reserved today) are bound to their device
and cannot move; the epic that enrolls one decides how export treats it ([open question 5](#open-questions)).

### Counters and routing

The approval state is copied byte for byte, so import neither lowers nor raises a counter, and it writes no config
file. On the destination's first `unlock`, the config check finds the committed approval with no `config.toml` beside
it, row 7 of the [recovery table](config-approval.md#recovery-table), and the service stays Unavailable with
`PolicyInvalid` ("the committed config or its signature is missing"). Unavailable with `PolicyInvalid` offers
`config approve` (`ServiceState::admin_allows`, `crates/iron-vault/src/service_state.rs`), whose reservation takes the
highest reserved version plus one. So the destination routes only
after a new approval at a higher version than any the source reserved
([§16](iron-vault-specification.md#16-administration-recovery-and-migration) step 5), and no state or edge is added
to the [service state model](iron-vault-specification.md#15-service-states-and-errors).

The source's config is not carried because it was approved for the source host: its listeners, peer accounts and CA
files may not exist on the destination. The config holds no secret, so the owner copies it by hand if it fits, then
approves it. A source config pair copied into the destination's config directory by hand would verify as the committed
approval and serve; see [open question 2](#open-questions).

## Transfer

The bundle travels between the service and the CLI as raw bytes inside the admin exchange, in **bundle data frames**:
a new frame kind, `9`, whose body is up to 65 536 bytes of the bundle, never parsed as fields. An empty bundle data
frame ends the bundle. `export` sends them from the service to the CLI; `import` sends them from the CLI to the service,
right after its admin request. Import counts the bytes against `MAX_BUNDLE_LEN` (260 MiB) and ends the exchange
with `bundle-invalid` past it; export cannot exceed it, because every entry it writes is within its own size limit.

The alternative was a service-owned output path: the service writing the bundle where the admin request names, and
reading it from there on import. It was rejected because the service account would then write and read files where an
admin connection points, and a protected install's service cannot reach the owner's home directory anyway. With
frames, file I/O stays in the CLI, as the owner, and the CLI only ever holds the bundle's bytes, which are ciphertext
and public metadata.

**Export, in the CLI.** Before it sends the request, the CLI refuses a `<bundle>` path that exists, and creates
`.<bundle name>.partial` beside it with `O_CREAT | O_EXCL` and mode `0600`, so a permission problem shows before any
prompt. It appends each frame's bytes. On the success response it checks that the byte count matches the result's,
fsyncs the file, hard-links it to `<bundle>`, which fails if that name appeared meanwhile, removes the partial name and
fsyncs the directory. On any other ending it removes the partial file. A crash can leave the partial file; it never
appears under the name the owner asked for, and import refuses it, because a cut bundle has no end.

**Import, in the CLI.** The CLI opens `<bundle>` read-only and refuses anything but a regular file of at most
`MAX_BUNDLE_LEN`, then streams it after the request. A service that refuses at its first check answers and closes while
the CLI is still sending; the CLI reads the response before it reports a failed write, as for any exchange
([CLI client](admin-protocol.md#cli-client)).

**Memory.** Export streams: it reads one file at a time under the service-wide lock and holds at most one record and
the manifest. Import holds the whole bundle in service memory until its writes end, bounded by `MAX_BUNDLE_LEN`. A full
vault of 4096 records at the record size limit is the worst case; a typical vault's bundle is a few hundred KiB.

## Export

### States

`export` runs only in Ready, which `ServiceContext::begin_migration` already requires
(`crates/iron-vault/src/service_context/migration.rs`). Ready means the vault opened and the config check passed,
so the manifest, the approval state and every record file were verified at the last check. Unavailable also holds the
vault identity, but its vault may be the damage that made it Unavailable. A damaged recipient inventory leaves the
service Ready, and export never reads the inventory, so it does not block a migration
([recipients.md](recipients.md#recipient-inventory)).

### The snapshot

The **export snapshot** is taken at step 10 of the exchange, after the migration authorization is consumed, under the
service-wide lock that the exchange has held since step 2 ([admin exchange](migration-authorization.md#admin-exchange)).
No `add`, `replace`, `rm`, approval or approver change can run in between, so the files read form one consistent vault
([§16](iron-vault-specification.md#16-administration-recovery-and-migration) step 1). In order:

1. Read `manifest.age` and open it with the vault identity; read `approval.age` and open it, and require it to equal
   the approval state the service holds.
2. For each pinned approver, in ascending approver ID, read its key file, bounded by `MAX_PASSPHRASE_ENVELOPE_LEN`,
   and require exactly one scrypt stanza. It is not opened: export never asks for an approval passphrase.
3. For each manifest entry, in ascending record ID, read `record-<record ID>.age`, bounded by `MAX_RECORD_FILE_LEN`,
   and require its digest to equal the entry's.
4. Seal the vault identity's secret text to the export passphrase as the exported identity envelope, at
   `PASSPHRASE_WORK_FACTOR`. Drop the export passphrase.
5. Encode and stream the bundle, entry by entry, in [bundle order](storage-formats.md#entries), then the empty bundle
   data frame.

The store reads each file once and streams it on; the binary relays the bytes into frames. Export writes nothing to the
state or config directory and changes no counter. The source keeps serving after it.

## Import

### States

`import` runs only in Locked, as `init` does, and only on these [initialization states](vault-initialization.md#initialization-state):

| Initialization state | `import` |
|---|---|
| Uninitialized | proceeds |
| Unfinished, by an initialization or by an import | sends a notice, discards it once the owner has confirmed the recovery key, and proceeds |
| Initialized | `already-initialized`; nothing is changed ([§16](iron-vault-specification.md#16-administration-recovery-and-migration): "must not … overwrite an initialized vault implicitly") |
| Unrecognized | `already-initialized`, naming the first offending files; nothing is changed |

Import never overwrites a vault. An Unfinished one never opened and never served, so discarding it overwrites nothing:
its recovery key opens nothing once it is discarded, as `init`'s discard says
([vault-initialization.md](vault-initialization.md#discarding-an-unfinished-initialization)).

A protected install also requires locked memory, as `unlock` and `recovery check` do: import unwraps the vault
identity, so without it import ends with `memory-unprotected` before any prompt.

### The unfinished import

An **unfinished import** is an import that started writing and has not reached its commit point. It is shown by the
empty state-directory file `import.unfinished`, written first and durably removed last, the same way `init.unfinished`
shows an [unfinished initialization](vault-initialization.md#write-order). The initialization state reads it as
Unfinished:

- **Check 1 of the initialization state** also matches `import.unfinished`. With it, the state is Unfinished if the
  state directory holds nothing but the ignored names, the files an import writes (`import.unfinished`, `identity.age`,
  `recipients.age`, `operational.age`, `manifest.age`, `approval.age`, approver key files and record files) and
  `recovery.toml`, and the config directory holds none of the four config files. Import writes no config file, so any
  config file beside `import.unfinished` makes the state Unrecognized. Both markers together are Unrecognized: no run
  writes both.
- **`unlock`** refuses it with `unlock-failed`, saying an import is unfinished or in progress and to run
  `iron-vault import` again, or `iron-vault init` for a new vault. `recovery check` answers
  `recovery-check-unavailable`, and `status` names it "import unfinished (run iron-vault import again)".
- **The discard** removes, each with `durable_remove` and only those present: `recovery.toml`, `approval.age`,
  `manifest.age`, the record files, the approver key files, `operational.age`, `recipients.age` and `identity.age`.
  The marker stays, so a crash during the discard reads Unfinished again.
- **Either command discards either kind.** `import` and `init` each discard an unfinished initialization and an
  unfinished import. When the kind changes, the discard ends by removing the other command's marker durably, which
  leaves Uninitialized, and the command's step 1 then writes its own. A crash between the two reads Uninitialized,
  which either command starts from.

### Write order

Every write happens after the owner's `yes` at the recovery key confirmation, under the service-wide lock, after the
second state check. Each step is durable before the next starts.

| Step | What the service does | Durable change |
|---|---|---|
| 1 | Removes a leftover `recovery.toml` on Uninitialized, as `init` does ([recovery.md](recovery.md#initialization)), or discards an unfinished vault. Writes the empty file `import.unfinished`. | `import.unfinished` |
| 2 | Writes every record file, in ascending record ID: each to its temp file, fsynced and renamed, then one fsync of the state directory for the step. | `record-<record ID>.age` |
| 3 | Writes every approver key file, in ascending approver ID, with `durable_replace`. | `approver-<approver ID>.age` |
| 4 | Writes `approval.age`, the bundle's bytes. | `approval.age` |
| 5 | Wraps the vault identity for {the new operational recipient key, the new recovery recipient key} with `wrap_identity` and writes it; reads it back and unwraps it once with each identity, requiring the bundle's vault identity each time. Then writes the recipient inventory: the `operational` and `recovery` entries, labelled `vault passphrase` and `recovery key`, enrolled at the import time, with the digest of the envelope as read back; reads it back. This is `init`'s step 2. | `identity.age`, then `recipients.age` |
| 6 | Seals the operational identity to the new vault passphrase and writes it. This is `init`'s step 3. | `operational.age` |
| 7 | Writes `manifest.age`, the bundle's bytes. | `manifest.age` |
| 8 | Opens the vault from disk with the vault identity, as `unlock`'s config check would: the manifest's MAC and every record file's digest, and the approval state's MAC and its pairing with the manifest. | none |
| 9 | Removes `import.unfinished` with `durable_remove`. **This is the import's commit point.** | `import.unfinished` removed |

Notes on the steps:

- **Step 2's one directory fsync** keeps a large import inside the CLI's 60-second timeout: the marker already makes
  every record file part of the unfinished import until step 9, so a record file a crash loses is discarded with the
  rest. Step 8 proves every one is on disk before the commit.
- **Steps 4 and 7 copy bytes.** The manifest and the approval state keep their state and peer generations, so they pair
  on the destination exactly as on the source ([state generation](storage-formats.md#state-generation)). Nothing is
  re-sealed, so nothing can change a counter.
- **Step 7 is last of the vault files** so the manifest, which says which records exist, is written only once all of
  them are. The marker alone decides the state, so this order is for the reader of a crashed directory, not for
  correctness.
- **Step 9's failed directory fsync** comes after the unlink, as `init`'s does: the vault reads Initialized now and may
  read Unfinished after a power loss. Import ends with `import-failed` naming step 9, with the
  [unknown-outcome advice](vault-initialization.md#failing-after-the-reveal), worded for `import`.

### Crash table

What each command does after a crash, or any failure, following each step. `status` answers in Locked in every row.

| Last step durable | Initialization state | `unlock` | `import` again | `init` |
|---|---|---|---|---|
| none | Uninitialized | `unlock-failed`: not initialized | removes a leftover `recovery.toml`, then proceeds from step 1 | proceeds |
| 1 `import.unfinished` | Unfinished | `unlock-failed`: import unfinished or in progress | notice, discards (nothing yet), proceeds | notice, discards, removes `import.unfinished`, proceeds |
| 2 to 7, any part | Unfinished | as row 1 | notice, discards whichever files exist, proceeds | as row 1, discarding whichever files exist |
| 8 (no write) | Unfinished | as row 1 | as row 2 | as row 2 |
| 9 `import.unfinished` removed | Initialized | prompts for the new vault passphrase; the config check ends Unavailable with `PolicyInvalid`, committed config missing | `already-initialized` | `already-initialized` |
| any step, with a config file or a foreign file present | Unrecognized | `unlock-failed`: names the first file | `already-initialized`: names the first file; nothing is changed | as `import` |

## Admin exchanges

### Export

`export` (command 19) takes no arguments; the bundle path stays in the CLI. It runs the
[migration authorization exchange](migration-authorization.md#admin-exchange); its own parts are:

| Step | What the service does | Refusal |
|---|---|---|
| 1 | Ready, holding the vault identity | `wrong-state` |
| 2 | Try the service-wide lock, recording the state and check generation | `busy` |
| 3 | No checks of its own | |
| 4 | The summary, below | |
| 5–7 | Migration authorization: challenge, `Vault passphrase`, proof | `busy`, `migration-unavailable`, `migration-rate-limited`, `migration-denied` |
| 8 | Two secret prompts: `Export passphrase`, `Repeat the export passphrase`, checked by the [passphrase rules](vault-initialization.md#passphrase-rules) once both are in | `passphrase-rejected` |
| 9 | Same state and check generation; consume the authorization | `wrong-state`, `migration-denied` |
| 10 | The [snapshot](#the-snapshot), streamed as bundle data frames, then the empty frame | `export-failed` |
| 11 | The success response: the vault ID, the record count and the bundle's byte count | |

The summary extends the one in [migration-authorization.md](migration-authorization.md#admin-exchange) with the counts:

```text
export the vault
  vault: 3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b
  credentials: 1
  approvers: 1
  authorize with: the vault passphrase
  then: a new export passphrase to protect the migration bundle
```

After success the CLI prints the path, the vault ID, the credential count and the size, then that the source keeps
serving until the owner retires it, and that the bundle opens only with the export passphrase.

**The export passphrase rules** are the vault passphrase's: typed twice, at least 12 Unicode scalar values, compared
in constant time ([passphrase rules](vault-initialization.md#passphrase-rules)). The service does not compare it with
the vault passphrase: migration authorization drops that at step 7, and keeping it to step 8 to compare would hold a
secret for no protection the length rule does not give. The notice before the prompt says to choose a passphrase used
nowhere else. There is no second try in the exchange.

**Work factor.** The exported identity envelope is sealed at `PASSPHRASE_WORK_FACTOR` (2^18), the work factor of
`operational.age`, so every machine that can unlock a vault can import its bundle, inside the service's locked memory.
A higher factor would slow an offline guess at a stolen bundle, at the cost of 1 GiB of locked memory per attempt at
2^20; the 12-character minimum is the defence this design relies on.

### Import

`import` (command 20) takes no arguments; the bundle follows the request as bundle data frames.

| Step | What the service does | Refusal |
|---|---|---|
| 1 | Locked; locked memory in a protected install; the initialization state is Uninitialized or Unfinished, with the Unfinished notice when it is | `wrong-state`, `memory-unprotected`, `already-initialized` |
| 2 | Read the bundle data frames to the empty one, at most `MAX_BUNDLE_LEN`; decode the bundle ([one encoding per bundle](storage-formats.md#one-encoding-per-bundle)) | `bundle-invalid` |
| 3 | A secret prompt, `Export passphrase`; open the exported identity envelope | `import-denied` |
| 4 | Verify the bundle with the vault identity (below) | `bundle-invalid` |
| 5 | The summary, below | |
| 6 | Two secret prompts, `Vault passphrase` and `Repeat the vault passphrase`, by the [passphrase rules](vault-initialization.md#passphrase-rules) | `passphrase-rejected` |
| 7 | Generate the operational identity and the recovery key; the [recovery key presentation](vault-initialization.md#recovery-key-presentation): notice, reveal, `Type yes once you have saved the recovery key` | `declined` |
| 8 | Try the service-wide lock; Locked and the initialization state again; the [write order](#write-order) | `busy`, `wrong-state`, `already-initialized`, `import-failed` |
| 9 | The success response: the vault ID, the record count, the committed version and the highest reserved version | |

**Step 4 verifies** what the destination will trust, before any write: the manifest opens with the vault identity and
names the header's vault ID; the approval state opens, names the same vault ID and pairs with the manifest; the
manifest's entries and the record entries name the same record IDs, and each record file's digest equals its entry's;
the approver key files name exactly the pinned approvers; and the counts equal the header's. Each failure names the
check, never a byte of the bundle.

**The import summary** is built from the verified files only, never from the header alone:

```text
import a migration bundle
  vault: 3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b
  credentials: 1
  approvers: approval passphrase
  committed approval: version 1; highest reserved version: 2
  then: a new vault passphrase and a new recovery key for this machine
  routing starts after iron-vault config approve, at version 3 or later
```

After success the CLI prints the next steps: `iron-vault unlock`, then `iron-vault config approve <config>` with one of
the approvers listed, then `iron-vault recovery check` with the new key, and only then retiring the source
([§16](iron-vault-specification.md#16-administration-recovery-and-migration) step 6).

**Prompts are not under a lock, and writes are**, as for `init`: step 8 takes the service-wide lock without waiting
and reads both states again, because another `init` or `import` may have run during the prompts. The endings after the
reveal follow [Failing after the reveal](vault-initialization.md#failing-after-the-reveal), with `import-failed` and
`iron-vault import` in place of `init-failed` and `iron-vault init`.

**A wrong export passphrase is not rate-limited.** Whoever holds the bundle can guess at it offline at scrypt's cost,
so a limit in the service would slow nobody. The exchange ends at the first wrong passphrase.

**The approval passphrase is not asked for.** The carried approver key files are opened at the destination's first
`config approve`. The summary lists the approvers by label, so the owner sees which approval passphrases still work
before writing anything. If none does, the source still works, and the owner exports again after enrolling an approver
there.

### Error codes

Four codes join the [admin protocol's table](admin-protocol.md#admin-response-error-kind-5):

| Code | Name | Meaning |
|---|---|---|
| `45` | `export-failed` | `export`: the snapshot or the transfer failed after the authorization was consumed; the message names the step and, for a file, its name and the error kind; no bundle was completed |
| `46` | `bundle-invalid` | `import`: the bytes are not a migration bundle this version reads, exceed `MAX_BUNDLE_LEN`, or fail a check with the vault identity; the message names the rule or check, never a byte of the bundle; nothing was written |
| `47` | `import-denied` | `import`: the export passphrase does not open the exported identity envelope; nothing was written |
| `48` | `import-failed` | `import`: a write failed; the message names the step, says to run `import` again, which discards the unfinished import, and gives the recovery key advice of [Failing after the reveal](vault-initialization.md#failing-after-the-reveal) |

Existing codes widen to the new commands: `busy` (6) and `wrong-state` (13) to both; `passphrase-rejected` (18) to
both; `declined` (8), `already-initialized` (17) and `memory-unprotected` (27) to `import`. `export` already raises
`migration-denied` (28), `migration-unavailable` (29) and `migration-rate-limited` (33).

### Audit events

These are audit events in the [catalogue](audit-logging.md#catalogue), under the `migration` subject. None carries a
passphrase, a key or a byte of a record.

| Event | Level | When | Fields |
|---|---|---|---|
| `migration.exported` | INFO | the last bundle data frame of an export was written | `vault_id`, `records`, `approvers`, `committed_version`, `highest_reserved` |
| `migration.export-failed` | WARN | an export failed after its authorization was consumed | `step` (`snapshot`, `seal` or `transfer`), `error_kind`; `file` when a file failed |
| `migration.import-refused` | WARN | an import was refused at steps 2 to 4 | `refusal` (`bundle_invalid` or `wrong_passphrase`); `detail`, the fixed name of the failed rule or check, for `bundle_invalid` |
| `migration.import-discarded` | WARN | an unfinished import was discarded, by `import` or `init` | `files` |
| `migration.imported` | INFO | the import's step 9 is durable | `vault_id`, `records`, `approvers`, `committed_version`, `highest_reserved`, `recipients`: the enrolled roles' names |
| `migration.import-failed` | WARN | an import write step failed | `step`, `error_kind` |

An unfinished initialization that `import` discards is recorded as `vault.init-discarded`, as when `init` discards it:
the event names what is discarded, not who discarded it.

Two fields are new: `records`, the number of credential records a bundle carries, and `highest_reserved`, the highest
reserved approval version. `approvers` widens to the approver count a bundle carries.

`migration.exported` follows the exchange's `migration.authorized`, closing it. An export that ends after the
authorization at step 8 or 9 adds no record of its own, as [migration-authorization.md](migration-authorization.md#audit-events)
says.

## Release checks

[§19](iron-vault-specification.md#19-v0-user-acceptance) asks that "Export/import preserves records, counters,
recovery access, and the service boundary without writing plaintext secret artifacts", and that export rejects
"missing, incorrect, expired, replayed, or cancelled source-owner authorization". The authorization cases are tested
by the migration authorization rejection suite, whose rows name `export` ([release checks](migration-authorization.md#release-checks)).
Each part of the first bullet is one test in `crates/iron-vault/tests/migration_linux.rs`, each moving a vault between
two service instances with their own state directories:

| §19 part | Test | What it proves |
|---|---|---|
| records | `export_import_preserves_records` | Every record ID, name and record file's bytes on the destination equal the source's, and a request through each route resolves the same credential |
| counters | `export_import_preserves_counters` | The destination's highest reserved and committed versions equal the source's; the first `config approve` commits the highest reserved plus one; the source's old config and signature pair copied over fails as superseded after it |
| routing waits for approval | `import_routes_only_after_new_approval` | After `unlock` the destination is Unavailable with `PolicyInvalid` and answers no route until `config approve` |
| recovery access | `import_recovery_key_opens_destination` | The recovery key the import revealed passes `recovery check` on the destination; the source's recovery key does not |
| service boundary | `export_bundle_holds_no_plaintext_secret` | Neither the bundle file, the CLI's output, nor any file written under the CLI's or the services' directories holds a credential's secret bytes or the vault identity's text; the destination's `identity.age` holds no scrypt stanza |
| service boundary | `import_requires_export_passphrase` | A wrong export passphrase writes nothing and ends with `import-denied` |
| no overwrite | `import_refuses_initialized_vault` | Import into an Initialized or Unrecognized directory changes nothing and ends with `already-initialized` |
| safe archive paths | `import_refuses_unsafe_bundles` | Bundles with an absolute name, `..`, a link, a directory, a device, a duplicate, an unknown name, a pax or GNU header, an oversized entry, trailing bytes, or more than `MAX_BUNDLE_LEN` bytes each end with `bundle-invalid` and write nothing |
| crash | `import_crash_is_discarded` | A fault at each write step leaves Unfinished, which `unlock` refuses and the next `import` discards and completes |

The store's bundle codec has its own unit tests for every [decoding rule](storage-formats.md#one-encoding-per-bundle).

## Open questions

Each point below is open in the specification or decided here against a reading of it. The design takes the default
stated for each, until the owner decides.

1. **Open question for the owner: recovery access after import.**
   [§19](iron-vault-specification.md#19-v0-user-acceptance): "Export/import preserves records, counters, recovery
   access, and the service boundary". [recipients.md](recipients.md#how-other-commands-see-recipients): "`export` and
   `import` (EP-30) carry no inventory from the source: an import wraps the vault identity for the destination's own
   recipients and writes the destination's own inventory." *Default:* import generates a new recovery key and reveals
   it, as `init` does, so the destination has two independent ways in from its commit point. "Recovery access" is read
   as the destination having a working recovery path, proved by `recovery check`, not as the old key working there.
   This keeps import independent of the source's recipient inventory, so a damaged inventory never blocks a migration,
   and rotates the recovery key as a side effect. *Alternative:* the bundle carries the source's `recipients.age`, and
   import wraps for its `recovery` entries, so the owner's existing recovery key keeps working and import reveals
   nothing. That needs a fallback when the source inventory is damaged, since it is the one documented way out of that
   damage ([recipients.md](recipients.md#recipient-inventory)), and it changes the recipients.md sentence above.
2. **Open question for the owner: a hand-copied config pair.**
   [§16](iron-vault-specification.md#16-administration-recovery-and-migration) step 5: "requires a new approval with a
   higher version before routing". *Default:* the bundle carries no config, so the destination cannot route until
   `config approve`. The owner who copies the source's `config.toml` and `config.toml.sig` into the destination's config
   directory by hand gets the committed approval served without a new one: the pair names the same vault and a pinned
   approver. That needs root on the destination, which the specification trusts
   ([§2](iron-vault-specification.md#2-security-promise-and-limits)). *Alternative:* the approval state marks its
   committed approval as imported, a new committed tag, which the config check treats as nothing committed for serving
   while keeping its version as a counter. That is a format change to approval state payload v1 and to recovery.
3. **The ticket's "refuse Unfinished".** The ticket asked import to refuse an Unfinished vault. *Default:* import and
   `init` each discard either kind of unfinished vault, because a refusal would leave an owner whose import crashed
   with no command that starts over, and an Unfinished vault never opened or served.
4. **"Bundle passphrase" and "export passphrase".**
   [§16](iron-vault-specification.md#16-administration-recovery-and-migration) uses both for one secret ("require the
   bundle passphrase on import"; "That export passphrase encrypts the bundle"). *Default:* the glossary keeps
   *export passphrase*, and the import prompt is `Export passphrase`, so the owner types it under the name it was
   chosen under.
5. **Device-bound approvers.** A `tpm` or `hardware` approver's key cannot move. *Default:* left to the epic that
   enrolls the first one (EP-33 for `tpm`); v0 decodes neither kind, so no v0 bundle holds one.
6. **Import into the Container profile.** `init --host-unlock` enrolls a host unlock recipient at init. *Default:*
   import has no `--host-unlock`; the owner adds the recipient afterwards with `recipient add --host-unlock`, and the
   container starts Locked until then.

## Implementation tickets

Each ticket updates the design documents and glossary entries it changes, in the same branch as its code.

| Order | Ticket | What | Depends on | Updates |
|---|---|---|---|---|
| 1 | K-308 | Store: the exported identity envelope, sealed and opened with the export passphrase | K-307 | storage-formats.md "Exported identity envelope" (Rust names); glossary "Export passphrase" and "Exported identity envelope" (Rust types) |
| 2 | K-309 | Store: the migration bundle codec | K-307 | storage-formats.md "Migration bundle v1" and the magic table (Rust names); glossary "Migration bundle" and "Bundle header" (Rust types) |
| 3 | K-310 | Store: the export snapshot | K-308, K-309 | |
| 4 | new | Protocol and CLI: the bundle data frame, commands 19 and 20, error codes 45 to 48 | K-307 | admin-protocol.md (frame kinds, exchange, commands, error codes, Versions); glossary "Bundle data frame" (Rust types) |
| 5 | new | Store: the unfinished import in the initialization state, and its discard | K-307 | vault-initialization.md "Initialization state", "Discarding an unfinished initialization" and the crash table; recovery.md "Initialization"; storage-formats.md, an "Unfinished import file" section; glossary "Unfinished import" and "Initialization state" |
| 6 | K-311 | `iron-vault export` | K-310, ticket 4 | audit-logging.md (`migration.exported`, `migration.export-failed`, the new fields); the manual's CLI, errors and audit log references |
| 7 | K-312 | Store: the import write order | K-308, K-309, ticket 5 | |
| 8 | K-313 | `iron-vault import` | K-312, ticket 4 | audit-logging.md (the `migration.import-*` events and `migration.imported`); the manual's CLI, errors, audit log and states references |
| 9 | K-314 | Migration release checks and the manual | K-311, K-313 | README features; the manual: the migration recipe out of the roadmap, the files reference |
