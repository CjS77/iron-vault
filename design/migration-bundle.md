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

- **Nothing in the bundle is plaintext secret.** The manifest, the approval state and the record files are already
  encrypted on disk and are copied byte for byte. Each approver key envelope is encrypted again, to the vault
  recipient, so it opens only once the export passphrase has opened the vault identity. The config holds no secret.
  The vault identity is sealed under the export passphrase. Neither the CLI nor any file ever holds a plaintext secret
  ([§16](iron-vault-specification.md#16-administration-recovery-and-migration) step 2).
- **The counters move unchanged.** The approval state is copied as it is, so the destination's highest reserved
  version and committed approval are the source's, and the destination's first approval is above every version the
  source ever reserved ([§12](iron-vault-specification.md#12-configuration-approval-and-reload)).
- **The destination makes its own ways in.** The bundle carries no recipient of the source. Import wraps the vault
  identity for a new vault passphrase and a new recovery key, and with `--host-unlock` for this machine's host unlock
  identity, as `init` does ([§14](iron-vault-specification.md#14-recipients-startup-and-memory)).
- **Import makes a vault only where none is.** It runs only where `init` could, and like `init` it has one commit
  point, so a crash leaves a state the next run discards.

The owner's decisions are marked *Decided*. Every default this design picks where the specification is silent, or
where it reads the specification one way of two, is listed under [Open questions](#open-questions).

## What the bundle holds

The vault is the set of state-directory files that the vault identity decrypts or authenticates. The bundle carries the
files that make up its credentials, its counters and its approvers, the committed config, and the vault identity
sealed for the transfer:

| Bundle entry | From | Why it is safe to copy | Why it is carried |
|---|---|---|---|
| `bundle-header` | built by `export` | holds only the vault ID and two counts | names the bundle format version, and lets import refuse a foreign file before any prompt |
| `exported-identity.age` | built by `export` | the vault identity's secret text sealed to the export passphrase | the destination needs the vault identity to open everything else |
| `manifest.age` | `manifest.age` | encrypted to the vault public key, MAC'd with the manifest key | the record IDs, names and file digests; preserves record identities ([§16](iron-vault-specification.md#16-administration-recovery-and-migration) step 5) |
| `approval.age` | `approval.age` | encrypted, MAC'd with the approval key | the pinned approvers, the highest reserved version and the committed approval |
| `config.toml` | the config directory's `config.toml` | holds no secret; its digest must equal the committed config digest in the MAC'd approval state | the destination approves it once for the new host instead of the owner copying it by hand ([The config](#the-config)) |
| `approver-<approver ID>.age` | the same file, encrypted to the vault public key | a [bundled approver key](storage-formats.md#entries): opens only with the vault identity, which needs the export passphrase; the envelope inside is sealed to that approver's approval passphrase | the destination's first approval is signed by an approver the source already pinned |
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
| `config.toml.sig` | The destination approves the config for itself before it routes ([§16](iron-vault-specification.md#16-administration-recovery-and-migration) step 5; [The config](#the-config)). |
| `config.toml.pending`, `config.toml.sig.staged` | Leftovers of an approval that never committed, on the source. |
| Host unlock handoff, TPM-sealed material, listener TLS keys | Bound to the source host; [§16](iron-vault-specification.md#16-administration-recovery-and-migration) moves no non-exportable key. |
| The owner-lock file (`locked-by-owner`), which TPM unlock adds to the state directory | It records an owner's `lock` on the source host; the destination starts with none. |

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

**Every pinned approver's key file is carried, under the export passphrase.** v0 pins only software approvers, each
with its key file. An approver key envelope is sealed only to its approval passphrase, which a party holding a copy
could guess at offline, and §16 step 2 puts every secret-bearing entry under the export passphrase. So export encrypts
each key file, unopened, to the vault public key, and the bundle entry is that `age` file. Import opens it with the
vault identity it got from the export passphrase and writes the envelope inside, byte for byte. A pinned approver whose
key file is missing, larger than `MAX_PASSPHRASE_ENVELOPE_LEN`, or not one scrypt stanza within the work factor
bounds is refused by export, naming the approver ID. Anyone who knows the vault public key could put another envelope
in the entry, but the pinned public key in the MAC'd approval state decides whose signature counts, so a substitute
only fails to sign. TPM and hardware approvers (signer kinds `tpm` and `hardware`, reserved today) are bound to their
device and cannot move; the epic that enrolls one decides how export treats it ([open question 3](#open-questions)).

### The config

*Decided (owner, 2026-11-11).* The bundle carries the source's committed `config.toml`, and not its signature.
Requiring the owner to copy the config by hand was friction for no protection: the config holds no secret, and the
approval state already names its digest. Import writes it into the destination's config directory unchanged, and the
vault routes only after the owner approves it once, on the destination:

- **Authenticated by the vault.** Export reads `config.toml` from the config directory and requires its BLAKE2b-256
  to equal the committed config digest. Import requires the same of the bundle's entry against the approval state the
  vault identity opened, so a changed config entry is refused as `bundle-invalid`.
- **Unsigned on the destination.** Import writes `config.toml` and no `config.toml.sig`. On the destination's first
  `unlock`, the config check finds the committed approval's config with no signature beside it, row 7 of the
  [recovery table](config-approval.md#recovery-table), and the service stays Unavailable with `PolicyInvalid`.
  Unavailable with `PolicyInvalid` offers `config approve` (`ServiceState::admin_allows`,
  `crates/iron-vault/src/service_state.rs`). Until then the request listeners are a provisional listener set, bound
  from the unverified `config.toml`, and answer every request with `503` (`ServiceState::listener_provenance`).
- **One approval, at a new version.** The CLI writes its own copy of the config beside the bundle
  ([The config copy](#the-config-copy)) and prints the exact command, such as
  `iron-vault config approve vault.bundle.config.toml`. That approval asks an approval passphrase and
  reserves the highest reserved version plus one, so the destination routes only after a new approval at a version
  above any the source reserved ([§16](iron-vault-specification.md#16-administration-recovery-and-migration) step 5).
  No state or edge is added to the [service state model](iron-vault-specification.md#15-service-states-and-errors).
- **Reviewed for the new host.** The config was approved for the source host: its listeners, peer accounts and CA files
  may not exist on the destination. The first approval's summary therefore shows the whole config, as for any approval
  with no active config ("no active config", everything added), and never the "same config" line, which the
  [approval summary](config-approval.md#approval-summary) prints today whenever the pending digest equals the committed
  one. That line is limited to a service with an active config whose digest it equals; the import ticket makes the
  change. To change the config for the new host, the owner approves an edited copy instead.

The rejected alternative carried `config.toml.sig` too, so the vault would serve at once. It needs §16 step 5 changed,
and it would serve a config approved for the old host's listeners, peer accounts and CA files without a review.

**A signature copied by hand.** Root on the destination can copy the source's `config.toml.sig` beside the imported
`config.toml`. It verifies as the committed approval, and the vault serves without a new one. Root is trusted
([§2](iron-vault-specification.md#2-security-promise-and-limits)) and could equally approve the config, so the design
does not stop it.

#### The config copy

*Decided (owner, 2026-11-11).* `config approve` reads its file in the CLI
([CLI client](admin-protocol.md#cli-client)), and the CLI cannot always read the service's config directory. In the
Compose profile `/etc/iron-vault` is a named volume inside the container, and the owner runs `sudo iron-vault` on the
host, not inside it ([docker-compose.md](docker-compose.md#admin-access)); over a forwarded admin socket the service's
files are on another machine. The CLI does hold the bundle, so it gives the owner a copy of the config from there:

- Before it sends the request, the CLI creates `<bundle>.config.toml` beside the bundle with `O_CREAT | O_EXCL` and
  mode `0600`, so a name already taken shows before any prompt; the error names the file, for the owner to move.
- After the success response, the CLI decodes the bundle with the store's bundle decoder up to the `config.toml` entry,
  the fifth, opening no `age` entry. It requires the entry's BLAKE2b-256 to equal the committed config digest in the
  result, which the service took from the approval state the vault identity opened, then writes the entry to the
  copy and fsyncs it. So the CLI holds only the config, which is no secret, and ciphertext, as
  [§16](iron-vault-specification.md#16-administration-recovery-and-migration) step 2 asks.
- On any ending but success, the CLI removes the copy. If the import committed but the copy cannot be written or does
  not match, as when the bundle file changed during the import, the CLI removes it too, says so, and prints the digest
  `blake2b:<hex>` for the owner to check their own copy of the source's config against before approving it.

The service still writes `config.toml` into its own config directory at write step 5: the provisional listener set
and the config check read it there. The copy is only what the owner approves.

*Alternative:* the CLI writes no copy. The result carries the committed config digest, and the CLI tells the owner to
approve their own copy of the source's config and to check it against `blake2b:<hex>` first. It needs no bundle
decoding in the CLI, but leaves the owner to find and carry the source's config by hand, the friction the bundled
config was chosen to remove.

### Counters and routing

The approval state is copied byte for byte, so import neither lowers nor raises a counter. The destination's first
approval commits at least the highest reserved version plus one ([The config](#the-config)), and from then on the
source's config and signature pair is superseded on the destination as on any vault.

**A bundle is not a freshness proof.** An old bundle imports with its old counters, as
[§16](iron-vault-specification.md#16-administration-recovery-and-migration) warns of any restored backup. The import
summary shows the committed version and the highest reserved version; before retiring the source, the owner compares
them with the source's `status`, which shows both while it is Ready. A source that has approved since the export shows
higher versions, and the owner exports again.

### Recovery access

*Decided (owner, 2026-11-11).* Import creates a new recovery key and shows it once, as `init` does, so the destination
has two independent ways in from its commit point.
[§19](iron-vault-specification.md#19-v0-user-acceptance) asks that export and import preserve "recovery access"; it is
read as the destination having a working recovery path, which `recovery check` proves, not as the old key working
there. This keeps import independent of the source's recipient inventory, which the bundle does not carry
([recipients.md](recipients.md#how-other-commands-see-recipients)), so a damaged inventory never blocks a migration,
and it rotates the recovery key as a side effect. The source's recovery key keeps opening the source and every copy
of its files until the source is retired.

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

**Deadlines.** Each bundle data frame must be written or read within the request deadline (30 seconds), and the whole
bundle within the **bundle transfer deadline** of 10 minutes, enough for a full bundle over a slow forwarded socket.
Export streams while it holds the service-wide lock, so a stalled CLI would otherwise block `lock`, approvals, reloads
and reset for as long as it stalls. A missed export deadline ends the export with `export-failed` (step `transfer`)
when the CLI can still be written to, and with a close otherwise. A missed import deadline closes the exchange without a
response, as a request that never arrives does, and is logged at WARN as a cancellation. Import receives before it
takes the lock, so its deadlines bound its memory, not the lock.

**Export, in the CLI.** Before it sends the request, the CLI refuses a `<bundle>` path that exists, and creates
`.<bundle name>.partial` beside it with `O_CREAT | O_EXCL` and mode `0600`, so a permission problem shows before any
prompt. A partial file left by a crashed export makes that create fail; the CLI's error names the file, for the owner to
remove. It appends each frame's bytes. On the success response it checks that the byte count matches the result's,
fsyncs the file, hard-links it to `<bundle>`, which fails if that name appeared meanwhile, removes the partial name and
fsyncs the directory. On any other ending it removes the partial file. A crash can leave the partial file; it never
appears under the name the owner asked for, and import refuses it, because a cut bundle has no end.

**Import, in the CLI.** The CLI opens `<bundle>` read-only and refuses anything but a regular file of at most
`MAX_BUNDLE_LEN`, then streams it after the request. A service that refuses at its first check answers and closes while
the CLI is still sending; the CLI reads the response before it reports a failed write, as for any exchange
([CLI client](admin-protocol.md#cli-client)).

**Memory.** Export streams: it reads one file at a time under the service-wide lock and holds at most one record, the
manifest, the config and the bundled approver keys. Import decodes as frames arrive: each frame is inflated as it comes
in and each entry header is checked as soon as its 512 bytes are there, so a bundle that breaks a rule is refused at
that point and the compressed bytes are never held whole. Import keeps the decoded entries until its writes end,
bounded by `MAX_BUNDLE_LEN`; a full vault of 4096 records at the record size limit is the worst case, and a typical
vault's bundle is a few hundred KiB. A protected install locks all its memory, so those entries sit in locked RAM beside
the scrypt runs of exchange step 3 and write step 7 (256 MiB each, one at a time). **One import at a time** past its
first step bounds this: the service holds an import slot from the end of step 1 until the exchange ends, and a second
import is refused with `busy` at step 1.

## Export

### States

`export` runs only in Ready, which `ServiceContext::begin_migration` already requires
(`crates/iron-vault/src/service_context/migration.rs`). Ready means the vault opened and the config check passed,
so the manifest, the approval state, the published config pair and every record file were verified at the last check.
Unavailable also holds the vault identity, but its vault may be the damage that made it Unavailable. A damaged
recipient inventory leaves the service Ready, and export never reads the inventory, so it does not block a migration
([recipients.md](recipients.md#recipient-inventory)).

### The snapshot

The **export snapshot** is checked at step 3 of the exchange and read at step 10, after the migration authorization
is consumed, both under the service-wide lock that the exchange holds from step 2
([admin exchange](migration-authorization.md#admin-exchange)). No `add`, `replace`, `rm`, approval or approver change
can run in between, so the files read form one consistent vault
([§16](iron-vault-specification.md#16-administration-recovery-and-migration) step 1).

**At step 3**, before any prompt, the read-only checks run, so a damaged vault is refused before the owner spends an
authorization or chooses an export passphrase:

1. Read `manifest.age` and open it with the vault identity; read `approval.age` and open it, and require it to equal
   the approval state the service holds.
2. Read `config.toml`, bounded by `MAX_CONFIG_LEN`, and require its BLAKE2b-256 to equal the committed config digest.
3. For each pinned approver, in ascending approver ID, read its key file, bounded by `MAX_PASSPHRASE_ENVELOPE_LEN`,
   and require exactly one scrypt stanza with a work factor no higher than `MAX_PASSPHRASE_WORK_FACTOR`. It is not
   opened: export never asks for an approval passphrase.
4. Read each record file the manifest names, one at a time and bounded by `MAX_RECORD_FILE_LEN`, and require its
   BLAKE2b-256 to equal its manifest entry's. No record file is kept.

**At step 10**, in order:

1. Read the manifest, the approval state, `config.toml` and the approver key files again, with the checks of step 3,
   and encrypt each approver key file to the vault public key as its bundled approver key.
2. Seal the vault identity's secret text to the export passphrase as the exported identity envelope, at
   `PASSPHRASE_WORK_FACTOR`. Drop the export passphrase.
3. Encode and stream the bundle, entry by entry, in [bundle order](storage-formats.md#entries), then the empty bundle
   data frame. Each record file is read again when its turn comes, and its digest is checked against its manifest
   entry before any of its bytes are sent.

The files are read again at step 10 rather than kept from step 3, so export holds one record at a time. The lock holds
off the service's own writers in between; the checks repeat because the bytes sent are the bytes read at step 10.

Between frames export checks for a waiting `lock`, through the same cancellation that cancels a prompt, and for its
deadlines. A `lock` ends the export with `export-failed` (step `transfer`, "cancelled by lock"), and the lock then
takes the service-wide lock. At step 10 the store reads each file once and streams it on; the binary relays the bytes
into frames. Export writes nothing to the state or config directory and changes no counter. The source keeps serving
after it. A credential or approval changed on the source after the export is not in the bundle: once imported, the
destination is the single active writer ([§16](iron-vault-specification.md#16-administration-recovery-and-migration)),
so the owner makes changes there, or exports again.

## Import

### States

`import` runs only in Locked, as `init` does, and only on these [initialization states](vault-initialization.md#initialization-state):

| Initialization state | `import` |
|---|---|
| Uninitialized | proceeds |
| Unfinished, by an initialization or by an import | sends a notice, discards it once the owner has confirmed the recovery key, and proceeds |
| Initialized | `already-initialized`; nothing is changed ([§16](iron-vault-specification.md#16-administration-recovery-and-migration): "must not … overwrite an initialized vault implicitly") |
| Unrecognized | `already-initialized`, naming the first offending files; nothing is changed |
| Unfinished reset: the reset marker `reset.unfinished` is present | `already-initialized`, saying a reset was interrupted and to run `iron-vault reset` again; nothing is changed |

Import never overwrites a vault. An Unfinished one never opened and never served, so discarding it overwrites nothing:
its recovery key opens nothing once it is discarded, as `init`'s discard says
([vault-initialization.md](vault-initialization.md#discarding-an-unfinished-initialization)). An interrupted reset is
refused, as `init` refuses it, because only `reset` finishes one. The reset design checks its marker before every other
state, so an import marker beside it never decides anything. A release without reset never writes `reset.unfinished`,
and reads one as a foreign file, which is Unrecognized and refused all the same.

A protected install also requires locked memory, as `unlock` and `recovery check` do: import unwraps the vault
identity, so without it import ends with `memory-unprotected` before any prompt.

### Destination recipients

*Decided (owner, 2026-11-11).* Import wraps the vault identity for the destination's own recipients, never the
source's: the `operational` recipient for the new vault passphrase, the `recovery` recipient for the new recovery key,
and, with `--host-unlock`, a `host-unlock` recipient for this machine's host unlock identity. So
[§16](iron-vault-specification.md#16-administration-recovery-and-migration) step 4, "wraps the recovered identity for
the destination TPM, hardware key, or separate operational passphrase recipient", holds as written for the TPM.

`import --host-unlock` is `init --host-unlock`'s handling, reused: it is accepted wherever `init --host-unlock` is, and
sets the same request flag. Before any prompt, the service reads the [unlock handoff](docker-compose.md#enrollment) as
Starting does; a profile that has no host unlock, an absent handoff or a refused one ends with `import-failed`, naming
the reason and nothing of the file's bytes, and nothing is written. Write step 6 then wraps for the third recipient,
proves it opens `identity.age` as it proves the other two, and adds the `host-unlock` entry labelled `host unlock` to
the inventory, as `init`'s step 2 does ([recipients.md](recipients.md#initialization)). Without the flag the owner can
still enrol the machine later with `recipient add --host-unlock`. Hardware key recipients come with the epic that adds
them.

### The unfinished import

An **unfinished import** is an import that started writing and has not reached its commit point. It is shown by the
empty state-directory file `import.unfinished`, written first and durably removed last, the same way `init.unfinished`
shows an [unfinished initialization](vault-initialization.md#write-order). The initialization state reads it as
Unfinished:

- **`import.unfinished` is store-owned.** The store keeps one list of the names it writes, which the initialization
  state's foreign-file test and every discard share, and which the reset command removes when it lands.
  `import.unfinished` joins that list. Import's discard removes the names on it that an import writes, so the list and
  the discard cannot drift apart.
- **Check 1 of the initialization state** also matches `import.unfinished`. With it, the state is Unfinished if the
  state directory holds nothing but the ignored names, the files an import writes (`import.unfinished`, `identity.age`,
  `recipients.age`, `operational.age`, `manifest.age`, `approval.age`, approver key files and record files) and
  `recovery.toml`, and the config directory holds no config file but `config.toml`. Import writes no other config
  file, so `config.toml.sig`, `config.toml.pending` or `config.toml.sig.staged` beside `import.unfinished` makes the
  state Unrecognized. `init.unfinished` and `import.unfinished` together are Unrecognized: no run writes both. A
  `reset.unfinished` beside either is Unfinished reset, which is checked first.
- **`unlock`** refuses it with `unlock-failed`, saying an import is unfinished or in progress and to run
  `iron-vault import` again, or `iron-vault init` for a new vault. `recovery check` answers
  `recovery-check-unavailable`, and `status` names it "import unfinished (run iron-vault import again)".
- **The discard** removes, each with `durable_remove` and only those present: `config.toml` in the config directory,
  then `recovery.toml`, `approval.age`, `manifest.age`, the record files, the approver key files, `operational.age`,
  `recipients.age` and `identity.age`. `config.toml` is removed whatever its bytes: beside `import.unfinished` it is
  the bundle's copy, and the bundle and the source still hold it. The Unfinished notice names `config.toml` when one is
  there, so the owner knows that file goes too. The marker stays, so a crash during the discard reads Unfinished again.
- **Either command discards either kind.** `import` and `init` each discard an unfinished initialization and an
  unfinished import. When the kind changes, the discard ends by removing the other command's marker durably, which
  leaves Uninitialized, and the command's step 1 then writes its own. A crash between the two reads Uninitialized,
  which either command starts from.

### Write order

Every write happens after the owner's `yes` at the recovery key confirmation, under the service-wide lock, after the
second state check. Each step is durable before the next starts, and every file is written with `durable_replace`,
which fsyncs the file, renames it and fsyncs its directory ([open question 5](#open-questions)).

| Step | What the service does | Durable change |
|---|---|---|
| 1 | Removes a leftover `recovery.toml` on Uninitialized, as `init` does ([recovery.md](recovery.md#initialization)), or discards an unfinished vault. Writes the empty file `import.unfinished`. | `import.unfinished` |
| 2 | Writes every record file, in ascending record ID, the bundle's bytes. | `record-<record ID>.age` |
| 3 | Writes every approver key file, in ascending approver ID: the envelope inside its bundled approver key. | `approver-<approver ID>.age` |
| 4 | Writes `approval.age`, the bundle's bytes. | `approval.age` |
| 5 | Writes `config.toml` in the config directory, the bundle's bytes. | `config.toml` |
| 6 | Wraps the vault identity for {the new operational recipient key, the new recovery recipient key}, plus the host unlock recipient key with `--host-unlock`, with `wrap_identity` and writes it; reads it back and unwraps it once with each identity, requiring the bundle's vault identity each time. Then writes the recipient inventory: the `operational` and `recovery` entries, labelled `vault passphrase` and `recovery key`, and with `--host-unlock` a `host-unlock` entry labelled `host unlock`, enrolled at the import time, with the digest of the envelope as read back; reads it back. This is `init`'s step 2. | `identity.age`, then `recipients.age` |
| 7 | Seals the operational identity to the new vault passphrase and writes it. This is `init`'s step 3. | `operational.age` |
| 8 | Writes `manifest.age`, the bundle's bytes. | `manifest.age` |
| 9 | Opens the vault from disk with the vault identity, as `unlock`'s config check would: the manifest's MAC and every record file's digest; the approval state's MAC and its pairing with the manifest; each approver key file's form; and `config.toml`'s digest against the committed config digest. | none |
| 10 | Removes `import.unfinished` with `durable_remove`. **This is the import's commit point.** | `import.unfinished` removed |

Notes on the steps:

- **Progress notices.** A full import writes over 4096 files, each with two fsyncs, runs scrypt at step 7 and reads
  up to 256 MiB back at step 9, which can take longer than the CLI's 60-second socket timeout on slow storage. The
  service sends a notice before each step and, within steps 2 and 9, at least every 10 seconds ("writing credentials:
  1024 of 4096"). Each notice is a frame, so the CLI's reads never wait 60 seconds, and the owner sees the import move.
  This is the progress frame the [CLI client](admin-protocol.md#cli-client) foresees, using the existing notice kind;
  the CLI's timeout is unchanged. A notice that cannot be written does not stop the write order, which runs on to the
  commit point, as `init`'s does after the reveal.
- **Steps 4, 5 and 8 copy bytes.** The manifest and the approval state keep their state and peer generations, so they
  pair on the destination exactly as on the source ([state generation](storage-formats.md#state-generation)). Nothing
  is re-sealed, so nothing can change a counter.
- **Step 8 is last of the vault files** so the manifest, which says which records exist, is written only once all of
  them are. The marker alone decides the state, so this order is for the reader of a crashed directory, not for
  correctness.
- **Step 9 proves** every file the commit depends on is on disk and reads back as the bundle held it.
- **Step 10's failed directory fsync** comes after the unlink, as `init`'s does: the vault reads Initialized now and may
  read Unfinished after a power loss. Import ends with `import-failed` naming step 10, with the
  [unknown-outcome advice](vault-initialization.md#failing-after-the-reveal), worded for `import`. A marker that comes
  back loses nothing. The vault holds only what the bundle holds, and the bundle and the source still exist, so the
  owner runs `import` again, which discards and redoes it with a new recovery key. Once the owner has approved a config
  on the destination, the marker cannot come back at all: `config approve` replaces `approval.age` durably, and that
  fsync of the state directory makes the earlier unlink durable too.

### Crash table

What each command does after a crash, or any failure, following each step. `status` answers in Locked in every row.

| Last step durable | Initialization state | `unlock` | `import` again | `init` |
|---|---|---|---|---|
| none | Uninitialized | `unlock-failed`: not initialized | removes a leftover `recovery.toml`, then proceeds from step 1 | proceeds |
| 1 `import.unfinished` | Unfinished | `unlock-failed`: import unfinished or in progress | notice, discards (nothing yet), proceeds | notice, discards, removes `import.unfinished`, proceeds |
| 2 to 8, any part | Unfinished | as row 1 | notice, discards whichever files exist, proceeds | as row 1, discarding whichever files exist |
| 9 (no write) | Unfinished | as row 1 | as row "2 to 8" | as row "2 to 8" |
| 10 `import.unfinished` removed | Initialized | prompts for the new vault passphrase; the config check ends Unavailable with `PolicyInvalid`, the committed config's signature missing. With `--host-unlock`, the next start reaches the same state from the handoff, with no `unlock` | `already-initialized` | `already-initialized` |
| any step before 10, with a foreign file or a config file other than `config.toml` | Unrecognized | `unlock-failed`: names the first file | `already-initialized`: names the first file; nothing is changed | as `import` |
| 10, with a foreign file | Initialized | as row 10, and logs the file's name at WARN (`vault.foreign-file`) | `already-initialized` | `already-initialized` |

## Admin exchanges

### Export

`export` (command 19) takes no arguments; the bundle path stays in the CLI. It runs the
[migration authorization exchange](migration-authorization.md#admin-exchange); its own parts are:

| Step | What the service does | Refusal |
|---|---|---|
| 1 | Ready, holding the vault identity | `wrong-state` |
| 2 | Try the service-wide lock, recording the state and check generation | `busy` |
| 3 | The [snapshot checks](#the-snapshot) | `export-failed` (step `check`), naming the file |
| 4 | The summary, below | |
| 5–7 | Migration authorization: challenge, `Vault passphrase`, proof | `busy`, `migration-unavailable`, `migration-rate-limited`, `migration-denied` |
| 8 | Two secret prompts: `Export passphrase`, `Repeat the export passphrase`, checked by the [passphrase rules](vault-initialization.md#passphrase-rules) once both are in | `passphrase-rejected`; `migration-unavailable` when a `lock` cancels either prompt, and the authorization drops unused; none (cancelled) when a prompt gets no owner input |
| 9 | Same state and check generation; consume the authorization | `wrong-state`, `migration-denied` |
| 10 | The [snapshot](#the-snapshot), read again and streamed as bundle data frames, then the empty frame | `export-failed`: a snapshot or seal failure, a missed frame or [transfer deadline](#transfer), or a `lock` between frames |
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
Import accepts exactly that factor, so a hostile bundle cannot make the service spend more memory or time. A higher
factor would slow an offline guess at a stolen bundle, at the cost of 1 GiB of locked memory per attempt at 2^20; the
12-character minimum is the defence this design relies on.

### Import

`import` (command 20) takes one argument, the host unlock flag, with `init`'s tag, encoding and rule
([admin-protocol.md](admin-protocol.md#init)); the bundle follows the request as bundle data frames.

| Step | What the service does | Refusal |
|---|---|---|
| 1 | Locked; locked memory in a protected install; the initialization state is Uninitialized or Unfinished, with the Unfinished notice when it is; take the import slot; with the host unlock flag, read the unlock handoff ([Destination recipients](#destination-recipients)) | `wrong-state`, `memory-unprotected`, `already-initialized`, `busy` (another import holds the slot), `import-failed` (no host unlock identity to enrol) |
| 2 | Read the bundle data frames to the empty one, at most `MAX_BUNDLE_LEN`, within the [deadlines](#transfer); decode the bundle as it arrives ([one encoding per bundle](storage-formats.md#one-encoding-per-bundle)) | `bundle-invalid`; a close on a missed deadline |
| 3 | A secret prompt, `Export passphrase`; open the exported identity envelope | `import-denied` |
| 4 | Verify the bundle with the vault identity (below) | `bundle-invalid` |
| 5 | The summary, below | |
| 6 | Two secret prompts, `Vault passphrase` and `Repeat the vault passphrase`, by the [passphrase rules](vault-initialization.md#passphrase-rules) | `passphrase-rejected` |
| 7 | Generate the operational identity and the recovery key; the [recovery key presentation](vault-initialization.md#recovery-key-presentation): notice, reveal, `Type yes once you have saved the recovery key` | `declined` |
| 8 | Try the service-wide lock; Locked and the initialization state again; the [write order](#write-order), with its progress notices | `busy`, `wrong-state`, `already-initialized`, `import-failed` |
| 9 | The success response: the vault ID, the record count, the committed version, the highest reserved version, the committed config digest, and the recipient roles enrolled, as `init`'s result gives them | |

**Step 4 verifies** what the destination will trust, before any write: the manifest opens with the vault identity and
names the header's vault ID; the approval state opens, names the same vault ID, pairs with the manifest and has a
committed approval; the config's BLAKE2b-256 equals the committed config digest; the manifest's entries and the record
entries name the same record IDs, and each record file's digest equals its entry's; the bundled approver keys name
exactly the pinned approvers, and each opens with the vault identity to an approver key envelope of at most
`MAX_PASSPHRASE_ENVELOPE_LEN` with exactly one scrypt stanza and a work factor no higher than
`MAX_PASSPHRASE_WORK_FACTOR`; and the counts equal the header's. Each failure names the check, never a byte of the
bundle.

**The import summary** is built from the verified files only, never from the header alone. The `host unlock` line
appears only with `--host-unlock`:

```text
import a migration bundle
  vault: 3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b
  credentials: 1
  approvers: approval passphrase
  committed approval: version 1; highest reserved version: 2
  config: the source's committed config, to be approved on this machine
  then: a new vault passphrase and a new recovery key for this machine
  host unlock: enrolled from this machine's unlock handoff
  routing starts after iron-vault config approve, at version 3 or later
```

After success the CLI writes [the config copy](#the-config-copy) and prints the next steps: `iron-vault unlock`; then
the exact approval command for the copy, such as `iron-vault config approve vault.bundle.config.toml`, with one of the
approvers listed, and that an edited copy may be approved instead if the new host needs changes; then
`iron-vault recovery check` with the new key; then comparing the versions above with the source's `status`; and only
then retiring the source ([§16](iron-vault-specification.md#16-administration-recovery-and-migration) step 6).

**Prompts are not under a lock, and writes are**, as for `init`: step 8 takes the service-wide lock without waiting
and reads both states again, because another `init` or `import` may have run during the prompts. The endings after the
reveal follow [Failing after the reveal](vault-initialization.md#failing-after-the-reveal), with `import-failed` and
`iron-vault import` in place of `init-failed` and `iron-vault init`.

**A wrong export passphrase is not rate-limited.** Whoever holds the bundle can guess at it offline at scrypt's cost,
so a limit in the service would slow nobody. The exchange ends at the first wrong passphrase.

**The approval passphrase is not asked for.** The carried approver key files are opened at the destination's first
`config approve` ([open question 4](#open-questions)). The summary lists the approvers by label, so the owner sees which
approval passphrases still work before writing anything. If none does, the source still works, and the owner exports
again after enrolling an approver there.

### Error codes

Four codes join the [admin protocol's table](admin-protocol.md#admin-response-error-kind-5):

| Code | Name | Meaning |
|---|---|---|
| `45` | `export-failed` | `export`: the snapshot checks found damage before any prompt; or the snapshot or the transfer failed after the authorization was consumed, a transfer deadline passed, or a `lock` cancelled it between frames; the message names the step and, for a file, its name and the error kind; no bundle was completed |
| `46` | `bundle-invalid` | `import`: the bytes are not a migration bundle this version reads, exceed `MAX_BUNDLE_LEN`, or fail a check with the vault identity; the message names the rule or check, never a byte of the bundle; nothing was written |
| `47` | `import-denied` | `import`: the export passphrase does not open the exported identity envelope; nothing was written |
| `48` | `import-failed` | `import`: the host unlock flag was set and the service has no host unlock identity to enrol, raised before any prompt, so nothing was written; or a write failed, and the message names the step, says to run `import` again, which discards the unfinished import, and gives the recovery key advice of [Failing after the reveal](vault-initialization.md#failing-after-the-reveal) |

Existing codes widen to the new commands: `busy` (6) and `wrong-state` (13) to both; `passphrase-rejected` (18) to
both; `declined` (8), `already-initialized` (17) and `memory-unprotected` (27) to `import`. `export` already raises
`migration-denied` (28), `migration-unavailable` (29) and `migration-rate-limited` (33); `migration-unavailable` widens
to a `lock` at the export passphrase prompts.

### Audit events

These are audit events in the [catalogue](audit-logging.md#catalogue), under the `migration` subject. None carries a
passphrase, a key or a byte of a record.

| Event | Level | When | Fields |
|---|---|---|---|
| `migration.exported` | INFO | the last bundle data frame of an export was written | `vault_id`, `records`, `approvers`, `committed_version`, `highest_reserved` |
| `migration.export-failed` | WARN | an export failed at its snapshot checks, or after its authorization was consumed | `step` (`check`, `snapshot`, `seal` or `transfer`), `error_kind` (`locked` for a `lock`, `deadline` for a missed deadline); `file` when a file failed |
| `migration.import-refused` | WARN | an import was refused at steps 2 to 4 | `refusal` (`bundle_invalid` or `wrong_passphrase`); `detail`, the fixed name of the failed rule or check, for `bundle_invalid` |
| `migration.import-discarded` | WARN | an unfinished import was discarded, by `import` or `init` | `files` |
| `migration.imported` | INFO | the import's step 10 is durable | `vault_id`, `records`, `approvers`, `committed_version`, `highest_reserved`, `recipients`: the enrolled roles' names |
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
| routing waits for approval | `import_routes_only_after_new_approval` | The destination's config directory holds the source's `config.toml` and no signature; after `unlock` it is Unavailable with `PolicyInvalid` and answers no route; the CLI's config copy beside the bundle equals the source's config, and `config approve` of the copy shows the whole config as added, and routing starts |
| recovery access | `import_recovery_key_opens_destination` | The recovery key the import revealed passes `recovery check` on the destination; the source's recovery key does not |
| service boundary | `export_bundle_holds_no_plaintext_secret` | Neither the bundle file, the CLI's output, nor any file written under the CLI's or the services' directories holds a credential's secret bytes or the vault identity's text; the bundle holds no approver key envelope's bytes in the clear; the destination's `identity.age` holds no scrypt stanza |
| service boundary | `import_requires_export_passphrase` | A wrong export passphrase writes nothing and ends with `import-denied` |
| no overwrite | `import_refuses_initialized_vault` | Import into an Initialized or Unrecognized directory changes nothing and ends with `already-initialized` |
| safe archive paths | `import_refuses_unsafe_bundles` | Bundles with an absolute name, `..`, a link, a directory, a device, a duplicate, an unknown name, a pax or GNU header, an oversized entry, trailing bytes, or more than `MAX_BUNDLE_LEN` bytes each end with `bundle-invalid` and write nothing |
| recovery access, host unlock | `import_host_unlock_enrolls_recipient` | In a build and profile that accept `init --host-unlock`, `import --host-unlock` enrols the handoff's identity: the inventory names `operational`, `recovery` and `host-unlock`, each opens `identity.age`, and a restart reaches the config check with no `unlock`; an absent handoff ends with `import-failed` before any prompt and writes nothing |
| crash | `import_crash_is_discarded` | A fault at each write step leaves Unfinished, which `unlock` refuses and the next `import` discards and completes |

The store's bundle codec has its own unit tests for every [decoding rule](storage-formats.md#one-encoding-per-bundle).
The transfer deadlines, the `lock` that cancels an export between frames, the one-import rule and the progress notices
are tested with the commands that own them.

## Open questions

Each point below was open in the specification or decided here against a reading of it. The owner decided every
point on 2026-11-11.

1. **Discarding an Unfinished vault.** *Decided: default accepted (2026-11-11).* The ticket asked import to refuse an
   Unfinished vault. *Default:* import and `init` each discard either kind of unfinished vault, because a refusal would
   leave an owner whose import crashed with no command that starts over, and an Unfinished vault never opened or
   served. An interrupted reset is still refused. *Alternative:* import refuses an Unfinished vault, as the ticket
   asked, and only `init` discards one.
2. **"Bundle passphrase" and "export passphrase".** *Decided: default accepted (2026-11-11).*
   [§16](iron-vault-specification.md#16-administration-recovery-and-migration) uses both for one secret ("require the
   bundle passphrase on import"; "That export passphrase encrypts the bundle"). *Default:* the glossary keeps
   *export passphrase*, and the import prompt is `Export passphrase`, so the owner types it under the name it was
   chosen under.
3. **Device-bound approvers.** *Decided: default accepted (2026-11-11).* A `tpm` or `hardware` approver's key cannot
   move. *Default:* left to the epic that enrolls the first one (EP-33 for `tpm`); v0 decodes neither kind, so no v0
   bundle holds one.
4. **The destination's approval signer.** *Decided: default accepted (2026-11-11).*
   [§16](iron-vault-specification.md#16-administration-recovery-and-migration) step 5: "The destination … enrolls its
   approval signer". *Default:* the destination's approval signers are the source's pinned approvers, carried in the
   bundle, and "enrolls" is read as their being pinned in the destination's approval state. The first `config approve`
   proves that one opens with its approval passphrase on the destination. *Alternative:* import proves it before any
   write, asking one carried approver's approval passphrase after the summary, or enrolls a new approver with a new
   approval passphrase. Enrolling re-seals the approval state with the counters unchanged, so it is no longer copied
   byte for byte.
5. **A directory fsync for every rename.** *Decided: default accepted (2026-11-11).*
   [§13](iron-vault-specification.md#13-vault-structure-and-durable-writes) requires one for each durable replacement,
   and [§19](iron-vault-specification.md#19-v0-user-acceptance) checks that "every durable rename includes its directory
   fsync". *Default:* every file of the write order is written with `durable_replace`, its own directory fsync
   included, and progress notices keep a slow import inside the CLI's timeout. *Alternative:* step 2 renames every
   record file, then fsyncs the state directory once. The marker makes every record file part of the unfinished import
   until step 10, and step 9 proves each is on disk before the commit, so a record file a crash loses is discarded with
   the rest. That saves up to 4096 directory fsyncs on a full vault, but reads §13 as allowing one fsync for many
   renames.
6. **The config the owner approves after import.** *Decided: default accepted (2026-11-11).* `config approve` reads
   its file in the CLI, which in the Compose profile and over a forwarded admin socket cannot read the service's config
   directory. *Default:* the CLI writes [the config copy](#the-config-copy) beside the bundle, from the bundle's
   `config.toml` entry, checked against the committed config digest in the import's result. *Alternative:* the result
   carries the digest only, and the owner approves their own copy of the source's config after checking it against
   `blake2b:<hex>`.

## Implementation tickets

Each ticket updates the design documents and glossary entries it changes, in the same branch as its code.

| Order | Ticket | What | Depends on | Updates |
|---|---|---|---|---|
| 1 | K-308 | Store: the exported identity envelope, sealed and opened with the export passphrase at exactly `PASSPHRASE_WORK_FACTOR` | K-307 | storage-formats.md "Exported identity envelope" (Rust names); glossary "Export passphrase" and "Exported identity envelope" (Rust types) |
| 2 | K-309 | Store: the migration bundle codec, decoding as frames arrive | K-307 | storage-formats.md "Migration bundle v1" and the magic table (Rust names); glossary "Migration bundle", "Bundle header" and "Bundled approver key" (Rust types) |
| 3 | K-310 | Store: the export snapshot, with the config and the bundled approver keys | K-308, K-309 | glossary "Export snapshot" (Rust types) |
| 4 | new | Protocol and CLI: the bundle data frame, the bundle transfer deadline, commands 19 and 20 (`import`'s host unlock flag), error codes 45 to 48 | K-307 | admin-protocol.md (frame kinds, exchange, commands, command 20's result with the committed config digest, error codes, `migration-unavailable` at the export passphrase prompts, Versions); migration-authorization.md (`migration-unavailable`); glossary "Bundle data frame" and "Bundle transfer deadline" (Rust types) |
| 5 | new | Store: the unfinished import in the initialization state, the store-owned list, and its discard | K-307 | vault-initialization.md "Initialization state", "Discarding an unfinished initialization" and the crash table; recovery.md "Initialization"; storage-formats.md, an "Unfinished import file" section; glossary "Unfinished import" and "Initialization state" |
| 6 | K-311 | `iron-vault export`: deadlines and the `lock` cancel between frames | K-310, ticket 4 | audit-logging.md (`migration.exported`, `migration.export-failed`, the new fields); the manual's CLI, errors and audit log references |
| 7 | K-312 | Store: the import write order, `config.toml` and the host unlock recipient included | K-308, K-309, ticket 5 | |
| 8 | K-313 | `iron-vault import`: `--host-unlock`, the import slot, the receive deadlines, progress notices, the committed config digest in the result, the config copy beside the bundle and its printed `config approve` command, and the first approval's full summary | K-312, ticket 4 | config-approval.md "Approval summary" (the same-config line needs an active config); docker-compose.md "Enrollment" and recipients.md "Initialization" (`import --host-unlock`); audit-logging.md (the `migration.import-*` events and `migration.imported`); the manual's CLI, errors, audit log and states references |
| 9 | K-314 | Migration release checks and the manual | K-311, K-313 | README features; the manual: the migration recipe out of the roadmap, the files reference |
