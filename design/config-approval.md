# Config approval transaction

How the service turns proposed config bytes into the config it serves (specification [§12](iron-vault-specification.md#12-configuration-approval-and-reload)), and what it does with
whatever a crash leaves behind. Terms follow the [glossary](glossary.md); the byte formats of the approval payload,
the approval envelope and the approval state are in [storage-formats.md](storage-formats.md), and the `config approve`
command is in [admin-protocol.md](admin-protocol.md#config-approve).

Three [§12](iron-vault-specification.md#12-configuration-approval-and-reload) rules drive everything below:

- **Never promote a signed but uncommitted version.** A signature alone proves nothing about freshness; only the
  committed approval in `approval.age` does.
- **Never fall back to an older committed version.** If the committed transaction cannot be completed, the service
  stays unavailable.
- **Reserved counters stay consumed.** A version handed out for a signing attempt is never handed out again, whether
  or not the attempt finished.

Every default this design picks where the specification is open, or where it departs from the specification's
wording, is listed under [Open questions](#open-questions), for the owner to decide.

## File layout

### Where the files live

`config.toml` lives in the **config directory**: `/etc/iron-vault` in a protected install, and
`$XDG_CONFIG_HOME/iron-vault-dev` in development. The vault's files live in the state directory, `/var/lib/iron-vault`.
The two may sit on different filesystems, so no step of the transaction may rename across them.

Every file the transaction writes therefore sits in the config directory, beside `config.toml`:

| File | Holds | Written by | Size limit |
|---|---|---|---|
| `config.toml` | the active config | publish only (a rename) | `MAX_CONFIG_LEN`, 61,440 bytes (60 KiB) |
| `config.toml.sig` | the active config approval, an approval envelope | publish only (a rename) | `MAX_APPROVAL_ENVELOPE_LEN`, 4096 bytes |
| `config.toml.pending` | the pending config | step 1, a durable replace | `MAX_CONFIG_LEN` |
| `config.toml.sig.staged` | the staged approval, an approval envelope | step 4, a durable replace | `MAX_APPROVAL_ENVELOPE_LEN` |
| `config.toml.lock` | nothing; its lock is the single-writer proof | created once at startup | empty |

Durable replace writes a private temporary file first, so a crash can also leave `.config.toml.pending.tmp` or
`.config.toml.sig.staged.tmp`. These are stale temp files, swept at startup under the config-directory lock as
`sweep_stale_temps` does for the state directory.

Every read is bounded before it starts (`StoreFs::read_bounded`): a file over its limit is refused without being read
whole, and a symlink, FIFO or device is refused before it is opened. A file that is over its limit or is not a regular
file reads as unusable, never as a crash.

**Why 60 KiB for a config.** The proposed bytes travel in one admin request frame, whose body is at most 64 KiB
(`MAX_BODY_LEN`, 65,536 bytes). The command field and the config field's header take 14 bytes, so a config can be at
most 65,522 bytes. 60 KiB leaves headroom for one more argument and is still about forty times the specification's
example config. A larger config would need the config split across frames, which nothing needs yet.

**Same-directory staging, no fallback.** Because the pending config and the staged approval sit beside their targets,
publish is two same-directory renames and one directory fsync. The copy-then-rename fallback the owner allowed for a
cross-filesystem layout is not needed and is not built.

### Ownership and the trusted-path rule

The service writes the config directory, so the service account owns it and only it may write it:

| Path | Owner | Mode | Rule |
|---|---|---|---|
| config directory | the service account (`iron-vault`; the invoking user in development) | `0700` | new `TrustedPathRule::ConfigDir` |
| `config.toml` | the service account | `0600` | `TrustedPathRule::Config`, unchanged |
| `config.toml.lock` | the service account | `0600` | `TrustedPathRule::StateFile`'s leaf rule: a regular file, never a symlink |
| ancestors of the config directory | root or the service account, writable by neither group nor others, not a shared sticky directory | | the ancestor rule, unchanged |

Today the config directory is checked only as an ancestor of `config.toml`, where root may own it. That is no longer
enough: the service must create and rename files in it, and root ownership would mean either the service cannot, or
the directory is group- or world-writable so that it can. `ConfigDir` is the `StateDir` leaf rule (a directory, the
service account's alone, mode exactly `0700`) applied to the config file's parent. The trusted-path report checks it
between the binary and the config file, and the lock file after the config file.

Once the service reads its config, a refused config directory, config file or config-directory lock file stops
startup, as the binary and runtime directory already do ([§4](iron-vault-specification.md#4-installation-and-ownership): "refuse an unsafe installation and explain which path
failed"). Today the check only reports these paths. The package creates `/etc/iron-vault` owned by `iron-vault` with
mode `0700`; in development the service creates its config directory with mode `0700` when it is missing. The mode and
the refusal are defaults ([open question 9](#open-questions)).

Administrator-installed files under the config directory, such as `/etc/iron-vault/tls/server.crt` in the
specification's example, keep their own rules (`AdminCertificate`, `AdminPrivateKey`). The service account owning the
directory above them adds nothing it could not already do, since both rules already accept a service-owned file.

### Single writer: a second lock

The service takes an exclusive, non-blocking lock on `config.toml.lock` right after the state-directory lock, and
holds both for its lifetime. Failing either one fails startup.

The state-directory lock alone is not enough. It proves one writer per state directory, but in development the state
directory and the config directory come from two independent variables (`$XDG_STATE_HOME`, `$XDG_CONFIG_HOME`), so two
instances with different state directories can share one config directory. One instance's publish could then rename
the other's pending config into place. The result would fail verification, so it is not a security hole, but it is a
vault left unavailable for no reason the owner could see. A second lock costs one empty file and closes the gap in
every profile.

### Store types

The config directory gets its own types in `iron-vault-store`, beside the state directory's, rather than a generalized
`StateFileName`:

- **`ConfigDirLock`**, the config directory's counterpart of `StateDirLock`, taken from the path the binary resolves
  from the deployment profile. The store never learns the profile.
- **`ConfigFileName`**, a closed enum of the four data files above: `Active`, `ActiveSignature`, `Pending` and
  `StagedSignature`. A closed set needs no validation and cannot name the lock file.
- The durable replace, durable remove and bounded read bodies move into one crate-private helper that takes a
  directory and a file name. `durable_replace`, `durable_remove` and `read_state_file` keep their signatures. New
  functions take `&ConfigDirLock` and a `ConfigFileName`, plus `publish`, which only the config directory has. A
  state file can never be written into the config directory, and the reverse, because each public function takes one
  directory's lock and one directory's name type.

Everything goes through `StoreFs`, so `FaultFs` can fail or cut power at any call in either directory.

## The transaction

The approval transaction runs the six steps of [§12](iron-vault-specification.md#12-configuration-approval-and-reload) in order. Each step is durable before the next one starts.

### The service-wide lock

Approvals, vault writes, reloads and every config check are serialized by one in-process lock, the **service-wide
lock**. A `config approve` request takes it before step 1 and holds it until its admin response, prompts included, so
the summary's predicted version stays exact and nothing changes the credential catalog under the review. Up to two
prompts can each wait up to the 5-minute prompt deadline, so an approval can hold the lock for about 10 minutes.
Meanwhile:

- another approval or a vault write fails at once with `busy`;
- SIGHUP is queued, and the reload runs once the approval ends; an `unlock` waits the same way, and then finds the
  service in a state that refuses it unless a `lock` came first;
- `lock` cancels an approval that is still waiting at a prompt, which has reserved nothing and answers
  `approval-unavailable`, and then locks. An approval past its passphrase prompt is not interrupted: `lock` waits for
  it, which takes seconds. A `lock` or a reload that waited checks `admin_allows` again once it holds the
  service-wide lock, because the approval may have left the service in a state that refuses it.

These are defaults ([open question 8](#open-questions)).

### Steps and service states

| Step | What the service does | Durable change | Service state |
|---|---|---|---|
| 1 | Writes the proposed bytes as `config.toml.pending`. Then parses, validates and activates them against the credential catalog, capabilities and account directory, using the one owned buffer it wrote, and dry-runs the upstream clients, so a config that cannot be served is invalid before any prompt. Never reads the file back to do this. | `config.toml.pending` | Ready, or Unavailable with `PolicyInvalid` |
| 2 | Shows the approval summary and asks the owner to confirm it. Then asks for one pinned approver's authorization, naming it by label (see [Choosing the signer](#choosing-the-signer)); for the software signer, takes the approval passphrase and opens the approver key with it. Then reserves the next version. | `approval.age`: highest reserved version + 1 | unchanged |
| 3 | Signs the approval payload (purpose, vault ID, the reserved version, the digest of the buffer), writes the envelope with the signer's approver ID, and drops the signer. | none | unchanged |
| 4 | Writes the envelope as `config.toml.sig.staged`. | `config.toml.sig.staged` | unchanged |
| 5 | **Admission pause starts:** from Ready, the service moves to Checking, and requests get `503` `checking` from then on. Then it commits `(version, digest)`. | `approval.age`: the committed approval | Checking |
| 6 | Publishes, then runs the config check, which builds the serving snapshot from the published files. The check passing moves the service to Ready, with the listener set rebuilt from the new config; failing moves it to Unavailable. **Admission pause ends.** | `config.toml`, `config.toml.sig` | Checking, then Ready or Unavailable |

The service enters Checking before the commit, not after it, because the pause must start before the commit ([§12](iron-vault-specification.md#12-configuration-approval-and-reload)),
and Checking is the state in which requests are refused while the service is unchanged in every other way. The
service state model has the edge from Ready to Checking. It is labelled "explicit reload", so the approval needs an
event of its own on that edge ([open question 3](#open-questions)).

From Unavailable with `PolicyInvalid`, the request interface already refuses everything, so step 5 changes no state.
After the commit, the service leaves Unavailable through `Repaired` to Checking, as the service state model's
`Repaired` event documents for an approval committed there, and step 6 runs as above. The service answers the admin
request only after the config check ends, so the result says whether the new config is active.

The step 1 dry run does not replace the config check. It only moves the failures it can find to before the first
prompt, where they consume no version.

**Why the order of step 2 is confirmation, passphrase, then reservation.** [§12](iron-vault-specification.md#12-configuration-approval-and-reload)'s text says "authenticate the owner,
show the summary, and durably reserve". Its sequence diagram instead puts the summary before the owner's authorization.
This design follows the diagram ([open question 6](#open-questions)): the admin principal is authenticated at
connect, by its peer credentials, and the approval passphrase comes after the summary, so the owner authorizes what
they have just read. Opening the approver key before reserving means a mistyped passphrase consumes no version. A TPM
signer authorizes inside step 3 instead, so its failed PIN does consume one, which [§12](iron-vault-specification.md#12-configuration-approval-and-reload) allows ("failed attempts
consume their versions").

### Choosing the signer

The approval state pins one or more approvers ([§14](iron-vault-specification.md#14-recipients-startup-and-memory)),
and any one of them may approve. Step 2 asks for one, names it by its label, and lets the owner switch to another
pinned approver before answering, for example `Tap "Dave YubiKey 3" to approve. Ctrl-Y to try another way.` Switching
asks for the next approver; nothing is reserved or signed until one of them authorizes. A wrong answer to one
approver's prompt ends the approval as `approval-denied`, as a wrong approval passphrase does today: it does not move
on to another approver, so switching is the owner's choice, never a retry ([open question 15](#open-questions)).
Which approver is asked first, the prompt's
exact text and the switch frame for "try another way" are in
[approval-signers.md](approval-signers.md#the-approver-prompt). `init` pins one approver, the software signer labelled
`approval passphrase`, so step 2 asks for its passphrase as `Approval passphrase for "approval passphrase"` until the
owner enrolls another.

The envelope written at step 3 carries the signer's approver ID, and verification checks the signature with that
approver's pinned key and algorithm ([storage-formats.md](storage-formats.md#approval-envelope-v1)). Owner presence
([credential-commands.md](credential-commands.md#owner-presence)) asks the same way and accepts any pinned approver.

### When a step fails

| Fails at | Version | Files | Service afterwards | `config approve` answers |
|---|---|---|---|---|
| step 1: validation, activation or the dry run | none reserved | pending removed | unchanged | `config-invalid` |
| step 1: the write | none reserved | pending removed | unchanged | `approval-unavailable` |
| step 2, before reserving: the owner declines or cancels, or the passphrase is wrong | none reserved | pending removed | unchanged | `declined`, `approval-denied`, `approval-unavailable` for a `lock`, or no response for a cancel |
| step 2, the reservation: counter exhausted, or its write failed before the rename | none reserved | pending removed | unchanged | `approval-unavailable` |
| step 2, the reservation: the directory fsync failed after the rename | consumed, unless power loss undoes it; nothing was signed under it, so reusing it after power loss is harmless | pending removed | unchanged; the in-memory approval state accepts no more writes until the next approval loads it again from disk, which restores consistency, not durability, and here only consistency matters | `approval-failed` |
| step 3 or 4 | consumed | pending and staged removed | unchanged | `approval-failed` |
| step 5, before the rename of `approval.age` | consumed | pending and staged removed | Checking: the config check runs on the unchanged published pair and normally returns to Ready on the old policy, which is still the committed one | `approval-failed` |
| step 5, the rename landed but the directory fsync failed | committed, if settled (below) | left in place | Checking: settle the commit, then publish and check; if settling fails, Unavailable with `RecoveryNeeded` | success, or `committed-not-active` |
| step 6, a rename failed | committed | left in place | Checking: the config check's recovery retries the renames (rows 2-4); if that fails too, Unavailable with `RecoveryNeeded` | success, or `committed-not-active` |
| step 6, the directory fsync failed | committed | renamed | Checking: the check goes on (see [Publish](#publish)) | success, or `committed-not-active` |
| step 6, the config check fails | committed | as recovery leaves them | Unavailable, with the check's failure reason | `committed-not-active` |
| any step 2 to 6: the task running the transaction panics | possibly consumed or committed | left in place for the next config check | Unavailable with `RecoveryNeeded` if it was Checking, otherwise unchanged; moving out of Checking logs `config.check-failed` | `approval-unavailable`, whose message says a version may be consumed or committed |

The "Service afterwards" column above is for an approval started from Ready. From either starting state, steps 5
and 6 move the service only along `next()` edges:

| Outcome of steps 5 and 6 | Started from Ready (in Checking since the pause began) | Started from Unavailable(`PolicyInvalid`) |
|---|---|---|
| step 5 fails before the rename of `approval.age` | the config check runs on the unchanged published pair: `CheckPassed` to Ready, or `CheckFailed` with its reason | no event: the service stays Unavailable(`PolicyInvalid`) |
| the commit is durable (step 5 succeeded, or the commit was settled), and publish and the config check pass | `CheckPassed` to Ready | `Repaired` to Checking, then `CheckPassed` to Ready |
| the commit is durable, but the publish retry or the config check fails | `CheckFailed` with the check's reason (`RecoveryNeeded` for a publish that cannot be finished) | `Repaired` to Checking, then `CheckFailed` with the check's reason |
| settling the commit fails | `CheckFailed(RecoveryNeeded)` at once, without running the check | `Repaired` to Checking, then `CheckFailed(RecoveryNeeded)` at once, without running the check |

**When `Repaired` fires.** Only for an approval started from Unavailable, and only after step 5 has an outcome. It
never fires before the commit, or after a clean failure before the rename. For a commit that is durable, because step
5 succeeded or the commit was settled, it fires once the commit is durable, and the config check then runs. A commit
that could not be settled has no path to `RecoveryNeeded` but through Checking, because `next()` has no edge from
Unavailable(`PolicyInvalid`) to Unavailable(`RecoveryNeeded`). There `Repaired` still fires, and Checking ends at once
with `CheckFailed(RecoveryNeeded)`. That is a default too ([open question 3](#open-questions)).

**If the caller goes away.** Once `commit` holds the context's mutex, a task of its own owns the guard, and the
service-wide lock with it, and runs steps 2 to 6. Dropping the `config approve` exchange after the commit (the admin
server's drain at shutdown does) therefore cannot leave the service in Checking: the task still ends in Ready, or in
Unavailable, and no other approval or vault write starts until it does. A task that panics fails closed from a guard it
owns: a service still in Checking moves to Unavailable (`RecoveryNeeded`) and logs `config.check-failed`. The version
may be consumed or committed then, and the next config check recovers a committed one.

Removing uncommitted files is best effort. One left behind is a leftover that the next config check discards (see the
recovery table).

### Settling an uncertain commit

A failed directory fsync after the rename of `approval.age` leaves the commit visible but possibly not durable.
Reading the file back proves nothing, because a read is served from the page cache. Re-running the fsync proves
nothing either: after a failed writeback, Linux can mark the pages clean and report a later fsync of the same file as
successful, even though the data never reached the disk. The transaction therefore **settles** the commit by writing
`approval.age` again, durably, with the same counters: a fresh temporary file, its fsync, the rename and the
directory fsync. A write with unchanged counters still takes the next state generation, by the vault-wide rule. Only
when that write succeeds is the commit trusted, and only then does step 6 publish.

Settling is part of the transaction, which holds the service-wide lock and is the approval state's writer. A config
check never settles, because loading never writes the approval state. The service leaves Unavailable with
`RecoveryNeeded` only through an authorized repair (`Repaired` to Checking) or a restart
([open question 13](#open-questions)).

### Publish

Publish is step 6's file change, and the only way `config.toml` or `config.toml.sig` is ever written:

1. rename `config.toml.pending` to `config.toml`;
2. rename `config.toml.sig.staged` to `config.toml.sig`;
3. fsync the config directory.

The order follows [§12](iron-vault-specification.md#12-configuration-approval-and-reload)'s wording ("publish the pending config and artifact"). Nothing depends on it. Until the
directory fsync returns, power loss can keep either rename, both or neither, whatever order they ran in. So recovery
never infers progress from which file landed. It decides from the committed approval alone. The two files are
published separately, never as one atomic swap.

The durable record of an approval is its commit in `approval.age`, not the published files. A failed directory fsync
after both renames is therefore logged at WARN and does not stop the transaction. If power loss later undoes a rename,
the files are back in a state that the recovery table finishes at the next start (rows 2-4). A failed rename is not
passed over in this way: the config check that follows finds the committed config unpublished, and its recovery
retries the rename. If the retry fails too, the service goes Unavailable with `RecoveryNeeded`.

The same publish finishes a committed transaction during the config check. There it renames only the files that are
not yet in place. Finishing a publish in a running service, and not only "on restart" as [§12](iron-vault-specification.md#12-configuration-approval-and-reload) puts it, is a default
([open question 7](#open-questions)).

## Recovery

Every config check runs recovery first. A config check is the work the service does in Checking: after an unlock,
after a reload, after an approval's commit, after a vault change by `replace` or `rm`, and after an authorized
repair. It needs the vault identity to open `approval.age`, so a locked service recovers when it is unlocked.
Recovery reads `approval.age` and never writes it, so loading never advances a counter.

The service context keeps the vault identity from unlock until lock or stop, in Checking, Ready and Unavailable alike.
Every config check opens a new vault from it: on success the vault moves into the serving snapshot, and on failure the
vault and its decrypted records are dropped while the identity stays. So a reload, an approval's commit and a repair
re-enter Checking without a new unlock, and an Unavailable service holds the one key and no credential record. The
identity has no copies: the context and each open vault share the one value, whose key bytes are cleared when the last
holder drops it. A `lock` drops the context's share at once and the withdrawn snapshot's vault holds the last, so the
identity is cleared when the lock drain releases that snapshot; a stop drops both.

### Inputs

- **C**, the committed approval `(version, digest)` from `approval.age`.
- The four data files in the config directory. A missing, oversized or non-regular file is *absent* for every purpose
  below.
- A file is *unreadable* when it is there but reading it fails with any other I/O error (permission denied, an I/O
  error from the disk, ...). An unreadable file is not absent: recovery cannot tell what it holds, so it refuses
  before the table.
- **Matches C**: a config file X and a signature file Y *match C* when `verify_approval(state, X, Y)` succeeds. That
  covers all of these: the envelope decodes; its approver ID is pinned; it is signed with that approver's algorithm
  and key; it names this vault; its digest is the digest of X; and its version and digest are C. A config file holds C's config when its
  digest is C's digest. A signature file holds C's approval when it matches C with that config.

### Before the table

The failure reasons are the service state model's `FailureReason`s. A request sees the matching `UnavailableReason`
text.

| Condition | Outcome |
|---|---|
| `approval.age` missing, damaged, a partial restore, or unreadable | **stay unavailable**, `RecoveryNeeded`; touch nothing |
| nothing committed (`NothingCommitted`: a vault whose first approval never committed) | **stay unavailable**, `PolicyInvalid` (detail: no approved config); touch nothing |
| `config.toml`, `config.toml.sig`, `config.toml.pending` or `config.toml.sig.staged` unreadable (`Unreadable`, naming the first in that order and the error kind) | **stay unavailable**, `RecoveryNeeded`; touch nothing |

The conditions are checked in this order.

An unreadable config file is not treated as absent, because the file recovery cannot read might be the one that
completes the commit: a staged approval that is there but unreadable would otherwise look like row 5, and discarding
around it could lose a committed approval. The owner fixes the permissions or the disk in place, then an authorized
repair or a restart runs the check again.

### Recovery table

Find where C's config is (`config.toml` or `config.toml.pending`) and where C's approval is (`config.toml.sig` or
`config.toml.sig.staged`). A file already in place is preferred over its pending or staged counterpart:

| Row | C's config in | C's approval in | State it comes from | Outcome |
|---|---|---|---|---|
| 1 | `config.toml` | `config.toml.sig` | published, or no transaction was running | **serve the published pair**; discard any pending or staged file |
| 2 | `config.toml` | `config.toml.sig.staged` | half published: new config, old signature | **finish publishing**: rename the staged approval, fsync |
| 3 | `config.toml.pending` | `config.toml.sig` | half published: new signature, old config | **finish publishing**: rename the pending config, fsync |
| 4 | `config.toml.pending` | `config.toml.sig.staged` | committed, nothing published yet (a crash in step 6, or between steps 5 and 6) | **finish publishing**: both renames, fsync |
| 5 | `config.toml.pending` | nowhere | committed, but its staged approval was lost | **stay unavailable**, `RecoveryNeeded`; touch nothing |
| 6 | nowhere | `config.toml.sig.staged` | committed, but its pending config was lost | **stay unavailable**, `RecoveryNeeded`; touch nothing |
| 7 | `config.toml`, or nowhere | nowhere | the published pair does not verify as C, and no file of C waits to be published | **stay unavailable**, `PolicyInvalid`; touch nothing |
| 8 | nowhere | `config.toml.sig` | as row 7 | **stay unavailable**, `PolicyInvalid`; touch nothing |

The rows cover all nine combinations of three places for C's config and three for C's approval.

After rows 2-4 the published pair matches C. Any pending or staged file still left is discarded, and the check goes
on as for row 1. A publish that fails midway leaves a state this table resolves to row 1, 2, 3 or 4, so recovery is
safe to run again. Each finish is recorded as `config.recovery-published`.

Recovery reads the published pair back after the renames. If that read-back finds a file unreadable, or a pair that
does not verify as C, the service stays unavailable with `RecoveryNeeded`, and the detail names C's version as
published but not verified (`PublishNotVerified`), never `Unreadable`: the renames have run, so something was touched.
The next recovery reads the files again and, once they read, resolves them as row 1.

*Discard* means durable remove, then the `config.recovery-discarded` event naming each file and, for a staged
approval, the version it was signed for. A discard that fails partway still records each file it removed. Discarding
never touches the counters: a discarded staged approval's version stays consumed.

**Why rows 5 and 6 differ from rows 7 and 8.** Rows 5 and 6 hold a file of C waiting to be published, so a committed
transaction is on disk that cannot be completed. The service state model documents exactly that case as
`RecoveryNeeded`. Rows 7 and 8 hold no such file: the published pair simply does not verify as the committed
approval, which is [§12](iron-vault-specification.md#12-configuration-approval-and-reload)'s "invalid signature, a previous version, or an uncommitted higher version", and the model's
`PolicyInvalid`. The split decides the way out, because the admin interface offers approving only for
`PolicyInvalid`, and for `RecoveryNeeded` only a repair. Both are defaults ([open question 4](#open-questions)). In
none of these rows may the service serve the older pair beside the committed one ([§12](iron-vault-specification.md#12-configuration-approval-and-reload)).

### Pending and staged files beside a published pair that matches C (row 1)

Every combination is an uncommitted leftover, from a transaction that ended before its commit or failed to clean up:

| Pending | Staged | Staged verifies as | Outcome |
|---|---|---|---|
| absent | absent | | serve, nothing to discard |
| present | absent | | discard pending (crash in steps 1-3, or after a failure before staging) |
| absent or present | present | a version above C (`Uncommitted`): signed, never committed (crash between steps 4 and 5) | discard; never promote |
| absent or present | present | a version below C (`Superseded`) | discard |
| absent or present | present | C itself, a duplicate of the published signature | discard |
| absent or present | present | C's version with another digest (`DigestNotCommitted`) | discard, and log at ERROR: only a misbehaving signer produces it |
| absent or present | present | does not verify (malformed, unknown approver, wrong algorithm, bad signature, wrong vault) | discard |

### Detail when the service stays unavailable (rows 5 to 8)

Recovery changes nothing on disk, so the files stay as evidence. The next `config approve` overwrites the pending
config and the staged approval anyway. In rows 5 and 6 the detail first names the committed version and which of
its two files is missing. Then, in every row, it gives the first of these that applies to the published pair, in
this order:

| Published pair | Detail | `VerifyError` |
|---|---|---|
| `config.toml` or `config.toml.sig` absent (missing, oversized or not a regular file) | the committed config or its signature is missing | none |
| the signature does not decode | signature malformed | `Malformed` |
| the approver ID is not a pinned approver's | signed by an approver this vault does not pin | `UnknownApprover` |
| another algorithm than the named approver's | signed with the wrong algorithm | `WrongAlgorithm` |
| the signature does not verify against the named approver's key | bad signature | `BadSignature` |
| the payload names another vault | approval is for another vault | `WrongVault` |
| the config's digest is not the signed one | config changed since it was approved | `ConfigChanged` |
| the version is below C | an old config and signature pair; never fall back to it | `Superseded` |
| the version is above C | signed but never committed; never promote it | `Uncommitted` |
| C's version with another digest | the signer signed one version twice | `DigestNotCommitted` |

### After recovery

The config check then parses, validates and activates the published config. A config that fails (for example, an
unknown credential reference) is `PolicyInvalid`. A damaged or needs-login record is not a failure: only its routes
are unavailable ([§12](iron-vault-specification.md#12-configuration-approval-and-reload)). Next the check builds the upstream clients, and a route's pinned CA that fails to load
([§10](iron-vault-specification.md#10-outbound-tls-and-environment)) is treated the same way: only the routes that pin it are unavailable, with the cause *pinned CA
unavailable*, and every other route keeps serving. It is not `PolicyInvalid`: the config verified and validated, and
the fault is in an administrator-installed file outside it, which the owner fixes and then reloads. The check logs one
WARN event per such route, naming the route and the `ca_file` field but never the path or the file's bytes, and
`status` reports the route as a route fault. A route can be unavailable for both causes, and reports both. Last, the
check builds the serving snapshot. The check passing moves Checking to Ready, and
the listener set is rebuilt from the verified config on entry to Ready.

### Power loss around the commit

`crates/iron-vault/tests/approval_release_linux.rs` runs `config approve` through a running service on an in-memory
filesystem that models power loss (`FaultFs`), cuts the power after each filesystem call the service makes from the
request on, restarts a service on whatever survived, and checks what it serves against the tables above. `cargo test
-p iron-vault --test approval_release_linux -- --nocapture` prints one row per cut and per way the crash can treat the
renames that no directory fsync had yet covered: *lose all* (the pessimistic model), *keep all*, or *keep* one of
the two renames of a publish alone. Reads count as calls, so the numbers below are for the current code; the
steps are what to compare. After every restart that reaches Ready, a second `config approve` is checked to reserve
the version after the highest one on disk, so a version a cut left reserved is never reused.

| Power cut after | Crash keeps | Surviving approval C | Recovery row | Restarted service |
|---|---|---|---|---|
| 0 to 6 calls made before the cut, which read the vault and the approval state | n/a | v1 | 1 | Ready, previous policy |
| calls 7-11: step 1, `config.toml.pending` written, renamed, directory fsynced | any | v1 | 1 (a leftover pending file is discarded) | Ready, previous policy |
| calls 12-17: step 2, the approver key and approval state read, the `approval.age` temp file written and fsynced | n/a | v1, version 2 not reserved | 1 | Ready, previous policy |
| call 18: step 2, rename onto `approval.age` | lose all | v1, version 2 not reserved | 1 | Ready, previous policy |
| call 18: step 2, rename onto `approval.age` | keep all | v1, version 2 reserved | 1 | Ready, previous policy; the next approval is version 3 |
| calls 19-24: steps 2-4, the reservation durable; `config.toml.sig.staged` written, renamed, directory fsynced | any | v1, version 2 reserved | 1 (leftover pending and staged files are discarded) | Ready, previous policy; the next approval is version 3 |
| calls 25-29: step 5, the approval state read again, the new `approval.age` temp file written and fsynced | n/a | v1, version 2 reserved | 1 | Ready, previous policy; the next approval is version 3 |
| call 30: step 5, rename onto `approval.age` | lose all | v1, version 2 reserved | 1 | Ready, previous policy; the next approval is version 3 |
| call 30: step 5, rename onto `approval.age` | keep all | v2 | 4 | Ready, approved policy: recovery publishes both files |
| calls 31-32: step 5 directory fsync done; step 6 about to publish | n/a | v2 | 4 | Ready, approved policy: recovery publishes both files |
| call 33: step 6, rename onto `config.toml` | lose all | v2 | 4 | Ready, approved policy |
| call 33: step 6, rename onto `config.toml` | keep all | v2 | 2 | Ready, approved policy: recovery renames the staged approval |
| call 34: step 6, rename onto `config.toml.sig` | lose all | v2 | 4 | Ready, approved policy |
| call 34: step 6, rename onto `config.toml.sig` | keep both renames | v2 | 1 | Ready, approved policy |
| call 34: step 6, rename onto `config.toml.sig` | keep only the first | v2 | 2 | Ready, approved policy: recovery renames the staged approval |
| call 34: step 6, rename onto `config.toml.sig` | keep only the second | v2 | 3 | Ready, approved policy: recovery renames the pending config |
| calls 35-49: step 6 directory fsync done; the config check, and the unlinks of the leftover pending and staged files | n/a | v2 | 1 | Ready, approved policy |

A cut before call 30 never leaves version 2 committed, so the previous policy is served: the previous pair is intact
at every point, because the transaction writes only `config.toml.pending`, `config.toml.sig.staged` and `approval.age`
before the commit. A cut from call 30 on either loses the commit's rename (the previous policy, with version 2 still
consumed) or keeps it, and then recovery finishes exactly that transaction. No cut of this transaction reaches rows
5 to 8, because steps 1 and 4 fsync their files and the config directory before the commit. Those rows are covered
by the recovery tests of the store.

The test asserts each restart against the recovery table, and the row decides the outcome: rows 1 to 4 serve the
committed version's policy, rows 5 and 6 are Unavailable with `RecoveryNeeded`, and rows 7 and 8 are Unavailable with
`PolicyInvalid`, even when the committed version is the previous one. So a service that serves a version its disk has
not committed, serves a published pair that does not verify as the committed approval, or ends in any other state than
the table prescribes, fails it. Every row also checks that the highest version reserved on disk is at least the
highest version of any signature file that survived, so a signed version is never signed again.

**What the model varies.** Only the renames that no directory fsync had yet covered, as lost, all kept or one kept.
A temp file's creation and an unlink are never kept without their directory fsync, and a file's contents are kept only
if it was fsynced. A real filesystem may keep more. The test service also skips `sweep_stale_temps`, which
production runs at startup, so leftover temp files from a cut are not swept before the config check.

### Reasons a request sees

The redacted reasons are the service state model's four `UnavailableReason`s, with their `503` texts. This design
adds none:

| `UnavailableReason` (text) | When, in this design |
|---|---|
| `Checking` (`checking`) | throughout an approval's admission pause, a reload, and the config check after a vault change ([credential-commands.md](credential-commands.md#reaching-serving)) |
| `RecoveryNeeded` (`recovery needed`) | `approval.age` cannot be loaded; a config file is unreadable before the table (`Unreadable`); recovery rows 5 and 6; an uncertain commit could not be settled; a committed publish could not be finished |
| `PolicyInvalid` (`policy invalid`) | recovery rows 7 and 8; nothing committed; the published config fails validation or activation |
| `Locked` (`locked`) | not produced here; the vault is locked |

Logs and `status` give the owner the detail.

## Admission pause

A request is **admitted** when its one load from the snapshot holder returns a serving snapshot. The proxy handler
loads once per request, before caller identification, because identification reads the snapshot's policy.

**Mechanism.** The snapshot holder holds one value. It is either *serve*, with a serving snapshot, or *refuse*, with
an `UnavailableReason`. A request's load and every state transition's store each take the holder's lock once, so a
request sees exactly one of the two, and that load is its admission. Every transition stores the value derived from
the new state's `request_interface()`: *serve* for Ready, *refuse* with that state's reason otherwise. So the reason a
`503` carries has one source, the service state model. Entering the pause is a single store of *refuse* `checking`,
made in step 5 before the write of `approval.age` begins. The store happens before the commit, and every
load that returned the old snapshot happened before the store. Admission never checks "is the service paused?" and
then loads the snapshot in a second step, because a commit could land between the two.

- **It starts** in step 5, with the move to Checking, immediately before the durable replace of `approval.age` that
  commits the new approval.
- **It ends** in step 6, when the config check ends: with a store of *serve* and the new snapshot on Ready, or a store
  of *refuse* and the failure reason on Unavailable. When the commit cleanly did not happen, the check runs on the
  unchanged published pair, and the pause normally ends on the old policy, which is still the committed one.

An approval started from Unavailable(`PolicyInvalid`) makes no move to Checking and no store: the holder already
holds *refuse* `policy invalid`, so no request is admitted, and nothing changes until `Repaired` and the config check
that follows.

**Invariant.** No request is admitted under the old policy after the commit. Every admission under the old snapshot
happened before the pause began, and the pause begins before the commit.

**A request that arrives during the pause** gets `503` `checking` at once, as in every Checking state, and is never
admitted. A bounded wait instead, and a `Retry-After` header, are options ([open question 5](#open-questions)).

**How long the pause lasts.** The pause covers the commit, publish, the config check and the listener rebuild on entry
to Ready. That is milliseconds for the files and the signature check, and longer when the listener set changes or a
TLS listener's key is loaded. The config check builds its own upstream clients inside the pause; the step 1 dry run
only finds earlier the configs whose clients cannot be built.

**A request admitted before the pause** keeps the snapshot it took. This holds whether its upstream request has been
sent or not. If the pause ends on Ready, it finishes on the old snapshot: its route, its credential record, its
upstream client and its rate-limit charge all come from the old activation. If the pause ends on Unavailable, the old
snapshot is withdrawn, and its outstanding work is cancelled where the transport permits ([§12](iron-vault-specification.md#12-configuration-approval-and-reload)). Both are defaults
([open question 1](#open-questions)).

## Reload

The service reloads on SIGHUP, never by watching files ([implementation spec §2.2](implementation-specification.md#22-product-decisions-and-resulting-behavior) Q-5), and only from Ready. SIGHUP in any other state is
logged at INFO and ignored. In particular, a reload is not a way out of Unavailable: that takes an authorized repair or
a restart.

A reload takes the service-wide lock, so one that arrives during an approval runs after it. It then moves Ready to
Checking: a single store of *refuse* `checking` in the snapshot holder, after which requests get `503` `checking` until
the config check ends, as [§15](iron-vault-specification.md#15-service-states-and-errors) draws it. A reload commits nothing, so it never writes the approval state. The check
passing moves the service to Ready with a store of *serve* and the new snapshot. Failing moves it to Unavailable: the old
snapshot is withdrawn, its outstanding work is cancelled where the transport permits, and the service keeps no old
route policy ([§12](iron-vault-specification.md#12-configuration-approval-and-reload)). A failed reload is recorded as `config.reload-failed`, with a WARN to the owner.

## Approval summary

The service writes the approval summary itself ([§5](iron-vault-specification.md#5-service-and-cli-separation-of-concerns)). The
owner reviews it, it goes to the audit log, and its headline is in the command's result. v0 has no owner notifications;
from v1, the one for a completed approval carries the version and the headline
([owner-notifications.md](owner-notifications.md#which-events-notify)). It is a diff of the pending validated config
against the active one: the config of the current serving snapshot, or, when the service is unavailable or this is the
first approval, the empty config, in which case the summary says "no active config" and lists everything as added
([open question 10](#open-questions)).

The order is fixed, so the same two configs always give the same text:

1. **Header**: the vault ID, the version this approval will commit, the config digest as `blake2b:<64 hex>`, and the
   currently committed version or "none". The version is the highest reserved version plus one. That is exact,
   because the service-wide lock keeps anything else from reserving before this approval does. The summary body is a
   pure function of the two configs, and the command adds the header.
2. **Callers**: added, removed, or changed, with listener, authentication kind, peer account, and "token changed".
   A token hash is never shown.
3. **Route grants**: per caller, the routes granted and the routes revoked.
4. **Routes**, the destinations and restrictions [§5](iron-vault-specification.md#5-service-and-cli-separation-of-concerns) asks for: added, removed, or changed. A changed route shows
   each field that changed, old → new: prefix, upstream (host, port, base path), credential name, slot, pinned CA file,
   methods, path patterns, rate limit and confirmation.
5. **Listeners**: added, removed or changed. [§5](iron-vault-specification.md#5-service-and-cli-separation-of-concerns) does not list them, but a listener moved to a non-loopback
   address changes who can reach the routes, so hiding it would mislead the owner
   ([open question 14](#open-questions)). A listener the running service cannot bind is marked "takes effect after
   restart" ([open question 2](#open-questions)).
6. **Limits**: each operational limit that changed, old → new.
7. **Logging**: the log destination, old → new, when `[logging] destination` changes, including a change to or from
   the default; a default is shown as `default`, not as the bootstrap destination it resolves to, so the text depends
   only on the two configs and not on the deployment profile. A moved directory adds the line
   "add a logrotate rule for the new directory", since the shipped rule names only the default
   ([audit-logging.md](audit-logging.md#log-destination)). The audit log is where every later change is recorded, so
   moving it is never hidden.
8. **Recovery**: the [recovery reminder](recovery.md#reminders) interval, old → new, when `[recovery] reminder_days`
   changes, a default shown as `default`, as for logging. A longer interval delays the owner's reminders, so it is
   shown like any other change.
9. **Text only**: when the bytes differ but no section above has an entry, the line "no policy change; text changed"
   (whitespace or comments), so the summary is never empty.

Within each section, entries are in name order (`BTreeMap` order). Each entry is marked `+` added, `-` removed or `~`
changed. Every configured name is printed through the configured-name escaping, so a hostile name cannot forge a
summary line ([§18](iron-vault-specification.md#18-logging)).

The **headline** is one line of counts per section, such as `callers: 1 added, 2 changed; route grants: 3 added; routes:
1 changed; listeners: none; limits: none; logging: none; recovery: none`. It is bounded whatever the config size, so it
fits in the command's result.

## Audit events

Each event has a distinct name, so a reserved version is never mistaken for a completed approval
([§12](iron-vault-specification.md#12-configuration-approval-and-reload)). They are audit events in the audit log;
[audit-logging.md](audit-logging.md#audit-events) is the one place that lists each one's fields, with their names and
types, and the record shape they share. None carries config bytes, signature bytes, key material or a passphrase.

| Event | Level | When |
|---|---|---|
| `config.approval-refused` | WARN | the approval passphrase was wrong or the key is not the asked approver's; nothing was reserved |
| `config.version-reserved` | INFO | step 2's reservation is durable |
| `config.approval-failed` | WARN | the transaction failed after its reservation and before its commit |
| `config.commit-uncertain` | WARN | step 5's rename of `approval.age` landed, but its directory fsync failed |
| `config.approval-completed` | INFO | the commit is durable: step 5 succeeded, or an uncertain commit was settled |
| `config.activation-failed` | WARN | the config check after a committed approval failed, or an uncertain commit could not be settled |
| `config.reload-failed` | WARN | the config check of a SIGHUP reload failed |
| `config.recovery-published` | WARN | a config check finished publishing a committed transaction |
| `config.recovery-discarded` | INFO | a config check removed uncommitted files |
| `config.conflicting-approval-discarded` | ERROR | a config check discarded a staged approval signed for the committed version over another config |

An uncertain commit records `config.commit-uncertain`, followed by `config.approval-completed` once it is settled, or
by `config.activation-failed` when settling fails. A commit followed by a failed publish or check records
`config.approval-completed` and then `config.activation-failed`: the approval did complete, and only its activation
failed. *Reload* stays the SIGHUP operation alone, so a check after an approval is never a "reload failed".

`config.approval-refused`, `config.version-reserved` and `config.approval-completed` also name the approver that was
asked or signed, by approver ID and label, so the log says which signer approved each version: `approver_id` and
`approver_label` ([audit-logging.md](audit-logging.md#audit-events)). The label goes through the configured-name escaping
there and in the passphrase prompt, `Approval passphrase for "<label>"`.

## Open questions

The specification leaves each point below open, or this design departs from its wording. The owner has decided
questions 1 to 14, all but question 2 by accepting their defaults, and the design stands on them; only question 15 is
open, and takes its default until the owner decides.

1. **Requests admitted before an approval's commit.** *Decided: default accepted (2026-11-09).*
   [§12](iron-vault-specification.md#12-configuration-approval-and-reload) forbids admitting new requests under the
   previous policy after the commit, and says operations already sent upstream "remain subject to the cancellation
   limits below". It does not say what happens to requests admitted under the old policy before the pause, whether
   already forwarded or still inside the pipeline at the commit. That matters when an approval revokes a caller whose
   long streaming response is still running. *Default:* when the check ends on Ready, they all finish on the old
   snapshot. When it ends on Unavailable, the old snapshot is withdrawn and they are cancelled where the transport
   permits. This may depart from [§12](iron-vault-specification.md#12-configuration-approval-and-reload) rather than
   fill a gap in it: [§12](iron-vault-specification.md#12-configuration-approval-and-reload) carves out only operations
   "already sent upstream", so a request admitted but not yet forwarded at the commit may count as admitted under the
   old policy after the commit. The alternative cancels, or re-admits under the new snapshot, every request not yet
   forwarded when the pause begins.
2. **Listener changes in an approval.** *Decided (2026-11-09):* the rebuild closes, binds or adopts as the default says,
   and logs a listener it cannot open at WARN as missing until restart while the service enters Ready
   (`crates/iron-vault/src/service_context.rs`), but the approval summary does not mark that listener "takes effect
   after restart" (`crates/iron-vault-policy/src/approval_summary.rs`). On entry to Ready the listener set is rebuilt
   from the verified config. But in a protected Linux install every TCP listener comes from socket activation
   ([§7](iron-vault-specification.md#7-caller-authentication-and-listeners)), so a running service cannot bind a TCP
   listener that the new config adds. *Default:* the rebuild closes the sockets the new config no longer names and binds
   or adopts what it can. A listener it cannot bind is logged at WARN and stays missing until restart, the service still
   enters Ready, and the approval summary marks that listener "takes effect after restart".
3. **The events an approval uses.** *Decided: default accepted (2026-11-09).* The
   [§15](iron-vault-specification.md#15-service-states-and-errors) diagram labels its one edge from Ready to Checking
   "explicit reload", and nothing else, and `ServiceEvent::Reload` is SIGHUP's. *Default:* a new event, such as
   `ApprovalCommitting`, on that existing edge, so *Reload* keeps one meaning. The alternative reuses `Reload`. Also by
   default, from Unavailable(`PolicyInvalid`), `Repaired` fires once the commit is durable, and also for a commit that
   could not be settled, only so that the service can reach `RecoveryNeeded` through Checking (see
   [When `Repaired` fires](#when-a-step-fails)). The alternative adds a direct edge from Unavailable(`PolicyInvalid`) to
   Unavailable(`RecoveryNeeded`), which [§15](iron-vault-specification.md#15-service-states-and-errors) does not draw.
4. **The failure reason for recovery rows 5 to 8.** *Decided: default accepted (2026-11-09).* *Default:* rows 5 and 6, a
   committed transaction with a file waiting to be published, are `RecoveryNeeded`, as `FailureReason::RecoveryNeeded`'s
   doc comment describes ("a committed transaction could not be completed"). Rows 7 and 8, a published pair that does
   not verify, are `PolicyInvalid`. Consequence: in rows 5 and 6 `config approve` is refused (`admin_allows` offers only
   repair). No repair command is specified, in
   [§16](iron-vault-specification.md#16-administration-recovery-and-migration) or in any ticket, and a restart reaches
   the same row. So until one is, rows 5 and 6 have no exit but `reset`, which discards the vault and rebuilds it from
   reissued credentials. The alternative makes rows 5 and 6 `PolicyInvalid` too, so a new approval at a higher version
   is the repair. That is safe, because the new version is above the lost committed one, but K-124's doc comment would
   change.
5. **What a request sees during the pause.** *Decided: default accepted (2026-11-09).* *Default:* `503` `checking` at
   once, like any Checking state, with no `Retry-After`. An earlier draft of this design had requests wait up to 5
   seconds for the pause to end, then answer `503` with a fifth reason, `reconfiguring`, and `Retry-After: 1`. That
   hides a sub-second approval from callers, but adds an `UnavailableReason` and a wait that Checking does not have
   anywhere else.
6. **The order of step 2.** *Decided: default accepted (2026-11-09).*
   [§12](iron-vault-specification.md#12-configuration-approval-and-reload)'s text puts "authenticate the owner" before
   "show the service-generated summary". Its sequence diagram puts the summary first. *Default:* the diagram's order:
   summary, confirmation, approval passphrase, then reservation. The admin principal itself is authenticated at connect.
7. **Finishing a publish in a running service.** *Decided: default accepted (2026-11-09).*
   [§12](iron-vault-specification.md#12-configuration-approval-and-reload) allows finishing publishing "on restart".
   *Default:* every config check may finish it, under the same rule (only the committed transaction, only when its files
   verify): the check after an approval's commit, after an unlock and after a repair, as well as at startup. A failed
   directory fsync after the publish renames is logged and does not stop the check, because the commit is the durable
   record.
8. **The service-wide lock across prompts.** *Decided: default accepted (2026-11-09).* *Default:* `config approve` holds
   it from its request to its response, up to about 10 minutes across two prompts. Meanwhile other approvals and vault
   writes get `busy`, SIGHUP waits, and `lock` cancels an approval that is still at a prompt. The alternative takes the
   lock only after the passphrase, and refuses the approval if the committed approval or the catalog changed since the
   summary.
9. **Config directory mode, and refusing to start.** *Decided: default accepted (2026-11-09).* *Default:* the config
   directory is the service account's, with mode exactly `0700`, the state directory's rule. A refused config directory,
   config file or config-directory lock file stops startup. Before this, the check only reported.
10. **The summary when nothing is active.** *Decided: default accepted (2026-11-09).* *Default:* when the service is
    Unavailable, or for the first approval, the summary diffs against the empty config, says "no active config" and
    lists everything as added. An Unavailable service still has a committed approval, so the alternative diffs against
    the committed config, whose bytes are then read from `config.toml` if they verify.
11. **The notice frame in protocol version 1.** *Decided: default accepted (2026-11-09).* *Default:* the notice frame,
    byte values, `config approve` and error codes 7 to 12 join version 1 without a version bump, because version 1 has
    not been released.
12. **Where the CLI reads the config.** *Decided: default accepted (2026-11-09).* *Default:* `config approve <file>`
    only. stdin is not accepted, because when stdin is not a terminal it carries the answers to the prompts. K-128's
    spec read stdin when no file is given; K-128 followed this default instead.
13. **Settling an uncertain commit, and restarting after one.** *Decided: default accepted (2026-11-09).* *Default:* the
    transaction settles it with a second durable write of `approval.age`. A config check never writes the approval
    state, so if settling fails the service stays Unavailable with `RecoveryNeeded`. A restart without a reboot then
    reads a commit of version N that is visible in the page cache but may not be durable, and trusts it. If a later
    power loss undoes that commit, `approval.age` is back at N-1. If the publish renames were undone as well, the N-1
    pair is published again beside N's pending and staged files, so recovery serves the N-1 pair and discards N's files
    as uncommitted leftovers. (If the renames survived, the published N pair is `Uncommitted` and the service stays
    Unavailable.) The service would then serve N-1 after it served N, which is what
    [§12](iron-vault-specification.md#12-configuration-approval-and-reload)'s "never fall back to an older committed
    version" forbids. The alternative: every startup config check settles `approval.age` with a durable re-write,
    because after a restart nothing records whether the last commit was settled. That breaks "loading never writes the
    approval state", which K-126 asserts in a test.
14. **Sections beyond [§5](iron-vault-specification.md#5-service-and-cli-separation-of-concerns)'s list.**
    *Decided: default accepted (2026-11-09).* [§5](iron-vault-specification.md#5-service-and-cli-separation-of-concerns)
    says the summary includes "changed callers, route grants, destinations, restrictions, and the committed version".
    *Default:* the summary also lists listener and limit changes, and a text-only change, so no change to the config
    goes unshown.
15. **A wrong answer with more than one approver.** [§14](iron-vault-specification.md#14-recipients-startup-and-memory)
    lets the owner switch to another approval signer at the prompt. *Default:* a wrong passphrase or PIN for the asked
    approver ends the approval as `approval-denied`, and nothing moves on to the next approver by itself, so a guess
    against one signer is never followed by a free guess against another. The alternative offers the next approver
    after a wrong answer, within the same exchange. [approval-signers.md](approval-signers.md#a-wrong-answer) keeps the default and gives its
    reasons.

### Which tickets each question blocks

| Ticket | Open questions |
|---|---|
| the approver prompt ticket of [approval-signers.md](approval-signers.md#implementation-tickets) | 15 |
