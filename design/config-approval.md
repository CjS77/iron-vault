# Config approval transaction

How the service turns proposed config bytes into the config it serves (specification §3.9), and what it does with
whatever a crash leaves behind. Terms follow the [glossary](glossary.md); the byte formats of the approval payload,
the approval envelope and the approval state are in [storage-formats.md](storage-formats.md), and the `config approve`
command is in [admin-protocol.md](admin-protocol.md#config-approve).

Three §3.9 rules drive everything below:

- **Never promote a signed but uncommitted version.** A signature alone proves nothing about freshness; only the
  committed approval in `approval.age` does.
- **Never fall back to an older committed version.** If the committed transaction cannot be completed, the service
  stays unavailable.
- **Reserved counters stay consumed.** A version handed out for a signing attempt is never handed out again, whether
  or not the attempt finished.

Points the specification leaves open, and this design does not settle, are listed under [Open questions](#open-questions).

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
startup, as the binary and runtime directory already do (§3.1: "refuse an unsafe installation and explain which path
failed"). The package creates `/etc/iron-vault` owned by `iron-vault` with mode `0700`; in development the service
creates its config directory with mode `0700` when it is missing.

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

The approval transaction runs the six steps of §3.9 in order. Each step is durable before the next one starts.
Approvals, vault writes, reload and the config check are serialized by one service-wide lock, taken when the
`config approve` request arrives. Taking that lock fails at once if another operation already holds it, and the
command answers `busy`. It is held to the end of the exchange, prompts included, so a reload that arrives during an
approval waits for it.

| Step | What the service does | Durable change |
|---|---|---|
| 1 | Writes the proposed bytes as `config.toml.pending`. Then parses, validates and activates them against the credential catalog, capabilities and account directory, using the one owned buffer it wrote. Never reads the file back to do this. | `config.toml.pending` |
| 2 | Shows the approval summary and asks the owner to confirm it. Then takes the approval passphrase and opens the approver key with it (the owner's authorization, as in the §3.9 sequence diagram). Then reserves the next version. | `approval.age`: highest reserved version + 1 |
| 3 | Signs the approval payload (purpose, vault ID, the reserved version, the digest of the buffer) and drops the signer. | none |
| 4 | Writes the envelope as `config.toml.sig.staged`. Then builds the candidate serving snapshot from the step 1 activation: upstream clients and a new rate limiter. | `config.toml.sig.staged` |
| 5 | **Admission pause starts.** Commits `(version, digest)`. | `approval.age`: the committed approval |
| 6 | Publishes. Reads `config.toml` and `config.toml.sig` back, requires the config to equal the buffer, and verifies them with `verify_approval`. Swaps in the candidate snapshot. **Admission pause ends.** | `config.toml`, `config.toml.sig` |

A failure ends the transaction at that step:

| Fails at | Version | Files | Service afterwards |
|---|---|---|---|
| step 1: write, validation or activation | none reserved | pending removed | unchanged; `config-invalid` |
| step 2, before reserving: the owner declines or cancels, or the passphrase is wrong | none reserved | pending removed | unchanged |
| step 2, the reservation itself (counter exhausted, write failed) | none, or the one the uncertain write may hold | pending removed | unchanged |
| step 3 or 4 | consumed | pending and staged removed | unchanged; `approval-failed` |
| step 5, before the rename of `approval.age` | consumed | pending and staged removed | the pause ends on the **old** snapshot: nothing was committed |
| step 5, after the rename (the directory fsync failed) | consumed | left in place | **unavailable**, `recovery-needed`: the commit may or may not survive power loss, so neither the old nor the new policy may be served until the next config check reads `approval.age` back |
| step 6 | committed | left in place | **unavailable**, `recovery-needed`; the next config check (reload or restart) finishes publishing |

Removing uncommitted files is best effort. One left behind is a leftover that the next config check discards (see the
recovery table).

**Why the order of step 2 is passphrase, then reservation.** §3.9's text reads "authenticate the owner, show the
summary, and durably reserve". The admin principal is authenticated at connect, by its peer credentials. The owner's
own authorization, the approval passphrase, comes after the summary, as the §3.9 sequence diagram draws it, so the
owner authorizes what they have just read. Opening the approver key before reserving means a mistyped passphrase
consumes no version. A TPM signer authorizes inside step 3 instead, so its failed PIN does consume one, which §3.9
allows ("failed attempts consume their versions").

**Why the candidate snapshot is built before the pause.** Building upstream clients reads pinned CA files and sets up
TLS configurations: work that can take milliseconds and fail. Doing it before step 5 keeps the pause down to one
durable replace, two renames, a directory fsync and a signature check. A candidate that cannot be built fails the transaction before the
commit, leaving the old policy committed and active. Only the swap waits for verification, so the snapshot still
activates only a verified approval.

### Publish

Publish is step 6's file change, and the only way `config.toml` or `config.toml.sig` is ever written:

1. rename `config.toml.pending` to `config.toml`;
2. rename `config.toml.sig.staged` to `config.toml.sig`;
3. fsync the config directory.

The order follows §3.9's wording ("publish the pending config and artifact"). Nothing depends on it. Until the
directory fsync returns, power loss can keep either rename, both or neither, whatever order they ran in. So recovery
never infers progress from which file landed. It decides from the committed approval alone. The two files are
published separately, never as one atomic swap.

The same publish finishes a committed transaction during the config check. There it renames only the files that are
not yet in place.

## Recovery

The config check runs recovery first, at startup and at reload. It needs the vault identity to open `approval.age`, so
a locked service recovers when it is unlocked. Recovery reads `approval.age` and never writes it, so loading never
advances a counter.

### Inputs

- **C**, the committed approval `(version, digest)` from `approval.age`.
- The four data files in the config directory. A missing, oversized or non-regular file is *absent* for every purpose
  below.
- **Matches C**: a config file X and a signature file Y *match C* when `verify_approval(state, X, Y)` succeeds. That
  covers all of these: the envelope decodes; it is signed with the pinned approver's algorithm and key; it names this
  vault; its digest is the digest of X; and its version and digest are C. A config file holds C's config when its
  digest is C's digest. A signature file holds C's approval when it matches C with that config.

### Before the table

| Condition | Outcome |
|---|---|
| `approval.age` missing, damaged, a partial restore, or unreadable | **stay unavailable**, `recovery-needed`; touch nothing |
| nothing committed (`NothingCommitted`: a vault whose first approval never committed) | **stay unavailable**, `policy-invalid` (detail: no approved config); touch nothing |

### Recovery table

Find where C's config is (`config.toml` or `config.toml.pending`) and where C's approval is (`config.toml.sig` or
`config.toml.sig.staged`). A file already in place is preferred over its pending or staged counterpart:

| Row | C's config in | C's approval in | State it comes from | Outcome |
|---|---|---|---|---|
| 1 | `config.toml` | `config.toml.sig` | published, or no transaction was running | **serve the published pair**; discard any pending or staged file |
| 2 | `config.toml` | `config.toml.sig.staged` | half published: new config, old signature | **finish publishing**: rename the staged approval, fsync |
| 3 | `config.toml.pending` | `config.toml.sig` | half published: new signature, old config | **finish publishing**: rename the pending config, fsync |
| 4 | `config.toml.pending` | `config.toml.sig.staged` | committed, nothing published yet (a crash in step 6, or between steps 5 and 6) | **finish publishing**: both renames, fsync |
| 5 | either, or nowhere | nowhere | | **stay unavailable**, `policy-invalid`; touch nothing |
| 6 | nowhere | either | | **stay unavailable**, `policy-invalid`; touch nothing |

After rows 2-4 the published pair matches C. Any pending or staged file still left is discarded, and the check goes
on as for row 1. A publish that fails midway leaves a state this table resolves to row 1, 2, 3 or 4, so recovery is
safe to run again. Each finish is recorded as `config.recovery-published`.

*Discard* means durable remove, then the `config.recovery-discarded` event naming each file and, for a staged
approval, the version it was signed for. Discarding never touches the counters: a discarded staged approval's version
stays consumed.

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
| absent or present | present | does not verify (malformed, wrong algorithm, bad signature, wrong vault) | discard |

### Detail when the service stays unavailable (rows 5 and 6)

The redacted reason is `policy-invalid` in both rows, and recovery changes nothing on disk, so the files stay as
evidence. The next `config approve` overwrites the pending config and the staged approval anyway. The detail logged
for the owner is the first that applies to the published pair, in this order:

| Published pair | Detail | `VerifyError` |
|---|---|---|
| `config.toml` or `config.toml.sig` absent | the committed config or its signature is missing | none |
| the signature does not decode | signature malformed | `Malformed` |
| another algorithm than the pinned approver's | signed with the wrong algorithm | `WrongAlgorithm` |
| the signature does not verify against the pinned key | bad signature | `BadSignature` |
| the payload names another vault | approval is for another vault | `WrongVault` |
| the config's digest is not the signed one | config changed since it was approved | `ConfigChanged` |
| the version is below C | an old config and signature pair; never fall back to it | `Superseded` |
| the version is above C | signed but never committed; never promote it | `Uncommitted` |
| C's version with another digest | the signer signed one version twice | `DigestNotCommitted` |

Row 5 with C's config in place but C's approval lost, and row 6 with C's approval staged but its config lost, are both
committed transactions that cannot be completed. §3.9 requires the service to stay unavailable then, never to serve
the older pair beside them. The repair is a new approval at a higher version.

### After recovery

The config check then parses, validates and activates the published config. A config that fails (for example, an
unknown credential reference) is `policy-invalid`. A damaged or needs-login record is not a failure: only its routes
are unavailable (§3.9). Last, the check builds the serving snapshot.

### Redacted reasons

A request answered `503` sees only the redacted reason, and logs and `status` give the owner the detail. The reasons
this design produces:

| Redacted reason | When |
|---|---|
| `recovery-needed` | `approval.age` cannot be loaded; a commit whose durability is uncertain; a committed transaction whose publish failed in the running service |
| `policy-invalid` | rows 5 and 6; nothing committed; the published config fails validation or activation |
| `reconfiguring` | an admission pause outlasted the request's wait (see below) |

`locked` is the service state model's reason, not this design's. The service state model owns the full set. This
design adds `reconfiguring` to it.

## Admission pause

A request is **admitted** when it takes a serving snapshot. The proxy handler does this once per request, before
caller identification, because identification reads the snapshot's policy. The admission pause is the interval in
which no request is admitted.

- **It starts** in step 5, immediately before the durable replace of `approval.age` that commits the new approval,
  after the candidate snapshot is built.
- **It ends** in step 6, when the candidate snapshot is swapped in, after publish and verification. If the transaction
  fails during the pause, it ends there instead: on the old snapshot when the commit cleanly did not happen, otherwise
  with the service unavailable (see the failure table).

**Invariant.** No request is admitted under the old policy after the commit. Every admission under the old snapshot
happened before the pause began, and the pause begins before the commit.

**A request that arrives during the pause waits.** It waits until the pause ends, at most `ADMISSION_WAIT` (5 seconds),
and never past its own request deadline. If the pause ends in time, the request is admitted under whatever follows:
the new snapshot, or a `503` with the redacted reason if the service went unavailable. If the wait runs out first,
the request gets `503` with reason `reconfiguring` and `Retry-After: 1`, and is never admitted. A normal pause is one
durable replace, two renames, a directory fsync and a signature check, well under a second, so callers see a short delay instead of an
error. The bound keeps a stalled disk from holding connections open indefinitely. The wait counts against the request
server's request timeout like any other handler time.

**A request admitted before the pause** keeps the snapshot it took and finishes on it: its route, its credential
record, its upstream client and its rate-limit charge all come from the old activation. A successful approval does not
cancel it. Only a withdrawn snapshot (a failed reload, a lock) cancels outstanding work, where the transport permits
(§3.9). See [open question 1](#open-questions).

**Reload has no pause.** A reload commits nothing. Requests keep the current snapshot until the check finishes. On
success, the new snapshot is swapped in. On failure, the old one is withdrawn at once, so new requests get `503`, and
the service keeps no old route policy (§3.9).

## Reload

The service reloads on SIGHUP, never by watching files (§8.2 Q-5). A reload takes the service-wide lock, so one that
arrives during an approval runs after it, and then runs the config check against the unlocked vault. A reload that
fails is recorded as `config.reload-failed`, with the detail, and a WARN to the owner.

## Approval summary

The service writes the approval summary itself (§3.2). The owner reviews it, it goes to the audit log and the owner
notification, and its headline is in the command's result. It is a diff of the pending validated config against the
active one: the config of the current serving snapshot, or, when the service is unavailable or this is the first
approval, the empty config, in which case the summary says "no active config" and lists everything as added.

The order is fixed, so the same two configs always give the same text:

1. **Header**: the vault ID, the version this approval will commit, the config digest as `blake2b:<64 hex>`, and the
   currently committed version or "none". The version is the highest reserved version plus one. That is exact,
   because the service-wide lock keeps anything else from reserving before this approval does. The summary body is a
   pure function of the two configs, and the command adds the header.
2. **Callers**: added, removed, or changed, with listener, authentication kind, peer account, and "token changed".
   A token hash is never shown.
3. **Route grants**: per caller, the routes granted and the routes revoked.
4. **Routes**, the destinations and restrictions §3.2 asks for: added, removed, or changed. A changed route shows
   each field that changed, old → new: prefix, upstream (host, port, base path), credential name, slot, pinned CA file,
   methods, path patterns, rate limit and confirmation.
5. **Listeners**: added, removed or changed. §3.2 does not list them, but a listener moved to a non-loopback
   address changes who can reach the routes, so hiding it would mislead the owner.
6. **Limits**: each operational limit that changed, old → new.
7. **Text only**: when the bytes differ but no section above has an entry, the line "no policy change; text changed"
   (whitespace or comments), so the summary is never empty.

Within each section, entries are in name order (`BTreeMap` order). Each entry is marked `+` added, `-` removed or `~`
changed. Every configured name is printed through the configured-name escaping, so a hostile name cannot forge a
summary line (§3.15).

The **headline** is one line of counts per section, such as `callers: 1 added, 2 changed; route grants: 3 added;
routes: 1 changed; listeners: none; limits: none`. It is bounded whatever the config size, so it fits in the
command's result.

## Audit events

Distinct names, so a reserved version is never mistaken for a completed approval (§3.9). EP-26 adopts them for the
audit log. Until then they are `tracing` events with these names. None carries config bytes, signature bytes, key
material or a passphrase.

| Event | Level | When | Fields |
|---|---|---|---|
| `config.version-reserved` | INFO | step 2's reservation is durable | version, config digest |
| `config.approval-completed` | INFO | the commit is durable (step 5) | version, config digest, the approval summary |
| `config.approval-failed` | WARN | the transaction failed after its reservation and before its commit | version (consumed), the step that failed, the error |
| `config.reload-failed` | WARN | a config check failed in a running service: a SIGHUP reload, or step 6 after a commit | trigger (`signal` or `approval`), redacted reason, detail |
| `config.recovery-published` | WARN | the config check finished publishing a committed transaction | version, which renames it ran |
| `config.recovery-discarded` | INFO | the config check removed uncommitted files | each file, and a staged approval's version |

A commit followed by a failed publish records `config.approval-completed` and then `config.reload-failed` with
trigger `approval`. The approval did complete, and only its activation failed.

## Open questions

These are points where the specification is ambiguous. The design above takes the default stated for each, which the
downstream tickets already assume, but each needs the owner's decision before the code is final.

1. **In-flight requests across a successful approval.** §3.9 says "never admit new requests under the previous policy
   after that commit" and "operations already sent upstream remain subject to the cancellation limits below". The
   cancellation limits are those of a failed reload ("cancel or stop outstanding work where the transport permits").
   It is unclear whether a successful approval must also cancel requests admitted under the old policy. That matters
   when an approval revokes a caller whose long streaming response is still running. *Default:* they finish on the
   old snapshot. Only a withdrawn snapshot cancels.
2. **Listener changes in an approval.** The serving snapshot carries callers and routes, but listeners are bound
   sockets, and in a protected Linux install every TCP listener must come from socket activation (§3.4), so the
   service cannot bind a new TCP listener while it runs. The specification does not say whether an approval that adds,
   removes or moves a listener applies it at once or at the next restart. *Default:* inside the admission pause,
   before the swap, the service rebuilds the listener set the way the service runtime does on entering Ready. Sockets
   the new config no longer names are closed. A listener the new config adds that cannot be bound or adopted now is
   logged at WARN and stays missing until restart, and the summary marks it "takes effect after restart". The other
   routes serve under the new policy.
