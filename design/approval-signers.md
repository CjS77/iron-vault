# Approval signers

How the owner lists, enrolls and removes approval signers with `iron-vault approver list`, `approver add` and
`approver remove`, and how a prompt chooses which pinned approver to ask (specification
[§12](iron-vault-specification.md#12-configuration-approval-and-reload),
[§14](iron-vault-specification.md#14-recipients-startup-and-memory),
[§16](iron-vault-specification.md#16-administration-recovery-and-migration)). It covers who may change the set of
pinned approvers, where a software signer's key lives, the approver prompt and the frame that switches it, and the
admin protocol rows, error codes and audit events the commands add. Terms follow the [glossary](glossary.md). The byte
formats are in [storage-formats.md](storage-formats.md#approval-state-file-v1), and the approval transaction that asks
an approver is in [config-approval.md](config-approval.md#choosing-the-signer).

Four rules drive the design:

- **Every pinned approver speaks for the owner.** Any one of them gives owner presence
  ([§14](iron-vault-specification.md#14-recipients-startup-and-memory)), so adding one is as powerful as approving a
  config. Enrolling or removing an approver therefore needs the same fresh proof: owner presence from an approver that
  is already pinned, the existing-owner authorization [§12](iron-vault-specification.md#12-configuration-approval-and-reload)
  requires for signing-key rotation.
- **Unlocking never grants approval** ([§14](iron-vault-specification.md#14-recipients-startup-and-memory)). The vault
  passphrase never enrolls an approver, or a stolen unlock secret would yield approval. When every signer is lost, the
  one way back is the offline recovery key, which already opens everything approval protects.
- **Switching is the owner's choice, never a retry.** A prompt names the approver it asks. The owner may switch to
  another before answering; a wrong answer ends the exchange.
- **No change leaves the vault without a signer, or serving a config that no pinned approver signed.** The last
  approver is never removed ([§14](iron-vault-specification.md#14-recipients-startup-and-memory)), and neither is the
  one that signed the active approval, so removing an approver never takes routes down.

Every default this design picks where the ticket or the specification leaves a choice is listed under
[Open questions](#open-questions).

## Signer kinds

Every pinned approver has one [signer kind](glossary.md), which says what signs for it and so how the service asks for
it. The algorithm alone cannot say that: a TPM and a hardware key may both sign with P-256.

| Code | Kind | Algorithms | What signs | Phase |
|---|---|---|---|---|
| `1` | `software` | Ed25519 (`01`) | The [software signer](glossary.md): an Ed25519 key in its own approver key envelope, opened by its approval passphrase | v0 |
| `2` | `tpm` | reserved; EP-33 chooses, P-256 (`02`) expected | A TPM approval key with a PIN ([§12](iron-vault-specification.md#12-configuration-approval-and-reload)) | EP-33 |
| `3` | `hardware` | reserved | A hardware key with PIN and touch ([future spec §2.1](future-specifications.md#21-hardware-key-recipients-signers-and-touch-confirmation)) | the hardware-key phase |

The kind is one byte in each approver entry of the [approval state payload v1](storage-formats.md#approval-state-payload-v1),
directly after the algorithm. As with [recipient roles](recipients.md#recipient-roles), codes 2 and 3 are reserved now
so that later epics need no new format version: this release refuses them when it reads the approval state, and the
epic that enrolls one makes the decoder accept it. A code above 3 is unknown, and decoding also refuses an entry whose
algorithm its kind does not allow. The approval state v1 has not been released, so the byte joins v1: each entry grows
to at most 171 bytes, the one-approver example payload becomes 187 bytes, and 16 entries fit in 37 + 8 + 16 × 171 + 49
= 2,830 bytes, inside `MAX_APPROVAL_STATE_LEN`. The kind names are what `approver list` prints and the audit log
records.

## Commands

| Command | Authorization | Changes |
|---|---|---|
| `iron-vault approver list` | none beyond the admin principal | nothing |
| `iron-vault approver add --label <text> [--kind software] [--with-recovery-key]` | owner presence, or [recovery-key authorization](#recovery-key-authorization) with the flag | enrolls a new approver of that kind |
| `iron-vault approver remove <approver ID> [--with-recovery-key]` | owner presence, or recovery-key authorization with the flag | removes that approver |

The noun is `approver` because the commands change the [pinned approvers](glossary.md); each has an approval signer
behind it. A command names an approver by its approver ID, never its label, because labels need not be unique, as
for [recipient labels](recipients.md#recipient-labels). An approver ID and a label are public, so they travel as
arguments; no secret is ever an argument ([§16](iron-vault-specification.md#16-administration-recovery-and-migration)).
The label follows the recipient label rule. `--kind` takes `software`, `tpm` or `hardware` and defaults to `software`,
the one kind v0 offers. The service, not the CLI, refuses a kind this install does not offer yet, because a method is
offered only after it passes its release checks
([§14](iron-vault-specification.md#14-recipients-startup-and-memory)).

### Authorization

**Owner presence.** Both changes ask through the [approver prompt](#the-approver-prompt), which accepts any pinned
approver, including the one being removed: the owner who holds a signer may retire it with that signer. This is
existing-owner authorization in the sense of [§12](iron-vault-specification.md#12-configuration-approval-and-reload):
proof, collected now, that the owner takes part in this exchange, for the one change the summary just described, and
never kept or reused ([credential-commands.md](credential-commands.md#owner-presence)).

**What does not authorize.** An admin connection alone does not: malware with one could otherwise enroll a signer of
its own and then approve any config, which is what approval exists to prevent. That is how this design reads
[§12](iron-vault-specification.md#12-configuration-approval-and-reload)'s "administrator or existing-owner
authorization" ([open question 1](#open-questions)). Neither does the vault passphrase, nor migration authorization,
which proves the vault passphrase: approval is separate from unlock
([§14](iron-vault-specification.md#14-recipients-startup-and-memory)).

### Recovery-key authorization

An owner who has forgotten every approval passphrase, or lost every signer, has no approver left to give presence.
Without a fallback that vault could never approve a config, replace a credential or remove a recipient again, and
`reset`, which discards the vault, would be the only way out. The fallback is the recovery key
([open question 2](#open-questions)).

With `--with-recovery-key`, the authorization step sends the secret prompt `Recovery key`, the label `recovery check`
uses ([recovery.md](recovery.md#the-exchange)), in place of the approver prompt. The service:

1. parses the text as a recovery key, and refuses anything else with `recovery-key-invalid`;
2. proves it as a recovery check does, from the files on disk: the key must unwrap `identity.age`, and the vault
   manifest's MAC must verify with the identity it unwraps ([recovery.md](recovery.md#what-the-check-proves)). The
   unwrapped identity's public key must also equal the vault identity the service holds. A key that fails is
   `recovery-check-failed`; a file that cannot be read is `recovery-check-unavailable`;
3. drops the key and the identity it unwrapped.

It does not write the [recovery check record](glossary.md): the record says when the owner last ran `recovery check`,
and reminders count from that alone.

This grants nothing the recovery key does not already give. The recovery key opens the vault identity, and with it
every credential the approval protects. The vault passphrase also opens the vault identity, but it is typed at every
start, and [§14](iron-vault-specification.md#14-recipients-startup-and-memory) keeps a stolen unlock secret from
changing policy. The recovery key is kept offline and used rarely, and its use here is loud: the summary says it
authorizes, the audit event records `authorized_by` `recovery_key`, and the completion notice tells the owner what to
do next.

Recovery-key authorization covers `approver add` and `approver remove` only. `remove` takes it too, so that a vault
whose 16 approvers are all lost can make room. It never authorizes `config approve`, a vault change or `recipient
remove`: once a new approver is pinned, the owner uses it. It is not a source-owner method, so migration authorization
is unchanged ([migration-authorization.md](migration-authorization.md#source-owner-method)).

### States and the service-wide lock

Every approver command needs Ready. The approval state is sealed to the vault public key and MAC'd with a key derived
from the vault identity; Locked holds no vault identity, Checking is transient, and Unavailable is for repair. In any
other state the exchange ends with `wrong-state` before any prompt. Repair needs no approver change: `config approve`
runs in Unavailable with `PolicyInvalid` and asks an approver that is already pinned. The three commands map onto the
admin operation `AdminOperation::VaultChange`, which the service state gate offers only in Ready, as the recipient
commands do.

Each command holds the service-wide lock from its checks to its response, prompts included. It tries the lock and
answers `busy` at once if it is taken. The lock serializes approver changes with approvals, so an approval's step 2
never asks an approver that a concurrent removal takes away, and the summary stays true until the write. A `lock`
cancels a command at any of its prompts. Before it writes, a change checks that the service is still in the state and
at the check generation it recorded when it took the lock, as `replace` does
([order of steps](credential-commands.md#order-of-steps), step 8), and answers `wrong-state` otherwise.

### `approver list`

| Step | What the service does | Refusal |
|---|---|---|
| 1 | The service is Ready | `wrong-state` |
| 2 | Try the service-wide lock | `busy` |
| 3 | Answer with every pinned approver, in [approver order](#approver-order), each marked with whether it signed the active approval | |

The CLI prints one line per approver to stdout: the approver ID in lowercase hyphenated form, two spaces, the kind
padded with spaces to 8 characters, two spaces, the enrolment time as `YYYY-MM-DDTHH:MM:SSZ`, two spaces, `active` or
`-` padded to 6 characters, two spaces and the label, with control characters removed. `active` marks the approver
whose signature the active `config.toml.sig` carries; the first line is the approver a prompt asks first. For example:

```text
4b0e3d2c-1a9f-4e8d-8c7b-6a5f4e3d2c1b  software  2026-11-08T10:12:44Z  active  backup passphrase
8d1c6f0e-2b7a-4c59-9e3d-5a4b3c2d1e0f  software  2026-11-06T09:49:13Z  -       approval passphrase
```

The output is a function of the service's answer, so two runs on the same state are byte-identical.

### `approver add`

| Step | What the service does | Refusal |
|---|---|---|
| 1 | The service is Ready; the label follows its rule; this install offers the kind | `wrong-state`, `approver-invalid`, `approver-kind-unavailable` |
| 2 | Try the service-wide lock, recording the state and check generation | `busy` |
| 3 | Remove [orphan key files](#orphan-key-files); fewer than `MAX_APPROVERS` (16) approvers are pinned | `approver-set-invalid` |
| 4 | The [summary](#summaries), as notices | |
| 5 | Authorization: the approver prompt, or the `Recovery key` prompt with `--with-recovery-key` | `approval-denied`, `approval-unavailable`; `recovery-key-invalid`, `recovery-check-failed`, `recovery-check-unavailable` |
| 6 | The new signer's secret. For `software`, two secret prompts, `New approval passphrase for "<label>"` and `Repeat the new approval passphrase`, checked by the [passphrase rules](vault-initialization.md#passphrase-rules): at least 12 Unicode scalar values, and the two must match, compared in constant time | `passphrase-rejected` |
| 7 | Still Ready at the recorded check generation | `wrong-state` |
| 8 | The [approver change](#approver-changes) that enrolls, then the [completion notice](#the-completion-notice) | `vault-write-failed` |

The result is the new approver ID and the approver count. The CLI prints the approver ID and a newline to stdout, so a
script can capture it, and nothing else.

Authorization comes before the new secret, so the owner never chooses a passphrase for a change that is then refused.
A refusal at step 3 comes before any prompt.

**A new approval passphrase is not compared with the vault passphrase.** `init` refuses an approval passphrase equal to
the vault passphrase, because it holds both. `approver add` holds only the new one, and the only way to compare would
be to try it on `operational.age`. That would answer, for anyone who holds a signer, whether a guess is the vault
passphrase, with no attempt limit, and the vault passphrase is what migration authorization and `recipient add` rest
on. The summary asks the owner to choose one that differs instead ([open question 5](#open-questions)).

### `approver remove <approver ID>`

| Step | What the service does | Refusal |
|---|---|---|
| 1 | The service is Ready; the argument is a version 4 UUID | `wrong-state`, `approver-invalid` |
| 2 | Try the service-wide lock, recording the state and check generation | `busy` |
| 3 | Remove orphan key files; the ID names a pinned approver; it is not the last; it did not sign the active approval | `unknown-approver`, `approver-set-invalid`, `approver-in-use` |
| 4 | The summary, as notices | |
| 5 | Authorization, as for `add` | as for `add` |
| 6 | Still Ready at the recorded check generation | `wrong-state` |
| 7 | The approver change that removes, then the completion notice | `vault-write-failed` |

The result is the approver count. On success the CLI prints nothing to stdout.

**Why the approver that signed the active approval cannot be removed.** The store allows it, and removing it stops the
active `config.toml.sig` verifying until the config is approved again
([§12](iron-vault-specification.md#12-configuration-approval-and-reload)). The next config check, at a reload, an
unlock or a restart, would then find a published pair that does not verify and stop proxying, with every route down
until the owner approved again. Refusing instead keeps rotation free of an outage: enroll the new approver, approve the
config with it (switching to it at the prompt), then remove the old one. The `approver-in-use` message says so. An
owner whose lost signer approved the active config approves it again with another approver first, which may be one
just enrolled with the recovery key ([open question 4](#open-questions)).

## Approver changes

An [approver change](glossary.md) is one of the store's two approval-state writes, enroll approver and remove approver
([storage-formats.md](storage-formats.md#writes)), together with the software signer's key file. Each keeps both
counters, and each runs only under the service-wide lock, after its authorization.

**Enroll, for `software`:**

1. Generate an Ed25519 key and a new approver ID, a random version 4 UUID that is never reused.
2. Seal the key to the new approval passphrase and write it, with a durable replace, as the approver's
   [key file](#software-signer-keys). The name is new, so nothing is overwritten.
3. Read the file back and open it with the passphrase, checked against the approver about to be pinned, as `init`'s
   step 7 does ([vault-initialization.md](vault-initialization.md#write-order)). A pinned software approver therefore
   always has a key file that opens. The passphrase and the key are dropped.
4. Enroll the pinned approver in `approval.age` with one durable replace. **This is the commit point**; the in-memory
   approval state changes only after it returns.

**Remove:**

1. Remove the pinned approver from `approval.age` with one durable replace. **This is the commit point.**
2. Remove its key file, then fsync the state directory. A failure here does not undo the removal: the approver is
   gone, the file is an orphan, the response still succeeds, and `approver.removed` records `key_file` `left`.

A failure before the commit point leaves the approval state as it was, and at most an orphan key file. A failed
directory fsync after the rename of `approval.age` leaves the change visible but perhaps not durable. The answer is
then `vault-write-failed`, whose message says the change may have committed and to run `approver list`, and the
in-memory approval state accepts no more writes until it is loaded again from disk, as after a reservation whose
directory fsync failed ([config-approval.md](config-approval.md#when-a-step-fails)).

### Orphan key files

A key file whose approver ID no pinned approver has is an orphan: an enrollment that failed before its commit point
left it, or a removal could not delete it. It signs nothing, because the service opens a key file only for the pinned
approver it names, and `open_signer_key` refuses a key that is not that approver's. Every approver change removes
orphans at its step 3, before any prompt, and logs each with `approver.orphan-removed`. Nothing else removes them:
`unlock` and the config check never write. An orphan is not a foreign file, because `approver-*.age` names are the
vault's own ([vault-initialization.md](vault-initialization.md#initialization-state)).

Removing an approver reaches future copies of the state directory only. A backup taken before still holds the key file
and an `approval.age` that pins it, and restoring the whole directory restores both; that is whole-storage rollback,
which [§12](iron-vault-specification.md#12-configuration-approval-and-reload) leaves outside v0. The summary says so.

## Software signer keys

Each software approver has its own [approver key envelope](storage-formats.md#approver-key-envelope), in the state
directory as `approver-<approver ID>.age`, with the ID in lowercase hyphenated form, for example
`approver-8d1c6f0e-2b7a-4c59-9e3d-5a4b3c2d1e0f.age`. The envelope's format is unchanged: one scrypt stanza and the
32-byte Ed25519 seed. `init` writes its one approver's key under this name too, so there is one rule for every
software approver.

One file each, rather than one file holding several keys, because:

- `age` cannot put two scrypt stanzas in one file, or an scrypt stanza beside any other, so several keys in one file
  would be a container format of Iron Vault's own;
- the approver prompt names one approver, so the service opens that approver's file alone: one scrypt run per answer,
  never a trial of each file in turn, each costing about a second and 256 MiB;
- an enrollment and a removal each touch one file, and no change rewrites another approver's key;
- it has the shape of record files, `record-<record ID>.age`.

Each software approver has its own approval passphrase, chosen when it is enrolled. Two may share one; the service does
not check, because it would have to open every other key file to know.

## The approver prompt

Owner presence ([credential-commands.md](credential-commands.md#owner-presence)) and step 2 of `config approve`
([config-approval.md](config-approval.md#choosing-the-signer)) ask through the [approver prompt](glossary.md). It names
one pinned approver by its label, and when more than one is pinned it lets the owner switch to the next before
answering.

### Approver order

The [approver order](glossary.md) is:

1. the approver that signed the active approval, when there is one;
2. then every other pinned approver by enrolment time, earliest first, with ties broken by approver ID.

The active approval is the one the serving snapshot was built from, so the service knows its signer whenever it is
Ready: the verified approval carries the approver ID from `config.toml.sig`. In Unavailable, where `config approve`
also runs, there is no active approval and the order is enrolment order alone.

Putting the active approval's signer first asks the owner for the signer they last approved with, and stores nothing to
do it: there is no preference to write and no command to set one. An owner who enrolls a hardware key switches to it
once, at the next approval, and from then on it is asked first. Enrolment order puts `init`'s approval passphrase
first ([open question 3](#open-questions)).

The prompt starts at the first approver in the order. Each switch moves to the next, wrapping round after the last, so
the owner can cycle through them all.

### Prompt text

The service writes the prompt label from the approver's kind and label:

| Kind | Label | Secret |
|---|---|---|
| `software` | `Approval passphrase for "<label>"` | yes |
| `tpm` | `TPM PIN for "<label>"`, which EP-33 confirms | yes |
| `hardware` | the hardware-key phase's, for a PIN and then a touch, such as `Tap "<label>" to approve` | |

The label is the pinned approver's own, which the CLI shows with control characters removed, as it shows every label.
It may hold a `"`; it is the owner's text, shown as is and never parsed.

At a terminal, the CLI writes a switchable prompt as the label, then ` (Ctrl-Y to try another way): `:

```text
Approval passphrase for "backup passphrase" (Ctrl-Y to try another way):
```

A prompt that cannot switch is written as before, the label and `: `. When stdin is not a terminal the CLI cannot
switch, so it writes the label alone, to stderr when that is a terminal. The text in
[§14](iron-vault-specification.md#14-recipients-startup-and-memory), `Tap "Dave YubiKey 3" to approve. Ctrl-Y to try
another way.`, is the touch form, which arrives with hardware keys ([Later signer kinds](#later-signer-kinds)).

### Switching

The [prompt frame](admin-protocol.md#prompt-kind-2) gains a third field, `switchable`, a flag that every prompt
carries. It is `1` only on an approver prompt while more than one approver is pinned. The CLI may answer a switchable
prompt with a [switch](glossary.md) frame, kind 8 with an empty body, instead of owner input. A switch answering any
other prompt is `unexpected-frame`, and a switch frame with a body is `malformed-frame`. On a switch the service sends
the approver prompt for the next approver in approver order. Nothing typed was sent, so nothing is dropped.

**Ctrl-Y.** For a switchable prompt at a terminal, the CLI sets `c_cc[VEOL]` to Ctrl-Y (`0x19`) for the read, beside
turning echo off, and the guard that restores echo restores it too. In canonical mode `VEOL` ends a line as Enter does,
so Ctrl-Y ends the read at once. A line that ends in `0x19` is a switch: the CLI clears whatever was typed before it,
writes a newline, and sends a switch frame. Linux gives Ctrl-Y no other meaning (it has no `VDSUSP`). A passphrase
holding the byte `0x19` cannot be typed at a switchable terminal prompt; it can still be piped. When stdin is not a
terminal the CLI never sends a switch, so a script answers the first approver in approver order, which `approver list`
shows ([open question 8](#open-questions)).

**Deadline.** The [prompt deadline](glossary.md) covers the whole approver prompt, from the first approver's prompt to
the answer, however many switches come between. Switching therefore never holds the service-wide lock longer than one
prompt can. A `lock` cancels the command at any approver prompt, as it does at every prompt. A switch records no audit
event; the events that end the prompt name the approver that answered.

### A wrong answer

A wrong passphrase or PIN for the asked approver ends the exchange as `approval-denied`, and the service never moves
on to another approver by itself. This design keeps the default of
[open question 15 in config-approval.md](config-approval.md#open-questions), for the owner to confirm:

- the owner switches before answering, so moving on after a wrong answer would help only a typo, which running the
  command again also fixes;
- each answer is then one exchange: a guess against any approver costs a whole exchange and is recorded on its own,
  naming that approver, instead of several guesses at several approvers sharing one;
- a wrong TPM PIN counts against the TPM's dictionary-attack lockout. Moving on silently would hide that count from the
  owner until the next approval.

## Summaries

The service writes each summary itself and sends it as notices before the authorization prompt
([§5](iron-vault-specification.md#5-service-and-cli-separation-of-concerns)). Answering the authorization prompt after
it is the confirmation; there is no separate `Type yes`, as for the [recipient commands](recipients.md#summaries).

```text
enroll an approval signer
  vault: 2a682de7-b14d-4900-9ea9-0c968e1a6589
  kind: software
  label: backup passphrase
  approvers after the change: 2
  the new signer alone can approve a config and authorize replace, rm, recipient remove and approver changes
  next: choose its approval passphrase, different from the vault passphrase
  authorize with: any pinned approver
```

```text
remove an approval signer
  vault: 2a682de7-b14d-4900-9ea9-0c968e1a6589
  approver: 8d1c6f0e-2b7a-4c59-9e3d-5a4b3c2d1e0f
  kind: software
  label: approval passphrase
  enrolled: 2026-11-06T09:49:13Z
  approvers after the change: 1
  it can no longer approve or give owner presence; copies of the state directory made before still pin it
  authorize with: any pinned approver
```

With `--with-recovery-key` the last line reads `authorize with: the recovery key`. Labels are written with control
characters removed.

### The completion notice

After a change commits, and before its success response, the service sends one notice:

- enrolled: `enrolled approver <approver ID> (<kind>); the vault has <n> approvers.` After recovery-key authorization a
  further line follows: `Approve the config again with the new approver, then remove the ones you lost with iron-vault
  approver remove.`
- removed: `removed approver <approver ID>; the vault has <n> approvers.` When its key file could not be removed, a
  further line: `Its key file could not be removed; the next approver change removes it.`

## Admin protocol

These rows join [admin-protocol.md](admin-protocol.md) with the command tickets.

| Command ID | Command | Arguments | Result |
|---|---|---|---|
| `16` | `approver list` | none | the pinned approvers, in approver order |
| `17` | `approver add` | the kind, the label and the authorization | the new approver ID and the approver count |
| `18` | `approver remove` | the approver ID and the authorization | the approver count |

`approver add`'s request:

| Tag | Field | Value |
|---|---|---|
| 2 | kind | `u8`: a signer kind code, 1 to 3 |
| 3 | label | UTF-8 text |
| 4 | authorization | `u8`: `1` the approver prompt, `2` the recovery key |

`approver remove`'s request has tag 2, the approver ID as a 16-byte value, and tag 3, the authorization as for `add`.
A kind or authorization outside its values, or an approver ID that is not 16 bytes, is a malformed frame. A label that
breaks its rule, or an ID that is not a version 4 UUID, is `approver-invalid`, decided by the service.

`approver list`'s result is tag 2, a byte value holding the entries in approver order:

| Size | Part |
|---|---|
| 16 | approver ID |
| 1 | signer kind code |
| 1 | active: `1` when this approver signed the active approval, else `0` |
| 1 | label length `l`, 1 to 64 |
| `l` | label |
| 8 | enrolled at: `u64` Unix seconds |

16 entries are under 1.5 KiB. `approver add`'s result is tag 2, the approver ID as a 16-byte value, and tag 3, the
approver count as `u8`. `approver remove`'s result is tag 2, the approver count as `u8`.

The [prompt frame](admin-protocol.md#prompt-kind-2) gains tag 3, `switchable`, a flag, on every prompt. Frame kind `8`,
**switch**, is sent by the CLI and has an empty body ([Switching](#switching)). Version 1 has not been released, so
these join it, as the notice frame did ([config-approval.md open question 11](config-approval.md#open-questions)).

### Error codes

Five codes are new, the next free numbers after 39:

| Code | Name | Meaning |
|---|---|---|
| `40` | `approver-invalid` | `approver add`: the label breaks its rule; `approver remove`: the ID is not a version 4 UUID; the message names the rule |
| `41` | `unknown-approver` | `approver remove`: no pinned approver has this ID; nothing was changed |
| `42` | `approver-set-invalid` | `approver add`: 16 approvers are already pinned; `approver remove`: it is the last approver; nothing was changed |
| `43` | `approver-in-use` | `approver remove`: this approver signed the active approval; the message says to approve the config with another approver first; nothing was changed |
| `44` | `approver-kind-unavailable` | `approver add`: this install does not offer that signer kind yet; nothing was changed |

Existing codes widen to cover the approver commands: `approval-denied` (9) and `approval-unavailable` (10) for owner
presence; `passphrase-rejected` (18) for a new approval passphrase that breaks a rule; `vault-write-failed` (22) for an
approver change that failed, whose message says whether it may have committed; `recovery-key-invalid` (30),
`recovery-check-failed` (31) and `recovery-check-unavailable` (32) for recovery-key authorization. `busy` and
`wrong-state` already cover them.

## Audit events

These join the [catalogue](audit-logging.md#catalogue), under a new subject, `approver`. None carries a secret: an
approver ID, label and public key are public, and no passphrase, PIN, recovery key or key file byte is logged.

| Event | Level | When | Fields |
|---|---|---|---|
| `approver.enrolled` | INFO | an approver change that enrolls committed | `approver_id`, `approver_label`, `signer_kind`, `approvers`, `authorized_by`; `authorizing_approver_id` and `authorizing_approver_label` when `authorized_by` is `approver` |
| `approver.removed` | INFO | an approver change that removes committed | as `approver.enrolled`, and `key_file` |
| `approver.change-failed` | WARN | an add or remove was refused at its own step 3 or 6, or by recovery-key authorization, or its approver change failed | `change`, `failure`; `approver_id` when known; `recovery_failure` for `recovery_key_refused`; `step`, `error_kind` and `committed` for `write_failed` |
| `approver.orphan-removed` | WARN | step 3 of an approver change removed an orphan key file | `approver_id`, the ID in the file's name |

| Field | Type | Form |
|---|---|---|
| `approver_id`, `authorizing_approver_id` | string | An approver ID in lowercase hyphenated form |
| `approver_label`, `authorizing_approver_label` | string | An approver label, escaped |
| `signer_kind` | string | `software`, `tpm` or `hardware` |
| `approvers` | number | The approver count after the change |
| `authorized_by` | string | `approver` or `recovery_key` |
| `key_file` | string | `removed`, `left`, or `none` for a kind without one |
| `change` | string | `add` or `remove` |
| `failure` | string | `unknown_approver`, `set_invalid`, `in_use`, `passphrase_rejected`, `recovery_key_refused` or `write_failed` |
| `recovery_failure` | string | as `recovery.checked` uses it, or `invalid` for text that is not a recovery key |
| `committed` | string | `no`, `unknown` or `yes`: whether the failed change committed |

`step` takes `key_file`, `key_check` or `approval_state`. Owner presence refusals keep their own event,
`vault.presence-refused`, which names the asked approver, and its "When" widens to the approver commands. A refusal at
step 1 or 2 records only `admin.command`, as for every command.

## Later signer kinds

A new kind is enrolled through the same command, `approver add --kind tpm` or `--kind hardware`, and is asked through
the same approver prompt. The epic that brings each kind decides, for that kind:

- its signer kind code becoming accepted, and its algorithm (storage-formats.md reserves `02`, ECDSA P-256, for the
  TPM);
- what it keeps in the state directory, if anything: a TPM key blob is not a secret, but naming it by approver ID,
  `approver-<approver ID>.<extension>`, keeps one rule for orphans;
- its enrollment steps in place of step 6: for the TPM, creating a signing key under the dictionary-attack lockout,
  never exempt from it, with a PIN the owner types twice ([§12](iron-vault-specification.md#12-configuration-approval-and-reload));
- its prompt text and its proof of presence: signing a fresh value the service chose, verified against the pinned key,
  never a cached PIN or an earlier touch;
- the release checks that let [§14](iron-vault-specification.md#14-recipients-startup-and-memory) offer it.

Three constraints carry over:

- **A TPM approver is also a source-owner method** ([migration-authorization.md](migration-authorization.md#source-owner-method)).
  Once the [independence rule](recipients.md#independence-rule) lets a vault drop `operational`, removing the last
  approver that is a source-owner method would leave migration with no method. EP-33 adds that refusal to
  `approver remove`'s step 3.
- **Touch needs another frame.** In an exchange the CLI answers each prompt before the service sends anything else, so
  it cannot express a service waiting on a device while the CLI watches the keyboard for Ctrl-Y. The hardware-key phase
  adds a frame for it, and the switch frame stays the CLI's way to ask for another approver.
- **No child processes.** If the running service is forbidden to `execve` (K-286, not yet decided), a signer adapter
  cannot be an `age` plugin or any other child process. It must run in-process, such as `tss-esapi` for the TPM, or as
  a host-side helper reached over a socket, as [docker-compose.md](docker-compose.md#approval-signing) already expects
  for a container.

## Release checks

`crates/iron-vault/tests/approvers_linux.rs` drives a real service through `init`, `unlock` and the approver
commands. Each command's own tests cover its exchange, output and refusals; this file covers what only holds across
them.

| Promise | Test | Specification |
|---|---|---|
| An enrolled approver approves a config, and the envelope names it | `an_enrolled_approver_approves_and_the_envelope_names_it` | [§12](iron-vault-specification.md#12-configuration-approval-and-reload), [§14](iron-vault-specification.md#14-recipients-startup-and-memory) |
| Rotation (enroll, approve with the new approver by switching, remove the old) keeps every route serving | `rotating_the_approver_keeps_routes_serving` | [§12](iron-vault-specification.md#12-configuration-approval-and-reload) |
| The last approver, and the approver that signed the active approval, cannot be removed | `the_last_and_the_active_approver_cannot_be_removed` | [§14](iron-vault-specification.md#14-recipients-startup-and-memory) |
| A wrong answer to one approver ends the exchange and never asks another | `a_wrong_answer_never_falls_through_to_another_approver` | [§14](iron-vault-specification.md#14-recipients-startup-and-memory) |
| The vault passphrase never enrolls an approver; the recovery key does, once every approval passphrase is forgotten | `only_the_recovery_key_replaces_a_forgotten_approval_passphrase` | [§14](iron-vault-specification.md#14-recipients-startup-and-memory) |
| A removed approver's passphrase no longer gives owner presence, and its key file is gone | `a_removed_approver_gives_no_presence_and_leaves_no_key_file` | [§14](iron-vault-specification.md#14-recipients-startup-and-memory) |
| No typed passphrase, recovery key or key file byte reaches the log | `no_typed_secret_reaches_the_log_through_approver_commands` | [§18](iron-vault-specification.md#18-logging) |

## Implementation tickets

| Order | Ticket | Depends on |
|---|---|---|
| 1 | Store: record each pinned approver's signer kind | K-276 |
| 2 | Store: one key file per software approver, named by approver ID | 1 |
| 3 | Store: approver changes that enroll and remove a software approver, with their key files | 2 |
| 4 | Protocol and CLI: the switchable prompt and the switch frame | K-276 |
| 5 | Service: approver order and switching at the approver prompt | 2, 4 |
| 6 | `iron-vault approver list` | 1, 5 |
| 7 | `iron-vault approver add` for software approvers, with owner presence | 3, 5 |
| 8 | `iron-vault approver remove`, with owner presence | 3, 5 |
| 9 | Recovery-key authorization for `approver add` and `approver remove` | 7, 8 |
| 10 | Approver release checks and the manual | 6, 9 |

## Open questions

The specification leaves each point below open, or this design departs from its wording. The design takes the default
stated for each, until the owner decides.

1. **"Administrator" authorization.** [§12](iron-vault-specification.md#12-configuration-approval-and-reload) says
   signing-key rotation "requires administrator or existing-owner authorization". *Default:* existing-owner
   authorization alone, owner presence, with the recovery key as the fallback; an admin connection alone never enrolls
   an approver, because malware with one could then approve any config. The alternative reads "administrator" as the
   admin principal, which in a protected install is root through `sudo`. If the default stands, §12's wording could say
   "existing-owner authorization, or the recovery key".
2. **The recovery key as the fallback.** [§14](iron-vault-specification.md#14-recipients-startup-and-memory) gives the
   recovery key one job: opening the vault identity when the unlock method is lost. *Default:* it also authorizes
   approver changes, and nothing else, when every approval signer is lost, because it already opens everything approval
   protects. The alternative leaves `reset` as the only way out for an owner who has lost every signer.
3. **Approver order.** *Default:* the approver that signed the active approval first, then enrolment order, which needs
   no stored preference. The alternatives are pure enrolment order, which keeps asking `init`'s passphrase first after
   the owner moves to a hardware key, or an owner-set order, which needs a field in the approval state and a command to
   set it.
4. **Removing the approver that signed the active approval.** *Default:* refused with `approver-in-use`; the owner
   approves again with another approver first, so a rotation never takes routes down.
   [§12](iron-vault-specification.md#12-configuration-approval-and-reload) says rotation "invalidates the previous
   active signature until reapproval"; under the default the reapproval comes before the removal. The alternative
   allows it, and the service stops proxying at its next config check until the owner approves again.
5. **A new approval passphrase equal to the vault passphrase.** *Default:* not checked at `approver add`, because the
   check would be an oracle on the vault passphrase outside its attempt limit; the summary asks the owner to choose a
   different one. The alternative tries the new passphrase on `operational.age` and counts every try against the
   passphrase attempt limit, so enrolling a few approvers in a row could lock out `unlock`.
6. **One key file per approver.** *Default:* `approver-<approver ID>.age` for every software approver, `init`'s
   included, so the state directory holds no `approver.age`. v0 is unreleased, so no vault needs migrating. The
   alternative keeps `approver.age` for `init`'s approver and names only later ones by ID, which gives one concept two
   naming rules.
7. **The signer kind in approval state v1.** *Default:* a kind byte joins each approver entry in v1, which has not been
   released. The alternative derives the kind from the algorithm, which cannot tell a TPM from a hardware key that both
   sign with P-256.
8. **Switching only at a terminal.** *Default:* Ctrl-Y, through `VEOL`, at a terminal; a CLI reading stdin from a pipe
   never switches, and answers the first approver in approver order. The alternative adds an option naming the approver
   to ask, for scripts, on every command that asks for owner presence.
9. **Ready only.** *Default:* all three commands need Ready, as the recipient commands do. The alternative also allows
   `approver list` in Unavailable, where the vault identity is held, to show which approver can repair the config.
10. **A wrong answer.** [Open question 15 of config-approval.md](config-approval.md#open-questions). *Default:* kept, as
    [A wrong answer](#a-wrong-answer) argues.
