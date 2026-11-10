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
- **Unlocking never grants approval** ([§14](iron-vault-specification.md#14-recipients-startup-and-memory)). Only a
  pinned approver's proof enrolls or removes an approver. Neither the vault passphrase nor a recovery key does, because
  the vault passphrase can make a recovery key ([Who cannot authorize](#who-cannot-authorize)). An owner who loses
  every signer has `reset` left, so the way to keep a forgotten passphrase from being fatal is a second approver.
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
to at most 171 bytes, the one-approver example payload becomes 187 bytes (147 for a new vault), and 16 entries fit in
37 + 8 + 16 × 171 + 49 = 2,830 bytes, inside `MAX_APPROVAL_STATE_LEN`. The kind names are what `approver list` prints
and the audit log records.

K-291 writes the byte into storage-formats.md's "Approval state payload v1" (the entry table, the example, the size
limit and the decoding rules) in the same commit as the decoder. The store's tests read that section's example bytes
from the document, so the document and the code cannot change apart.

## Commands

| Command | Authorization | Changes |
|---|---|---|
| `iron-vault approver list` | none beyond the admin principal | nothing |
| `iron-vault approver add --label <text> [--kind software]` | [owner presence](#authorization) | enrolls a new approver of that kind |
| `iron-vault approver remove <approver ID>` | owner presence | removes that approver |

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

Owner presence is the only authorization for either change. It never bypasses a refusal: `approver remove` checks at
its step 3, before the prompt, that the approver is not the last and did not sign the active approval, so no proof
removes either.

### Who cannot authorize

**An admin connection alone.** Malware with one could otherwise enroll a signer of its own and then approve any
config, which is what approval exists to prevent. That is how this design reads
[§12](iron-vault-specification.md#12-configuration-approval-and-reload)'s "administrator or existing-owner
authorization" ([open question 1](#open-questions)).

**The vault passphrase, or migration authorization, which proves it.** Approval is separate from unlock
([§14](iron-vault-specification.md#14-recipients-startup-and-memory)).

**A recovery key.** A recovery key could look like a fallback for an owner who has lost every signer, since it opens the
vault identity and so everything approval protects. It is not one, because the vault passphrase can make a key that
passes any recovery-key test:

1. `recipient add --recovery` generates a new recovery key and shows it, and `recipient add <age1…>` enrolls a key the
   caller already holds. Both need only migration authorization, which is the vault passphrase
   ([recipients.md](recipients.md#authorization)).
2. That key unwraps `identity.age`, and the vault manifest's MAC verifies with the identity it unwraps, exactly as for
   the recovery key `init` made ([recovery.md](recovery.md#what-the-check-proves)).
3. If a recovery key authorized `approver add`, the holder of that key would enroll a signer of their own, which then
   approves any config.

So a stolen vault passphrase plus an admin connection would yield approval, which
[§14](iron-vault-specification.md#14-recipients-startup-and-memory) forbids: "A stolen unlock secret alone therefore
cannot change route policy". The rule that breaks the chain is that only a pinned approver's proof authorizes an
approver change. A recovery key or the vault passphrase typed at the approver prompt is only a wrong answer, refused as
`approval-denied` ([open question 2](#open-questions)).

### When no approver can answer

A vault always has a pinned approver, because the last is never removed. An owner who has forgotten every approval
passphrase, or lost every signer, has pinned approvers and none that can give presence. That vault can still unlock and
serve its active config, but it can never approve a config, replace or remove a credential, remove a recipient, or
change its approvers again. The way out is `iron-vault reset`
([§16](iron-vault-specification.md#16-administration-recovery-and-migration)), which discards the vault; the owner
rebuilds it from reissued credentials.

The guard is a second approver, enrolled while the owner still holds one: a second approval passphrase kept apart from
the first, or later a TPM or hardware key. Then a forgotten passphrase costs one `approver remove`, after approving the
config with the other approver if the forgotten one signed it. The manual's approval-signer pages tell the owner to
enroll one (K-300).

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
| 3 | [Read `approval.age` back](#reading-the-approval-state-back), then remove [orphan key files](#orphan-key-files); fewer than `MAX_APPROVERS` (16) approvers are pinned | `vault-write-failed`, `approver-set-invalid` |
| 4 | The [summary](#summaries), as notices | |
| 5 | Owner presence: the [approver prompt](#the-approver-prompt) | `approval-denied`, `approval-unavailable` |
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
| 3 | Read `approval.age` back, then remove orphan key files; the ID names a pinned approver; it is not the last; it did not sign the active approval | `vault-write-failed`, `unknown-approver`, `approver-set-invalid`, `approver-in-use` |
| 4 | The summary, as notices | |
| 5 | Owner presence: the approver prompt | `approval-denied`, `approval-unavailable` |
| 6 | Still Ready at the recorded check generation | `wrong-state` |
| 7 | The approver change that removes, then the completion notice | `vault-write-failed` |

The result is the approver count. On success the CLI prints nothing to stdout. Every refusal at step 3 comes before
any prompt, so no authorization, however it is given, removes the last approver or the active approval's signer.

**Why the approver that signed the active approval cannot be removed.** The store allows it, and removing it stops the
active `config.toml.sig` verifying until the config is approved again
([§12](iron-vault-specification.md#12-configuration-approval-and-reload)). The next config check, at a reload, an
unlock or a restart, would then find a published pair that does not verify and stop proxying, with every route down
until the owner approved again. Refusing instead keeps rotation free of an outage: enroll the new approver, approve the
config with it (switching to it at the prompt), then remove the old one. The `approver-in-use` message says so. An
owner whose lost signer approved the active config approves it again with another pinned approver first
([open question 4](#open-questions)).

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
in-memory approval state accepts no more writes until the next approver change or approval loads it again from disk
([Reading the approval state back](#reading-the-approval-state-back)), as after a reservation whose directory fsync
failed ([config-approval.md](config-approval.md#when-a-step-fails)).

### Reading the approval state back

Step 3 of `approver add` and `approver remove` reads `approval.age` from disk and opens it before anything is deleted
or asked. When an earlier write left the in-memory approval state unsettled (its directory fsync failed after the
rename, so that state accepts no more writes), the state read from disk replaces it, as the next approval does after
such a reservation. Otherwise the two must be equal, the check the store makes before every approval-state write
([storage-formats.md](storage-formats.md#writes)). A file that cannot be read or opened, or that differs from the
in-memory state, ends the command with `vault-write-failed`, whose message says nothing was changed, and no key file is
deleted.

The orphan sweep relies on this. An in-memory state that missed a committed enrollment would make that approver's key
file look like an orphan, and the sweep would delete the only key of a pinned approver.

### Orphan key files

A key file whose approver ID no pinned approver has is an orphan: an enrollment that failed before its commit point
left it, or a removal could not delete it. It signs nothing, because the service opens a key file only for the pinned
approver it names, and `open_signer_key` refuses a key that is not that approver's. `approver add` and
`approver remove` remove orphans at their step 3, after reading the approval state back and before any prompt, and log
each with `approver.orphan-removed`. Nothing else removes them: `unlock` and the config check never write. An orphan is not a
foreign file, because `approver-<approver ID>.age` names are the vault's own
([vault-initialization.md](vault-initialization.md#initialization-state)).

Removing an approver reaches future copies of the state directory only. A backup taken before still holds the key file
and an `approval.age` that pins it, and restoring the whole directory restores both; that is whole-storage rollback,
which [§12](iron-vault-specification.md#12-configuration-approval-and-reload) leaves outside v0. The summary says so.

## Software signer keys

Each software approver has its own [approver key envelope](storage-formats.md#approver-key-envelope), in the state
directory as `approver-<approver ID>.age`, with the ID in lowercase hyphenated form, for example
`approver-8d1c6f0e-2b7a-4c59-9e3d-5a4b3c2d1e0f.age`. Each envelope is a plain `age` file with one scrypt stanza,
sealed to that approver's approval passphrase, holding its 32-byte Ed25519 seed. `init` writes its one approver's key
under this name too, so there is one rule for every software approver.

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

A prompt that cannot switch, such as the approver prompt while one approver is pinned, is written as the label and
`: `, as every other prompt is. When stdin is not a terminal the CLI cannot switch, so it writes the label alone, to
stderr when that is a terminal. The text in
[§14](iron-vault-specification.md#14-recipients-startup-and-memory), `Tap "Dave YubiKey 3" to approve. Ctrl-Y to try
another way.`, is the touch form, which arrives with hardware keys ([Later signer kinds](#later-signer-kinds)).

### Switching

The [prompt frame](admin-protocol.md#prompt-kind-2) gains a third field, `switchable`, a flag that every prompt
carries. It is `1` only on an approver prompt while more than one approver is pinned. The CLI may answer a switchable
prompt with a [switch frame](glossary.md), kind 8 with an empty body, instead of owner input. A switch frame answering
any other prompt is `unexpected-frame`, and a switch frame with a body is `malformed-frame`. On a switch frame the
service sends the approver prompt for the next approver in approver order. Nothing typed was sent, so nothing is dropped.

**Ctrl-Y.** For a switchable prompt at a terminal, the CLI sets `c_cc[VEOL]` to Ctrl-Y (`0x19`) for the read, beside
turning echo off, and the guard that restores echo restores it too. In canonical mode `VEOL` ends a line as Enter does,
so Ctrl-Y ends the read at once. A line that ends in `0x19` asks to switch: the CLI clears whatever was typed before it,
writes a newline, and sends a switch frame. Linux gives Ctrl-Y no other meaning (it has no `VDSUSP`). A passphrase
holding the byte `0x19` cannot be typed at a switchable terminal prompt; it can still be piped. When stdin is not a
terminal the CLI never sends a switch frame, so a script answers the first approver in approver order, which
`approver list` shows ([open question 8](#open-questions)).

**Deadline.** The [prompt deadline](glossary.md) covers the whole approver prompt, from the first approver's prompt to
the answer, however many switches come between. Switching therefore never holds the service-wide lock longer than one
prompt can. A `lock` cancels the command at any approver prompt, as it does at every prompt. A switch frame records no
audit event; the events that end the prompt name the approver that answered.

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

Labels are written with control characters removed.

### The completion notice

After a change commits, and before its success response, the service sends one notice:

- enrolled: `enrolled approver <approver ID> (<kind>); the vault has <n> approvers.`
- removed: `removed approver <approver ID>; the vault has <n> approvers.` When its key file could not be removed, a
  further line: `Its key file could not be removed; the next approver add or remove removes it.`

## Admin protocol

These rows join [admin-protocol.md](admin-protocol.md) with K-296, K-297 and K-298.

| Command ID | Command | Arguments | Result |
|---|---|---|---|
| `16` | `approver list` | none | the pinned approvers, in approver order |
| `17` | `approver add` | the kind and the label | the new approver ID and the approver count |
| `18` | `approver remove` | the approver ID | the approver count |

`approver add`'s request:

| Tag | Field | Value |
|---|---|---|
| 2 | kind | `u8`: a signer kind code, 1 to 3 |
| 3 | label | UTF-8 text |

`approver remove`'s request has tag 2, the approver ID as a 16-byte value. A kind outside its values, or an approver
ID that is not 16 bytes, is a malformed frame. A label that breaks its rule, or an ID that is not a version 4 UUID, is
`approver-invalid`, decided by the service.

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

The [prompt frame](admin-protocol.md#prompt-kind-2) gains tag 3, `switchable`, a flag, on every prompt. Frame kind
`8`, the **switch frame**, is sent by the CLI and has an empty body ([Switching](#switching)). Version 1 has not been
released, so these join it, as the notice frame did
([config-approval.md open question 11](config-approval.md#open-questions)).

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
approver change that failed, whose message says whether it may have committed, and for an approval state that does
not read back at step 3. `busy` and `wrong-state` already cover them.

## Audit events

These join the [catalogue](audit-logging.md#catalogue), under a new subject, `approver`. None carries a secret: an
approver ID, label and public key are public, and no passphrase, PIN or key file byte is logged.

| Event | Level | When | Fields |
|---|---|---|---|
| `approver.enrolled` | INFO | an approver change that enrolls committed | `approver_id`, `approver_label`, `signer_kind`, `approvers`, `authorizing_approver_id`, `authorizing_approver_label` |
| `approver.removed` | INFO | an approver change that removes committed | as `approver.enrolled`, and `key_file` |
| `approver.change-failed` | WARN | `approver add` was refused at step 3 (`set_invalid`, `write_failed`) or step 6 (`passphrase_rejected`); `approver remove` was refused at step 3 (`unknown_approver`, `set_invalid`, `in_use`, `write_failed`); or either command's approver change failed at its last step (`write_failed`) | `change`, `failure`; `approver_id` when known; `step`, `error_kind` and `committed` for `write_failed` |
| `approver.orphan-removed` | WARN | step 3 of an approver command removed an orphan key file | `approver_id`, the ID in the file's name |

New fields:

| Field | Type | Form |
|---|---|---|
| `authorizing_approver_id` | string | The approver that gave owner presence for the change: its approver ID, a hyphenated UUID |
| `authorizing_approver_label` | string | That approver's label, escaped |
| `signer_kind` | string | `software`, `tpm` or `hardware` |
| `approvers` | number | The approver count after the change |
| `key_file` | string | `removed`, `left`, or `none` for a kind without one |

Fields [audit-logging.md](audit-logging.md#audit-events) already defines, which widen:

- `approver_id` and `approver_label` also name the approver an approver command enrolls, removes or finds orphaned;
- `failure` gains `unknown_approver`, `in_use` and `passphrase_rejected` for `approver.change-failed`, beside
  `set_invalid` and `write_failed`, which `recipient.change-failed` already uses;
- `committed` also says whether a failed approver change committed: always `no` when `step` is `read_back`;
- `step` gains `read_back` (step 3's [read-back](#reading-the-approval-state-back)), `key_file`, `key_check` and
  `approval_state`, the steps of an [approver change](#approver-changes).

`change` keeps its values, `add` and `remove`. Owner presence refusals keep their own event,
`vault.presence-refused`, which names the asked approver, and its "When" widens to the approver commands. A refusal at
step 1 or 2 records only `admin.command`, as for every command; so does the `wrong-state` of `approver add`'s step 7
and `approver remove`'s step 6.

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
| Only a pinned approver's proof authorizes an approver change: the vault passphrase, and a recovery key that `recipient add --recovery` has just made with it, are each refused at `approver add`'s approver prompt as `approval-denied`, and nothing is enrolled | `only_a_pinned_approver_authorizes_an_approver_change` | [§14](iron-vault-specification.md#14-recipients-startup-and-memory) |
| A removed approver's passphrase no longer gives owner presence, and its key file is gone | `a_removed_approver_gives_no_presence_and_leaves_no_key_file` | [§14](iron-vault-specification.md#14-recipients-startup-and-memory) |
| No typed passphrase or key file byte reaches the log | `no_typed_secret_reaches_the_log_through_approver_commands` | [§18](iron-vault-specification.md#18-logging) |

## Implementation tickets

Each ticket updates the design documents and glossary entries it changes, in the same branch as its code.

| Order | Ticket | What | Depends on | Updates |
|---|---|---|---|---|
| 1 | K-291 | Store: record each pinned approver's signer kind | K-276 | storage-formats.md "Approval state payload v1" (entry table, example, size limit, decoding rules); glossary "Pinned approver" and "Signer kind" |
| 2 | K-292 | Store: one key file per software approver, named by approver ID | K-291 | credential-commands.md "Owner presence"; recovery.md; secret-handling.md; linux-package.md; docker-compose.md "Approval signing"; the manual's files reference |
| 3 | K-293 | Store: approver changes that enroll and remove a software approver, with their key files | K-292 | glossary "Approver change" |
| 4 | K-294 | Protocol and CLI: the switchable prompt and the switch frame | K-276 | admin-protocol.md (frame kinds, Prompt, Owner input, Versions); glossary "Prompt" and "Switch frame" |
| 5 | K-295 | Service: approver order and switching at the approver prompt | K-292, K-294 | config-approval.md "Choosing the signer"; credential-commands.md "Owner presence"; glossary "Prompt deadline", "Approver order" and "Approver prompt" |
| 6 | K-296 | `iron-vault approver list` | K-291, K-295 | admin-protocol.md (command 16); the manual's CLI reference |
| 7 | K-297 | `iron-vault approver add` for software approvers, with owner presence | K-293, K-295 | admin-protocol.md (command 17, error codes 40, 42 and 44, the widened codes); audit-logging.md (the `approver` subject, `approver.enrolled`, `approver.change-failed`, `approver.orphan-removed`, the new and widened fields); the manual's CLI, errors and audit log references |
| 8 | K-298 | `iron-vault approver remove`, with owner presence | K-293, K-295 | admin-protocol.md (command 18, error codes 41 and 43); audit-logging.md (`approver.removed`, `key_file`); the manual's CLI, errors and audit log references |
| 9 | K-300 | Approver release checks and the manual | K-296, K-297, K-298 | README features; the manual: rotating an approval signer, enrolling a second approver so a forgotten passphrase is not fatal, and `reset` as the way out when no approver can answer; the security model |

This design already carries the `approver-<approver ID>.age` naming through storage-formats.md "Approver key
envelope", vault-initialization.md and the glossary "Approver key envelope", ahead of K-292's code.

## Open questions

The specification leaves each point below open, or this design departs from its wording. The design takes the default
stated for each, until the owner decides. Question 2 is decided.

1. **"Administrator" authorization.** [§12](iron-vault-specification.md#12-configuration-approval-and-reload) says
   signing-key rotation "requires administrator or existing-owner authorization". *Default:* existing-owner
   authorization alone, owner presence from a pinned approver; an admin connection alone never enrolls an approver,
   because malware with one could then approve any config. The alternative reads "administrator" as the admin
   principal, which in a protected install is root through `sudo`. If the default stands, §12's wording could say
   "existing-owner authorization".
2. **No recovery-key fallback. Decided by the owner.** The recovery key never authorizes an approver change. The vault
   passphrase can make a key that passes any recovery-key test: `recipient add --recovery` mints a new recovery key, and
   `recipient add <age1…>` enrolls a key of the caller's own, each with migration authorization alone. If a recovery
   key authorized `approver add`, a stolen vault passphrase would enroll an approver and then approve any config. The
   rule that breaks the chain: only a pinned approver's proof authorizes `approver add` or `approver remove`, so
   [§14](iron-vault-specification.md#14-recipients-startup-and-memory) holds and unlocking never grants approval. An
   owner who loses every signer has `reset` left; a second approver, enrolled while one still answers, is the guard
   ([When no approver can answer](#when-no-approver-can-answer)). The alternative not taken would have accepted only a
   recipient of role `recovery` and required owner presence for every `recipient add` that makes one.
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
