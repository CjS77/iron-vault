# Recipients

How `iron-vault recipient list`, `recipient add` and `recipient remove` show and change the recipients of the identity
envelope (specification [§13](iron-vault-specification.md#13-vault-structure-and-durable-writes),
[§14](iron-vault-specification.md#14-recipients-startup-and-memory),
[§16](iron-vault-specification.md#16-administration-recovery-and-migration)). It covers the service-owned record of
which recipient keys `identity.age` is wrapped for, how that record and the envelope stay consistent across a crash,
the rule that keeps two independent ways into the vault, and each command's exchange, output, error codes and audit
events. Terms follow the [glossary](glossary.md). Migration authorization, which `recipient add` runs, is designed in
[migration-authorization.md](migration-authorization.md).

The record is needed because nothing else says who the recipients are. An X25519 stanza in `identity.age` does not
name its recipient, and the service keeps the recovery key's recipient key only in memory during `init`
([vault-initialization.md](vault-initialization.md#recovery-key-presentation)). To rewrap the vault identity for a new
set, the service must know the public keys of the recipients it keeps.

Three rules drive the design:

- **Only the service can say who the recipients are.** The recipient inventory is a [MAC'd file](storage-formats.md#macd-file-frame)
  keyed from the vault identity, like the vault manifest, so a party holding only public keys cannot write one that
  opens ([§13](iron-vault-specification.md#13-vault-structure-and-durable-writes)).
- **No change leaves the vault with fewer than two independent ways in**
  ([§14](iron-vault-specification.md#14-recipients-startup-and-memory)). The [independence rule](#independence-rule)
  is checked before any prompt, on the set the change would write.
- **Adding a recipient is a migration; removing one is not.** Whoever holds an added key can open the vault, so `add`
  needs the same fresh source-owner authorization as `export` (§16). Removal grants nobody access, and it reaches
  only future envelopes (§16), which every change says.

Every default this design picks where the ticket or the specification leaves a choice is listed under
[Open questions](#open-questions).

## Recipient roles

Every enrolled recipient has one **recipient role**, which says what reaches the vault through it. The role decides
whether the recipient counts toward the [independence rule](#independence-rule).

| Code | Role | Class | What it is | Enrolled by |
|---|---|---|---|---|
| `1` | `operational` | unlock | The operational identity, opened by the vault passphrase through `operational.age` | `init` |
| `2` | `recovery` | recovery | An offline recovery key the service generated and showed once | `init`, `recipient add --recovery` |
| `3` | `added` | none | A recipient key the owner supplied, such as a destination device for the alternate migration path ([§16](iron-vault-specification.md#16-administration-recovery-and-migration)) | `recipient add <age1…>` |
| `4` | `tpm` | unlock | Reserved: a TPM-sealed intermediate identity ([§14](iron-vault-specification.md#14-recipients-startup-and-memory)) | the TPM epic |
| `5` | `hardware` | unlock | Reserved: a hardware-key intermediate identity ([future spec §2.1](future-specifications.md#21-hardware-key-recipients-signers-and-touch-confirmation)) | the hardware-key phase |
| `6` | `host-unlock` | unlock | The intermediate identity of a host unlock adapter, read from the unlock handoff ([§17](iron-vault-specification.md#17-docker-remote-servers-and-appliances)) | `init --host-unlock` in a build that is not dev-mode, `recipient add --host-unlock <age1…>` |

Codes 4 and 5 are reserved now so that later epics need no new format version: this release refuses them when it reads
an inventory, and the epic that enrolls one makes the decoder accept it. Code 6 is accepted: the Compose epic enrolls
it. A code above 6 is unknown. The role names are
also the labels the CLI prints and the audit log records.

`added` is in no class because the service cannot tell who holds the key or whether it is independent of the
operational path: it may be another copy of the same machine. Only a key the service generated and revealed offline
takes the `recovery` role ([open question 8](#open-questions)).

## Recipient labels

Each recipient has a **recipient label**: owner text that says which device or copy a key is, such as
`alice laptop 2026` or `paper copy, safe`. The service never interprets it. The rule:

- 1 to 64 bytes of UTF-8;
- no control or format character (Unicode general categories Cc and Cf), so a label cannot start a new log line, move
  the cursor ([§18](iron-vault-specification.md#18-logging)), or reorder the summary shown before
  a prompt with a bidirectional control such as U+202E;
- no leading or trailing whitespace.

Labels need not be unique: commands name a recipient by its key, never its label. The audit log writes a label through
the policy crate's escaping, as it does every value an admin principal chose. `init` labels its two recipients
`vault passphrase` and `recovery key`.

## Recipient inventory

The **recipient inventory** is the state-directory file `recipients.age`. It lists every recipient key `identity.age`
is wrapped for, each with its role, its label and the UTC second it was enrolled, and it carries the
[envelope digest](#binding-to-identityage) of the `identity.age` it describes. Only the service writes it, by durable
replace. The inventory is the only place the service learns the recipient set it rewraps for.

It is a [MAC'd file](storage-formats.md#macd-file-frame), sealed to the vault public key and authenticated with a MAC
keyed from the vault identity, for the reason the vault manifest is one: anyone who knows the vault public key can seal
a list, and a forged list would let them choose which keys the next rewrap enrolls. The store ticket adds the sections
below to [storage-formats.md](storage-formats.md), with a worked example. It also narrows the
[state generation](storage-formats.md#state-generation) section's sentence that every MAC'd file payload carries two
`u64` counters right after its vault ID to the manifest and the approval state: the inventory carries its envelope
digest there.

**It is not part of the state generation.** The state generation detects one MAC'd file restored without the other. An
inventory restored alone no longer matches `identity.age`'s digest and is refused as damaged, so it needs no counter.
Restoring `identity.age` and the inventory together brings back an older recipient set, removed keys included. That is
an old copy of the envelope put back by someone who can write the state directory, which
[§16](iron-vault-specification.md#16-administration-recovery-and-migration) already says removal cannot reach
([open question 5](#open-questions)). It gives a removed key nothing new: the vault identity never rotates, so whoever
holds that key and any old copy of `identity.age` already holds the vault identity.

### Recipient inventory file v1

| Frame parameter | Value |
|---|---|
| Magic | ASCII `IVRF` (`49 56 52 46`) |
| Version | `01` |
| Payload | The recipient inventory payload v1 (below) |
| Personalization | `iv-recipients-v1` (16 bytes); the derived key is the **inventory key** |
| Domain tag | `iron-vault recipients file v1 mac` followed by a zero byte (34 bytes) |
| Size limit | `MAX_RECIPIENT_INVENTORY_LEN` (16 KiB) |

The inventory key is independent of the manifest and approval keys, so a MAC from one file never verifies another. The
domain tag is 34 bytes, where the manifest's and the approval state's are 32. Domain separation does not depend on the
length, because each tag ends in its only zero byte, but [the MAC section](storage-formats.md#mac) says "32-byte
domain tag", and the store ticket changes that sentence to "the file type's domain tag".

### Recipient inventory payload v1

It uses the conventions of [record payload v1](storage-formats.md#conventions): big-endian unsigned integers, `u64`
length-prefixed fields, lengths checked against the bytes remaining before anything is read, and no trailing bytes.

| Offset | Size | Content |
|---|---|---|
| 0 | 4 | Magic: ASCII `IVRP` (`49 56 52 50`) |
| 4 | 1 | Version: `01` |
| 5 | 16 | Vault ID: equal to the file header's |
| 21 | 32 | Envelope digest: BLAKE2b-256 of the `identity.age` this inventory describes |
| 53 | 8 | Entry count: `u64`, from 2 to `MAX_RECIPIENTS` (64) |
| 61 | var | Entries, in strictly ascending byte order of their recipient key text (below) |

Each entry:

| Size | Content |
|---|---|
| var | Recipient key: a field holding the canonical `age1…` text, exactly 62 bytes |
| 1 | Role: a [role code](#recipient-roles) |
| var | Label: a field holding the [recipient label](#recipient-labels), 1 to 64 bytes |
| 8 | Enrolled at: `u64` Unix seconds, a [UTC second](glossary.md) |

The canonical text is the lowercase Bech32 that `RecipientKey`'s `Display` writes. Byte order of that text is the
order `RecipientKey` sorts by, so the entries follow the [recipient set](glossary.md)'s own order and the same
inventory always encodes to the same bytes.

### One encoding per inventory

Decoding accepts a payload only if it is that encoding:

- the vault ID is a version 4 UUID and equals the header's;
- the entry count is from 2 to 64;
- every recipient key is 62 bytes, parses as an X25519 recipient key and is in canonical lowercase form;
- keys are strictly ascending, so none repeats;
- every role code is 1, 2, 3 or 6; a reserved or unknown code is refused as a role this release does not know;
- every label passes the label rule;
- every enrolment time is within the UTC second range.

Decoding rejects a wrong magic, an unknown version, truncation and trailing bytes. It does not apply the independence
rule: that rule governs changes, and every inventory the service writes already satisfies it.

### Size limit

An entry is at most 151 bytes: an 8-byte length and a 62-byte key, a role byte, an 8-byte length and a 64-byte label,
and an 8-byte time. A full payload is at most 61 + 64 × 151 = 9,725 bytes. `age` adds a header of under 400 bytes, a
16-byte nonce and a 16-byte tag, and the frame adds 53 bytes: under 10,300 bytes in all, well inside 16 KiB. Building
an inventory with more than 64 entries is refused, as `RecipientSet` refuses a set that large, so the service never
writes one it cannot read back.

## Binding to `identity.age`

The **envelope digest** is the BLAKE2b-256 (unkeyed, 32-byte output) of `identity.age`'s bytes exactly as they sit on
disk, as a manifest entry's digest covers its record file. An inventory describes the envelope whose digest it
carries, and no other.

A recipient change writes two files, and a crash can fall between them. The inventory is therefore written twice: once
as a **staged inventory**, `recipients.age.staged`, before the envelope, and once in place after it. The envelope's
durable replace is the change's single commit point. The staged inventory is the service's own MAC'd record of the
change it was committing, so the next inventory check can finish a committed change, or discard an uncommitted one,
without guessing ([open question 3](#open-questions)).

### The inventory check

Every recipient command opens the inventory this way, under the service-wide lock, with the vault identity the
service holds. The first case that matches decides:

1. **Read the envelope.** Read `identity.age` (at most `MAX_IDENTITY_ENVELOPE_LEN`), take its envelope digest and
   count its X25519 stanzas with `stanza_kinds`. A file that cannot be read, or holds a stanza other than X25519 and
   grease, is damage `envelope_unreadable`.
2. **The inventory matches.** `recipients.age` opens as this vault's inventory, carries the envelope's digest, and
   its entry count equals the X25519 stanza count. The inventory is current. If a staged inventory is also present,
   it is removed with `durable_remove`: it is either an uncommitted change, whose digest is not the envelope's, or
   the leftover of a change that finished. That is recorded as `recipient.change-recovered`, `discarded` or
   `completed` respectively.
3. **The staged inventory matches.** `recipients.age.staged` opens as this vault's inventory, carries the envelope's
   digest, and its entry count equals the stanza count. A change committed and was not finished. The service writes
   `recipients.age` with the staged bytes by durable replace, removes the staged file with `durable_remove`, and
   records `recipient.change-recovered` with `completed`.
4. **Otherwise** the inventory is damaged, and nothing is written. The damage is the first that applies:
   `missing` (no `recipients.age`), `unreadable` (it cannot be read, or is over the size limit), `mac` (the MAC does
   not verify: altered, or not this vault's), `malformed` (anything else the frame or decoder refuses),
   `unknown_role` (a role this release does not know), `other_vault` (it names another vault ID than the one the
   service holds), `envelope_mismatch` (it carries another digest) or `count_mismatch` (it carries this digest but a
   different number of entries from the envelope's stanzas). A staged file that matches nothing is left in place.

A damaged inventory is damaged shared state ([§13](iron-vault-specification.md#13-vault-structure-and-durable-writes),
[§15](iron-vault-specification.md#15-service-states-and-errors)). It is never rebuilt and never repaired: the
command ends with `recipient-inventory-damaged`, naming the damage, and records `recipient.inventory-damaged`. Cases 2
and 3 are not repairs. Each finishes or abandons a change from a file only the service could have written, and only
when it matches the envelope on disk, as approval recovery publishes a committed staged approval
([config-approval.md](config-approval.md)).

The check runs only in the recipient commands ([open question 4](#open-questions)). Nothing else reads the inventory:
`unlock`, migration authorization's vault passphrase method and `recovery check` read `identity.age` alone, and serving
never depends on the recipient list. A damaged inventory therefore leaves the service Ready and the vault usable, and
blocks only recipient changes. The owner recovers through `export` and `import` (EP-30), or `reset`: `recipient add`,
the other migration path, is blocked by the same damage.

### The recipient change

A **recipient change** rewraps the vault identity for a new recipient set and writes the inventory that describes it.
The store runs it, from Ready, under the service-wide lock, with the vault identity the service holds and the inventory
the check just opened. In order:

| Step | Label | What the service does | Durable change |
|---|---|---|---|
| 1 | | Applies the change to the inventory under the [independence rule](#independence-rule). Wraps the vault identity for the new set with `wrap_identity`. For `recipient add --recovery`, unwraps the new bytes in memory with the new recovery identity and requires the vault public key the service holds, then drops the recovery identity. Builds the new inventory with the new bytes' envelope digest. | none |
| 2 | `stage` | Writes `recipients.age.staged` by durable replace | `recipients.age.staged` |
| 3 | `envelope` | Writes `identity.age` by durable replace. **This is the commit point.** | `identity.age` |
| 4 | `read_back` | Reads `identity.age` back; its digest must be the staged one | none |
| 5 | `inventory` | Writes `recipients.age` with the staged bytes by durable replace | `recipients.age` |
| 6 | `cleanup` | Removes `recipients.age.staged` with `durable_remove` | staged file removed |

No credential record, manifest, approval file or config file is touched, and nothing is re-encrypted but the vault
identity ([§13](iron-vault-specification.md#13-vault-structure-and-durable-writes)). The vault identity itself does
not change, so the serving snapshot, the manifest's MAC and every record stay valid: a change runs no config check and
pauses no request.

The new envelope can be proved only with a private key the service holds at that moment. For `--recovery` that is the
new recovery identity, so step 1 proves the envelope before anything is written, as `init` proves both of its
recipients. For an added key, and for a removal, the service holds none: the vault passphrase method drops the
operational identity at its own step 4 ([source-owner method](migration-authorization.md#source-owner-method)), and
`unlock` drops it too. `age` wraps the same file key for every stanza, so a fault that broke one stanza would be a
library defect, not a crash state.

| Last step durable | The next inventory check finds | Outcome |
|---|---|---|
| none, or 2 | `recipients.age` matches the old envelope | case 2: the staged file is discarded; the change never happened |
| 3 or 4 | the staged inventory matches the new envelope | case 3: the change is finished |
| 5 | `recipients.age` matches the new envelope, staged file present | case 2: the staged file is removed as `completed` |
| 6 | `recipients.age` matches | nothing to do |

A failure answers as follows. Before step 3, or at step 3 before the rename, nothing changed: `vault-write-failed`,
and `recipient.change-failed` with `committed` `no`. At step 3 after the rename (its directory fsync failed) or at step
4, the outcome is unknown: `vault-write-failed`, whose message says the change may have committed and that
`iron-vault recipient list` settles it, with `committed` `unknown`. At steps 5 and 6 the change stands: the command
succeeds, with a notice that the inventory is finished at the next recipient command, and records both its
`recipient.added` or `recipient.removed` and `recipient.change-failed` with `committed` `yes`.

## Independence rule

[§14](iron-vault-specification.md#14-recipients-startup-and-memory) requires every vault to keep at least two
independent ways in: its unlock method and an offline recovery key. The unlock method is the owner's choice of
passphrase, TPM or hardware key, and none is required in particular. The **independence rule** turns that into a check
on the inventory a change would write. The inventory after the change must hold:

1. **the recipient of each configured unlock method, and at least one unlock-class recipient.** The passphrase's is
   `operational`; a TPM's is `tpm`, a hardware key's `hardware`, and a host unlock adapter's `host-unlock`. No unlock
   method is required beside another;
2. **the `operational` recipient while the vault passphrase is the only source-owner method.**
   [Migration authorization](migration-authorization.md#source-owner-method), which `recipient add` and `export` run,
   proves authority through a source-owner method. A vault left with none could never add a recipient or migrate
   again. In v0 the vault passphrase, through `operational`, is the only method, so this part keeps `operational` in
   every v0 vault, even with the TPM approval signer (EP-33) or a hardware key as a method: dropping `operational` is not
   in v0 ([tpm-approval-signer.md](tpm-approval-signer.md#open-questions) open question 3);
3. **at least one `recovery` recipient**, an offline key the owner keeps apart from this machine and its unlock
   method;
4. **at least two recipients, and at most `MAX_RECIPIENTS` (64).**

In v0, parts 2 and 3 already make part 4's floor hold. It stays explicit so the rule still means two ways in when later
roles join. A refusal names which part failed: a configured unlock method's recipient, the last unlock recipient, the
last source-owner method, the last recovery recipient, or the limit of 64.

Every v0 vault refuses exactly the changes it refused before this wording: part 2 keeps `operational`, and a
`host-unlock` recipient is kept by part 1 while the host unlock adapter is configured. The wording changes what later
methods may do, not what v0 does.

The rule is pure and lives in the store, beside the inventory, so `remove` and `add` apply it in memory before any
prompt and the recipient change applies it again before it writes.

**How later roles join.** Each role is in the unlock class, the recovery class or neither (the
[roles table](#recipient-roles)). An unlock-class recipient that a configured unlock method uses is kept by part 1,
and part 3 becomes "at least one recipient of the recovery class":

- **`tpm`** joins the unlock class. Part 1 keeps it while TPM unlock is configured. It never counts as recovery, because
  it is bound to one machine and fails with it (§16). A TPM vault keeps `operational` in v0
  ([open question 11](#open-questions)).
- **`hardware`** joins the unlock class. Whether a second hardware key may count as recovery is that phase's decision.
- **`host-unlock`** joins the unlock class. Part 1 keeps it while the host unlock adapter is configured. It never counts
  as recovery, because its secret lives on the host. The adapter is configured for the `host-unlock` recipient whose
  key the unlock handoff holds when the command runs, in the Protected and Container profiles
  ([docker-compose.md](docker-compose.md#its-role-among-the-recipients)); any other `host-unlock` recipient, and any
  `added` one, is not kept by part 1.

## Commands

| Command | Authorization | Changes |
|---|---|---|
| `iron-vault recipient list` | none beyond the admin principal | nothing, unless the inventory check finishes or discards a change |
| `iron-vault recipient add <age1…> --label <text>` | migration authorization, `AddRecipient(<key>)` | enrolls the key with role `added` |
| `iron-vault recipient add --host-unlock <age1…> --label <text>` | migration authorization, `AddRecipient(<key>)` | enrolls the key with role `host-unlock` |
| `iron-vault recipient add --recovery --label <text>` | migration authorization, `AddRecipient(<new key's recipient key>)` | generates a recovery key, shows it once, and enrolls it with role `recovery` |
| `iron-vault recipient remove <age1…>` | owner presence | removes the key from the envelope and the inventory |

A recipient key and a label are public, so they travel as arguments. No command takes a secret as an argument
([§16](iron-vault-specification.md#16-administration-recovery-and-migration)). `recipient add` takes exactly one of
a key and `--recovery`, and `--label` always; `--host-unlock` needs a key and conflicts with `--recovery`; anything
else is a usage error. `recipient list` is not in §16's table,
but `remove` cannot be used without knowing what is enrolled ([open question 1](#open-questions)).

### Authorization

**`recipient add` runs migration authorization.** An added key opens the vault identity, and with it every credential.
That makes it the alternate migration path of
[§16](iron-vault-specification.md#16-administration-recovery-and-migration), which requires the same fresh
source-owner authorization as `export`. It runs the [admin exchange](migration-authorization.md#admin-exchange) of
migration authorization, steps 1 to 10, with the operation `AddRecipient` naming the key to be enrolled. For
`--recovery` that is the new key's recipient key, so the challenge binds the very key that is revealed.
`--host-unlock` is authorized exactly as a plain key is, by the vault passphrase: the host unlock identity opens the
vault, so enrolling one is the same migration whatever role it takes. Unlocking, by any method, never authorizes it.

**`recipient remove` requires owner presence**, the approval passphrase
([credential-commands.md](credential-commands.md#owner-presence)), and nothing else.
[§16](iron-vault-specification.md#16-administration-recovery-and-migration) asks "fresh existing-owner authorization"
of both commands. Owner presence is that for removal: it is proof that the owner takes part in this exchange now,
collected for this one change and never reused ([§3](iron-vault-specification.md#3-terms-and-definitions)). Removal grants nobody
access, so the attack §16 describes does not apply. What removal can do is lose a way in, which the independence rule
bounds, and a change that can lose something is a destructive change, which the owner authorizes through owner presence
([§3](iron-vault-specification.md#3-terms-and-definitions)), as for `rm`. This settles [open question 3 of
migration-authorization.md](migration-authorization.md#open-questions): removal is not a migration operation, and no
third operation tag is added ([open question 10](#open-questions)).

`recipient list` needs nothing beyond the admin principal, as credential `list` does: it shows public keys and owner
labels only.

### States and the service-wide lock

Every recipient command needs Ready. Each needs the vault identity: to open the inventory, whose MAC is keyed from it,
and, for a change, to rewrap it. Locked holds no vault identity, Checking is transient, and Unavailable is for repair.
In any other state the exchange ends with `wrong-state` before any prompt. The three commands map onto the existing
admin operation `AdminOperation::VaultChange`, which the service state gate offers only in Ready, as it does for `add`,
`replace` and `rm`. `list` maps there too, unlike credential `list`, which shares `status`: it opens a file keyed from
the vault identity, which only Ready holds.

Each command holds the service-wide lock from its checks to its response, prompts included, as `replace` and `rm` do.
It tries the lock and answers `busy` at once if it is taken. Holding it is what keeps the inventory check, the summary
and the change true until the write, and it keeps `list` from reading between a change's two files. `recipient add`
takes the lock as the `MigrationSession` (`ServiceContext::begin_migration`), because the authorization step requires
it. A `lock` cancels a command at any of its prompts, and before it writes, the command checks that the service is
still in the state and at the check generation it recorded when it took the lock, as `replace` does
([order of steps](credential-commands.md#order-of-steps), step 8).

### `recipient list`

| Step | What the service does | Refusal |
|---|---|---|
| 1 | The service is Ready | `wrong-state` |
| 2 | Try the service-wide lock | `busy` |
| 3 | The [inventory check](#the-inventory-check) | `recipient-inventory-damaged`, `vault-write-failed` |
| 4 | Answer with every entry, in inventory order | |

The CLI prints one line per recipient to stdout: the key, two spaces, the role padded with spaces to 11 characters,
two spaces, the enrolment time as `YYYY-MM-DDTHH:MM:SSZ`, two spaces and the label, with control characters removed. For
example:

```text
age1csc5wgcsw68jdz8uxh9sramjkys02nk8qf740lpywzvlzm9pjf7qxffk4e  recovery     2026-11-06T09:49:13Z  recovery key
age1jy4a0t77ngkqdm42qqd3xuja9zrjsy6f62u49qw06tza9z9rxpxqwf95ly  operational  2026-11-06T09:49:13Z  vault passphrase
age1v4q6gqhc84l6yrmyeqcske956a65frdww5rc4jnrdfhkpsdglqksx4muhw  added        2026-11-07T14:02:51Z  bob's new laptop
```

### `recipient add <age1…>`

The steps are migration authorization's [admin exchange](migration-authorization.md#admin-exchange); this table fills
in the command's own.

| Step | What the service does | Refusal |
|---|---|---|
| 1 | The service is Ready; the key parses as a recipient key; the label follows its rule | `wrong-state`, `recipient-invalid` |
| 2 | `begin_migration`: the service-wide lock, recording the state and check generation | `busy` |
| 3 | The inventory check; the key is not enrolled; the independence rule allows the new set | `recipient-inventory-damaged`, `vault-write-failed`, `recipient-enrolled`, `recipient-set-invalid` |
| 4 | The [summary](#summaries), as notices | |
| 5–7 | Migration authorization for `AddRecipient(<key>)` | `busy`, `migration-denied`, `migration-unavailable`, `migration-rate-limited` |
| 8 | none | |
| 9 | Still Ready at the recorded check generation; consume the authorization | `wrong-state`, `migration-denied` |
| 10 | The [recipient change](#the-recipient-change), then the [completion notice](#the-completion-notice) | `vault-write-failed` |

### `recipient add --host-unlock <age1…>`

The same exchange as `recipient add <age1…>`, in the same states, with the label rule every recipient follows. The
entry's role is `host-unlock` rather than `added`, so the summary, the completion notice and `recipient.added` name
that role. It re-enrols host unlock after the host unlock identity is lost with its TPM, the motherboard, a TPM clear
or a change to the bound PCR: the host provisions a new identity, whose recipient key the provisioning script prints,
and the owner enrolls it with this command. Once a restart reaches Ready with no `unlock`, the unlock handoff holds the
new identity, so part 1 of the [independence rule](#independence-rule) no longer keeps the old `host-unlock` recipient,
and `recipient remove` takes it out. An `added` recipient never counts as the host unlock adapter's recipient: only role
`host-unlock` does. Every profile accepts the command; the role only matters to part 1 in the Protected and Container profiles, where
a host unlock adapter can be configured.

### `recipient add --recovery`

The same exchange, with the recovery key shown between the summary and the challenge:

| Step | What the service does | Refusal |
|---|---|---|
| 1 | The service is Ready; the label follows its rule | `wrong-state`, `recipient-invalid` |
| 2 | `begin_migration` | `busy` |
| 3 | The inventory check; the independence rule allows a set with one more recipient; then generate the recovery key | `recipient-inventory-damaged`, `vault-write-failed`, `recipient-set-invalid` |
| 4 | The summary, which names the new key's recipient key | |
| 4a | The recovery key notices, one reveal of its `AGE-SECRET-KEY-1…` text, and the prompt `Type yes once you have saved the recovery key`, as `init` presents them ([vault-initialization.md](vault-initialization.md#recovery-key-presentation)) | `declined` |
| 5–7 | Migration authorization for `AddRecipient(<new key's recipient key>)` | as above |
| 9 | as above | as above |
| 10 | The recipient change, which proves the new envelope with the recovery identity before writing; then the completion notice | `vault-write-failed` |

The key is shown before the challenge is issued, not after it is proved, because a challenge lives 2 minutes and saving
a key into a password manager can take longer ([open question 7](#open-questions)). A key shown to an exchange that
is then refused opens nothing. The service keeps only the parsed recovery identity after the reveal, for step 10's
proof, and drops it there. It never writes the key's text anywhere.

The CLI checks for a controlling terminal before it sends the request, as for `init`, so the reveal never reaches a CLI
that will refuse to show it. Every ending after the reveal says what to do with the key, as `init`'s do
([Failing after the reveal](vault-initialization.md#failing-after-the-reveal)):

- **The key is dead:** `declined`, any migration refusal, `wrong-state` at step 9, `vault-write-failed` with
  `committed` `no`, or a cancel before the CLI sent the vault passphrase. The message says *the recovery key shown
  opens nothing: discard it*.
- **The outcome is unknown:** `vault-write-failed` with `committed` `unknown`, or the command cancelled or lost after
  the CLI sent the vault passphrase. The message says *keep the recovery key and run `iron-vault recipient list`. If
  it lists `<age1…>`, the key is enrolled; check it with `iron-vault recovery check`. If it does not, discard the key.*

### `recipient remove <age1…>`

| Step | What the service does | Refusal |
|---|---|---|
| 1 | The service is Ready; the key parses as a recipient key | `wrong-state`, `recipient-invalid` |
| 2 | Try the service-wide lock, recording the state and check generation | `busy` |
| 3 | The inventory check; the key is enrolled; in the Protected and Container profiles, read the unlock handoff for the configured host unlock recipient; the independence rule allows the set without it | `recipient-inventory-damaged`, `vault-write-failed`, `unknown-recipient`, `recipient-set-invalid` |
| 4 | The summary, as notices | |
| 5 | Owner presence: the `Approval passphrase for "<label>"` prompt | `approval-denied`, `approval-unavailable` |
| 6 | Still Ready at the recorded check generation | `wrong-state` |
| 7 | The recipient change, then the completion notice | `vault-write-failed` |

A refusal at step 3 comes before any prompt, so the owner never types a passphrase for a change that cannot happen.

## Summaries

The service writes each summary itself and sends it as notices before the authorization prompt
([§5](iron-vault-specification.md#5-service-and-cli-separation-of-concerns)). Typing the passphrase after it is the confirmation;
there is no separate `Type yes`. The counts after the change are by role. The first lines of the add summary are the
ones [migration-authorization.md](migration-authorization.md#admin-exchange) requires the challenge's binding to show.

```text
add a recipient to the vault
  vault: 2a682de7-b14d-4900-9ea9-0c968e1a6589
  recipient: age1v4q6gqhc84l6yrmyeqcske956a65frdww5rc4jnrdfhkpsdglqksx4muhw
  role: added
  label: bob's new laptop
  recipients after the change: 3 (operational 1, recovery 1, added 1)
  this key will open the vault identity, and with it every credential, in every copy of identity.age written from now on
  authorize with: the vault passphrase
```

```text
add a new recovery key to the vault
  vault: 2a682de7-b14d-4900-9ea9-0c968e1a6589
  recipient: age1csc5wgcsw68jdz8uxh9sramjkys02nk8qf740lpywzvlzm9pjf7qxffk4e
  role: recovery
  label: recovery key 2026
  recipients after the change: 3 (operational 1, recovery 2)
  next: the new recovery key is shown once; save it, then type yes
  authorize with: the vault passphrase
```

```text
remove a recipient from the vault
  vault: 2a682de7-b14d-4900-9ea9-0c968e1a6589
  recipient: age1v4q6gqhc84l6yrmyeqcske956a65frdww5rc4jnrdfhkpsdglqksx4muhw
  role: added
  label: bob's new laptop
  enrolled: 2026-11-07T14:02:51Z
  recipients after the change: 2 (operational 1, recovery 1)
  removing a recipient protects future copies of identity.age only; copies made before still open with this key
  authorize with: the approval passphrase
```

Labels are written with control characters removed, as the CLI shows every notice.

### The completion notice

After a change commits, and before its success response, the service sends one notice. Its last three sentences are
fixed and every completed change prints them, add or remove
([§16](iron-vault-specification.md#16-administration-recovery-and-migration)):

```text
enrolled age1v4q6gqhc84l6yrmyeqcske956a65frdww5rc4jnrdfhkpsdglqksx4muhw as added; the vault has 3 recipients.
Removing a recipient protects future copies of identity.age only.
Old copies of identity.age, and backups, still open with a removed key.
If a machine was lost, rotate the provider credentials it could reach.
```

The first line reads `removed <age1…>; the vault has <n> recipients.` for a removal. After `--recovery` a further line
follows: `Check the new key with iron-vault recovery check, then remove the old recovery key with iron-vault recipient
remove.` After removing a `recovery` recipient the further line is `Check the recovery key you keep with iron-vault
recovery check.` ([open question 9](#open-questions)).

The CLI prints the notice as it prints every notice, to the terminal or stderr, and on success prints nothing to
stdout but `list`'s lines.

## Admin protocol

The rows below join [admin-protocol.md](admin-protocol.md) with the command tickets.

| Command ID | Command | Arguments | Result |
|---|---|---|---|
| `13` | `recipient list` | none | the entries |
| `14` | `recipient add` | the source, the recipient key and the label | the enrolled key and the recipient count |
| `15` | `recipient remove` | the recipient key | the recipient count |

`recipient add`'s request:

| Tag | Field | Value |
|---|---|---|
| 2 | source | `u8`: `1` a recipient key the owner gives, `2` a new recovery key the service generates, `3` a host unlock identity's recipient key the owner gives |
| 3 | recipient key | UTF-8 text: the `age1…` key for sources `1` and `3`; empty for source `2` |
| 4 | label | UTF-8 text: the label |

A source other than 1, 2 or 3, an empty key with source `1` or `3`, or a key with source `2` is a malformed frame. A key or label
that breaks its rule is `recipient-invalid`, decided by the service. `recipient remove`'s request has one field, tag
2, the recipient key as UTF-8 text.

`recipient list`'s result is tag 2, a byte value holding the entries, in inventory order:

| Size | Part |
|---|---|
| 1 | key length `k`, always 62 |
| `k` | recipient key |
| 1 | role code |
| 1 | label length `l`, 1 to 64 |
| `l` | label |
| 8 | enrolled at: `u64` Unix seconds |

64 entries are under 9 KiB, inside the [64 KiB frame bound](admin-protocol.md#frame), so `list` needs no too-large
error. `recipient add`'s result is tag 2, the enrolled key as UTF-8 text, and tag 3, the recipient count as `u8`.
`recipient remove`'s result is tag 2, the recipient count as `u8`.

### Error codes

Five codes are new, the next free numbers after 34:

| Code | Name | Meaning |
|---|---|---|
| `35` | `recipient-invalid` | `recipient add`, `recipient remove`: the key is not an `age1…` X25519 recipient key, or the label breaks its rule; the message names the rule |
| `36` | `recipient-enrolled` | `recipient add`: the key is already enrolled; nothing was changed |
| `37` | `unknown-recipient` | `recipient remove`: no enrolled recipient has this key; nothing was changed |
| `38` | `recipient-set-invalid` | `recipient add`, `recipient remove`: the set after the change would break the independence rule or hold more than 64 recipients; the message names which part; nothing was changed |
| `39` | `recipient-inventory-damaged` | `recipient list`, `recipient add`, `recipient remove`: the inventory check found the inventory missing or damaged; the message names the damage, and for `missing` says a vault initialized before recipient commands has none; nothing was changed |

`recipient-invalid` is a fifth code beside the four the ticket names, because an argument that breaks its rule is
neither of the other four, and `credential-invalid` names credentials.

Existing codes widen to cover the recipient commands: `declined` (8) for `--recovery`'s confirmation;
`approval-denied` (9) and `approval-unavailable` (10) for `recipient remove`'s owner presence; `vault-write-failed`
(22) for a recipient change or an inventory check write that failed, whose message says whether it may have committed.
`busy`, `wrong-state` and the migration codes 28, 29 and 33 already cover them.

## Audit events

These join the [catalogue](audit-logging.md#catalogue). None carries a secret: a recipient key is public, and a
recovery key's secret text is never logged.

| Event | Level | When | Fields |
|---|---|---|---|
| `recipient.added` | INFO | a recipient change that adds committed | `recipient`, `recipient_role`, `recipient_label`, `recipients` |
| `recipient.removed` | INFO | a recipient change that removes committed | `recipient`, `recipient_role`, `recipient_label`, `recipients` |
| `recipient.change-failed` | WARN | an add or remove was refused at its own step 3, or its recipient change failed | `change`, `recipient`, `failure`; `step`, `error_kind` and `committed` for `write_failed` |
| `recipient.inventory-damaged` | WARN | the inventory check found the inventory damaged | `inventory_damage` |
| `recipient.change-recovered` | WARN | the inventory check finished a committed change or removed a staged inventory | `recovery` |

| Field | Type | Form |
|---|---|---|
| `recipient` | string | A recipient key's `age1…` text; for `--recovery`, the new key's |
| `recipient_role` | string | A role name: `operational`, `recovery`, `added` or `host-unlock` |
| `recipient_label` | string | A recipient label, escaped |
| `recipients` | number | The recipient count after the change |
| `change` | string | `add` or `remove` |
| `failure` | string | `already_enrolled`, `unknown_recipient`, `set_invalid` or `write_failed` |
| `committed` | string | `no`, `unknown` or `yes`: whether the failed change committed |
| `inventory_damage` | string | `envelope_unreadable`, `missing`, `unreadable`, `mac`, `malformed`, `unknown_role`, `other_vault`, `envelope_mismatch` or `count_mismatch` |
| `recovery` | string | `completed` or `discarded` |

`step` takes a [recipient change](#the-recipient-change) step label. Refusals that already have their own events are
not repeated in `recipient.change-failed`: migration authorization records `migration.*`, owner presence records
`vault.presence-refused`, and an inventory check failure records `recipient.inventory-damaged`. A refusal at step 1 or
2 records only `admin.command`, as for every command.

## Initialization

`init` writes the first inventory: the `operational` and `recovery` recipients, with the labels `vault passphrase` and
`recovery key` and the init time. A build that is not dev-mode accepts `init --host-unlock`, which adds a third entry, role `host-unlock`,
labelled `host unlock`, for the identity in the unlock handoff. It is the only moment the service knows the recovery
key's recipient key, so a vault whose `init` did not write one can never have one.

The inventory needs the vault ID, for its header and payload, and step 5 (`Vault::create`) is where the vault ID is
generated today. The vault ID therefore joins the [new vault keys](glossary.md), generated before anything is written,
and `Vault::create` takes it. Step 2 then writes `identity.age`, proves both recipients on it as read back, and writes
`recipients.age` with that envelope's digest. The step stays number 2, so no later step is renumbered, and its label
becomes "writing and checking the identity envelope and the recipient inventory". A crash between the two files leaves
`init.unfinished`, so the next `init` discards both; init needs no staged inventory.

[vault-initialization.md](vault-initialization.md) changes with the init ticket:

- the files an initialization writes, the vault's own files, and the discard list gain `recipients.age`;
- the vault's own files gain `recipients.age.staged`, so a leftover staged inventory in an Initialized vault is not a
  foreign file. It is not on the Unfinished list: `init` never writes one, so beside `init.unfinished` it is foreign;
- the write-order table and the crash table name `recipients.age` in step 2.

## Vaults with no inventory

A vault initialized before this design has no `recipients.age`, and nothing can rebuild one: the X25519 stanzas do not
name their recipients, and the recovery key's recipient key was never kept. Every recipient command refuses such a
vault with `recipient-inventory-damaged`, damage `missing`, whose message says the vault was initialized before
recipient commands existed or the file was deleted, and that a vault from `iron-vault init` has one. v0 is unreleased,
so no owner holds such a vault yet ([open question 2](#open-questions)). The rest of the service works on it as before.

## How other commands see recipients

- **`recovery check`** still proves a key against `identity.age` and the manifest, and never reads the inventory. Any
  `recovery` recipient passes it. The recovery check record names no key, so it is not changed by a recipient change.
- **`unlock` and migration authorization** still go through `operational.age` to `identity.age`. While the vault
  passphrase is the only source-owner method, the independence rule keeps the `operational` recipient, so no recipient
  change can break them. A later vault that drops `operational` unlocks with its other unlock method and authorizes
  migration with its other source-owner method.
- **`export` and `import` (EP-30)** carry no inventory from the source: an import wraps the vault identity for the
  destination's own recipients and writes the destination's own inventory.
- **`status`** does not report recipients ([open question 4](#open-questions)).

## Out of scope

- TPM and hardware-key recipients. Their epics enroll the roles and extend the independence rule as
  [described above](#independence-rule).
- `forget-machine`, which checks recipient removal and guides TPM clearing
  ([§16](iron-vault-specification.md#16-administration-recovery-and-migration)); it is designed in
  [forget-machine.md](forget-machine.md).
- Changing the vault passphrase. It reseals `operational.age` around the same operational identity, so it changes no
  recipient and no inventory entry.

## Release checks

`crates/iron-vault/tests/signers/recipients.rs` drives a real service through `init`, `unlock` and the recipient commands,
with one test per promise of the recipient epic. Each command's own suite (`recipient_list_linux.rs`,
`recipient_add_linux.rs`, `recipient_add_recovery_linux.rs`, `recipient_remove_linux.rs`) covers its exchange, output
and refusals; this file covers what only holds across them.

| Promise | Test | Specification |
|---|---|---|
| An added recipient opens the vault after a restart, and the manifest MAC verifies under the identity it unwraps | `an_added_recipient_opens_the_vault_after_a_restart` | [§14](iron-vault-specification.md#14-recipients-startup-and-memory) |
| A rewrap leaves every credential record and the manifest byte-identical, and a route keeps serving without a restart | `a_rewrap_leaves_every_credential_file_byte_identical_and_the_route_working` | [§13](iron-vault-specification.md#13-vault-structure-and-durable-writes), [§14](iron-vault-specification.md#14-recipients-startup-and-memory) |
| A change that would leave fewer than two independent paths is refused and writes nothing | `a_change_that_leaves_fewer_than_two_independent_paths_is_refused_and_changes_nothing` | [§14](iron-vault-specification.md#14-recipients-startup-and-memory) |
| A removed key still opens a copy of `identity.age` taken before the removal, and not the new envelope | `a_removed_key_still_opens_a_copy_of_the_envelope_taken_before_the_removal` | [§16](iron-vault-specification.md#16-administration-recovery-and-migration) |
| `recipient add` needs the vault passphrase even while Ready; the approval passphrase does not stand in for it | `adding_a_recipient_needs_the_vault_passphrase_even_while_ready` | [§16](iron-vault-specification.md#16-administration-recovery-and-migration), [§18](iron-vault-specification.md#18-logging) |
| After rotating the recovery key and removing the old one, `recovery check` passes with the new key and fails with the old | `after_rotating_the_recovery_key_the_new_key_passes_recovery_check_and_the_old_fails` | [§16](iron-vault-specification.md#16-administration-recovery-and-migration) |
| No typed passphrase, credential secret or secret-key text reaches the log through a session of all these commands | `no_typed_secret_or_secret_key_reaches_the_log_through_a_full_session` | [§18](iron-vault-specification.md#18-logging) |

## Open questions

The specification leaves each point below open, or this design departs from its wording or from the ticket's default.
The design takes the default stated for each, until the owner decides.

1. **`recipient list`.** [§16](iron-vault-specification.md#16-administration-recovery-and-migration)'s table names
   `recipient add` and `remove`, not `list`. *Default:* add `recipient list`, Ready only, because `remove` takes a key
   the owner cannot otherwise find. The alternative shows the inventory in `status`, which answers in every state and
   so could not open a MAC'd file while Locked.
2. **Vaults with no inventory.** *Default:* the recipient commands refuse them with `recipient-inventory-damaged`,
   damage `missing`; v0 is unreleased. The alternative lets the owner supply every recipient key once, and the service
   writes an inventory whose entry count matches the envelope's stanzas. The service cannot check that those are the
   keys the stanzas were wrapped for, so a wrong key would be enrolled and a real one silently dropped at the next
   rewrap.
3. **A staged inventory before the envelope.** The ticket's default writes `identity.age`, then the inventory, and
   reports any mismatch as damage. A crash between the two replaces would then leave a vault whose recipient commands
   refuse for good, though nothing was damaged. *Default:* write a staged inventory first, make the envelope's replace
   the commit point, and let the inventory check finish or discard the change from the staged file
   ([The inventory check](#the-inventory-check)). Any other mismatch is still damage, never repaired.
4. **Where the inventory is checked.** *Default:* only the recipient commands open it; `unlock`, the config check and
   `status` do not, so a damaged inventory never stops serving and is reported when a recipient command runs. This
   departs from [§15](iron-vault-specification.md#15-service-states-and-errors), where damaged shared state makes the
   service Unavailable: serving never reads the inventory, so taking every route down would protect nothing. The
   alternative checks it at every config check and reports it in `status`, at the cost of writes during a config check
   to finish a staged change.
5. **Outside the state generation.** *Default:* the inventory does not take part in the
   [state generation](storage-formats.md#state-generation); the envelope digest already refuses an inventory restored
   alone. Restoring `identity.age` and the inventory together restores removed recipients, which is the old copy
   [§16](iron-vault-specification.md#16-administration-recovery-and-migration) says removal cannot reach. The
   alternative extends the peer generation to three files.
6. **The word "inventory".** [§16](iron-vault-specification.md#16-administration-recovery-and-migration) says "The
   service keeps no separate inventory", meaning a list of credentials to reissue after complete loss
   ([recovery.md](recovery.md)). *Default:* no spec change; the term is always "recipient inventory" in full, and it
   holds no credential. The alternatives rename the file's concept, or reword the spec's sentence to "no separate
   credential inventory".
7. **When `--recovery` reveals the key.** *Default:* after the summary and before the challenge, because a challenge
   lives 2 minutes and saving a key can take longer; a key shown to an exchange that is then refused opens nothing.
   The alternative reveals it only after authorization succeeds, so an unauthorized exchange never sees a key, which
   needs a longer challenge lifetime for this one command.
8. **Which keys count as recovery.** *Default:* only keys the service generated and revealed take the `recovery` role,
   as [§14](iron-vault-specification.md#14-recipients-startup-and-memory) speaks of "a generated offline recovery
   recipient"; an owner's own key is `added` and does not count. The alternative lets `recipient add <age1…>` take
   `--recovery`, so an owner-held offline key counts.
9. **The recovery check record after a recovery change.** *Default:* recipient changes leave `recovery.toml` alone,
   and the completion notice tells the owner to run `recovery check` with the key they keep. The alternative restarts
   the reminder schedule after any change to a `recovery` recipient, so the reminder no longer counts from a check of
   a key that may have been removed.
10. **Authorizing removal.** *Decided: default accepted (2026-11-09).*
    [§14](iron-vault-specification.md#14-recipients-startup-and-memory) names `recipient remove` among the sensitive
    changes the approval signer authorizes through owner presence. This settles [open question 3 of
    migration-authorization.md](migration-authorization.md#open-questions). *Default:* owner presence, the approval
    passphrase, because removal grants no access and is a destructive change, and owner presence is the "fresh
    existing-owner authorization" §16 asks for. The alternative also requires migration authorization with a third
    operation tag, so removal needs the vault passphrase.
11. **`operational` beside a TPM.** *Superseded (owner, 2026-11-11):* `operational` stays enrolled while the vault
    passphrase is the only source-owner method, and v0 does not relax part 2 for a TPM approver
    ([tpm-approval-signer.md](tpm-approval-signer.md#open-questions) open question 3). The decision of 2026-11-09 was:
    [§14](iron-vault-specification.md#14-recipients-startup-and-memory) now gives passphrase, TPM and hardware key
    equal weight as the unlock method, with the offline recovery key as the second way in, so the passphrase is not
    required beside another method. The [independence rule](#independence-rule) keeps `operational` only while the
    vault passphrase is the only source-owner method, so migration authorization always has a method. The former
    default kept `operational` in every profile as the fallback when another unlock method fails.
12. **The role name `operational`.** The owner's own word for the unlock method's recipient is "operational", whatever
    its kind, but role 1 means the passphrase's recipient alone, and `tpm`, `hardware` and `host-unlock` name the other
    kinds. *Default:* keep `operational` for role 1, and say "unlock method" for the concept, as
    [§14](iron-vault-specification.md#14-recipients-startup-and-memory) and the [glossary](glossary.md) do. The
    alternative renames role 1 to `passphrase`, which changes what `recipient list`, the summaries and the audit log
    print, and the glossary's operational identity.
