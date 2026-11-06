# Migration authorization

How the service checks that the owner authorizes a migration before `export` writes a migration bundle or `recipient
add` rewraps the vault identity for a destination (specification
[§3.13](iron-vault-specification.md#313-administration-recovery-and-migration),
[§3.15](iron-vault-specification.md#315-logging-and-v0-acceptance), R-23). It covers the challenge the service issues,
how the owner proves authority over the vault identity, what the proof authorizes, and how the admin exchange and the
audit log show it. Terms follow the [glossary](glossary.md). The commands that consume an authorization are designed
by their own epics: `export` (EP-30), `recipient add` (EP-28) and the TPM approval-key PIN method (EP-33).

Three rules drive the design:

- **Only an enrolled factor, proved now, authorizes.** An unlocked vault, an authenticated admin connection, an
  earlier unlock or a newly chosen export passphrase never does
  ([§3.13](iron-vault-specification.md#313-administration-recovery-and-migration)). Otherwise malware with an admin
  connection could export every credential under a passphrase it chose (R-23).
- **An authorization covers one pending migration.** It is bound to the vault, the operation and the destination
  recipient, and it is used once, before it expires.
- **The service runs the proof itself.** It issues the challenge, asks for the input, starts any hardware proof and
  verifies the result. The CLI only relays prompts and input ([§3.2](iron-vault-specification.md#32-service-and-cli-boundary)).

## The v0 method: the vault passphrase

In v0 the one source-owner method is the vault passphrase, the vault-unlock `Passphrase`. Inside one exchange the
service:

1. sends a secret prompt, `Vault passphrase`, the label `unlock` uses, since it asks for the same secret;
2. reads `operational.age` and `identity.age` from disk, opens the passphrase envelope with the passphrase, and unwraps
   the identity envelope with the operational identity;
3. compares the unwrapped vault identity's public key with that of the vault identity it holds;
4. drops the passphrase, the owner input it came from, the operational identity and the unwrapped vault identity.
   Each clears itself on drop.

The check runs on the blocking pool, as `unlock` does, because scrypt holds a thread for about a second. The store
provides it as `verify_vault_passphrase`.

Nothing held in memory counts. The service does not ask whether it holds a vault identity, or whether some earlier
`unlock` succeeded: it opens the envelopes on disk again with what the owner just typed. Step 3 is what makes the
proof about *this* vault. Envelopes from another vault, opened with that vault's passphrase, unwrap cleanly but yield
another identity. Someone who could write the state directory could otherwise plant a pair made under a passphrase
they know.

Empty or non-UTF-8 input cannot be the passphrase and is refused as a wrong one. There is no second try in the same
exchange.

**Owner decision: the vault passphrase, not the approval passphrase.**
[§3.13](iron-vault-specification.md#313-administration-recovery-and-migration)'s method table asks the owner to
"re-enter the original source-vault passphrase", verified "against the existing enrolled identity envelope". The
approval passphrase is the right factor for config and credential changes
([owner presence](credential-commands.md#owner-presence)). Authority over the vault identity itself belongs to the
factor that unwraps it. The two passphrases are separate types, so the approval passphrase cannot be passed where the
vault passphrase is expected.

## Migration operation

A migration operation is what an authorization permits. There are two, the two paths of
[§3.13](iron-vault-specification.md#313-administration-recovery-and-migration):

| Operation | Label | Destination recipient | Consumed by |
|---|---|---|---|
| `Export` | `export` | none: the migration bundle is protected by the export passphrase chosen after authorization | `export`, before it takes its snapshot |
| `AddRecipient(RecipientKey)` | `add_recipient` | the recipient key to be enrolled in the identity envelope | `recipient add`, before it rewraps `identity.age` |

The destination of `AddRecipient` is part of the operation, so an authorization to add one recipient never adds
another. `Export` names no destination, because the export passphrase is chosen only after authorization and is never
evidence of authority.

## Migration challenge

The service issues a migration challenge after it has shown its summary and just before it prompts. The challenge
holds:

| Field | Value |
|---|---|
| Vault ID | the vault ID of the vault the service holds |
| Operation | the migration operation, with its destination recipient when there is one |
| Nonce | 32 bytes from the operating system's random source |
| Issued at | the monotonic clock when the challenge was issued |
| Expires at | issued at plus the challenge lifetime, 2 minutes |

The clock is monotonic, so changing the wall clock can neither extend nor shorten a challenge. Two minutes covers the
vault passphrase prompt, the scrypt check and, for `export`, the export passphrase prompts that follow before the export
starts. When the random source fails, no challenge is issued and the command ends with `migration-unavailable`.

### Binding digest

The binding digest is BLAKE2b-256, unkeyed with a 32-byte output, personalized with `iv-migration-v1` (15 bytes), of
the challenge's canonical encoding. The encoding uses the conventions of
[record payload v1](storage-formats.md#conventions): big-endian unsigned integers, and a field is a `u64` byte length
followed by its bytes.

| Size | Content |
|---|---|
| 16 | Vault ID: the 16 bytes of the version 4 UUID, in the order its hyphenated text shows them |
| 1 | Operation tag: `01` export, `02` add recipient |
| var | Destination: a field holding the destination recipient key's canonical `age1…` text; zero length for export |
| 32 | Nonce |
| 8 | Issued at: `u64` milliseconds from the service's clock origin, an instant fixed when the service starts |
| 8 | Expires at: `u64` milliseconds from the same origin |

The persona separates this digest from every other BLAKE2b use in the service. Its `v1` versions the encoding, so a
change to the layout takes a new persona. The times are meaningful only inside the process that issued the challenge,
which is the only process that ever verifies it.

A source-owner method that signs proves the challenge by signing its binding digest. The TPM approval key (EP-33)
signs it, and the service verifies the signature against the enrolled key. The passphrase method has nothing to sign.
Its binding comes from the service: the challenge it proves is the one the service took out of the pending slot by its
binding digest, and the authorization it yields carries that challenge.

### Lifetime

The service holds at most one pending challenge, in one slot. Issuing a challenge while one is pending is refused with
`busy`, expired or not, until the exchange that issued it ends. Issuing never replaces a pending challenge, because that
would retire the challenge of an owner still typing at a prompt. The commands that consume an authorization hold the
service-wide lock from before their summary until their response (see [Admin exchange](#admin-exchange)), so a second
migration exchange is refused `busy` before it reaches the slot. The slot's own refusal is a second guard.

When the owner input arrives, the service takes the challenge out of the slot, naming it by its binding digest. The
slot must hold exactly that challenge, unexpired. Only then does the method run. An expired challenge is refused before
any scrypt work, so no passphrase is ever checked against one. Taking it is what makes a challenge single-use: once
taken, the slot is empty, whether the method then proves it or refuses.

A challenge is therefore retired:

- when the method's proof succeeds, and the challenge moves into the authorization;
- when the method refuses, or the check cannot run;
- when the prompt gets no owner input (cancelled);
- when it is taken after its expiry;
- on `lock`, whose path empties the slot, and which cancels the prompt that was waiting;
- when the exchange that issued it ends, however it ends.

No challenge is ever verified twice, and none outlives its exchange.

## Migration authorization

A migration authorization is the proof that the owner authorized one migration operation. Only the migration
authorization module constructs one, from a challenge that a source-owner method has just proved. It holds that
challenge, and with it the binding digest. It is move-only: not `Clone`, not `Copy`, never serialized, and never stored
in the service context. Its `Debug` output shows only the operation and the expiry.

The operation that needs it consumes it, at the moment the operation starts:

- `export` just before it takes its snapshot under the write lock;
- `recipient add` just before it rewraps `identity.age`.

Consuming it checks that the vault ID, the operation and the destination recipient are the consuming operation's own,
and that the challenge's expiry has not passed. A mismatch is refused as `binding_mismatch` and an expired proof as
`expired`, both with `migration-denied`. For an expired proof the owner runs the command again, which issues a new
challenge and asks again: §3.13 step 1, "if the authorization expires before export begins, repeat the check"
([open question 2](#open-questions)).

The authorization holds no reference to the service and does not notice a `lock` itself. A `lock` cancels the
exchange at its next prompt, and the authorization drops with it, unused. Before it consumes the authorization, the
command checks that the service is still in the state and at the check generation it recorded when it took the
service-wide lock, as `replace` does ([order of steps](credential-commands.md#order-of-steps), step 8), and answers
`wrong-state` otherwise.

A command that needs authorization cannot be written without one: the operation takes the authorization by value, and
the type has no other constructor. That is how a missing authorization fails.

## Source-owner method

A source-owner method is a way to prove authority over the vault identity through a factor already enrolled for this
vault. It is a trait, so `export` and `recipient add` do not depend on which factor the owner uses. Each method gives:

- a stable label, recorded in the audit events' `method` field;
- the prompt it needs: its label, and whether the input is secret;
- `prove`, which takes the challenge and the owner's input and either succeeds or refuses. It refuses with an owner
  refusal (a wrong secret, or a factor that is not this vault's) or as unavailable (the factor cannot be checked).

| Method | Label | Phase | The service proves the challenge by |
|---|---|---|---|
| Vault passphrase | `vault_passphrase` | v0 | opening the envelopes from disk with the typed passphrase ([above](#the-v0-method-the-vault-passphrase)) |
| TPM approval-key PIN | `tpm_pin` | EP-33 | having the TPM sign the binding digest with the approval key under the typed PIN, then verifying the signature |
| YubiKey touch | `yubikey_touch` | the hardware-key phase | a fresh touch on the enrolled key for this challenge, plus any PIN its policy requires |

The service starts and verifies every hardware proof itself. A signature over another digest, an earlier touch or a
cached PIN proves nothing. The TPM's unattended unwrap of the vault identity is not a method: it shows the machine
started, not that the owner is present.

These do not authorize a migration: the recovery key, which §3.13 keeps for loss rather than listing as a migration
factor; the approval passphrase; an earlier unlock or migration authorization; an admin connection; and the export
passphrase. Which method to ask for when a vault has more than one enrolled is EP-33's decision, made when the TPM
method lands.

A hardware device's own lockout applies as the device enforces it, such as the TPM's dictionary-attack lockout
([§3.12](iron-vault-specification.md#312-service-states-and-errors)). The service adds no limit of its own in v0.

## Passphrase attempt limit

v0 has no passphrase attempt limit. The limit is on the v1 roadmap
([§2](iron-vault-specification.md#2-release-plan)). Deferring it is acceptable for these reasons:

- **Each guess is slow.** One exchange allows one attempt, and each attempt costs an scrypt run at the vault's work
  factor (2^18, about half a second to a second and 256 MiB of memory). Each attempt also holds the service-wide lock,
  so attempts run one at a time: about one a second at best.
- **Only an admin principal can guess.** The admin socket accepts only admin principals. In a protected installation
  that means acting through `sudo`, and host administrators are already trusted
  ([§1.2](iron-vault-specification.md#12-security-promise-and-limits)).
- **A limit on migration alone would slow no one.** An admin principal can `lock` the service and guess through
  `unlock` at the same cost. A useful limit has to cover every prompt for the vault passphrase, which is a v1 design.
- **Guessing is visible.** Every refused attempt is a WARN audit record (`migration.authorization-refused` with
  `wrong_passphrase`), and in v1 the `migration_refused` owner notification shows it on the desktop.

**v1 direction, not decided.** One count across every vault passphrase prompt (`unlock` and migration
authorization). After 5 consecutive failures, further attempts are refused for a cooldown that doubles with each
further failure, capped at 15 minutes. The count is held in memory, survives `lock`, and resets on success and on a
restart. The `rate_limited` refusal and its error case arrive with it. Whether the limit is configurable is decided
then.

## Admin exchange

`export` and `recipient add` each run migration authorization as one step of their own exchange. Their other steps are
their epics'. In order:

| Step | What the service does | Refusal |
|---|---|---|
| 1 | It is in a state the command allows, holding the vault identity; the arguments follow their rules | `wrong-state`, the command's own |
| 2 | Try the service-wide lock, and record the state and the check generation | `busy` |
| 3 | The command's own checks, such as that the destination recipient is not already enrolled | the command's own |
| 4 | The command's summary, as one or more notices | |
| 5 | Issue the migration challenge, recorded as `migration.challenge-issued` | `busy`, `migration-unavailable` |
| 6 | A secret prompt, `Vault passphrase` | none (cancelled), `migration-unavailable` (a `lock`) |
| 7 | Take the challenge out of the slot and run the method; on success, `migration.authorized` | `migration-denied`, `migration-unavailable` |
| 8 | The command's own prompts: for `export`, the new export passphrase | the command's own |
| 9 | The service is still in the recorded state and check generation; consume the authorization | `wrong-state`, `migration-denied` |
| 10 | The operation | the command's own |

**The service-wide lock is held from step 2 to the response, prompts included,** as `replace` and `rm` hold it. The
summary therefore stays true until the operation, and the challenge in the slot always belongs to the one exchange
that can take it. A `lock` cancels the exchange at any of its prompts.

**The summary names what the challenge binds:** the operation, the vault ID and the destination recipient when there
is one. It also says which factor is asked for, and for `export` that a new export passphrase follows. The command
writes the rest. For example:

```text
export the vault
  vault: 2a682de7-b14d-4900-9ea9-0c968e1a6589
  authorize with: the vault passphrase
  then: a new export passphrase to protect the migration bundle
```

```text
add a recipient to the vault
  vault: 2a682de7-b14d-4900-9ea9-0c968e1a6589
  recipient: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
  authorize with: the vault passphrase
```

There is no separate `Type yes` confirmation. As with owner presence, typing the vault passphrase after the summary is
the confirmation, and cancelling the prompt declines.

Only after step 7 succeeds does `export` ask for the export passphrase
([§3.13](iron-vault-specification.md#313-administration-recovery-and-migration): "only after this source-owner check
succeeds may the service accept a new passphrase"). The owner never types the new passphrase into an exchange that has
not been authorized.

### Error codes

Two new codes join the [admin protocol's table](admin-protocol.md#admin-response-error-kind-5). They start at 28,
because 27 is taken by `memory-unprotected` (K-198, not yet landed).

| Code | Name | Meaning |
|---|---|---|
| `28` | `migration-denied` | `export`, `recipient add`: migration authorization was refused: the vault passphrase was wrong, the envelopes it opened are not this vault's, or the authorization expired, was already used or is for another operation; nothing was exported or rewrapped |
| `29` | `migration-unavailable` | `export`, `recipient add`: migration authorization could not be checked: an envelope could not be read or opened for a reason other than the passphrase, the random source failed, or a `lock` cancelled the command at its vault passphrase prompt; nothing was exported or rewrapped |

The messages are fixed phrases, and none holds owner input. Each refusal ends the exchange as follows:

| Refusal | When | The exchange ends with |
|---|---|---|
| `wrong_passphrase` | the passphrase does not open `operational.age`, or the input is empty or not UTF-8 | `migration-denied` |
| `not_this_vault` | the envelopes opened, to a vault identity other than the one the service holds | `migration-denied` |
| `expired` | the challenge was taken, or the authorization consumed, after its expiry | `migration-denied` |
| `not_pending` | the slot does not hold the challenge: it was already taken or retired | `migration-denied` |
| `binding_mismatch` | the consuming operation's vault ID, operation or destination is not the authorization's | `migration-denied` |
| `unavailable` | an envelope could not be read or opened for a reason other than the passphrase | `migration-unavailable` |
| `locked` | a `lock` cancelled the command at its vault passphrase prompt | `migration-unavailable` |
| `cancelled` | the prompt got no owner input: the CLI closed, the connection failed, or the prompt deadline passed | no response, as for any prompt without owner input |

`not_pending` and `binding_mismatch` cannot be reached through a command, which issues and consumes its own
challenge. They exist so that a defect fails closed and so that the release checks can drive them. Neither is a reason
to try again.

## Audit events

These are audit events in the audit log. When the migration authorization ticket emits them, it adds their rows to
the [catalogue](audit-logging.md#catalogue), adds `migration` to the event subjects and types the new fields there. None
carries owner input.

| Event | Level | When | Fields |
|---|---|---|---|
| `migration.challenge-issued` | INFO | a migration challenge was issued (step 5) | `operation`, `method`; `destination_recipient` for `add_recipient` |
| `migration.authorized` | INFO | a source-owner method proved the challenge (step 7) | `operation`, `method`; `destination_recipient` for `add_recipient` |
| `migration.authorization-refused` | WARN | the challenge or the authorization was refused, or the prompt was cancelled | `operation`, `method`, `refusal`; `destination_recipient` for `add_recipient`; `error_kind` for `unavailable` |

| Field | Type | Form |
|---|---|---|
| `operation` | string | `export` or `add_recipient` |
| `method` | string | A source-owner method's label: `vault_passphrase` in v0 |
| `destination_recipient` | string | The destination recipient key's `age1…` text, which is public |
| `refusal` | string | One of the refusal labels [above](#error-codes) |

Every issued challenge is followed by exactly one `migration.authorized` or `migration.authorization-refused`, so the
log shows how each attempt ended. `migration.authorized` records the proof, not the migration. `export` and
`recipient add` each record their own completion.

The owner notification topic `migration_refused` is reserved for `migration.authorization-refused`
([owner-notifications.md](owner-notifications.md#reserved-topics)). It is v1 work, like every owner notification.

## Release checks

[§3.15](iron-vault-specification.md#315-logging-and-v0-acceptance) requires export and destination-recipient
enrollment to "reject missing, incorrect, expired, replayed, or cancelled source-owner authorization, including when
the vault is already unlocked". Each case maps to a mechanism above:

| §3.15 case | How it is refused | Refusal |
|---|---|---|
| Missing | The operation takes a migration authorization by value, and only a method's proof constructs one | none: the code cannot be written |
| Incorrect: a wrong passphrase, or the approval passphrase in its place | The passphrase does not open `operational.age` | `wrong_passphrase` |
| Incorrect: another vault's envelopes | The unwrapped identity is not the one the service holds | `not_this_vault` |
| Expired | The challenge is taken, or the authorization consumed, after its expiry | `expired` |
| Replayed | The authorization is move-only and consumed by its operation; a used challenge is no longer in the slot | `not_pending` |
| Cancelled | No owner input at the prompt, or a `lock` there | `cancelled`, `locked` |
| The vault already unlocked | Being Ready constructs no authorization, and the method reads the envelopes from disk | `wrong_passphrase` unless the owner proves the passphrase now |
| Each method authorizes only its pending migration | The vault ID, operation and destination must be the consuming operation's own | `binding_mismatch` |
| A new export passphrase never authorizes on its own | It is asked for only after step 7 and is never checked as a source factor | none: the passphrase is never offered to a method |
| An earlier unlock never authorizes on its own | Nothing held in memory counts; every exchange runs the method again | none: the method always runs |

The epic's rejection suite names one test per row.

## Open questions

The specification leaves each point below open. The design takes the default stated for each, until the owner
decides.

1. **Code without a caller.** Until `recipient add` (EP-28) or `export` (EP-30) lands, nothing outside tests calls
   the migration authorization modules. *Default:* expect `dead_code` allowances on them, or land this epic just
   before EP-30's first command ticket.
2. **Expiry within one exchange.** [§3.13](iron-vault-specification.md#313-administration-recovery-and-migration) step
   1 says that if the authorization expires before export begins, the check is repeated. *Default:* the exchange ends
   with `migration-denied` (`expired`), and running the command again repeats the check, with a new challenge. The
   alternative issues a new challenge and prompts again inside the same exchange, which would make it the one place
   with a second try.
3. **`recipient remove`.** §3.13 asks for "fresh existing-owner authorization" for `recipient remove` as well as
   `recipient add`, but removal is not a migration path. *Default:* removal is not a migration operation, and EP-28
   chooses its check. If EP-28 uses this one, a third operation tag is the only change: the existing encodings stay
   as they are, so the persona does not change.
