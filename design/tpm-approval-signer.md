# TPM approval signer

This document decides how a protected Linux installation uses a TPM-resident signing key, protected by a PIN, as an
approval signer ([§12](iron-vault-specification.md#12-configuration-approval-and-reload),
[§14](iron-vault-specification.md#14-recipients-startup-and-memory)). It covers: which process talks to the TPM; what
key it creates and how the PIN reaches it; how `approver add --kind tpm` enrolls one; how the approver prompt proves
presence with it; how it serves as a source-owner method for migration
([§16](iron-vault-specification.md#16-administration-recovery-and-migration)); what a forgotten PIN or a cleared TPM
costs; how dictionary-attack lockout and power loss bear on it; and what the release checks must show.

The approval passphrase stays as it is. A TPM approver is one more pinned approver, asked through the same
[approver prompt](approval-signers.md#the-approver-prompt), signing the same
[approval envelope](storage-formats.md#approval-envelope-v1) (implementation spec Q-9).

This document introduces eight terms, defined in the [glossary](glossary.md): *TPM signer*, *TPM approval key*,
*TPM key blob*, *TPM approval PIN*, *TPM signing helper*, *Presence payload*, *Migration proof payload* and *Lockout
reserve*. The PIN here is always the TPM approval PIN, after §12's "approval PIN". It is not the *TPM PIN* of
[§4](iron-vault-specification.md#4-installation-and-ownership) and
[§14](iron-vault-specification.md#14-recipients-startup-and-memory), which unlocks the vault and which v0 does not have ([tpm-unlock.md](tpm-unlock.md#scope)).

## Scope

In scope: the [Linux package](linux-package.md), running the `Protected` deployment profile as
`iron-vault.service`, on a machine with a TPM 2.0 exposed as `/dev/tpmrm0`. **v0 offers the TPM signer on Ubuntu
24.04 LTS only**, the release [TPM unlock](tpm-unlock.md#supported-releases) supports, so one release check covers
both.

Out of scope:

- **TPM unlock.** It is a recipient of `identity.age`, unsealed by root at boot with no PIN
  ([tpm-unlock.md](tpm-unlock.md)). §12 keeps the approval key separate from the unwrapping key: they share no TPM
  object, no handle and no process. A machine may use either, both or neither.
- **The Compose profile.** Its host-side signing helper is K-255 (EP-45), which can reuse the helper below
  ([Interactions](#interactions)).
- **Development mode.** The helper needs a TPM device and a system account. A dev-mode build offers only
  `software` approvers, as now.
- **Windows and macOS**, whose platform providers are a later phase.

## The adapter

Three ways to reach the TPM were weighed:

| | (a) In the service | (b) A separate signing helper | (c) `tpm2-tools` as a subprocess |
|---|---|---|---|
| Who opens `/dev/tpmrm0` | The service account | A dedicated helper account | The service account, through the tools |
| §14: "the service account never opens the TPM" | Breaks it | Keeps it | Breaks it |
| Implementation spec §3: "The service account gets no TPM device" | Breaks it: `PrivateDevices=yes` goes | Keeps it | Breaks it |
| Native code in the credential process | `tpm2-tss` (C) linked into the process holding every provider secret | None: the service links no TPM library | None linked, but the service parses tool output |
| Who can spend the shared dictionary-attack counter | Anything running as the service | Only the helper, which keeps a [reserve](#lockout-reserve) | Anything running as the service |
| Unit hardening the service loses | `PrivateDevices=`, plus `DeviceAllow=` and the `tss` group | None | As (a) |
| PIN handling | In service memory | In service memory, then over a local socket as a derived value | On a pipe or command line to a child process |
| Moving parts | One process | Two units and a socket | Several processes per signature, context files on disk |

**Decision: (b), a separate signing helper**, `iron-vault-tpm-signer`. Option (a) contradicts the specification
twice, and the second contradiction is the reason for the first: the TPM does not know which program is asking, so a
process that can open it can unseal any sealed object whose policy the boot satisfies and can drive the
dictionary-attack counter that every PIN-protected key on the machine shares ([§17](iron-vault-specification.md#17-docker-remote-servers-and-appliances)
says the same of containers). Option (c) has the same exposure, adds a parser of another program's output on the
security path, and needs the PIN on a pipe or in a file the tool reads.

[§4](iron-vault-specification.md#4-installation-and-ownership)'s Linux row names "an in-service adapter with a TPM
PIN in a later phase". That is the unlock PIN, not this one, and §4 names no adapter for approval signing. This helper
is the Linux adapter for approval signing; whether §4's row should name it is
[open question 6](#open-questions).

The helper is the service's adapter, not a second authority: it holds no state, makes no decision about a config, and
signs only the three fixed payloads [below](#what-the-helper-signs), each only under a PIN the owner typed. The service
remains the only process the CLI talks to ([§5](iron-vault-specification.md#5-service-and-cli-separation-of-concerns)):
the owner types the PIN into the CLI, which sends it to the service as it sends every secret, and the service derives
the authorization value the helper uses.

### The helper process

- **Binary.** `/usr/libexec/iron-vault/iron-vault-tpm-signer`, a Rust binary using `tss-esapi` (7.x, which links the
  system's `libtss2-esys`). It is its own crate, so `/usr/bin/iron-vault` never links `tpm2-tss`; `build-deb.sh`
  checks that with `ldd`. The [wire protocol](#helper-protocol) and the [key blob](#the-tpm-key-blob) are in a pure
  library crate, `iron-vault-tpm-protocol`, that both binaries use.
- **Activation.** `iron-vault-tpm-signer.socket` listens on `/run/iron-vault-tpm/signer.sock` with `Accept=yes` and
  `MaxConnections=1`. systemd starts one `iron-vault-tpm-signer@.service` instance per connection, which answers one
  request and exits. Nothing runs between requests, and no request can see another's memory. The instance unit sets
  `StandardInput=socket`: the helper reads the request from standard input and writes the response back on that same
  descriptor. It also sets `StandardOutput=journal`, and stderr follows stdout to the journal. With
  `StandardInput=socket` alone, systemd would send stdout and stderr to the socket, so the helper's diagnostics would
  reach the peer.
- **One request at a time.** `MaxConnections=1` keeps a second instance from running while one is in the TPM, so no two
  instances read the dictionary-attack counter before either spends a try; the [lockout reserve](#lockout-reserve)
  rests on this. systemd closes a connection beyond the limit at once, and the service reads that as the helper being
  unavailable. The service never meets it: it asks the helper only under the service-wide lock, one call at a time.
- **Who may connect.** The socket is `SocketUser=iron-vault`, `SocketGroup=root`, `SocketMode=0600`: the service
  account and root, and no group. A group-readable socket in the `iron-vault` group would not do, because that group
  may hold a log collector's account ([linux-package.md](linux-package.md#admin-access)). The helper also reads
  `SO_PEERCRED` and refuses, before reading the request, a peer whose uid is not the one named by `--peer-user`
  (default `iron-vault`); that check is the control, and the socket mode keeps everyone else from reaching it.
- **Account.** A dedicated system account, `iron-vault-tpm`, from the package's `sysusers.d` file, with no shell and no
  home. It is not in the `tss` group in `/etc/group`; the unit adds the group with `SupplementaryGroups=tss`, so only
  the helper process ever holds it.
- **Device.** `DevicePolicy=closed` and `DeviceAllow=/dev/tpmrm0 rw`: the resource manager only, never `/dev/tpm0`.
- **Hardening.** As the service unit's, where it applies: `ProtectSystem=strict`, `ProtectHome=yes`,
  `PrivateTmp=yes`, `PrivateNetwork=yes`, `NoNewPrivileges=yes`, empty `CapabilityBoundingSet=`,
  `RestrictAddressFamilies=AF_UNIX`, `SystemCallFilter=@system-service`, `MemoryDenyWriteExecute=yes`, `LimitCORE=0`,
  `UMask=0077`, no writable path. It clears `PR_SET_DUMPABLE` and zeroizes the authorization value on drop.
- **Deadlines.** The helper drops a connection whose request has not arrived within 5 seconds, and
  `RuntimeMaxSec=30` ends an instance stuck in the TPM. The service waits at most 30 seconds for an answer and treats
  silence as the helper being unavailable.
- **Test seam.** `--tcti <spec>` selects the TPM, default `device:/dev/tpmrm0`; the tests point it at `swtpm`
  ([Testing](#testing)). The unit never passes it.

The service unit is unchanged: `PrivateDevices=yes` stays and no `DeviceAllow=` is added. Connecting to a Unix socket
on a read-only mount is allowed, so the service needs no new `ReadWritePaths=`.

**Offered.** The service offers the `tpm` kind when it runs in the `Protected` profile and
`/run/iron-vault-tpm/signer.sock` exists. Otherwise `approver add --kind tpm` answers `approver-kind-unavailable`
(44) before anything else, as it does today. A dev-mode build never offers it. An offered kind can still fail: on a
machine with no `tss` group or no `/dev/tpmrm0` the socket exists but the instance cannot start, and the helper's
create request at [enrollment](#enrollment) then answers `approver-kind-unavailable` with a message saying the helper
is unavailable.

## The TPM approval key

### Parent

Each helper request creates the parent as a transient primary key under the owner hierarchy, from the TCG storage root
key template for ECC NIST P-256 (restricted decryption key, `noDA`, AES-128-CFB, zero-length unique). The same TPM
always derives the same key from that template, so nothing persists in the TPM: no persistent handle, no NV index.
Using systemd's key at `0x81000001` would tie the signer to `systemd-creds` having run, and a key Iron Vault made
persistent would be one more TPM object for `forget-machine` and `reset` to remove.

The owner hierarchy's authorization is empty on Linux by default. Where another OS set it, creating the primary fails
and the helper answers `tpm-error` with the response code.

The primary's name (its `nameAlg` and the SHA-256 digest of its public area) goes into the
[key blob](#the-tpm-key-blob). The helper compares it before loading anything. A different name means another TPM, or
this TPM after a clear, and the helper answers `not-this-tpm` without trying any authorization.

### The signing key

A child of that primary, made with `TPM2_Create`:

| Attribute or field | Value | Why |
|---|---|---|
| Type, curve, scheme | ECC, NIST P-256, ECDSA with SHA-256 | Algorithm `02`, reserved for the TPM in [approval envelope v1](storage-formats.md#approval-envelope-v1) |
| `nameAlg` | SHA-256 | |
| `sign` | set | |
| `decrypt`, `restricted` | clear | A plain signing key, so it signs a digest the helper supplies, of a message the helper has checked |
| `fixedTPM`, `fixedParent` | set | The key cannot be duplicated off this TPM |
| `sensitiveDataOrigin` | set | The TPM generated the private key; nobody ever held it |
| `userWithAuth` | set | Signing needs the authorization value: the PIN |
| `adminWithPolicy` | clear | The admin role also needs the PIN; there is no policy |
| `noDA` | **clear** | Every wrong PIN counts against the TPM's dictionary-attack lockout; §12 forbids an exempt key |
| Authorization value | 32 bytes, [from the PIN](#the-approval-pin) | |
| Policy | empty | |

At each signature the helper loads the key, reads its public area back with `TPM2_ReadPublic`, and refuses unless
these attributes hold and its point is the pinned key the service sent. A blob replaced in the state directory, even
by a key the same TPM made, therefore cannot sign for a pinned approver.

**The pinned key** is the 65-byte uncompressed SEC1 point (`04 ‖ x ‖ y`), algorithm `02`, signer kind `2`, in the
approver's entry of the [approval state](storage-formats.md#approval-state-payload-v1), which already allows a 65-byte
key.

**Signatures** are 64 bytes, `r ‖ s`, each a 32-byte big-endian integer: the helper left-pads the TPM's two
`TPM2B_ECC_PARAMETER`s. The service rewrites `s` to the low half of the curve order before writing an envelope, and
every verifier refuses a high `s`, so each signature has one encoding, as each payload does. A v1 envelope with
algorithm `02` is therefore exactly 191 bytes, the same size as an Ed25519 one; storage-formats.md's "at most 199 with
a DER-encoded" note changes to match. The service verifies with the `p256` crate, already in `Cargo.lock`.

### Protected authorization session

Every command that uses the key's authorization runs in an HMAC session **salted** with the transient primary, with
SHA-256 and AES-128-CFB parameter encryption. `TPM2_Create` sets the session's `decrypt` attribute, so the new key's
authorization value crosses the bus encrypted. An unsalted session would let anyone who records the TPM's traffic test
PIN guesses offline against the session HMAC, out of reach of the lockout. This is the "protected authorization
session" §12 requires, and the release check proves it with a recorded session ([Release checks](#release-checks)).

### The approval PIN

- **Typing.** At enrollment the owner types the PIN twice; the two must match, compared in constant time. It is UTF-8
  of at least **6** Unicode scalar values, nothing trimmed or normalized ([open question 1](#open-questions)). A
  broken rule ends the exchange with `passphrase-rejected` (18), whose message names the rule. Like a new approval
  passphrase, it is not compared with the vault passphrase
  ([approval-signers.md](approval-signers.md#approver-add)).
- **Authorization value.** The service derives it as BLAKE2b-256, personalized with `iv-tpm-pin-v1`, of the
  approver ID's 16 bytes followed by the PIN's UTF-8 bytes. The value is exactly the length of the key's `nameAlg` digest, which
  is the most a TPM accepts, and binding the approver ID gives two keys with the same PIN different values. The PIN is
  cleared as soon as the value exists. A fast hash is enough: nothing derived from the PIN is written anywhere, the
  salted session keeps it off the bus, the service that computes it already sees the PIN, and the TPM's lockout is what
  limits guessing. A slow hash would protect nothing an attacker can reach.
  Rust: `iron_vault_tpm_protocol::{TpmApprovalPin, TpmAuthValue}`.
- **Lifetime.** The service holds the value, never the PIN, and only within one exchange: from the prompt's answer to
  the last helper call of that exchange, as it holds an opened software key between steps 2 and 3 of an approval. It is
  in memory cleared on drop, never written, never logged. The helper holds it for one request.
- **No PIN change.** v0 has no command to change a TPM approval PIN. The owner enrolls a new TPM approver with the new
  PIN and removes the old one; `TPM2_ObjectChangeAuth` is not used.

## What the helper signs

The helper signs ECDSA over SHA-256 of a message, and only three messages, each recognised by its whole encoding
before any TPM command runs:

| Message | Magic | Size | Signed when |
|---|---|---|---|
| [Approval payload v1](storage-formats.md#approval-payload-v1) | `IVAP` | 89 | Step 3 of a config approval |
| Presence payload v1 | `IVPP` | 69 | Owner presence, step 2 of a config approval, and the read-back at enrollment |
| Migration proof payload v1 | `IVMA` | 37 | A migration authorization by TPM approval PIN |

**Presence payload v1** (`iron_vault_store::PresencePayload`), in the conventions of
[record payload v1](storage-formats.md#conventions):

| Offset | Size | Content |
|---|---|---|
| 0 | 4 | Magic: ASCII `IVPP` (`49 56 50 50`) |
| 4 | 1 | Format version: `01` |
| 5 | 16 | Vault ID |
| 21 | 16 | Approver ID of the approver asked |
| 37 | 32 | Nonce: 32 bytes from the operating system's random source, fresh for this prompt |

The service chooses the nonce, asks for one signature over it, verifies that signature against the pinned key, and
drops the nonce. A signature over an earlier nonce, or for another vault or approver, proves nothing.

**Migration proof payload v1** (`iron_vault_store::MigrationProofPayload`):

| Offset | Size | Content |
|---|---|---|
| 0 | 4 | Magic: ASCII `IVMA` (`49 56 4d 41`) |
| 4 | 1 | Format version: `01` |
| 5 | 32 | The challenge's [binding digest](migration-authorization.md#binding-digest) |

The TPM never signs the bare [binding digest](migration-authorization.md#binding-digest), only this wrapper of it, so
that a signature over a migration challenge can never be read as one over 32
bytes of some other structure. The magics are the domain separation: no message can be read as another, which is why
the helper needs no state to refuse being an [arbitrary signing oracle](iron-vault-specification.md#17-docker-remote-servers-and-appliances).

Both payloads go into storage-formats.md's magic table beside the formats below, with examples the store's tests read
from the document, as for the approval payload.

## The TPM key blob

The TPM returns the new key wrapped by its parent: a public area and a private area that only this TPM, under that
primary, can load. Neither is secret, but both are needed at every signature, so the service keeps them in the state
directory as `approver-<approver ID>.tpm`, beside the software signers' `approver-<approver ID>.age`.

| Size | Content |
|---|---|
| 4 | Magic: ASCII `IVTK` (`49 56 54 4b`) |
| 1 | Format version: `01` |
| 16 | Approver ID, equal to the one in the file name |
| var | Primary name: field (`u64` length, then the bytes) |
| var | Public area: field holding the marshalled `TPM2B_PUBLIC` |
| var | Private area: field holding the marshalled `TPM2B_PRIVATE` |

`MAX_TPM_KEY_BLOB_LEN` is 4096 bytes, checked before anything is read. Rust: `iron_vault_tpm_protocol::TpmKeyBlob`.
The service checks only the framing and the approver ID; the helper parses the TPM structures. The file is written
with the [durable write procedure](iron-vault-specification.md#13-vault-structure-and-durable-writes), mode `0600`.

The `.tpm` name joins the vault's own names: [orphan key files](approval-signers.md#orphan-key-files) include it, the
[initialization state](vault-initialization.md#initialization-state) knows it, and [reset](reset.md)'s store-owned list
gains `approver-<approver ID>.tpm`.

## Helper protocol

One request and one response per connection, each a `u32` big-endian length (at most 8192) followed by the body, in the
record payload conventions. The protocol, with its encode and decode, is in `iron-vault-tpm-protocol`.

**Request** (`IVTQ`, version `01`), one of:

| Operation | Fields |
|---|---|
| `01` create | authorization value (32 bytes) |
| `02` sign | authorization value (32); primary name, public area, private area (from the blob); pinned key (65); message |

**Response** (`IVTR`, version `01`): a status byte, then the fields that status carries.

| Status | Meaning | Fields |
|---|---|---|
| `00` created | The key exists | primary name, public area, private area, public key (65) |
| `01` signed | The message is signed | signature (64, `r ‖ s`) |
| `02` wrong PIN | The TPM refused the authorization value at the key's sign (`TPM_RC_AUTH_FAIL` or `TPM_RC_BAD_AUTH`); one try spent | |
| `03` locked out | The TPM is in lockout, or the [lockout reserve](#lockout-reserve) withheld the try | seconds to wait (`u64`) |
| `04` not this TPM | The primary's name differs from the blob's | |
| `05` key mismatch | The loaded key's attributes or point are not the pinned key's | |
| `06` dictionary-attack settings too weak | The interval is below the floor, or the maximum leaves no share ([Lockout reserve](#lockout-reserve)) | |
| `07` refused message | The message is none of the [three](#what-the-helper-signs) | |
| `08` TPM error | Any other failure, including an authorization failure from any command but the key's sign | TPM response code (`u32`); 0 when the failure has none (a TSS or TCTI error) |
| `09` malformed | The request does not decode | |

A refusal that needs no authorization (`04` to `07`, `09`) comes before any authorized command, so it spends no try.

**Create** checks the dictionary-attack settings, creates the primary and the key in a salted session, flushes both,
and returns the blob's parts with the public key. **Sign** checks the message and the settings, creates the primary,
compares its name, loads the key, reads its public area back, applies the reserve, signs the SHA-256 digest with a null
validation ticket in a salted session, and flushes everything, on failure as well as success.

## Lockout reserve

The TPM has one dictionary-attack counter for every DA-protected object on the machine, including a LUKS slot opened
with a PIN through the TPM. A process that spends it to lockout denies all of them. Before any authorized command, the
helper reads `TPM2_PT_LOCKOUT_COUNTER`, `TPM2_PT_MAX_AUTH_FAIL`, `TPM2_PT_LOCKOUT_INTERVAL` and `TPMA_PERMANENT.inLockout`. Its
share of the counter is `share = min(⌊max / 2⌋, 16)`: the reserve, `⌈max / 2⌉`, is never its to spend, and it never
spends more than 16 at a time however large the maximum. It then:

- answers `06` when the TPM's settings would not limit guessing well enough, which §12 requires of it: an interval
  below **600 seconds** (0 turns protection off), or a share of 0, which a maximum of 0 or 1 gives. A TPM approver on
  such a machine is unavailable until the administrator raises the settings;
- answers `03` when the TPM is in lockout;
- answers `03` when `counter ≥ share`, that is, while trying would take the counter past Iron Vault's share. The
  seconds to wait are `(counter − share + 1) × interval`, the time the TPM takes to forget enough failures.

So Iron Vault never brings the TPM into lockout by itself: the reserve is at least half the tries, and the TPM recovers
the share at one try per interval. **The reserve rests on serialisation.** The check and the try are two TPM commands,
so two instances running at once could each read a counter below the share and both spend a try; `MaxConnections=1`
([The helper process](#the-helper-process)) is what makes the read and the try one step.

**The interval floor bounds guessing.** A compromised service can spend the share at once and then about one try per
interval: at the 600-second floor, 16 guesses and then at most 144 a day. Against a PIN of 6 decimal digits, the weakest
the [PIN rules](#the-approval-pin) allow, finding it takes about 9 years on average. The floor and the PIN minimum are
one decision, [open question 1](#open-questions). Root, or any member of the `tss` group, can lower the interval through
the empty lockout authorization; the helper reads the settings at every request, so a lowered interval makes the
approver unavailable rather than guessable.

The reserve is not an attempt count of Iron Vault's own: it reads the device's counter, and what it withholds the
device restores. [migration-authorization.md](migration-authorization.md#source-owner-method)'s "The service adds no
limit of its own for a device" gains that qualification.

The helper never changes the dictionary-attack parameters, never uses the lockout hierarchy, and never clears the TPM.

## Enrollment

`approver add --kind tpm "<label>"` follows [approval-signers.md](approval-signers.md#approver-add) step by step.
Steps 1 to 5 are unchanged; step 1's "this install offers the kind" is the [offered](#the-helper-process) rule.

**Step 6, for `tpm`:** two secret prompts, `New TPM approval PIN for "<label>"` and `Repeat the new TPM approval PIN`,
checked by the [PIN rules](#the-approval-pin). A `lock` at either prompt cancels the command, as for `software`.

**The approver change that enrolls, for `tpm`:**

1. Generate a new approver ID, derive the authorization value, and send the helper a create request.
2. Write the [key blob](#the-tpm-key-blob) with a durable replace as `approver-<approver ID>.tpm`. The name is new, so
   nothing is overwritten.
3. Read the file back and send the helper a sign request for a fresh presence payload, then verify the signature
   against the key the create returned. A pinned TPM approver therefore always has a blob that signs under its PIN.
4. Enroll the pinned approver in `approval.age` with one durable replace. **This is the commit point.** The
   authorization value is dropped.

A failure before the commit point leaves the approval state as it was and at most an orphan `.tpm` file, which the
next `approver add` or `approver remove` removes at its step 3. The TPM holds nothing to clean up. A helper refusal at
step 1 or 3 answers `approver-kind-unavailable` (44), whose meaning widens to "this install cannot make that kind of
signer now", with a message naming the helper's status; `tpm-locked-out` comes back as itself.

**Remove** is unchanged, with the `.tpm` file in place of the `.age` file; `approver.removed` reports `key_file` as
it does now.

The [summary](approval-signers.md#summaries) for a `tpm` enrollment adds two lines: that the key works only on this
machine's TPM and will not move with a migration bundle ([Migration bundles](#migration-bundles)), and that a forgotten
PIN is recovered only through another approver ([Forgotten approval PIN](#forgotten-approval-pin-and-a-cleared-tpm)).

## Prompt and proof

The [prompt text](approval-signers.md#prompt-text) for `tpm` is `TPM approval PIN for "<label>"`, secret, switchable
when more than one approver can be asked. An answer that is not UTF-8, or has fewer than the 6 Unicode scalar values
[enrollment](#the-approval-pin) requires (empty included), is a wrong PIN and never reaches the TPM: it cannot be the
enrolled PIN, so asking would only spend a lockout try. Its refusal event has no `tpm_status`, since the TPM never saw it.

**Owner presence** ([credential-commands.md](credential-commands.md#owner-presence)): for a `tpm` approver, the service
derives the authorization value from the answer, asks the helper to sign a fresh presence payload, verifies the
signature against the pinned key, and drops the value. Presence still reserves nothing and writes nothing to
`approval.age`; it spends no TPM try when the PIN is right.

**`config approve`** with a `tpm` approver makes two helper calls inside the transaction
([config-approval.md](config-approval.md#choosing-the-signer)):

- **step 2** signs a presence payload, as owner presence does. A wrong PIN ends the approval with `approval-denied`
  before any reservation, as a wrong approval passphrase does;
- **step 3** signs the approval payload under the reserved version, with the authorization value held since step 2.
  The PIN was just proven, so this spends no try. A failure here is a step 3 failure: the version is consumed and the
  answer is `approval-failed`.

Both helper calls run on the blocking pool, never on the service's runtime thread, so a slow or hung helper delays only
the approval, not proxying, other admin connections or timers.

Signing at step 2 instead would need the version before the owner is authenticated, which §12's order forbids.

**Approver order** ([approval-signers.md](approval-signers.md#approver-order)) leaves out a `tpm` approver this install
cannot ask: one with no `.tpm` file, or any while the helper socket is missing. A vault moved to another machine, or a
service whose helper is not installed, therefore starts at an approver that can answer, which a script that cannot
switch needs. When no pinned approver can be asked, the command answers `approval-unavailable`.

**A wrong PIN** ends the exchange, as a wrong passphrase does, and the service never moves on to another approver. The
CLI shows `approval-denied`'s message, which for a `tpm` approver adds that each wrong PIN counts against the TPM's
lockout.

**Lockout.** One new error code, `51` (the migration bundle has 45 to 48, reset 49 and 50, `forget-machine` 52).

| Code | Name | Meaning |
|---|---|---|
| `51` | `tpm-locked-out` | `config approve`, `replace`, `rm`, `recipient remove`, `approver add`, `approver remove`, `export`, `recipient add`: the TPM is in dictionary-attack lockout, or the [lockout reserve](#lockout-reserve) withheld the try; the message gives the whole seconds to wait; nothing was reserved, signed or changed |

The service asks the helper only after the owner answers, so the refusal comes after the prompt: the TPM's counter is
not the service's to read. Every other helper failure is `approval-unavailable` in an approval and presence, and
`migration-unavailable` in a migration, with a message naming the status (`not this TPM`, `dictionary-attack
settings too weak`, `TPM error 0x…`) and never owner input.

**Audit.** The events that end a prompt already name the approver. A `tpm` approver's denial or unavailability adds a
`tpm_status` field with the helper's status name, for an answer the helper was asked about, so `tpm-locked-out` and
`not-this-tpm` can be told apart in the log.
The events are `config.approval-refused` and `vault.presence-refused`; their `refusal` is `wrong_pin` for a wrong PIN and
`tpm_refused` for a lockout or any other helper status, and `tpm_status` is one of `wrong_pin`, `locked_out`,
`not_this_tpm`, `key_mismatch`, `weak_da_settings`, `refused_message`, `tpm_error`, `malformed`, `unreachable` (the socket,
or an answer the service cannot read) and `bad_signature` (the helper's signature does not verify against the pinned key).
A step 3 failure is `config.approval-failed` as for any signer.

## Migration

A `tpm` approver is a [source-owner method](migration-authorization.md#source-owner-method), labelled `tpm_pin`. Its
`prove` derives the authorization value, asks the helper to sign the challenge's migration proof payload, and verifies
the signature against the pinned key. It refuses with `wrong_pin` (`migration-denied`), `tpm_locked_out`
(`tpm-locked-out`) and `unavailable` (`migration-unavailable`).

**Which method is asked.** Step 6 of the [admin exchange](migration-authorization.md#admin-exchange) becomes a
switchable prompt over every method this install can ask: the vault passphrase first, while `operational` is enrolled
and the [attempt limit](migration-authorization.md#passphrase-attempt-limit) is not in a cooldown, then each `tpm`
approver in approver order. The switch frame moves between them as at the approver prompt, under one prompt deadline. A
method that cannot be asked is left out; when none is left the exchange ends with `migration-rate-limited` if the
vault passphrase was left out for a cooldown, and `migration-unavailable` otherwise. The summary's `authorize with:`
line names the method asked first. The vault passphrase comes first because it is the one every vault has, and because
a wrong vault passphrase costs the owner a cooldown of their own, while a wrong PIN costs a try shared with the whole
machine ([open question 2](#open-questions)).

The approval passphrase is still not a migration method; only a `tpm` approver's PIN is, because the TPM's lockout is
what makes a short PIN safe to accept as source-owner proof.

**`migration.authorized` and `migration.authorization-refused`** record the method label, and for `tpm_pin` also the
approver ID (`approver_id`).

### The independence rule stays

[recipients.md](recipients.md#independence-rule) part 2 keeps `operational` enrolled while the vault passphrase is the
only source-owner method, and the owner decided (2026-11-09, recipients open question 11) that a vault with another
method may drop it. **The owner decided on 2026-11-11 not to relax part 2 in v0**
([open question 3](#open-questions)), for these reasons:

- a TPM approval key dies with the machine. A vault whose only source-owner method is that key cannot be migrated off a
  machine whose TPM failed, was cleared, or moved to another board, which is exactly when migration is wanted;
- v0 has no command that authorizes migration with the recovery key, so the recovery key would open the vault on this
  machine but not move it;
- a Secure Boot or firmware change does not touch the approval key, but a TPM clear during a firmware reset does.

The relaxation, when it comes, is: part 2 holds while no `tpm` approver is pinned, and `approver remove` refuses to
remove the last `tpm` approver of a vault without `operational`, with `approver-set-invalid`
([approval-signers.md](approval-signers.md#later-signer-kinds)). Specified here so a later ticket can make it; no v0
ticket implements it.

## Migration bundles

A TPM approval key cannot leave its TPM (§16: "Neither migration path moves a non-exportable TPM private key").

- **Export** carries `approval.age` unchanged, with every pinned approver, and every software key file. It carries no
  `.tpm` file: the blob would load on no other TPM.
- **Export refuses** before any prompt, with `approver-set-invalid` (42, which widens to `export`), when no `software`
  approver is pinned. The destination could otherwise route nothing, since it must approve a config before routing
  ([§16](iron-vault-specification.md#16-administration-recovery-and-migration)) and no pinned approver could sign
  there. The message says to enroll a software approver first.
- **Import** expects no key file for a `tpm` approver. Its summary lists each as `bound to the source machine`, and
  the [approver order](#prompt-and-proof) leaves them out because no `.tpm` file exists. After the first approval with a
  software approver, the owner removes them with `approver remove` and may enroll a new `tpm` approver on the
  destination.

This settles [migration-bundle.md](migration-bundle.md)'s open question 3 for the TPM.

## Forgotten approval PIN and a cleared TPM

The TPM keeps no copy of the PIN and no way round it, by design. A forgotten PIN, a TPM cleared by a firmware reset,
or a replaced board all leave the approver unusable (`approval-denied`, or `not this TPM`). The way out is another
approver:

1. `approver add` a new approver, authorized by any other pinned approver;
2. `config approve` with the new one, if the lost approver signed the active approval;
3. `approver remove` the lost one.

Both counters carry over ([§12](iron-vault-specification.md#12-configuration-approval-and-reload)). A vault whose only
approver is a lost TPM approver has no way to authorize anything, and its owner uses
[reset](reset.md), which discards the vault. The enrollment summary says so, and `approver add --kind tpm` recommends
keeping a `software` approver. Like every recipient change, none of this touches `identity.age`: the recovery key and
the unlock method still open the vault.

A cleared TPM also invalidates every other key under its owner hierarchy, so the helper's `not this TPM` is the
expected result after a clear, not a fault.

## Power loss and dictionary-attack state

§15: "The implementation must verify how unclean power loss affects its chosen TPM session and dictionary-attack state;
it must not assume that repeated power loss cannot cause lockout."

Unlike [TPM unlock](tpm-unlock.md#power-loss-and-dictionary-attack-state), the approval key is DA-protected by design.
The TPM 2.0 library specification (Part 1, dictionary-attack protection) says that after an unclean shutdown the TPM
counts one failed try if a DA-protected authorization was used since the last orderly shutdown. So each boot in which
an approval, a presence or a migration used the key, ended by power loss, costs one try.

That cost is bounded: approvals are rare, the TPM forgets one failure per interval, and the
[lockout reserve](#lockout-reserve) keeps half the tries back, so repeated power loss makes the TPM approver wait, not
the whole machine's TPM users. A wrong PIN costs the same. The release check measures the count on a real firmware TPM
rather than relying on the specification.

## Threats

| Threat | Control | What remains |
|---|---|---|
| A compromised service guesses the PIN | Each guess is a TPM authorization under DA; one helper instance at a time; the share stops the helper at no more than 16 failures; the interval floor | 16 guesses, then about 144 a day: about 9 years on average for a 6-digit PIN |
| A compromised service unseals other TPM objects or locks the TPM out | The service has no TPM device; the helper signs only three payloads, and keeps the reserve | None from the service |
| A compromised service signs a config with the owner's PIN | None beyond the software signer's: the owner types the PIN into a CLI talking to the service | The same as a typed approval passphrase: the service the owner talks to decides what is signed, and a service that kept the PIN can sign any approval payload later, until the owner removes that approver |
| A recorded TPM bus yields the PIN | Salted session; the authorization value is encrypted at create and never sent in clear | — |
| A planted or swapped blob signs for a pinned approver | The helper checks the loaded key's attributes and point against the pinned key before authorization | — |
| A blob is copied off the machine | `fixedTPM`: it loads only on this TPM | A copy is useful to someone at this machine who knows the PIN, as the original is |
| Another account, such as a log collector in the `iron-vault` group, reaches the helper | `SO_PEERCRED` check; socket owned by the service account, mode `0600` | Root, who is trusted |
| Root resets the lockout counter and guesses | None: the lockout hierarchy's authorization is empty on Linux | Root is outside the threat model ([§2](iron-vault-specification.md#2-security-promise-and-limits)) |
| Power loss locks the TPM out | The reserve; one try per affected boot | Measured by the release check |
| Root or a `tss` member weakens the DA settings so guesses are cheap | The helper reads them at every request and refuses below the floor (`06`) | The approver is unavailable until the settings are raised |

## Testing

Unit tests need no TPM: the protocol, the blob, the payloads, the reserve arithmetic, low-S normalization, and the
service's handling of every helper status through a fake helper on a socket pair.

Integration tests run the real helper against `swtpm`, the software TPM:

```sh
swtpm socket --tpm2 --tpmstate dir="$state" --server type=tcp,port=2321 --ctrl type=tcp,port=2322 \
    --flags not-need-init,startup-clear
```

The tests are `#[ignore]` with a reason, run by `cargo test -- --ignored` where `IRON_VAULT_SWTPM` names the TCTI
(`swtpm:host=127.0.0.1,port=2321`); test support spawns the helper per connection with `--tcti`, as the socket unit
would. They cover create and sign, a wrong PIN, lockout and the reserve (setting `TPM2_DictionaryAttackParameters` on
the emulator only), `not this TPM` after `tpm2_clear` on the emulator, a swapped blob, DA turned off, and each
refused message. CI installs `libtss2-dev`, `pkg-config` and `swtpm` and runs them.

**Building without `libtss2-dev`.** `tss-esapi` is an optional dependency of `iron-vault-tpm-signer` behind its `tpm`
feature, and the binary has `required-features = ["tpm"]`. A plain `cargo build --workspace` or `cargo test
--workspace` therefore builds and tests everything else, including the protocol crate, on a machine without the TPM
library. CI, `cargo deb` and the `swtpm` tests enable the feature. To build it locally the machine needs packages no
agent can install: `sudo apt install libtss2-dev pkg-config swtpm swtpm-tools tpm2-tools`.

## Release checks

`scripts/release/tpm-signer-check.sh` runs on a disposable machine with the package installed, behind the same
`--i-know-this-is-a-disposable-vm` opt-in as [TPM unlock](tpm-unlock.md#release-checks)'s, printing one PASS, FAIL or
SKIP line per item. With that script's run it is the evidence for the implementation spec's "TPM authorization and
power failure" gate, and for §14 to list the TPM approval signer as offered.

1. `iron-vault.service` still has `PrivateDevices=yes` and no `DeviceAllow=`; its `/dev` has no `tpm*` node;
   `/usr/bin/iron-vault` does not link `libtss2`.
2. The helper's instance runs as `iron-vault-tpm` with `tss` only as a supplementary group of the process; the
   socket is `iron-vault:root 0600` with `MaxConnections=1`; an account in the `iron-vault` group cannot connect, and
   a second connection while one is open is closed at once.
3. `approver add --kind tpm` enrolls; `approver list` shows kind `tpm`; `approver-<id>.tpm` exists, `0600`.
4. `config approve` with the TPM approver succeeds, and `config.toml.sig` is a 191-byte envelope with algorithm `02`
   that verifies after a restart.
5. `replace`, `rm` and `recipient remove` accept the PIN as owner presence.
6. A wrong PIN is `approval-denied`, and `TPM2_PT_LOCKOUT_COUNTER` rose by exactly one.
7. **The reserve** (emulated TPM only): wrong PINs until `tpm-locked-out`; the counter stops at the share, and a
   PIN-protected throwaway key outside Iron Vault still authorizes. Many wrong-PIN connections opened at once leave the
   counter at the share too. With the interval set below 600 seconds, or the maximum set to 1, the helper answers
   `06` and the counter does not move.
8. `export` and `recipient add` accept the PIN by switching to the TPM approver; the audit log names `tpm_pin` and the
   approver.
9. **Protected session:** a TCTI trace (`TSS2_LOG=tcti+trace`) of an enrollment and an approval contains neither the
   PIN nor the authorization value.
10. A copy of the blob on a second machine, or the same machine after `tpm2_clear` (emulated only), gives `not this
    TPM`, and the approver order starts at the software approver.
11. Removing the TPM approver deletes its `.tpm` file.

Two items need the hypervisor or the machine, and are recorded with its output:

- **Power loss:** on a firmware TPM, read `TPM2_PT_LOCKOUT_COUNTER`; then, three times, approve with the TPM approver
  and cut power. The check records the counter after each boot. It passes when the counter rose by at most one per
  cycle and an approval still works; the record is the evidence §15 asks for.
- **A firmware TPM's DA settings:** `tpm2_getcap properties-variable` on the release hardware, recorded, so the
  manual can say what the reserve allows there.

The gate is met by a run on Ubuntu 24.04 in a VM with `swtpm`, and a run on Ubuntu 24.04 hardware with a firmware TPM
for the non-destructive items and the power-loss item.

## Interactions

- **TPM unlock** ([tpm-unlock.md](tpm-unlock.md)). Independent: no shared object, handle, unit or account. The handoff
  unit's unseal is not DA-protected, so the approver's tries never block unlock, and unlock never spends them.
  [§14](iron-vault-specification.md#14-recipients-startup-and-memory) recommends a different kind of method for each;
  the `approver add --kind tpm` summary repeats that when TPM unlock is enrolled.
- **Reset** ([reset.md](reset.md)). `approver-<approver ID>.tpm` joins the store-owned list. The TPM holds nothing of
  Iron Vault's, so reset and `forget-machine` have nothing to remove from it.
- **Compose host signing helper** (K-255). K-255 can run this helper unchanged on the host, with the socket directory
  bind-mounted into the service container, and a drop-in setting `SocketUser=` and `--peer-user` to the container's
  service uid as the host sees it.
  The PIN then reaches it through the service, as here. K-255's card says the PIN is typed on the host terminal and the
  helper refuses non-increasing versions; that is a different design, with a host-rendered summary and a stateful
  helper ([open question 4](#open-questions)).
- **Docker Compose** ([docker-compose.md](docker-compose.md#approval-signing)). Its "waits for EP-33's signer" sentence
  then points here and to K-255.
- **Owner run on hardware** (K-335). It runs [the release check](#release-checks) on the owner's machine.

## Implementation tickets

In order, each a separate PR:

1. **K-329, store.** Accept signer kind `2` with algorithm `02`; ECDSA P-256 verification with the 65-byte SEC1 key,
   64-byte `r ‖ s` signatures and the low-S rule; the 191-byte size note; `PresencePayload` and
   `MigrationProofPayload` with their storage-formats.md sections and magics (`IVPP`, `IVMA`), plus `IVTK`, `IVTQ` and
   `IVTR` in the magic table; the `.tpm` name in the initialization state's known names and reset's list; the
   glossary's *Signer kind* row, and its *Approval signer* row, which says a signer signs only an approval payload.
2. **K-330, the helper.** The `iron-vault-tpm-protocol` crate (wire protocol, key blob, `TpmApprovalPin`) and the
   `iron-vault-tpm-signer` binary behind its `tpm` feature: the parent, the key, salted sessions, the three messages,
   the share and reserve, the 600-second interval floor, every status; `swtpm` tests and CI. Dependency: `tss-esapi`
   7.x (no third copy of `rand`, per [tpm-unlock.md](tpm-unlock.md)). Packaging (units, account, `build-deb.sh` checks) moves to item 6, so this ticket
   stays under the size limit.
3. **K-331, enrollment.** `approver add --kind tpm`: the offered rule, step 6's prompts and PIN rules, the
   authorization value, the enroll change with read-back, the blob file and orphan handling (and the glossary's
   *Orphan key file* row, which names only `.age`), the summary lines.
4. **K-332, prompt and proof.** The prompt text (and approval-signers.md's prompt table), owner presence and the
   two-call approval, the approver order rule,
   `tpm-locked-out` and its admin-protocol entry, the `tpm_status` audit field.
5. **K-333, migration.** The `tpm_pin` method, the switchable step 6 across methods, the refusals and audit fields,
   and in migration-authorization.md the reserve's sentence, plus "Binding digest" and the `tpm_pin` row of
   "Source-owner method", which say the TPM signs the bare binding digest rather than the migration proof payload. **Not** the part 2 relaxation or the `approver remove`
   refusal ([open question 3](#open-questions)).
6. **K-334, packaging, release check and manual.** The socket unit (`MaxConnections=1`, `iron-vault:root 0600`) and
   the service unit, the `iron-vault-tpm` account, the
   `libexec` install, linux-package.md's tables and lifecycle (remove and purge stop the socket; the account stays, as
   `iron-vault` does), `build-deb.sh`'s `ldd` and unit checks, `tpm-signer-check.sh`, and the manual: a cookbook
   recipe, the CLI reference, and the install guide's PIN and recovery advice.
7. **New: export with TPM approvers.** The export refusal and the import summary of
   [Migration bundles](#migration-bundles). Depends on K-331 and the bundle's export and import tickets.

K-335 (EP-46) then runs the release check on real hardware, and K-255 (EP-45) builds on item 2.

## Open questions

All six were decided by the owner on 2026-11-11, who accepted the default of each.

1. **PIN length and the interval floor**, one decision ([Lockout reserve](#lockout-reserve)). *Decided (owner,
   2026-11-11):* at least 6 Unicode scalar values, and a lockout interval of at least 600 seconds: about 9 years on
   average for a 6-digit PIN against a compromised service. Firmware TPMs commonly ship with intervals far above the
   floor, so it refuses only weakened settings.
2. **Which migration method is asked first.** *Decided (owner, 2026-11-11):* the vault passphrase, then TPM approvers
   ([Migration](#migration)).
3. **Dropping `operational` once a TPM approver exists.** *Decided (owner, 2026-11-11):* not in v0, for the reasons in
   [The independence rule stays](#the-independence-rule-stays). This replaces the owner's decision of 2026-11-09
   ([recipients.md](recipients.md#open-questions) open question 11), and drops the `approver remove` refusal K-328's card
   asked for. The rule for when dropping is allowed is specified there for a later ticket; no v0 ticket, K-333 included, implements it.
4. **K-255's host helper.** *Decided (owner, 2026-11-11):* K-255 reuses this helper, PIN through the service, and the
   helper stays stateless. A stateless helper that receives the PIN through the container is the weaker reading of
   [§17](iron-vault-specification.md#17-docker-remote-servers-and-appliances)'s "the container may request only the
   service's validated approval transaction": the helper checks the message's form, not that the owner saw what it
   approves. A host-rendered summary with the PIN typed on the host is a stronger design for a container the host does
   not trust, and K-255 decides whether Compose needs it.
5. **The `tss` group.** *Decided (owner, 2026-11-11):* the package relies on Ubuntu's `tpm-udev` rule (`/dev/tpmrm0`
   `tss:tss 0660`) and does not create the group. On a machine without it the kind is offered, because the socket
   exists, but the helper's instance cannot start, and enrollment answers `approver-kind-unavailable`
   ([Offered](#the-helper-process)). Declaring `Recommends: tpm-udev` is K-334's call.
6. **§4's Linux row.** It names the unlock adapters and "an in-service adapter with a TPM PIN in a later phase", and no
   adapter for approval signing. *Decided (owner, 2026-11-11):* no spec edit in this ticket. That later unlock PIN, if it
   comes, should go through a helper too, since §14 keeps the service account away from the TPM.
