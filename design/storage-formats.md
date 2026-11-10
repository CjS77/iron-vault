# Iron Vault storage formats

Byte layouts of the data Iron Vault writes to disk. Each format carries a version so a later release can read what an
earlier one wrote and refuse what it does not understand ([implementation spec §3](implementation-specification.md#3-implementation-gates-and-unresolved-details)). Terms follow the
[glossary](glossary.md).

## Magic numbers

Every format below starts with four ASCII bytes naming it: `IV` for Iron Vault, then two letters for the format. A
reader refuses a file whose magic is not the one it expects. In a signed or MAC'd payload the magic is also domain
separation: those bytes can be read only as the format they name.

| Magic  | Format                                                          |
|--------|-----------------------------------------------------------------|
| `IVCR` | Credential record (record payload v1)                           |
| `IVMF` | Manifest file                                                   |
| `IVMP` | Manifest payload                                                |
| `IVAP` | Approval payload: the bytes a config approval signs             |
| `IVAS` | Approval signature: the envelope in `config.toml.sig`           |
| `IVAF` | Approval state file                                             |
| `IVAM` | Approval metadata: the approval state payload                   |
| `IVRF` | Recipient inventory file                                        |
| `IVRP` | Recipient inventory payload                                     |

## Record payload v1

The plaintext of one [credential record](iron-vault-specification.md#6-credential-records-and-configuration): the
bytes a credential file encrypts. Encryption, file names and the manifest are separate layers; this section covers
only what is inside the encryption. Rust: `iron_vault_store::{encode, decode}`.

### Why binary

The payload is a small hand-written, length-prefixed binary layout rather than TOML or a serde format. Decoding reads
each secret field as a borrowed slice of the decrypted buffer, checks it is UTF-8 in place, and copies it once, straight
into the `SecretString` that owns it from then on. A TOML or serde decoder would first build its own `String` for each
value, a heap copy of the secret that nothing zeroizes. Specification [§14](iron-vault-specification.md#14-recipients-startup-and-memory) asks for as few copies of a secret as
possible, each cleared on release. The encoder sizes its `Zeroizing<Vec<u8>>` exactly before writing, so the buffer
never reallocates and leaves no stale copy behind either.

### Conventions

- Integers are unsigned and big-endian.
- A **field** is a `u64` byte length followed by that many bytes. Text fields hold UTF-8.
- A length or count larger than the bytes remaining is an error, checked before anything is read.
- The payload ends exactly after the source tag; any trailing byte is an error.

### Layout

| Offset | Size | Content                                                                                                  |
|--------|------|----------------------------------------------------------------------------------------------------------|
| 0      | 4    | Magic: ASCII `IVCR` (`49 56 43 52`)                                                                      |
| 4      | 1    | Version: `01`                                                                                            |
| 5      | 16   | Record ID: the 16 bytes of a version 4 UUID, in the order its hyphenated text shows them                 |
| 21     | var  | Name: field holding the credential name                                                                  |
| …      | 1    | Material tag: `01` static, `02` basic                                                                    |
| …      | var  | Material fields, by tag (below)                                                                          |
| …      | 8    | Origin count: `u64`, at least 1                                                                          |
| …      | var  | Origins, each one host field then a 2-byte port, in strictly ascending order (below)                     |
| …      | 1    | Source tag: `01` direct entry                                                                            |

Material fields:

| Tag  | Kind     | Fields, in order                                    |
|------|----------|-----------------------------------------------------|
| `01` | `static` | key                                                 |
| `02` | `basic`  | username, then password (which may be empty)        |

The kind is the material tag; the record stores no separate kind, so a kind and its material cannot disagree.

Each origin is a field holding the host in its canonical form, followed by the port as a `u16`. The scheme is not
stored: specification [§6](iron-vault-specification.md#6-credential-records-and-configuration) makes HTTPS mandatory, so every origin is an HTTPS origin.

### Example

A static record named `fx_key` with key `k`, permitting `api.example` on port 443:

```text
49 56 43 52                                        magic "IVCR"
01                                                 version 1
7c 9e 66 79 74 25 40 de 94 4b e0 7f c1 f9 0a e7    record ID 7c9e6679-7425-40de-944b-e07fc1f90ae7
00 00 00 00 00 00 00 06  66 78 5f 6b 65 79         name "fx_key"
01                                                 material tag: static
00 00 00 00 00 00 00 01  6b                        key "k"
00 00 00 00 00 00 00 01                            one origin
00 00 00 00 00 00 00 0b  61 70 69 2e 65 78 61 6d   host "api.example"
70 6c 65
01 bb                                              port 443
01                                                 source: direct entry
```

### One encoding per record

The same record always encodes to the same bytes. Origins are written in ascending order of host bytes, then port,
whatever order they were added in; every other field has exactly one form. Decoding enforces the reverse, so a payload
is accepted only if it is the encoding of the record it decodes to:

- the record ID is a version 4, RFC 9562 variant UUID;
- the name passes the credential name rule;
- each host parses as a host and is already in canonical form (lowercase, punycode, canonical IP literal);
- each port is from 1 to 65535;
- the origin count is at least 1, and the origins are strictly ascending, so none repeats;
- the material passes its kind's rules: a static key is non-empty with no control character; a Basic username is
  non-empty with no `:`, and neither username nor password contains a control character ([RFC 7617 §2](https://www.rfc-editor.org/rfc/rfc7617#section-2)).

Decoding rejects a wrong magic, an unknown version, an unknown material or source tag, truncation, trailing bytes and
any of the rule failures above. Its errors name the rule or field that failed, never a secret byte.

### Size limit

A record file, `record-<record id>.age`, is at most `MAX_RECORD_FILE_LEN` (64 KiB) on disk, and its payload at most
64 KiB. A v0 record is a name of at most 64 bytes, a few origins of at most 263 bytes each and a key or username and
password, so it is a few KiB even with dozens of origins; the limit leaves room for later kinds' keys and certificates.
A longer file is a damaged record and is never read in full.

### Versions

Payload version 1 holds no provider settings or operational state. Specification [§6](iron-vault-specification.md#6-credential-records-and-configuration) lists both, and both arrive
with OAuth in product phase v1 ([future spec §1](future-specifications.md#1-v1-oauth-login-and-refresh)). Adding them means a new version byte with its own layout, and a reader for every
version still on disk. A reader never guesses at a version it does not know.

## MAC'd file frame

A [MAC'd file](glossary.md) is a control file the service alone may write. `age` does not authenticate the sender, so
anyone holding the vault public key can write a file that decrypts cleanly. A MAC'd file is therefore sealed to the
vault public key and then authenticated with a MAC keyed from the private vault identity, which only the service holds
while the vault is unlocked (specification [§13](iron-vault-specification.md#13-vault-structure-and-durable-writes)). The manifest file, the approval state file and the recipient inventory file are MAC'd files; each
fixes its own magic, version, key persona, domain tag and size limit. Rust: `MacFileKind`, crate-private.

### Layout

| Offset   | Size | Content                                                                                    |
|----------|------|--------------------------------------------------------------------------------------------|
| 0        | 4    | Magic: four ASCII bytes naming the file type                                               |
| 4        | 1    | Version: `01`                                                                              |
| 5        | 16   | Vault ID: the 16 bytes of a version 4 UUID                                                 |
| 21       | var  | The file's payload, sealed to the vault public key as binary `age`                         |
| end − 32 | 32   | MAC                                                                                        |

The vault ID is in clear so that the MAC, which covers it, can be checked before anything is decrypted. The payload
repeats the vault ID, and a payload whose ID differs from the header's is refused.

### MAC

```text
file key = BLAKE2b-512(personalization = persona, message = vault identity secret text)
MAC      = BLAKE2b-256(key = file key, message = domain tag || bytes 0 .. end − 32)
```

- The **vault identity secret text** is exactly the 74 ASCII bytes of the uppercase Bech32 string `age`'s
  `Identity::to_string` gives, `AGE-SECRET-KEY-1…`, with no trailing newline; the `age` specification fixes this
  encoding. It carries the full 256-bit X25519 key. It is hashed as the message rather than used as the BLAKE2b key
  because it is 74 bytes long and a BLAKE2b key is at most 64.
- The **personalization** (at most 16 bytes, zero-padded to BLAKE2b's 16) is the file type's own, so each file's key is
  independent of every other key derived from the same identity, and a MAC from one file type never verifies another.
- The 64-byte file key is a full-length BLAKE2b key. It lives only in a buffer that is cleared on drop.
- The MAC message starts with the file type's domain tag, which ends in a zero byte, then every file byte
  before the MAC: magic, version, vault ID and ciphertext.

A party holding only the vault public key can seal any payload, but cannot compute the MAC. A file from another vault
fails the MAC too, because its key comes from another identity.

### Reading order

Opening a MAC'd file does the cheap, key-free checks first and decrypts last:

1. A file longer than the file type's size limit is refused before anything else is read.
2. A file shorter than header plus MAC is truncated. A wrong magic or unknown version is refused; the version is read
   before the MAC because it decides how the MAC is computed.
3. The MAC is compared in constant time. A mismatch is reported as damaged shared state: the file was altered, or was
   not written by this vault, and specification [§13](iron-vault-specification.md#13-vault-structure-and-durable-writes) says the vault may need recovery.
4. Only then is the vault ID parsed and the ciphertext opened, with the size limit also bounding the plaintext, and
   decoded. A payload naming a different vault from the header is refused.

### State generation

The manifest and the approval state, the MAC'd files that carry one, put two `u64` counters right after the vault ID in
their payloads (the recipient inventory is not part of the state generation and carries its envelope digest there
instead):

- the **state generation**: the vault-wide count of MAC'd file writes at which this file was written;
- the **peer generation**: the state generation the other MAC'd file had at that moment.

Every write of the manifest or the approval state takes its state generation from one rule, applied to both files as
they are on disk:

```text
state generation of the new file = max(manifest's state generation, approval state's state generation) + 1
```

Each write reads the other file from disk before it touches any file, under the state-directory lock that makes the
service the only writer. A missing approval state counts as none before one has been written; a missing manifest refuses
an approval state write, because the vault is always created first; a file that cannot be read or opened as this vault's
refuses the write as damaged shared state. So a vault's first manifest is at state generation 1, every later write of
either file is exactly one above the latest write of both, and no two files share a state generation: a file's peer
generation is always below its own state generation, and decoding refuses one that is not. The addition is checked: once
either file is at `u64::MAX`, the next write of either fails before any file is touched, and the counter never wraps.

A state generation is never 0, so a peer generation of 0 means "no peer". The vault is created before its approval
state, so its first manifest, and any manifest written before the approval state exists, records 0. The approval
state always has a manifest to name, so its peer generation is never 0.

Creating the approval state is followed at once by a manifest-only write with unchanged entries that records it as the
peer (`Vault::create_approval_state`, then `Vault::record_approval_state`). Approvals never write the manifest, so
without that write a vault whose credentials do not change would keep peer generation 0 for good, and a deleted
`approval.age` would go unnoticed. With it, a manifest with peer generation 0 beside a missing `approval.age` means no
approval state was ever created. The one exception is a crash between the two writes: it leaves `approval.age` beside a
manifest with peer generation 0, a pair the table accepts. Opening the vault flags that pair in its open report and logs
it at WARN, and the service finishes the creation with `Vault::record_approval_state`; until it does, deleting
`approval.age` is not detected.

Whichever file was written last names the state generation it expects the other to hold. Only one file changes per
write, so the file with the higher state generation was written last, and its peer generation must be exactly the
other file's state generation:

| Files on disk                        | Accepted when                                                           |
|--------------------------------------|-------------------------------------------------------------------------|
| Manifest only, no `approval.age`     | the manifest's peer generation is 0                                     |
| Both, the manifest's is higher       | the manifest's peer generation is the approval state's state generation |
| Both, the approval state's is higher | the approval state's peer generation is the manifest's state generation |
| Both at the same state generation    | never: no write produces it                                             |

Any other pair is a [partial restore](glossary.md): one file was restored from an older copy, or `approval.age` was
deleted after the manifest recorded it. A crash cannot produce one, because each write is one atomic replace of one
file and both the old and the new file agree with the other. Opening the vault and loading the approval state both
refuse a partial restore as damaged shared state, naming the file that is behind with the state generation expected
and the one found, and every write of either file refuses it before touching any file: writing over it would record
the restored file as the peer and make the pair agree again. Creating the approval state is refused once the manifest
records one, since that would reset its counters. A partial restore is never repaired automatically (specification
[§12](iron-vault-specification.md#12-configuration-approval-and-reload)); the owner recovers the vault with the recovery key or resets it.

The check cannot tell a pair that was once on disk together from the current one. That covers restoring both files
together, the whole-storage rollback of specification [§12](iron-vault-specification.md#12-configuration-approval-and-reload), and restoring one file to a copy that the other file's
latest write already saw. Outside v0, anchoring the state generation in a TPM monotonic counter is what detects those.

## Manifest file v1

The [vault manifest](glossary.md): the service's index of which credential records exist, in the state-directory file
`manifest.age`. Specification [§13](iron-vault-specification.md#13-vault-structure-and-durable-writes) makes the service's own index the authority on which records exist, and [§6](iron-vault-specification.md#6-credential-records-and-configuration) says
only the service may index record files. A manifest sealed only to the vault public key would be as forgeable as the
records it indexes, so it is a [MAC'd file](#macd-file-frame). Rust: `iron_vault_store::{seal_manifest, open_manifest}`.

| Frame parameter | Value                                                                  |
|-----------------|------------------------------------------------------------------------|
| Magic           | ASCII `IVMF` (`49 56 4d 46`)                                           |
| Version         | `01`                                                                   |
| Payload         | The manifest payload v1 (below)                                        |
| Personalization | `iv-manifest-v1` (14 bytes); the derived key is the **manifest key**   |
| Domain tag      | `iron-vault manifest file v1 mac` followed by a zero byte              |
| Size limit      | `MAX_MANIFEST_LEN` (1 MiB)                                             |

Test vectors, checked by the store's tests. The ciphertext is a fixed stand-in, because real `age` output is
randomized; the MAC does not care what the ciphertext bytes are.

```text
identity      AGE-SECRET-KEY-1QYPQXPQ9QCRSSZG2PVXQ6RS0ZQG3YYC5Z5TPWXQERGD3C8G7RUSQGPQYEE
              (the X25519 key bytes 01 02 03 … 20)
manifest key  54b3475d66332fd31a99dd0cf3632ec70381dbae5167db31dd4d13b3fb59a04f
              3a9171433d19abd09ad7e9adaa6f1e45c87291b03a6a76546702074436e7d75e
MAC input     the domain tag, then these bytes before the MAC:
              49564d46013f2b8c1e5d4a4e6f9a7b1c2d3e4f5a6b6e6f74207265616c6c7920616765
              (magic "IVMF", version 01, vault ID 3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b, ciphertext "not really age")
MAC           57773e0c4c341207ffc71eb80ccb19c399bab8042a1d3c9f38603af1c7cc1ab2
```

### Size limit

A manifest holds at most `MAX_MANIFEST_ENTRIES` (4096) entries. An entry is at most 120 bytes: a 16-byte record ID, an
8-byte name length, a name of at most 64 bytes and a 32-byte digest. A full payload is therefore at most
45 + 4096 × 120 = 491,565 bytes. `age` adds a header of a few hundred bytes, one 16-byte payload nonce and a 16-byte
tag per 64 KiB chunk (8 chunks), and the file adds 53 bytes of header and MAC: under 492,500 bytes, less than half of
`MAX_MANIFEST_LEN`. Building a manifest with more entries is refused, so the service can never write one it cannot
read back.

## Manifest payload v1

The plaintext a manifest file seals. It uses the conventions of record payload v1: big-endian unsigned integers, `u64`
length prefixes, lengths checked against the bytes remaining before anything is read, and no trailing bytes.

### Layout

| Offset | Size | Content                                                                    |
|--------|------|----------------------------------------------------------------------------|
| 0      | 4    | Magic: ASCII `IVMP` (`49 56 4d 50`)                                        |
| 4      | 1    | Version: `01`                                                              |
| 5      | 16   | Vault ID: equal to the file header's                                       |
| 21     | 8    | State generation: `u64`, at least 1                                        |
| 29     | 8    | Peer generation: `u64`, the approval state's; 0 if none had been written   |
| 37     | 8    | Entry count: `u64`, at most 4096                                           |
| 45     | var  | Entries, in strictly ascending order of record ID bytes (below)            |

Each entry:

| Size | Content                                                                                 |
|------|-----------------------------------------------------------------------------------------|
| 16   | Record ID: the 16 bytes of a version 4 UUID                                             |
| var  | Name: field holding the credential name                                                 |
| 32   | File digest: BLAKE2b-256 (unkeyed, 32-byte output) of the record file's ciphertext bytes |

The digest covers the record file exactly as it sits on disk, so a record file replaced by a different ciphertext,
even one that decrypts to the same record, no longer matches its entry. Record files are named `record-<record id>.age`.

A new vault's first manifest is at state generation 1 with peer generation 0 and no entries, written before any record
file and before the approval state. Every later manifest takes its state generation from the
[vault-wide rule](#state-generation). Rolling the whole state directory back to an older consistent copy is outside
what the manifest detects ([implementation spec §3](implementation-specification.md#3-implementation-gates-and-unresolved-details)).

### Example

Vault `3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b` with one record `fx_key` whose file digest is 32 bytes of `11` (an
illustrative value). The vault's first manifest was state generation 1 and its approval state was created at 2, so
adding `fx_key` wrote this manifest at state generation 3 with peer generation 2:

```text
49 56 4d 50                                        magic "IVMP"
01                                                 version 1
3f 2b 8c 1e 5d 4a 4e 6f 9a 7b 1c 2d 3e 4f 5a 6b    vault ID 3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b
00 00 00 00 00 00 00 03                            state generation 3
00 00 00 00 00 00 00 02                            peer generation 2
00 00 00 00 00 00 00 01                            one entry
7c 9e 66 79 74 25 40 de 94 4b e0 7f c1 f9 0a e7    record ID 7c9e6679-7425-40de-944b-e07fc1f90ae7
00 00 00 00 00 00 00 06  66 78 5f 6b 65 79         name "fx_key"
11 11 11 11 11 11 11 11  11 11 11 11 11 11 11 11   file digest
11 11 11 11 11 11 11 11  11 11 11 11 11 11 11 11
```

### One encoding per manifest

Entries are written in ascending record ID order, so the same manifest always encodes to the same bytes. Decoding
accepts a payload only if it is that encoding:

- the vault ID and every record ID are version 4, RFC 9562 variant UUIDs;
- the state generation is not 0, and the peer generation, unless 0, is below it;
- record IDs are strictly ascending, so none repeats;
- every name passes the credential name rule, and no name appears in two entries;
- the entry count is at most 4096.

Decoding rejects a wrong magic, an unknown version, truncation, trailing bytes and any of the rule failures above.

## Identity envelope

The [identity envelope](glossary.md), state-directory file `identity.age`, is a plain binary `age` v1 file with no
Iron Vault framing. Its plaintext is the vault identity's secret text: the 74 ASCII bytes of `AGE-SECRET-KEY-1…` that
`age`'s `Identity::to_string` gives, uppercase Bech32 with no trailing newline, the same text the manifest key is
derived from. Rust: `iron_vault_store::{wrap_identity, unwrap_identity}`.

- **Stanzas.** One X25519 stanza per recipient key, plus the one random `*-grease` stanza `age` adds to every file
  without a passphrase. Specification [§14](iron-vault-specification.md#14-recipients-startup-and-memory) forbids an scrypt stanza beside other recipients, so the envelope never
  holds one; passphrase unlock and the recovery key each reach it through an X25519 recipient.
- **Recipients.** Between 2 and `MAX_RECIPIENTS` (64), so a vault always has a second way in.
- **Size limit.** `MAX_IDENTITY_ENVELOPE_LEN` is 16 KiB. An X25519 stanza is 98 bytes, the grease stanza at most about
  220, the version and MAC lines 70, and the payload 106 (16-byte nonce, 74-byte secret text, 16-byte tag): a full set
  of 64 recipients gives under 6,700 bytes.
- **Reading order.** `unwrap_identity` refuses an oversized file first, then any header stanza other than X25519 or
  grease, so a planted passphrase file never starts scrypt. Only then does it decrypt, with the recipient identity
  alone, and parse the plaintext as an X25519 identity.
- **Trust.** `age` does not authenticate the sender, so anyone who knows a recipient key can write an envelope. An
  unwrapped identity is trusted only once the vault manifest's MAC, keyed from it, verifies.

## Passphrase envelope

The [passphrase envelope](glossary.md), state-directory file `operational.age`, is a plain binary `age` v1 file with no
Iron Vault framing. Its plaintext is the [operational identity](glossary.md)'s secret text: the 74 ASCII bytes of
`AGE-SECRET-KEY-1…`, uppercase Bech32 with no trailing newline, in the same form as the identity envelope's plaintext.
The operational identity's recipient key is an ordinary X25519 recipient of `identity.age`, so unlock goes passphrase,
then operational identity, then vault identity. Rust: `iron_vault_store::{seal_passphrase_envelope,
open_passphrase_envelope, unlock_with_passphrase}`.

| Bytes | Content                                                                 |
|------:|-------------------------------------------------------------------------|
|    22 | `age-encryption.org/v1` and a newline                                   |
|    36 | `-> scrypt <salt> <log_n>`: a 22-character base64 salt (16 bytes) and the work factor in decimal, then a newline |
|    44 | the stanza body: the 32-byte wrapped file key in 43 base64 characters, then a newline |
|    48 | `--- ` and the 43-character header MAC, then a newline                  |
|   106 | the payload: a 16-byte nonce, the 74-byte secret text and a 16-byte tag |

- **Stanzas.** Exactly one scrypt stanza and no other. `age` adds its random grease stanza only to files without an
  scrypt stanza, and refuses to write an scrypt stanza beside any other, so this file never holds one. `stanza_kinds`
  of it is `[Scrypt]`, and of `identity.age` never contains `Scrypt` (specification [§14](iron-vault-specification.md#14-recipients-startup-and-memory), [§19](iron-vault-specification.md#19-v0-user-acceptance)).
- **Work factor.** New envelopes are sealed at `PASSPHRASE_WORK_FACTOR` = 18 (N = 2^18, r = 8: 256 MiB and roughly
  half a second to a second per unlock). Opening refuses a header asking for more than `MAX_PASSPHRASE_WORK_FACTOR` = 20
  (1 GiB) before any scrypt work. The work factor must be one or two decimal digits without a leading zero.
- **Size limit.** `MAX_PASSPHRASE_ENVELOPE_LEN` is 1 KiB; the file is about 256 bytes.
- **Reading order.** `open_passphrase_envelope` refuses an oversized file first, then any header that is not exactly
  one scrypt stanza, then a work factor above the maximum. Only then does it run scrypt with the passphrase, and parse
  the plaintext as an X25519 identity. A passphrase that does not unwrap the stanza is `WrongPassphrase`.
- **Changing the passphrase.** `reseal_passphrase_envelope` opens the file with the old passphrase and seals the same
  operational identity to the new one. Only `operational.age` is rewritten; `identity.age` stays byte-identical.

## Unfinished initialization file

The state-directory file `init.unfinished` is empty: its presence is the whole of its meaning. `iron-vault init` writes
it with a durable replace before any other file of a new vault, and durably removes it as its last step, which is
init's commit point. While it exists the vault is an [unfinished initialization](glossary.md): `unlock` refuses it, and
the next `init` discards the files the unfinished run wrote and starts over. See
[vault-initialization.md](vault-initialization.md#write-order).

- **Content.** Zero bytes. A non-empty file is read as present too: only the name is looked at, never the bytes, so
  there is nothing to parse and nothing to refuse.
- **Reading.** The [initialization state](vault-initialization.md#initialization-state) is read from the directory
  listings, with only the initial config's bytes compared, without the vault identity, so it is known while the vault
  is locked. The file is not sealed or MAC'd:
  only the service account can write the state directory, and anyone who can could delete the vault's files outright.
- **Temp file.** A crash during its durable replace can leave `.init.unfinished.tmp`, a stale temp file that the
  startup sweep removes like any other.

## Recovery check record

The [recovery check record](glossary.md), state-directory file `recovery.toml`, holds when the recovery reminder
schedule started counting and when the last successful recovery check ran. It is plaintext TOML, written by the
service with a durable replace and read back by the same code, so its bytes are fixed. Rust:
`iron_vault_store::RecoveryCheckRecord`. See [recovery.md](recovery.md#the-recovery-check-record).

```toml
since = 2026-11-06T09:49:13Z
last_checked = 2027-02-01T10:00:00Z
```

- **Content.** One line `since = <time>`, then, after a successful check, one line `last_checked = <time>`, each
  ending in a newline, in that order. Each time is a TOML offset date-time in UTC, written with `Z` and whole seconds.
- **Reading.** The file must be a regular file of at most 1 KiB and valid TOML holding `since` and at most
  `last_checked`, each an offset date-time with offset `Z` and no fractional seconds. Any other key, value, offset or
  size makes the record unusable; a reader never repairs it. Key order and whitespace are not checked, since TOML
  ignores them, but the writer's bytes are always the ones above.
- **No MAC and no version.** It is not sealed, MAC'd or versioned, so a locked service can read it. Forging it can
  only move a reminder, and only the service account can write the state directory. A key a later release adds makes
  the record unusable to this one, which then counts a reminder as due until the next check rewrites it.
- **Temp file.** A crash during its durable replace can leave `.recovery.toml.tmp`, a stale temp file that the
  startup sweep removes like any other.

## Approver key envelope

The [approver key envelope](glossary.md) holds one software approver's private key, the key of its
[software signer](glossary.md). Each software approver has its own, in the state-directory file
`approver-<approver ID>.age`, with the ID in lowercase hyphenated form, such as
`approver-8d1c6f0e-2b7a-4c59-9e3d-5a4b3c2d1e0f.age`. It is a plain binary `age` v1 file with no Iron Vault framing,
written by the same passphrase envelope code as `operational.age` but opened only with that approver's
[approval passphrase](glossary.md). Its plaintext is the 32-byte Ed25519 private key (the RFC 8032 seed), raw. Rust:
`iron_vault_store::{seal_signer_key, open_signer_key, write_signer_key, read_signer_key}`.

| Bytes | Content                                                                 |
|------:|-------------------------------------------------------------------------|
|    22 | `age-encryption.org/v1` and a newline                                   |
|    36 | `-> scrypt <salt> <log_n>`: a 22-character base64 salt (16 bytes) and the work factor in decimal, then a newline |
|    44 | the stanza body: the 32-byte wrapped file key in 43 base64 characters, then a newline |
|    48 | `--- ` and the 43-character header MAC, then a newline                  |
|    64 | the payload: a 16-byte nonce, the 32-byte private key and a 16-byte tag |

- **Stanzas, work factor and reading order.** As for the passphrase envelope: exactly one scrypt stanza, sealed at
  `PASSPHRASE_WORK_FACTOR`, refused from the header above `MAX_PASSPHRASE_WORK_FACTOR` or with any other stanza, and
  bounded by `MAX_PASSPHRASE_ENVELOPE_LEN` (1 KiB; the file is 214 bytes). A plaintext that is not exactly 32 bytes is
  malformed, so `operational.age` never opens as an approver key.
- **Separate passphrase.** The vault-unlock passphrase and the approval passphrase are separate types and separate
  files, so holding the unlock passphrase gives no way to sign an approval.
- **Pinned key check.** `open_signer_key` derives the public key from the decrypted private key and refuses with
  `KeyMismatch` unless it equals the public key of the [pinned approver](#approval-state-payload-v1) it is opened for,
  so a key file renamed or swapped to another approver's name signs nothing.
- **One file per approver.** The service opens only the file named by the approver it asks, so each answer costs one
  scrypt run. `init` writes its one approver's file, and `approver add` writes one for each later software approver
  ([approval-signers.md](approval-signers.md#software-signer-keys)). A file whose ID no pinned approver has is an
  [orphan](approval-signers.md#orphan-key-files), which the next `approver add` or `approver remove` deletes.
- **Lifetime.** A software signer is opened for one approval and dropped; the private key is cleared on drop and never
  cached.

## Approval payload v1

The bytes a [config approval](glossary.md) signs (specification [§12](iron-vault-specification.md#12-configuration-approval-and-reload)). It binds the fixed purpose, the vault, the
approval version and the config digest, so a signature cannot be moved to another vault, another version or another
config. It uses the conventions of record payload v1: big-endian unsigned integers, `u64` length prefixes, lengths
checked against the bytes remaining before anything is read, and no trailing bytes. Rust:
`iron_vault_store::ApprovalPayload::{encode, decode}`.

### Layout

| Offset | Size | Content                                                                                 |
|--------|------|-----------------------------------------------------------------------------------------|
| 0      | 4    | Magic: ASCII `IVAP` (`49 56 41 50`)                                                     |
| 4      | 1    | Format version: `01`                                                                    |
| 5      | 28   | Purpose: field holding exactly the 20 ASCII bytes `iron-vault-config-v1`                |
| 33     | 16   | Vault ID: the 16 bytes of a version 4 UUID                                              |
| 49     | 8    | Approval version: `u64`, never zero                                                     |
| 57     | 32   | Config digest: BLAKE2b-256 (unkeyed, 32-byte output) of the exact config bytes reviewed |

A payload is always 89 bytes. The magic and the purpose are its domain separation: a signature over any other
structure, or over a payload for a later purpose, is never read as a config approval. The purpose is
length-prefixed so a later purpose of a different length cannot be confused with this one by its prefix.

The digest covers the config file byte for byte, so a change to whitespace or a comment needs a fresh approval.

### Example

Vault `3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b`, approval version 1, approving an empty config (the BLAKE2b-256
digest of zero bytes):

```text
49 56 41 50                                        magic "IVAP"
01                                                 format version 1
00 00 00 00 00 00 00 14                            purpose length 20
69 72 6f 6e 2d 76 61 75 6c 74 2d 63 6f 6e 66 69    "iron-vault-confi"
67 2d 76 31                                        "g-v1"
3f 2b 8c 1e 5d 4a 4e 6f 9a 7b 1c 2d 3e 4f 5a 6b    vault ID 3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b
00 00 00 00 00 00 00 01                            approval version 1
0e 57 51 c0 26 e5 43 b2 e8 ab 2e b0 60 99 da a1    config digest
d1 e5 df 47 77 8f 77 87 fa ab 45 cd f1 2f e3 a8
```

### One encoding per payload

Decoding accepts only the encoding above, so the bytes a verifier re-encodes are the bytes that were signed. It
rejects a wrong magic, an unknown format version, any purpose other than `iron-vault-config-v1`, a vault ID that is
not a version 4 UUID, approval version 0, truncation and trailing bytes.

## Approval envelope v1

The file `config.toml.sig`: an approval payload, the [signature algorithm](glossary.md) and the
[approver ID](glossary.md) of the approver that signed it, and the signature. Software, TPM and later YubiKey signers
all write this one envelope ([implementation spec §2.2](implementation-specification.md#22-product-decisions-and-resulting-behavior) Q-9). Rust:
`iron_vault_store::ApprovalEnvelope::{encode, decode}`.

### Layout

| Offset | Size | Content                                                                    |
|-----|-----|-----------------------------------------------------------------------------|
| 0   | 4   | Magic: ASCII `IVAS` (`49 56 41 53`)                                         |
| 4   | 1   | Format version: `01`                                                        |
| 5   | 1   | Signature algorithm ID (below)                                              |
| 6   | 16  | Approver ID: the 16 bytes of the version 4 UUID of the approver that signed |
| 22  | var | Payload: field holding an approval payload v1                               |
| var | var | Signature: field holding the signature over the payload field's bytes       |

| ID   | Algorithm                                                                  |
|------|----------------------------------------------------------------------------|
| `00` | Never valid                                                                |
| `01` | Ed25519 (RFC 8032), the software signer; the signature is exactly 64 bytes |
| `02` | Reserved for ECDSA P-256 with SHA-256, the TPM signer; not accepted in v0  |

Any other ID is refused as unknown. The signature is over exactly the bytes inside the payload field.

The envelope carries **no public key**. Specification [§12](iron-vault-specification.md#12-configuration-approval-and-reload) forbids trusting a key from the signature file. The
approver ID only says which pinned approver to check: the verifier looks it up among the approvers pinned in the
approval state, refuses an ID that is not there, refuses an envelope whose algorithm differs from that approver's, and
verifies the signature with that approver's key.

The approver ID sits outside the signed payload, and needs no signature of its own. Changing it makes the verifier
check the signature against another approver's key, which fails, because no two approvers share a key. A signature
that verifies therefore also proves which approver made it, so the approver ID can be logged as the signer.

A v1 envelope without an approver ID was never released, so the ID joins v1 rather than starting v2.

### Example

The payload example above, signed with Ed25519. The signature here is 64 bytes of `5a`, a stand-in: the format does
not check signatures, verification does.

```text
49 56 41 53                                        magic "IVAS"
01                                                 format version 1
01                                                 algorithm Ed25519
8d 1c 6f 0e 2b 7a 4c 59 9e 3d 5a 4b 3c 2d 1e 0f    approver ID 8d1c6f0e-2b7a-4c59-9e3d-5a4b3c2d1e0f
00 00 00 00 00 00 00 59                            payload length 89
…                                                  the 89 payload bytes from the example above
00 00 00 00 00 00 00 40                            signature length 64
5a 5a 5a 5a 5a 5a 5a 5a  5a 5a 5a 5a 5a 5a 5a 5a   signature (stand-in)
5a 5a 5a 5a 5a 5a 5a 5a  5a 5a 5a 5a 5a 5a 5a 5a
5a 5a 5a 5a 5a 5a 5a 5a  5a 5a 5a 5a 5a 5a 5a 5a
5a 5a 5a 5a 5a 5a 5a 5a  5a 5a 5a 5a 5a 5a 5a 5a
```

The whole file is 191 bytes.

### One encoding per envelope

Decoding rejects a wrong magic, an unknown format version, an unknown or reserved algorithm ID, an approver ID that is
not a version 4 UUID, a payload that is not a canonical approval payload v1 (including trailing bytes inside the
payload field), a signature of the wrong length for its algorithm, truncation and trailing bytes. Whether the approver
ID is pinned is the verifier's check, not the decoder's.

### Size limit

`MAX_APPROVAL_ENVELOPE_LEN` is 4096 bytes, checked before anything else is read. A v1 envelope is 191 bytes with an
Ed25519 signature and at most 199 with a DER-encoded ECDSA P-256 one; the limit leaves room for a later algorithm with
a larger signature while keeping a planted file cheap to refuse.

## Approval state file v1

The [approval state](glossary.md) of one vault, in the state-directory file `approval.age`: the pinned approvers, the
highest reserved version and the committed approval (specification [§12](iron-vault-specification.md#12-configuration-approval-and-reload)). Versioned approval rejects an old
`config.toml` and `config.toml.sig` pair only while these counters never go backwards, so the file is a
[MAC'd file](#macd-file-frame) that a party holding only the vault public key cannot write. Rust:
`iron_vault_store::{seal_approval_state, open_approval_state, ApprovalState}`.

| Frame parameter | Value                                                                |
|-----------------|----------------------------------------------------------------------|
| Magic           | ASCII `IVAF` (`49 56 41 46`)                                         |
| Version         | `01`                                                                 |
| Payload         | The approval state payload v1 (below)                                |
| Personalization | `iv-approval-v1` (14 bytes); the derived key is the **approval key** |
| Domain tag      | `iron-vault approval file v1 mac` followed by a zero byte            |
| Size limit      | `MAX_APPROVAL_STATE_LEN` (4 KiB)                                     |

The approval key is independent of the manifest key, so a MAC from one file never verifies the other.

Test vectors, checked by the store's tests, with the manifest's known-answer identity and a stand-in ciphertext:

```text
identity      AGE-SECRET-KEY-1QYPQXPQ9QCRSSZG2PVXQ6RS0ZQG3YYC5Z5TPWXQERGD3C8G7RUSQGPQYEE
              (the X25519 key bytes 01 02 03 … 20)
approval key  16774b3a8005def61dba01300f8d95323135bdc40e911fadd247058656d40372
              dc06a4d9099da2e01ddec5c2c017772f903cf6083fb0f38d1ca5fbac6b8df64c
MAC input     the domain tag, then these bytes before the MAC:
              49564146013f2b8c1e5d4a4e6f9a7b1c2d3e4f5a6b6e6f74207265616c6c7920616765
              (magic "IVAF", version 01, vault ID 3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b, ciphertext "not really age")
MAC           432bf6223d8cfcab01ea4ba4f7e3757ed426bb724c440ccbf42d2ecdeca76e3f
```

A MAC mismatch, a payload naming another vault, or a payload whose committed version is above its highest reserved
version is damaged shared state: approvals cannot be checked, so the service stops proxying (specification [§12](iron-vault-specification.md#12-configuration-approval-and-reload),
[§13](iron-vault-specification.md#13-vault-structure-and-durable-writes)).

### Size limit

A payload with one Ed25519 approver labelled `approval passphrase` is 187 bytes. An approver entry is at most 171 bytes:
a 16-byte ID, an algorithm byte, a signer kind byte, an 8-byte length and a public key of at most 65 bytes (an
uncompressed P-256 point), an 8-byte length and a 64-byte label, and an 8-byte time. With `MAX_APPROVERS` (16) entries
the payload is at most 37 + 8 + 16 × 171 + 49 = 2,830 bytes. `age` adds a header of at most about 400 bytes, a 16-byte
payload nonce and a 16-byte tag, and the file adds 53 bytes of header and MAC: about 3,315 bytes, inside
`MAX_APPROVAL_STATE_LEN` (4096 bytes). The same limit bounds the decrypted payload. Enrolling a seventeenth approver is
refused, so the service never writes a state it cannot read back.

### Writes

The service changes the state only by durably replacing the whole file, and changes its in-memory copy only after the
replace returns. Every write reads the manifest from disk first and takes its state generation from the
[vault-wide rule](#state-generation), recording the manifest's state generation as its peer generation:

- **Create.** A new vault's state has nothing reserved and nothing committed, and takes its vault ID from the
  manifest, which must already exist. It is written only where no `approval.age` exists and the manifest records no
  approval state, and the vault then writes a manifest that records it, so once that write lands, deleting the state
  and creating it again is refused and can never reset the counters. If that manifest write fails, the approval state
  stands, the error says it is not yet recorded, and the open report flags it until `Vault::record_approval_state`
  records it.
- **Reserve.** Writes the highest reserved version plus one and returns it; the returned version is already durable, so
  it is never handed out twice. At `u64::MAX` it fails without writing, and nothing may be signed.
- **Commit.** Writes a new committed approval. The version must be reserved and newer than the committed one.
- **Enroll approver.** Adds a pinned approver with a new approver ID and keeps both counters. It refuses a public key
  that is already pinned, and a seventeenth approver.
- **Remove approver.** Removes a pinned approver and keeps both counters. It refuses to remove the last one. If the
  removed approver signed the active `config.toml.sig`, that signature stops verifying until the config is approved
  again at a new version, as specification [§12](iron-vault-specification.md#12-configuration-approval-and-reload)
  says of signing-key rotation.

Signing-key rotation is an enroll followed by a remove. `init` writes the state with its one approver; `approver add`
and `approver remove` enroll and remove the others, after owner presence from a pinned approver
([approval-signers.md](approval-signers.md#authorization)).

Before each write the service reads the file back and requires it to equal its in-memory state, so a stale copy can
never write lower counters over newer ones. Restoring the whole state directory from an older copy restores older
counters too; specification [§12](iron-vault-specification.md#12-configuration-approval-and-reload) leaves that outside v0.

## Approval state payload v1

The plaintext an approval state file seals. It uses the conventions of record payload v1: big-endian unsigned integers,
`u64` length prefixes, lengths checked against the bytes remaining before anything is read, and no trailing bytes.

### Layout

| Offset | Size | Content                                                                            |
|--------|------|------------------------------------------------------------------------------------|
| 0      | 4    | Magic: ASCII `IVAM` (`49 56 41 4d`)                                                |
| 4      | 1    | Format version: `01`                                                               |
| 5      | 16   | Vault ID: equal to the file header's                                               |
| 21     | 8    | State generation: `u64`, at least 1                                                |
| 29     | 8    | Peer generation: `u64`, the manifest's; at least 1                                 |
| 37     | 8    | Approver count: `u64`, from 1 to `MAX_APPROVERS` (16)                              |
| 45     | var  | Approvers: one entry each (below), in strictly ascending byte order of approver ID |
| …      | 8    | Highest reserved version: `u64`, 0 before the first reservation                    |
| …      | 1    | Committed tag: `00` nothing committed, `01` a committed approval follows           |
| …      | 8    | Committed version (tag `01` only): `u64`, from 1 to the highest reserved version   |
| …      | 32   | Committed config digest (tag `01` only): BLAKE2b-256 of the approved config        |

Each approver entry, a **pinned approver**:

| Size | Content                                                                                                                |
|------|------------------------------------------------------------------------------------------------------------------------|
| 16   | Approver ID: the 16 bytes of a version 4 UUID, generated when the approver is enrolled                                 |
| 1    | Algorithm: a signature algorithm ID, as in approval envelope v1                                                        |
| 1    | Signer kind: `01` `software`; `02` `tpm`, `03` `hardware` reserved ([signer kinds](approval-signers.md#signer-kinds))  |
| var  | Public key: field; 32 bytes for Ed25519                                                                                |
| var  | Label: field holding the owner's name for the signer, under the [recipient label](recipients.md#recipient-labels) rule |
| 8    | Enrolled at: `u64` Unix seconds, a [UTC second](glossary.md)                                                           |

The approver ID is the approver's identity: the approval envelope names it, and an audit event records it. It is
never reused, so an envelope signed by a removed approver can never be read as signed by a later one. The label is
what a prompt shows the owner, such as `Dave YubiKey 3`; it need not be unique, and nothing looks an approver up by it.

### Example

Vault `3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b` with one Ed25519 software signer approver (the RFC 8032 test 1 public key),
enrolled by `init` with the label `approval passphrase`, versions 1 and 2 reserved, and version 1 committed for an empty
config. Version 2 was reserved for a signing attempt that never committed, and stays consumed. After the manifest
example above (state generation 3), the state was written three times, reserving 1, committing 1 and reserving 2, so it
is at state generation 6 with peer generation 3.

```text
49 56 41 4d                                        magic "IVAM"
01                                                 format version 1
3f 2b 8c 1e 5d 4a 4e 6f 9a 7b 1c 2d 3e 4f 5a 6b    vault ID 3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b
00 00 00 00 00 00 00 06                            state generation 6
00 00 00 00 00 00 00 03                            peer generation 3
00 00 00 00 00 00 00 01                            approver count 1
8d 1c 6f 0e 2b 7a 4c 59 9e 3d 5a 4b 3c 2d 1e 0f    approver ID 8d1c6f0e-2b7a-4c59-9e3d-5a4b3c2d1e0f
01                                                 algorithm Ed25519
01                                                 signer kind software
00 00 00 00 00 00 00 20                            public key length 32
d7 5a 98 01 82 b1 0a b7 d5 4b fe d3 c9 64 07 3a    public key
0e e1 72 f3 da a6 23 25 af 02 1a 68 f7 07 51 1a
00 00 00 00 00 00 00 13                            label length 19
61 70 70 72 6f 76 61 6c 20 70 61 73 73 70 68 72    "approval passphr"
61 73 65                                           "ase"
00 00 00 00 6a ed a2 99                            enrolled at 2026-11-06T09:49:13Z
00 00 00 00 00 00 00 02                            highest reserved version 2
01                                                 an approval is committed
00 00 00 00 00 00 00 01                            committed version 1
0e 57 51 c0 26 e5 43 b2 e8 ab 2e b0 60 99 da a1    committed config digest
d1 e5 df 47 77 8f 77 87 fa ab 45 cd f1 2f e3 a8
```

The payload is 187 bytes. A new vault's payload has the same layout up to the last approver, then eight zero bytes and
the tag `00`: 147 bytes with this approver.

A state with one approver was never released, so the approver list and the signer kind join v1 rather than starting
v2.

### One encoding per state

Every field has one form, so the same state always encodes to the same bytes. Decoding rejects a wrong magic, an unknown
format version, a vault ID that is not a version 4 UUID, a state or peer generation of 0, a peer generation not below
the state generation, an approver count of 0 or above 16, approver IDs that are not version 4 UUIDs or not strictly
ascending, an unknown or reserved algorithm ID, a reserved signer kind (`02`, `03`) or an unknown one (`00`, above
`03`), a signer kind whose algorithms exclude the entry's algorithm, a public key of the wrong length for its algorithm,
a public key that is not a valid, non-weak key for its algorithm, a public key pinned twice, a label that breaks its
rule, an enrolment time outside the UTC second range, a committed tag other than `00` or `01`, committed version 0, a
committed version above the highest reserved version, truncation and trailing bytes.

## Recipient inventory file v1

The [recipient inventory](glossary.md): the state-directory file `recipients.age`, listing every recipient key
`identity.age` is wrapped for. It is a [MAC'd file](#macd-file-frame) because anyone holding the vault public key could
otherwise seal a list of their own choosing, and the next rewrap would enroll its keys. The design is in
[recipients.md](recipients.md#recipient-inventory). Rust: `iron_vault_store::{seal_recipient_inventory,
open_recipient_inventory, write_recipient_inventory, read_recipient_inventory}`.

| Frame parameter | Value                                                                              |
|-----------------|------------------------------------------------------------------------------------|
| Magic           | ASCII `IVRF` (`49 56 52 46`)                                                       |
| Version         | `01`                                                                               |
| Payload         | The recipient inventory payload v1 (below)                                         |
| Personalization | `iv-recipients-v1` (16 bytes); the derived key is the **inventory key**            |
| Domain tag      | `iron-vault recipients file v1 mac` followed by a zero byte (34 bytes)             |
| Size limit      | `MAX_RECIPIENT_INVENTORY_LEN` (16 KiB)                                             |

The inventory key is independent of the manifest and approval keys, so a MAC from one file never verifies another.
Domain separation does not depend on the tag's length, because each tag ends in its only zero byte.

The inventory is not part of the [state generation](#state-generation) and carries no counters: it carries the
**envelope digest** instead, the BLAKE2b-256 (unkeyed, 32-byte output) of `identity.age` exactly as it sits on disk
(`envelope_digest`). An inventory restored alone no longer matches the envelope and is refused as damaged.

### Size limit

An entry is at most 151 bytes: an 8-byte length and a 62-byte key, a role byte, an 8-byte length and a 64-byte label,
and an 8-byte time. A full payload is at most 61 + 64 × 151 = 9,725 bytes. `age` adds a header of under 400 bytes, a
16-byte nonce and a 16-byte tag, and the frame adds 53 bytes: under 10,300 bytes in all, well inside 16 KiB. Building
an inventory with more than `MAX_RECIPIENTS` (64) entries is refused, so the service never writes one it cannot read
back.

## Recipient inventory payload v1

The plaintext an inventory file seals. It uses the conventions of [record payload v1](#conventions): big-endian
unsigned integers, `u64` length prefixes, lengths checked against the bytes remaining before anything is read, and no
trailing bytes.

### Layout

| Offset | Size | Content                                                                                 |
|--------|------|-----------------------------------------------------------------------------------------|
| 0      | 4    | Magic: ASCII `IVRP` (`49 56 52 50`)                                                     |
| 4      | 1    | Version: `01`                                                                           |
| 5      | 16   | Vault ID: equal to the file header's                                                    |
| 21     | 32   | Envelope digest: BLAKE2b-256 of the `identity.age` this inventory describes             |
| 53     | 8    | Entry count: `u64`, from 2 to 64                                                        |
| 61     | var  | Entries, in strictly ascending byte order of their recipient key text (below)           |

Each entry:

| Size | Content                                                                                          |
|------|--------------------------------------------------------------------------------------------------|
| var  | Recipient key: a field holding the canonical lowercase `age1…` text, exactly 62 bytes            |
| 1    | Role: `01` operational, `02` recovery, `03` added, `06` host-unlock; `04`, `05` reserved and refused |
| var  | Label: a field holding the recipient label, 1 to 64 bytes of UTF-8                               |
| 8    | Enrolled at: `u64` Unix seconds, at most 253402300799 (9999-12-31T23:59:59Z)                      |

### One encoding per inventory

The same inventory always encodes to the same bytes: entries are written in ascending key order. Decoding enforces the
reverse, so a payload is accepted only if it is the encoding of the inventory it decodes to:

- the vault ID is a version 4, RFC 9562 variant UUID and equals the header's;
- the entry count is from 2 to 64, and is checked before any entry is read;
- every recipient key is 62 bytes, parses as an X25519 recipient key and is in canonical lowercase form;
- keys are strictly ascending, so none repeats;
- every role code is 1, 2, 3 or 6; a reserved or unknown code is refused;
- every label is valid UTF-8 and follows the label rule;
- every enrolment time is within the UTC second range.

Decoding rejects a wrong magic, an unknown version, truncation and trailing bytes. It does not apply the independence
rule: that rule governs changes, and every inventory the service writes already satisfies it.

### Example

Vault `3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b`, whose `identity.age` has an illustrative digest of 32 bytes of `ab`, with
three recipients. Their secret keys are the X25519 key bytes `01 … 20`, `21 … 40` and `41 … 60`, and the entries are
in the byte order of their key text, which here is also the order of the roles:

```text
49 56 52 50                                        magic "IVRP"
01                                                 version 1
3f 2b 8c 1e 5d 4a 4e 6f 9a 7b 1c 2d 3e 4f 5a 6b    vault ID 3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b
ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab
ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab    envelope digest
00 00 00 00 00 00 00 03                            three entries
00 00 00 00 00 00 00 3e                            key length 62
age1q73he0q5yzfu3d64msd3p6rvksnrwjk3d2598mgtmlqt9wrdr37q2vrn72
                                                   recipient key, 62 ASCII bytes
01                                                 role operational
00 00 00 00 00 00 00 10  "vault passphrase"        label
00 00 00 00 6a ed a8 1d                            enrolled at 1793959965
```

The second entry is the `recovery` key `age1tp56lazs2jtn9ja2a409m7dnpfk6x89su46zht266js6w6835eascutqdx`, label
`recovery key`, enrolled at the same second, with role `02`. The third is the `added` key
`age1vjcsrvwshedgwp9aq78e39gqrlqrar5lj530rzxaz2xes3k5s3nqxdc696`, label `alice laptop 2026`, enrolled at 1794000000
(`6a ee 44 80`), with role `03`. The complete payload, as the store's tests check it:

```text
49565250013f2b8c1e5d4a4e6f9a7b1c2d3e4f5a6babababababababababababababababababababababababababababababababab0000000000000003000000000000003e616765317137336865307135797a6675336436346d736433703672766b736e72776a6b3364323539386d67746d6c717439777264723337713276726e37320100000000000000107661756c742070617373706872617365000000006aeda81d000000000000003e61676531747035366c617a73326a746e396a6132613430396d37646e70666b36783839737534367a68743236366a7336773638333565617363757471647802000000000000000c7265636f76657279206b6579000000006aeda81d000000000000003e61676531766a63737276777368656467777039617137386533396771726c71726172356c6a353330727a78617a32786573336b3573336e71786463363936030000000000000011616c696365206c6170746f702032303236000000006aee4480
```
