# Iron Vault storage formats

Byte layouts of the data Iron Vault writes to disk. Each format carries a version so a later release can read what an
earlier one wrote and refuse what it does not understand (specification §9). Terms follow the
[glossary](glossary.md).

## Record payload v1

The plaintext of one [credential record](iron-vault-specification.md#33-credential-records-and-configuration): the
bytes a credential file encrypts. Encryption, file names and the manifest are separate layers; this section covers
only what is inside the encryption. Rust: `iron_vault_store::{encode, decode}`.

### Why binary

The payload is a small hand-written, length-prefixed binary layout rather than TOML or a serde format. Decoding reads
each secret field as a borrowed slice of the decrypted buffer, checks it is UTF-8 in place, and copies it once, straight
into the `SecretString` that owns it from then on. A TOML or serde decoder would first build its own `String` for each
value, a heap copy of the secret that nothing zeroizes. Specification §3.11 asks for as few copies of a secret as
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
stored: specification §3.3 makes HTTPS mandatory, so every origin is an HTTPS origin.

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
  non-empty with no `:`, and neither username nor password contains a control character (RFC 7617 §2).

Decoding rejects a wrong magic, an unknown version, an unknown material or source tag, truncation, trailing bytes and
any of the rule failures above. Its errors name the rule or field that failed, never a secret byte.

### Size limit

A record file, `record-<record id>.age`, is at most `MAX_RECORD_FILE_LEN` (64 KiB) on disk, and its payload at most
64 KiB. A v0 record is a name of at most 64 bytes, a few origins of at most 263 bytes each and a key or username and
password, so it is a few KiB even with dozens of origins; the limit leaves room for later kinds' keys and certificates.
A longer file is a damaged record and is never read in full.

### Versions

Payload version 1 holds no provider settings or operational state. Specification §3.3 lists both, and both arrive
with OAuth in product phase v1 (§4). Adding them means a new version byte with its own layout, and a reader for every
version still on disk. A reader never guesses at a version it does not know.

## MAC'd file frame

A [MAC'd file](glossary.md) is a control file the service alone may write. `age` does not authenticate the sender, so
anyone holding the vault public key can write a file that decrypts cleanly. A MAC'd file is therefore sealed to the
vault public key and then authenticated with a MAC keyed from the private vault identity, which only the service holds
while the vault is unlocked (specification §3.10). The manifest file and the approval state file are MAC'd files; each
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
- The MAC message starts with the file type's 32-byte domain tag, which ends in a zero byte, then every file byte
  before the MAC: magic, version, vault ID and ciphertext.

A party holding only the vault public key can seal any payload, but cannot compute the MAC. A file from another vault
fails the MAC too, because its key comes from another identity.

### Reading order

Opening a MAC'd file does the cheap, key-free checks first and decrypts last:

1. A file longer than the file type's size limit is refused before anything else is read.
2. A file shorter than header plus MAC is truncated. A wrong magic or unknown version is refused; the version is read
   before the MAC because it decides how the MAC is computed.
3. The MAC is compared in constant time. A mismatch is reported as damaged shared state: the file was altered, or was
   not written by this vault, and specification §3.10 says the vault may need recovery.
4. Only then is the vault ID parsed and the ciphertext opened, with the size limit also bounding the plaintext, and
   decoded. A payload naming a different vault from the header is refused.

## Manifest file v1

The [vault manifest](glossary.md): the service's index of which credential records exist, in the state-directory file
`manifest.age`. Specification §3.10 makes the service's own index the authority on which records exist, and §3.3 says
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
37 + 4096 × 120 = 491,557 bytes. `age` adds a header of a few hundred bytes, one 16-byte payload nonce and a 16-byte
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
| 21     | 8    | Generation: `u64`                                                          |
| 29     | 8    | Entry count: `u64`, at most 4096                                           |
| 37     | var  | Entries, in strictly ascending order of record ID bytes (below)            |

Each entry:

| Size | Content                                                                                 |
|------|-----------------------------------------------------------------------------------------|
| 16   | Record ID: the 16 bytes of a version 4 UUID                                             |
| var  | Name: field holding the credential name                                                 |
| 32   | File digest: BLAKE2b-256 (unkeyed, 32-byte output) of the record file's ciphertext bytes |

The digest covers the record file exactly as it sits on disk, so a record file replaced by a different ciphertext,
even one that decrypts to the same record, no longer matches its entry. Record files are named `record-<record id>.age`.

A new vault's first manifest is at generation 0 with no entries, written before any record file. The generation
increases by exactly one with every manifest the service writes, and never wraps: a manifest at generation `u64::MAX`
cannot be followed. A reader that remembers the last generation it saw can tell a stale copy
from the current one within one storage history; rolling the whole state directory back to an older consistent copy
is outside what the manifest detects (specification §9).

### Example

Vault `3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b` at generation 1, with one record `fx_key` whose file digest is 32 bytes
of `11` (an illustrative value):

```text
49 56 4d 50                                        magic "IVMP"
01                                                 version 1
3f 2b 8c 1e 5d 4a 4e 6f 9a 7b 1c 2d 3e 4f 5a 6b    vault ID 3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b
00 00 00 00 00 00 00 01                            generation 1
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
  without a passphrase. Specification §3.11 forbids an scrypt stanza beside other recipients, so the envelope never
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
  of it is `[Scrypt]`, and of `identity.age` never contains `Scrypt` (specification §3.11, §3.15).
- **Work factor.** New envelopes are sealed at `PASSPHRASE_WORK_FACTOR` = 18 (N = 2^18, r = 8: 256 MiB and roughly
  half a second to a second per unlock). Opening refuses a header asking for more than `MAX_PASSPHRASE_WORK_FACTOR` = 20
  (1 GiB) before any scrypt work. The work factor must be one or two decimal digits without a leading zero.
- **Size limit.** `MAX_PASSPHRASE_ENVELOPE_LEN` is 1 KiB; the file is about 256 bytes.
- **Reading order.** `open_passphrase_envelope` refuses an oversized file first, then any header that is not exactly
  one scrypt stanza, then a work factor above the maximum. Only then does it run scrypt with the passphrase, and parse
  the plaintext as an X25519 identity. A passphrase that does not unwrap the stanza is `WrongPassphrase`.
- **Changing the passphrase.** `reseal_passphrase_envelope` opens the file with the old passphrase and seals the same
  operational identity to the new one. Only `operational.age` is rewritten; `identity.age` stays byte-identical.

## Approver key envelope

The [approver key envelope](glossary.md), state-directory file `approver.age`, holds the
[software signer](glossary.md)'s private key. It is a plain binary `age` v1 file with no Iron Vault framing, written by
the same passphrase envelope code as `operational.age` but opened only with the [approval passphrase](glossary.md).
Its plaintext is the 32-byte Ed25519 private key (the RFC 8032 seed), raw. Rust:
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
  `KeyMismatch` unless it equals the pinned approver's, so a swapped `approver.age` signs nothing.
- **Lifetime.** A software signer is opened for one approval and dropped; the private key is cleared on drop and never
  cached.

## Approval payload v1

The bytes a [config approval](glossary.md) signs (specification §3.9). It binds the fixed purpose, the vault, the
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

The file `config.toml.sig`: an approval payload, the [signature algorithm](glossary.md) that signed it and the
signature. Software, TPM and later YubiKey signers all write this one envelope (specification §8.2 Q-9). Rust:
`iron_vault_store::ApprovalEnvelope::{encode, decode}`.

### Layout

| Offset | Size | Content                                                               |
|--------|------|-----------------------------------------------------------------------|
| 0      | 4    | Magic: ASCII `IVAS` (`49 56 41 53`)                                   |
| 4      | 1    | Format version: `01`                                                  |
| 5      | 1    | Signature algorithm ID (below)                                        |
| 6      | var  | Payload: field holding an approval payload v1                         |
| var    | var  | Signature: field holding the signature over the payload field's bytes |

| ID   | Algorithm                                                                      |
|------|--------------------------------------------------------------------------------|
| `00` | Never valid                                                                    |
| `01` | Ed25519 (RFC 8032), the software signer; the signature is exactly 64 bytes     |
| `02` | Reserved for ECDSA P-256 with SHA-256, the TPM signer; not accepted in v0      |

Any other ID is refused as unknown. The signature is over exactly the bytes inside the payload field.

The envelope carries **no public key**. Specification §3.9 forbids trusting a key from the signature file; the
verifier uses the approver key and algorithm pinned in protected vault metadata, and refuses an envelope whose
algorithm differs from the pinned one.

### Example

The payload example above, signed with Ed25519. The signature here is 64 bytes of `5a`, a stand-in: the format does
not check signatures, verification does.

```text
49 56 41 53                                        magic "IVAS"
01                                                 format version 1
01                                                 algorithm Ed25519
00 00 00 00 00 00 00 59                            payload length 89
…                                                  the 89 payload bytes from the example above
00 00 00 00 00 00 00 40                            signature length 64
5a 5a 5a 5a 5a 5a 5a 5a  5a 5a 5a 5a 5a 5a 5a 5a   signature (stand-in)
5a 5a 5a 5a 5a 5a 5a 5a  5a 5a 5a 5a 5a 5a 5a 5a
5a 5a 5a 5a 5a 5a 5a 5a  5a 5a 5a 5a 5a 5a 5a 5a
5a 5a 5a 5a 5a 5a 5a 5a  5a 5a 5a 5a 5a 5a 5a 5a
```

The whole file is 175 bytes.

### One encoding per envelope

Decoding rejects a wrong magic, an unknown format version, an unknown or reserved algorithm ID, a payload that is not
a canonical approval payload v1 (including trailing bytes inside the payload field), a signature of the wrong length
for its algorithm, truncation and trailing bytes.

### Size limit

`MAX_APPROVAL_ENVELOPE_LEN` is 4096 bytes, checked before anything else is read. A v1 envelope is 175 bytes with an
Ed25519 signature and at most 183 with a DER-encoded ECDSA P-256 one; the limit leaves room for a later algorithm with
a larger signature while keeping a planted file cheap to refuse.

## Approval state file v1

The [approval state](glossary.md) of one vault, in the state-directory file `approval.age`: the pinned approver, the
highest reserved version and the committed approval (specification §3.9). Versioned approval rejects an old
`config.toml` and `config.toml.sig` pair only while these counters never go backwards, so the file is a
[MAC'd file](#macd-file-frame) that a party holding only the vault public key cannot write. Rust:
`iron_vault_store::{seal_approval_state, open_approval_state, ApprovalState}`.

| Frame parameter | Value                                                                  |
|-----------------|------------------------------------------------------------------------|
| Magic           | ASCII `IVAF` (`49 56 41 46`)                                           |
| Version         | `01`                                                                   |
| Payload         | The approval state payload v1 (below)                                  |
| Personalization | `iv-approval-v1` (14 bytes); the derived key is the **approval key**   |
| Domain tag      | `iron-vault approval file v1 mac` followed by a zero byte              |
| Size limit      | `MAX_APPROVAL_STATE_LEN` (4 KiB)                                       |

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
version is damaged shared state: approvals cannot be checked, so the service stops proxying (specification §3.9,
§3.10).

### Size limit

A payload with an Ed25519 approver is 111 bytes. `age` adds a header of at most about 400 bytes, a 16-byte payload nonce
and a 16-byte tag, and the file adds 53 bytes of header and MAC: under 600 bytes. `MAX_APPROVAL_STATE_LEN` is 4096
bytes, which leaves room for a later algorithm with a longer public key. The same limit bounds the decrypted payload.

### Writes

The service changes the state only by durably replacing the whole file, and changes its in-memory copy only after the
replace returns:

- **Create.** A new vault's state has nothing reserved and nothing committed. It is written only where no
  `approval.age` exists, so creating it again can never reset the counters.
- **Reserve.** Writes the highest reserved version plus one and returns it; the returned version is already durable, so
  it is never handed out twice. At `u64::MAX` it fails without writing, and nothing may be signed.
- **Commit.** Writes a new committed approval. The version must be reserved and newer than the committed one.
- **Replace approver.** Writes a new pinned approver and keeps both counters, so the active signature stops verifying
  until the config is approved again at a new version.

Before each write the service reads the file back and requires it to equal its in-memory state, so a stale copy can
never write lower counters over newer ones. Restoring the whole state directory from an older copy restores older
counters too; specification §3.9 leaves that outside v0.

## Approval state payload v1

The plaintext an approval state file seals. It uses the conventions of record payload v1: big-endian unsigned integers,
`u64` length prefixes, lengths checked against the bytes remaining before anything is read, and no trailing bytes.

### Layout

| Offset | Size | Content                                                                              |
|--------|------|--------------------------------------------------------------------------------------|
| 0      | 4    | Magic: ASCII `IVAM` (`49 56 41 4d`)                                                  |
| 4      | 1    | Format version: `01`                                                                 |
| 5      | 16   | Vault ID: equal to the file header's                                                 |
| 21     | 1    | Approver algorithm: a signature algorithm ID, as in approval envelope v1             |
| 22     | var  | Approver public key: field; 32 bytes for Ed25519                                     |
| …      | 8    | Highest reserved version: `u64`, 0 before the first reservation                      |
| …      | 1    | Committed tag: `00` nothing committed, `01` a committed approval follows             |
| …      | 8    | Committed version (tag `01` only): `u64`, from 1 to the highest reserved version     |
| …      | 32   | Committed config digest (tag `01` only): BLAKE2b-256 of the approved config          |

### Example

Vault `3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b` with an Ed25519 approver (the RFC 8032 test 1 public key), versions 1 and
2 reserved, and version 1 committed for an empty config. Version 2 was reserved for a signing attempt that never
committed, and stays consumed.

```text
49 56 41 4d                                        magic "IVAM"
01                                                 format version 1
3f 2b 8c 1e 5d 4a 4e 6f 9a 7b 1c 2d 3e 4f 5a 6b    vault ID 3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b
01                                                 approver algorithm Ed25519
00 00 00 00 00 00 00 20                            public key length 32
d7 5a 98 01 82 b1 0a b7 d5 4b fe d3 c9 64 07 3a    public key
0e e1 72 f3 da a6 23 25 af 02 1a 68 f7 07 51 1a
00 00 00 00 00 00 00 02                            highest reserved version 2
01                                                 an approval is committed
00 00 00 00 00 00 00 01                            committed version 1
0e 57 51 c0 26 e5 43 b2 e8 ab 2e b0 60 99 da a1    committed config digest
d1 e5 df 47 77 8f 77 87 fa ab 45 cd f1 2f e3 a8
```

The payload is 111 bytes. A new vault's payload is the same up to the public key, then eight zero bytes and the tag
`00`.

### One encoding per state

Every field has one form, so the same state always encodes to the same bytes. Decoding rejects a wrong magic, an
unknown format version, a vault ID that is not a version 4 UUID, an unknown or reserved algorithm ID, a public key of
the wrong length for its algorithm, a public key that is not a valid, non-weak key for its algorithm, a committed tag other than `00` or `01`, committed version 0, a committed version
above the highest reserved version, truncation and trailing bytes.
