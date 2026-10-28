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

## Manifest file v1

The [vault manifest](glossary.md): the service's index of which credential records exist, in the state-directory file
`manifest.age`. `age` does not authenticate the sender, so anyone holding the vault public key can write a record file
that decrypts cleanly. Specification §3.10 makes the service's own index the authority on which records exist, and
§3.3 says only the service may index record files. The manifest is sealed to the same public key, so on its own it
would be just as forgeable; it therefore carries a MAC keyed from the private vault identity, which only the service
holds while the vault is unlocked. Rust: `iron_vault_store::{seal_manifest, open_manifest}`.

### Layout

| Offset   | Size | Content                                                                                    |
|----------|------|--------------------------------------------------------------------------------------------|
| 0        | 4    | Magic: ASCII `IVMF` (`49 56 4d 46`)                                                        |
| 4        | 1    | Version: `01`                                                                              |
| 5        | 16   | Vault ID: the 16 bytes of a version 4 UUID                                                 |
| 21       | var  | The manifest payload v1 (below), sealed to the vault public key as binary `age`            |
| end − 32 | 32   | MAC                                                                                        |

The vault ID is in clear so that the MAC, which covers it, can be checked before anything is decrypted. The payload
repeats the vault ID, and a payload whose ID differs from the header's is refused.

### MAC

```text
manifest key = BLAKE2b-512(personalization = "iv-manifest-v1", message = vault identity secret text)
MAC          = BLAKE2b-256(key = manifest key, message = "iron-vault manifest file v1 mac" 00 || bytes 0 .. end − 32)
```

- The **vault identity secret text** is exactly the 74 ASCII bytes of the uppercase Bech32 string `age`'s
  `Identity::to_string` gives, `AGE-SECRET-KEY-1…`, with no trailing newline; the `age` specification fixes this
  encoding. It carries the full 256-bit X25519 key. It is hashed as the message rather than used as the BLAKE2b key
  because it is 74 bytes long and a BLAKE2b key is at most 64.
- The **personalization** `iv-manifest-v1` (14 bytes, zero-padded to BLAKE2b's 16) separates the manifest key from any
  other key a later format derives from the same identity.
- The 64-byte manifest key is a full-length BLAKE2b key. It lives only in a buffer that is cleared on drop.
- The MAC message starts with the 32-byte domain tag `iron-vault manifest file v1 mac` and a zero byte, then every file
  byte before the MAC: magic, version, vault ID and ciphertext.

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

A party holding only the vault public key can seal any payload, but cannot compute the MAC. A manifest from another
vault fails the MAC too, because its key comes from another identity.

### Reading order

`open_manifest` does the cheap, key-free checks first and decrypts last:

1. A file longer than `MAX_MANIFEST_LEN` (1 MiB) is refused before anything else is read.
2. A file shorter than header plus MAC is truncated. A wrong magic or unknown version is refused; the version is read
   before the MAC because it decides how the MAC is computed.
3. The MAC is compared in constant time. A mismatch is reported as damaged shared state: the manifest was altered, or
   was not written by this vault, and specification §3.10 says the vault may need recovery.
4. Only then is the vault ID parsed and the ciphertext opened and decoded.

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

The generation increases by exactly one with every manifest the service writes, and never wraps: a manifest at
generation `u64::MAX` cannot be followed. A reader that remembers the last generation it saw can tell a stale copy
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
