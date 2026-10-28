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

### Versions

Payload version 1 holds no provider settings or operational state. Specification §3.3 lists both, and both arrive
with OAuth in product phase v1 (§4). Adding them means a new version byte with its own layout, and a reader for every
version still on disk. A reader never guesses at a version it does not know.
