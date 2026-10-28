# Secret handling in memory

Spec §3.11 requires the service to hold secret values in types that suppress debugging and clear their buffers on
release, to minimize copies, and to clear cached values on lock or replacement. This document lists every type that
holds secret bytes, how each one is cleared, and the copies the code knows about but cannot yet avoid.

A **secret-bearing type** is any type whose value contains provider credential bytes, a caller token, a private key or
a passphrase, directly or through a field.

## Rules

Every secret-bearing type:

- has a `Debug` that shows no secret byte, in both `{:?}` and `{:#?}`;
- has no `Display`, `Copy`, `Clone`, `serde::Serialize` or `serde::Deserialize`;
- clears its bytes when dropped, through `secrecy`, `zeroize` or a field type that does.

Each crate's `secret_types_tests` module enforces the trait rule at compile time with `static_assertions`, and checks
the `Debug` rule with a marker secret. Adding a type to this table means adding it to that module.

## Inventory

| Type | Crate | Holds | Cleared by | Allowed trait | Debug check |
|---|---|---|---|---|---|
| `SlotValue` | policy | the credential text for a slot | `SecretString` | none | `secret_types_tests` |
| `HeaderValue` | policy | an outgoing header value, possibly the filled slot or a caller token | its own `Drop`, `zeroize` | none | `secret_types_tests` |
| `OutgoingHeaders` | policy | `HeaderValue`s | each `HeaderValue` | none | `secret_types_tests` |
| `UpstreamTarget` | policy | the upstream URL, whose query may hold a filled query slot | not cleared: see residual copies | none | `secret_types_tests` |
| `OutgoingRequest` | policy | an `UpstreamTarget` and `OutgoingHeaders` | its fields | none | `secret_types_tests` |
| `CheckedRequest` | policy | the final URL and `OutgoingHeaders` | headers by `HeaderValue`; URL not cleared | none | `secret_types_tests` |
| `CredentialMaterial` | kinds | a static key, or a username and password | `SecretString` per field | none | `secret_types_tests` |
| `ScrubPatterns` | kinds | every encoded form of the injected secret | `Zeroizing<Vec<u8>>` per pattern | none | `secret_types_tests` |
| `Resolution` | kinds | a `SlotValue` and its `ScrubPatterns` | its fields | none | `secret_types_tests` |
| `VaultIdentity` | store | the vault's X25519 private key | `age::x25519::Identity`, which zeroizes on drop | none | `secret_types_tests` |
| `RecipientIdentity` | store | a recipient's X25519 private key: operational or recovery | `age::x25519::Identity` | none | `secret_types_tests` |
| `RecoveryKeySecret` | store | the recovery key's `AGE-SECRET-KEY-1…` text | `SecretString` | none | `secret_types_tests` |
| `Passphrase` | store | the owner's passphrase | `SecretString` | none | `secret_types_tests` |
| `CredentialRecord` | store | a `CredentialMaterial` | its material | none | `secret_types_tests` |
| `Vault` | store | the `VaultIdentity` and every healthy `CredentialRecord` | its fields | none | `secret_types_tests` |
| `ApprovalPassphrase` | store | the approver's passphrase for `approver.age` | `SecretString` | none | `secret_types_tests` |
| `SoftwareSignerKey` | store | the software signer's Ed25519 private key | the inner `ed25519_dalek::SigningKey`, which zeroizes on drop (`zeroize` feature) | none | `software_signer/tests` |
| `SoftwareSigner` | store | the opened Ed25519 private key and its `PinnedApprover` | the inner `SigningKey` | none | `software_signer/tests` |

`ScrubPatterns` stores each pattern in a private `ScrubPattern` newtype, which has no `Clone`, `Display` or `Debug`.
It is private to its module, so the test module cannot name it; it is covered through `ScrubPatterns`.

`OperationalIdentity` holds nothing: it only generates a `RecipientIdentity`.

`SoftwareSignerKey` and `SoftwareSigner` do not carry the `ZeroizeOnDrop` marker themselves; only the inner
`SigningKey` does, and dropping the wrapper drops it. Their `Debug` checks build them from a known seed, which only
their own module can do, so they live in `approval/software_signer/tests.rs`; their trait assertions are in
`secret_types_tests` with the rest.

### Transient buffers

Some secrets exist only inside one function call, in a buffer that clears itself on drop. `Zeroizing` derives `Debug`
and `Clone` whenever its contents do, so a `Zeroizing` buffer is safe only while it stays function-local: it must never
become a field of a long-lived type or be logged. Each buffer below is created and dropped within one store or kind
operation.

| Buffer | Where | Type | Notes |
|---|---|---|---|
| Manifest key | `VaultIdentity::derive_key(MANIFEST_KEY_PERSONA)` in `manifest.rs` | `Zeroizing<[u8; 64]>` | Written by `finalize_into` straight into the buffer, then used as the `Blake2bMac` key. |
| Approval-state MAC key | `VaultIdentity::derive_key(APPROVAL_KEY_PERSONA)` in `approval/state/file.rs` | `Zeroizing<[u8; 64]>` | As above. |
| Identity secret text | `VaultIdentity::secret_text` and `RecipientIdentity::secret_text`, sealed by `envelope.rs` and `passphrase.rs`, and moved into `RecoveryKeySecret` by `RecoveryKey::generate` | `SecretString` | `SecretString` has a redacted `Debug` and no `Clone`. |
| Decrypted plaintext | `sealed::open` | `Zeroizing<Vec<u8>>` | Sized from the ciphertext length before reading, so it never reallocates. |
| Record payload | `record::encode` | `Zeroizing<Vec<u8>>` | Sized before filling. |
| Basic `user:pass` | `basic_kind::join` | `Zeroizing<String>` | Sized before filling. |
| Filled query and its encoding | `outgoing_request::filled_query`, `final_check` | `Zeroizing<String>` | Sized before filling; the `url::Url` it is copied into is a residual copy. |

`blake2`'s `zeroize` feature, enabled in the workspace, clears the `Blake2b512` hasher that derives a key and the
`Blake2bMac` state keyed with it when each is dropped. Without it, the key would survive in the dropped MAC's state.

## Clearing a vault

`Vault` owns its identity and records by value. The store's production code uses no `Rc`, `Arc`, `OnceLock`,
`LazyLock`, `OnceCell`, `thread_local!` or `static mut`, so no other owner can keep a copy alive after the `Vault` is
dropped. `secret_types_tests` checks this by scanning the store's sources, and asserts `Vault: Send + Sync`, which
`Rc` would break. The lock state machine that decides when to drop it is EP-23.

## Known residual copies

| Copy | Why it is accepted, or what removes it |
|---|---|
| `age`'s `StreamWriter` keeps its last 64 KiB plaintext chunk in a buffer it does not wipe (K-33 review). | `age` owns the buffer. Locked memory (K-45) keeps it out of swap. |
| `age`'s `StreamReader` (age 0.12.1, `primitives/stream.rs:410`) keeps the decrypted chunk in a `SecretSlice<u8>`, which is wiped. The AEAD's output `Vec` is 16 bytes larger than the plaintext (room for the tag), so converting it into a `SecretSlice` shrinks it, and the allocator may move it, leaving a freed, unwiped copy of the chunk. | `age` owns the conversion. Locked memory (K-45) keeps it out of swap; the plaintext `sealed::open` returns is in a `Zeroizing` buffer. |
| `age`'s scrypt recipient and identity take a `SecretString` copy of the passphrase (`Passphrase::for_age`), and derive the wrapping key inside `age`. | The copy is a `SecretString` and is wiped; `age`'s internal key derivation is not audited here. Locked memory (K-45) keeps it out of swap. |
| The `url::Url` inside `UpstreamTarget` and `CheckedRequest` holds a filled query slot and is never wiped, because `Url` owns its buffer. | The transport epic wipes or avoids it when the request is sent (`TODO(transport epic)` in `outgoing_request.rs`). |
