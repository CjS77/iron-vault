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

| Type | Crate | Holds | Cleared by | Debug check |
|---|---|---|---|---|
| `CallerToken` | policy | a caller token's text, `ivt_` and its base64url body | `SecretString` | `secret_types_tests` |
| `SlotValue` | policy | the credential text for a slot | `SecretString` | `secret_types_tests` |
| `BoundCredential` | policy | a borrow of a `SlotValue` and of its record's permitted origins | not an owner: the `SlotValue` it borrows | `secret_types_tests` |
| `HeaderValue` | policy | an outgoing header value, possibly the filled slot or a caller token | its own `Drop`, `zeroize` | `secret_types_tests` |
| `OutgoingHeaders` | policy | `HeaderValue`s | each `HeaderValue` | `secret_types_tests` |
| `UpstreamTarget` | policy | the upstream URL, whose query may hold a filled query slot | not cleared: see residual copies | `secret_types_tests` |
| `OutgoingRequest` | policy | an `UpstreamTarget` and `OutgoingHeaders` | its fields | `secret_types_tests` |
| `CheckedRequest` | policy | the final URL and `OutgoingHeaders` | headers by `HeaderValue`; URL not cleared | `secret_types_tests` |
| `CredentialMaterial` | kinds | a static key, or a username and password | `SecretString` per field | `secret_types_tests` |
| `ScrubPatterns` | kinds | every encoded form of the injected secret | `Zeroizing<Vec<u8>>` per pattern | `secret_types_tests` |
| `Resolution` | kinds | a `SlotValue` and its `ScrubPatterns` | its fields | `secret_types_tests` |
| `VaultIdentity` | store | the vault's X25519 private key | `age::x25519::Identity`, which zeroizes on drop | `secret_types_tests` |
| `RecipientIdentity` | store | a recipient's X25519 private key: operational or recovery | `age::x25519::Identity` | `secret_types_tests` |
| `RecoveryKeySecret` | store | the recovery key's `AGE-SECRET-KEY-1…` text | `SecretString` | `secret_types_tests` |
| `Passphrase` | store | the owner's passphrase | `SecretString` | `secret_types_tests` |
| `CredentialRecord` | store | a `CredentialMaterial` | its material | `secret_types_tests` |
| `ResolvedCredential` | store | a `Resolution`, and a borrow of its record's `PermittedOrigins` | its resolution | `secret_types_tests` |
| `Vault` | store | the `VaultIdentity` and every healthy `CredentialRecord` | its fields | `secret_types_tests` |
| `ApprovalPassphrase` | store | the approver's passphrase for `approver.age` | `SecretString` | `secret_types_tests` |
| `SoftwareSignerKey` | store | the software signer's Ed25519 private key | the inner `Box<ed25519_dalek::SigningKey>`, which zeroizes on drop (`zeroize` feature); built once into its box, so moves copy only the pointer | `software_signer/tests` |
| `SoftwareSigner` | store | the opened Ed25519 private key and its `PinnedApprover` | the inner `Box<ed25519_dalek::SigningKey>`, which zeroizes on drop; `SoftwareSigner::new` takes the box from `SoftwareSignerKey` by pointer | `software_signer/tests` |
| `OwnerInput` | iron-vault | the bytes the owner typed in answer to a prompt, in the CLI from the owner console until sent, and in the service from decoding until its handler is done | `Zeroizing<Vec<u8>>`, a private field: the type has no `Clone` and a `Debug` that shows no byte | `secret_types_tests` |
| `Frame` | iron-vault | an `OwnerInput` when it is an owner-input frame | its `OwnerInput` | `secret_types_tests` |
| `Decoded` | iron-vault | a decoded `Frame` | its `Frame` | `secret_types_tests` |
| `Scrubber` | iron-vault | a borrow of a request's `ScrubPatterns`, and the bytes held back between chunks, which may be a secret prefix | `Zeroizing<Vec<u8>>` for the held bytes, sized once for the longest pattern so it never reallocates; the patterns are borrowed, never copied | `secret_types_tests` |
| `ServingSnapshot` | iron-vault | the `Vault`, so every healthy `CredentialRecord` | its `Vault`; shared through an `Arc`, so the vault is cleared when the last request holding the snapshot ends | `secret_types_tests`, `serving_snapshot/tests` |
| `SnapshotHolder` | iron-vault | the current `ServingSnapshot` | the snapshot, once no request holds it | `secret_types_tests`, `serving_snapshot/tests` |
| `ListenerTls` | iron-vault | a TLS listener's signing key, inside its rustls `ServerConfig` | not cleared: see residual copies | `listener_tls/tests` (its `Debug` shows only the listener name and handshake timeout) |

`ScrubPatterns` stores each pattern in a private `ScrubPattern` newtype, which has no `Clone`, `Display` or `Debug`.
It is private to its module, so the test module cannot name it; it is covered through `ScrubPatterns`.

`OwnerInput` is decoded by copying the frame body once, straight into its clearing buffer; it never passes through
the admin protocol's field decoder or `serde` (`design/admin-protocol.md`). Its encoded frame holds the value too, so
`encode` writes into a buffer the caller supplies, and a caller sending owner input passes a `Zeroizing<Vec<u8>>`.

`OperationalIdentity` holds nothing: it only generates a `RecipientIdentity`.

`SoftwareSignerKey` and `SoftwareSigner` do not carry the `ZeroizeOnDrop` marker themselves; only the inner
boxed `SigningKey` does, and dropping the wrapper drops it. Their `Debug` checks build them from a known seed, which
only their own module can do, so they live in `approval/software_signer/tests.rs`; their trait assertions are in
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
| CLI line buffer | `read_raw_line` in `cli/console.rs` | `Zeroizing<Vec<u8>>` | Holds the line the owner types, filled one byte at a time and sized once for the longest line, so it never reallocates. With its line ending stripped it becomes the `OwnerInput`. Stdin is read through a duplicate of its descriptor, bypassing `io::Stdin`'s buffer, which is never cleared. |
| CLI owner-input frame | `send_input` in `cli/client.rs` | `Zeroizing<Vec<u8>>` | The encoded frame, sized for it before encoding; dropped with the `OwnerInput` as soon as it is written to the socket. |
| Administrator-installed file | `admin_file::read` in `admin_file.rs` | `Zeroizing<Vec<u8>>` | Holds a TLS listener key (or certificate) read from disk. Sized from the open file's `fstat` length before reading, so it never reallocates; a file that grows or shrinks while being read is refused. Returned to the caller, which must parse it and drop it within the same listener setup. |
| Scrubber pending bytes | `Scrubber::push` in `scrub.rs` | `Zeroizing<Vec<u8>>` | The held bytes followed by the new chunk, sized for both before filling, so it never reallocates; the scan runs over it and its unmatched tail becomes the new held bytes. The chunk the caller passes is the HTTP stack's buffer, not the scrubber's. |
| Admin read buffer | `Exchange` in `admin/server.rs` | `Zeroizing<Vec<u8>>` | Holds each frame, owner input included, before decoding. Sized once for the largest frame and never reallocated; the bytes of each frame are cleared once it is decoded. It is a field of the per-connection `Exchange`, which has no `Debug` or `Clone` and is dropped when the connection closes. |

`blake2`'s `zeroize` feature, enabled in the workspace, clears the `Blake2b512` hasher that derives a key and the
`Blake2bMac` state keyed with it when each is dropped. Without it, the key would survive in the dropped MAC's state.

## Clearing a vault

`Vault` owns its identity and records by value. The store's production code uses no `Rc`, `Arc`, `OnceLock`,
`LazyLock`, `OnceCell`, `thread_local!` or `static mut`, so no other owner can keep a copy alive after the `Vault` is
dropped. (The service's `ServingSnapshot` shares its vault through an `Arc`: the vault is dropped when the holder has
replaced the snapshot and the last request that loaded it has finished.) `secret_types_tests` checks this by scanning
the store's sources, and asserts `Vault: Send + Sync`, which `Rc` would break. The lock state
machine that decides when to drop it is EP-23.

## Known residual copies

| Copy | Why it is accepted, or what removes it |
|---|---|
| `age`'s `StreamWriter` keeps its last 64 KiB plaintext chunk in a buffer it does not wipe (K-33 review). | `age` owns the buffer. Locked memory (K-45) keeps it out of swap. |
| `age`'s `StreamReader` (age 0.12.1, `primitives/stream.rs:410`) keeps the decrypted chunk in a `SecretSlice<u8>`, which is wiped. The AEAD's output `Vec` is 16 bytes larger than the plaintext (room for the tag), so converting it into a `SecretSlice` shrinks it, and the allocator may move it, leaving a freed, unwiped copy of the chunk. | `age` owns the conversion. Locked memory (K-45) keeps it out of swap; the plaintext `sealed::open` returns is in a `Zeroizing` buffer. |
| `age`'s scrypt recipient and identity take a `SecretString` copy of the passphrase (`Passphrase::for_age`), and derive the wrapping key inside `age`. | The copy is a `SecretString` and is wiped; `age`'s internal key derivation is not audited here. Locked memory (K-45) keeps it out of swap. |
| `base64`'s `encode_string`, used by both `CallerToken` constructors, encodes through a 1 KiB stack buffer it does not wipe, leaving a copy of the token's body in a dead stack frame. | The next calls on that thread overwrite it; locked memory (K-45) keeps it out of swap. The 32 raw bytes are held in `Zeroizing` buffers. |
| The kernel holds owner input outside the CLI: in the terminal's line buffer while the owner types, in the pipe buffer when it is piped, and in the admin socket's buffers in transit. | Outside any process's control. Each buffer is drained by the read that empties it. |
| When SIGINT, SIGQUIT or SIGTERM arrives while the CLI has the terminal open, its watcher thread restores the terminal and calls `process::exit`, which runs no destructors, so a line buffer the main thread is filling is not wiped. | The process exits at once and the kernel frees its memory. Core dumps and same-account `ptrace` are off, so nothing can read the buffer between the signal and the exit. |
| The CLI's memory is not locked, so an owner-input buffer could be swapped out while it lives. | It lives only from the read until the frame is written. The CLI disables core dumps and same-account `ptrace` before connecting; encrypted swap, which the install guide requires, covers the rest. |
| `rustls-pki-types` 1.15.1's `PrivateKeyDer`, which holds a TLS listener's decoded key, implements `Zeroize` but has no `Drop`, so it does not wipe itself on drop. | `ListenerTls::open` moves the decoded key straight into ring's key provider, which wraps it in `Zeroizing` (rustls 0.23.46, `crypto/ring/mod.rs:61`), so the `PrivateKeyDer` buffer itself is wiped as soon as loading returns, whether or not the key loads. Nothing else holds a `PrivateKeyDer`. Copies the loader makes while parsing are the next row. |
| rustls's ring loader converts a SEC1 (`EC PRIVATE KEY`) key to PKCS#8 before ring parses it (rustls 0.23.46, `crypto/ring/sign.rs:245-261`, `convert_sec1_to_pkcs8`). The conversion copies the secret into two `Vec<u8>`s, `sec1_wrap` and `pkcs8` (`x509.rs:12-58`), which are freed without being wiped. `any_ecdsa_type` tries P-256 before P-384, so a P-384 key is converted twice and leaves four such copies. | rustls owns the buffers. When the key loads, it lives on in the listener's signing key (two rows down), so the freed copies expose nothing that row does not. Locked memory (K-45) keeps them out of swap, and core dumps and same-account `ptrace` are off. |
| `rustls-pki-types`' PEM decoder collects a TLS listener key's base64 text in its own buffer (`SliceIter`'s `b64_buf`), which is freed without being wiped. If base64 decoding fails partway through the key's body, the decoder also frees its partly filled `der` output `Vec` without wiping it (rustls-pki-types 1.15.1, `pem.rs:318-323`, the `?` on `Error::Base64Decode` in `read()`), so a key file with a bad character late in its body leaves part of the key in freed memory. | The decoder owns both buffers. A key that decodes lives on in the listener's signing key (next row), so the freed copies expose nothing that row does not; a key that fails to decode stops the listener opening. Locked memory (K-45) keeps both buffers out of swap, and core dumps and same-account `ptrace` are off. |
| A TLS listener's `ServerConfig` holds its signing key (ring's RSA, ECDSA or Ed25519 key pair, in the `CertifiedKey` its certificate resolver holds) for as long as the listener lives, and ring does not wipe it on drop. | The listener must sign every handshake, so the key stays in memory until the listeners are next opened. Locked memory (K-45) keeps it out of swap; core dumps and same-account `ptrace` are off. |
| The `url::Url` inside `UpstreamTarget` and `CheckedRequest` holds a filled query slot and is never wiped, because `Url` owns its buffer. | The service never clones it: it moves from the `UpstreamTarget` into the `CheckedRequest`, and `UpstreamClient::send` moves it out through `CheckedRequest::into_parts` into the `reqwest::Request`. From there it is one of the HTTP stack's copies in the next row, freed unwiped when reqwest drops it. |
| `reqwest`, `hyper` and `http` copy a checked request's URL and header values into their own buffers, which are never wiped: `UpstreamClient::send` moves the URL and copies each header value into a `reqwest::Request`, reqwest keeps a copy of both for the life of the exchange (and the URL in its `Response`), hyper writes them into its connection's write buffer, and HTTP/2 encodes them into HPACK frames. | The libraries own these buffers. Every header value is marked sensitive, so HPACK never adds it to the connection's dynamic table, where it would outlive the request, and `http`'s `Debug` hides it. h2 never adds `:path` to the dynamic table either (`Header::skip_value_index`, h2 0.4.20 `hpack/header.rs:205`), so a filled query slot stays out of it too. No re-send makes another set: reqwest's retry layer would clone the URL and headers before every send in case it retries, but `UpstreamClient::new` sets a policy that never retries and allows zero retries, so it neither re-sends nor clones (reqwest 0.12.28 `retry.rs`, `clone_request`). Errors are classified and dropped without being formatted (`TransportError`). Locked memory (K-45) keeps the copies out of swap. |
