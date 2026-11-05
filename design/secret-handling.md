# Secret handling in memory

Spec [§3.11](iron-vault-specification.md#311-recipients-startup-and-memory) requires the service to hold secret values in types that suppress debugging and clear their buffers on
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
| `InitPassphrases` | store | the vault passphrase and the approval passphrase the owner chose at initialization | its `Passphrase` and `ApprovalPassphrase`; the passphrase rules borrow their text and copy none of it | `secret_types_tests` |
| `NewVaultKeys` | store | every key initialization generates, and the recovery key's text for the one reveal | its `SealingKeys` and `RecoveryKeySecret`; `into_sealing` drops the text | `secret_types_tests` |
| `SealingKeys` | store | the vault identity, the operational and recovery `RecipientIdentity`, and the `SoftwareSignerKey` with its pinned approver | its fields; `initialize` takes it by value and each key is dropped after the step that uses it, the vault identity with the `Vault` it creates | `secret_types_tests` |
| `OwnerInput` | iron-vault | the bytes the owner typed in answer to a prompt, in the CLI from the owner console until sent, and in the service from decoding until its handler is done | `Zeroizing<Vec<u8>>`, a private field: the type has no `Clone` and a `Debug` that shows no byte | `secret_types_tests` |
| `RevealedSecret` | iron-vault | a secret value the service shows the owner once in a reveal frame, such as the recovery key's `AGE-SECRET-KEY-1…` text, in the CLI from decoding until it is shown on the terminal; the service never builds one, and encodes the frame straight from the secret's own type (`encode_reveal`) | `Zeroizing<Vec<u8>>`, a private field: the type has no `Clone` and a `Debug` that shows no byte | `secret_types_tests` |
| `AdminResponse` | iron-vault | a `CallerToken` when it is `caller-token`'s result, in the service from issue until the encoded frame is written, and in the CLI from decoding until the token is written to stdout | its `CallerToken`; the encoded frame is a `Zeroizing<Vec<u8>>`, as is the CLI's stdout line | `secret_types_tests` |
| `Frame` | iron-vault | an `OwnerInput` when it is an owner-input frame, a `RevealedSecret` when it is a reveal frame, a `CallerToken` when it is `caller-token`'s result | its `OwnerInput`, `RevealedSecret` or `AdminResponse` | `secret_types_tests` |
| `Decoded` | iron-vault | a decoded `Frame` | its `Frame` | `secret_types_tests` |
| `Scrubber` | iron-vault | a request's `ScrubPatterns`, borrowed for a header scrub or owned for a response body (`Scrubber::owning`), and the bytes held back between chunks, which may be a secret prefix | `Zeroizing<Vec<u8>>` for the held bytes, sized once for the longest pattern so it never reallocates; owned patterns by `ScrubPatterns`; the patterns are never copied | `secret_types_tests` |
| `ResponseContext` | iron-vault | the request's `ScrubPatterns`, moved from `Prepared` to the response stage | its patterns, which move on into the `RelayedBody`'s scrubber | `secret_types_tests` (no `Debug`) |
| `RelayedBody` | iron-vault | a `Scrubber` that owns the request's `ScrubPatterns` and its held bytes, and a `ResponseDecoder` for a coded body | the scrubber and decoder, dropped when the body ends, when it fails (without releasing the held bytes) or when the body is dropped; the upstream chunk in flight and each decoded piece before it is scrubbed are plain `Bytes`, the same exposure as any unscrubbed chunk from the upstream client | `secret_types_tests` (no `Debug`) |
| `ResponseDecoder` | iron-vault | the decompression window and the 64 KiB piece buffer: response plaintext that may echo a secret before the scrubber has seen it | the piece buffer is a `Zeroizing<Vec<u8>>`; brotli's byte buffers, the window up to 16 MiB among them, come from `WipingAlloc` and are `Zeroizing<Vec<u8>>`; the gzip and deflate window (32 KiB) is wiped best-effort: `Inflate`'s `Drop` calls `flate2::Decompress::reset`, and miniz_oxide's reset zeroes the window with ordinary (non-volatile) stores, which a `black_box` keeps the compiler from removing | `secret_types_tests` |
| `ServingSnapshot` | iron-vault | the `Vault`, so every healthy `CredentialRecord` | its `Vault`; shared through an `Arc`, so the vault is cleared when the last request holding the snapshot ends | `secret_types_tests`, `serving_snapshot/tests` |
| `SnapshotHolder` | iron-vault | the current `ServingSnapshot` | the snapshot, once no request holds it | `secret_types_tests`, `serving_snapshot/tests` |
| `RequestHead` | iron-vault | the caller's `HeaderValue`s, which may hold a caller token | each `HeaderValue`; its target text, whose query may hold caller secrets, is not cleared | `secret_types_tests`, `pipeline/tests` (its `Debug` shows the method and header names only) |
| `Prepared` | iron-vault | the `CheckedRequest` and the request's `ScrubPatterns` | its fields | `secret_types_tests`, `pipeline/tests` |
| `ListenerTls` | iron-vault | a TLS listener's signing key, inside its rustls `ServerConfig` | not cleared: see residual copies | `listener_tls/tests` (its `Debug` shows only the listener name and handshake timeout) |

`ScrubPatterns` stores each pattern in a private `ScrubPattern` newtype, which has no `Clone`, `Display` or `Debug`.
It is private to its module, so the test module cannot name it; it is covered through `ScrubPatterns`.

`OwnerInput` and `RevealedSecret` are each decoded by copying the frame body once, straight into a clearing buffer;
neither passes through the admin protocol's field decoder or `serde` (`design/admin-protocol.md`). Each encoded frame
holds the value too, so `encode` and `encode_reveal` write into a buffer the caller supplies, and a caller sending owner
input or a reveal passes a `Zeroizing<Vec<u8>>`. The CLI reads every frame from the service into a clearing buffer sized
once for the largest frame, because a reveal frame holds the value. The CLI writes a `RevealedSecret` only to the controlling terminal, never to stdout
or stderr (`design/vault-initialization.md`).

The CLI also draws each revealed value as a QR code with the `qrcode` crate (no dependencies of its own), on the same
descriptor as the text. The drawn `String` is held in a clearing buffer and overwritten before it is dropped, and the
`QrCode` is dropped as soon as it is drawn. The library's internal module buffers are not cleared. This residual is
accepted: the CLI is short-lived, and it disables core dumps and `ptrace` attachment before it connects
(`design/admin-protocol.md`, "Hardening").

`OperationalIdentity` holds nothing: it only generates a `RecipientIdentity`.

Initialization keeps the recovery key's `RecipientIdentity` from generation (`RecoveryKey::generate_with_identity`)
instead of parsing the revealed text back, so no second copy of that text is ever made.

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

## Streamed response compatibility

Spec [§9](iron-vault-specification.md#9-implementation-gates-and-unresolved-details) asks for measured overlap buffering and SSE latency. `crates/iron-vault/tests/proxy_scrub_stream_linux.rs` runs
the real request server and pipeline against a test upstream that sends scripted chunks, each flushed as its own write.

The scrubber holds back only the tail of the pending bytes that is a proper prefix of some pattern (`Scrubber::scan`
stops at the first such position), at most the longest pattern minus one. A chunk that ends in no such prefix is released
whole, so an SSE event never waits for the next.

**Bytes held back per chunk** come from `measure_bytes_held_back_per_chunk`, as bytes pushed minus bytes the caller
received once none arrived for 150 ms. The test pushes a typical chat-completion event, then a chunk that ends in the
longest pattern minus its last byte, which is the worst case. Run it with `--nocapture`.

| Credential (test stand-in) | Longest pattern | Maximum held | Typical chunk held |
|---|---|---|---|
| FX, static in the `access_key` query slot: 32-byte hex key | 44 bytes | 43 | 0 |
| Generic Basic: 8-byte username, 19-byte password | 46 bytes | 45 | 0 |
| Brave, static: 31-byte key | 44 bytes | 43 | 0 |
| Venice, static: 43-byte key | 60 bytes | 59 | 0 |

The longest pattern is the padded base64 form of a static key, and `Basic <token>` for a Basic credential (a generic
row, not one of the three target credentials). A typical event ends in `\n\n`, which begins no pattern, so nothing is held. A chunk that ends in a pattern's first byte is held
only that far: a chunk ending in `B` holds one byte when a Brave key is injected. The stand-ins have the shape of each
provider's key, not a real key; a longer real key raises the maximum by 4/3 of the difference.

**Latency per SSE event** comes from `measure_sse_latency_per_event`: 200 events, each sent by the upstream only after the
caller has received the one before, timed from the upstream's write to the caller's read, through TLS to the proxy, the
scrubber and the Unix socket. Observed in a debug build on one development machine (Linux 6.8, loopback), twelve runs:
median 75-78 us, 95th percentile 82-106 us, maximum 210-247 us. These are loopback figures with no network, so they
bound the proxy's own cost and do not predict a deployment's.

**Chunk boundaries.** `a_body_split_at_every_byte_offset_scrubs_to_the_same_bytes` sends a body holding every scrub
pattern of a Basic credential and of a static key with URL-reserved characters, split at every byte offset, and requires
the caller to receive exactly the one-shot scrubbed body. `an_sse_event_reaches_the_caller_before_the_next_one_is_sent`
proves the first event is relayed while the upstream is still waiting to send the second, and
`a_streamed_chat_completion_without_the_secret_arrives_unchanged_and_in_at_least_as_many_chunks` checks that traffic
holding no secret is byte-identical and not coalesced.

Not covered here: the HTTP/2 upstream path, whose relay shares the scrubber but is not exercised with scripted chunks.
Compressed bodies are covered in the next section.

### Compressed responses

Spec [§3.8](iron-vault-specification.md#38-responses-redirects-and-scrubbing) and [§9](iron-vault-specification.md#9-implementation-gates-and-unresolved-details) ask for tests that combine compression with chunk boundaries and unchanged traffic, and for measured
decompression limits. `crates/iron-vault/tests/proxy_coding_stream_linux.rs` runs the same assembled service against an
upstream that sends already compressed, scripted chunks; the refusals are in `proxy_coding_linux.rs`.

**Supported codings and refusals.** The service decodes `gzip`, `deflate` (zlib) and `br`, and asks upstreams for
exactly `Accept-Encoding: gzip, deflate, br`. It refuses with `502` and sends none of the body for an unknown coding
(`zstd`), a stacked coding (`gzip, br`) and a coded `206`
(`an_unsupported_or_stacked_coding_is_502_with_none_of_its_body`, `a_coded_partial_content_reply_is_502`). A body that is
corrupt, truncated or past a limit aborts the caller's connection after the head (`a_truncated_gzip_body_aborts_the_connection`,
`a_decompression_bomb_aborts_the_connection_before_a_secret_planted_past_the_limit`). The response sheds
`Content-Encoding` and `Content-Length` unless the caller refuses identity, when it gets gzip of the scrubbed body.

**Default limits.** `max_decompressed_response_bytes` is 64 MiB and `max_decompression_ratio` is 100, checked once 1 MiB
has decoded. `s3_8_the_default_limits_accept_a_10_mib_gzip_json_reply` sends 10 MiB of JSON that gzip shrinks 3.8 times and
requires it byte for byte. `s3_8_a_decompression_bomb_is_cut_off_with_no_chunk_over_one_decoder_step_plus_the_hold_back`
sends 16 MiB of zeros (a thousandfold, 17 KB compressed) with a key planted past the limit, all in one upstream chunk. The
caller's connection is aborted, receives under 2 MiB, never sees the key, and no chunk it received exceeds `PIECE_SIZE`
(64 KiB) plus the longest pattern minus one.

**Peak bytes held per response.** The relay decodes one piece, counts it against the budget, scrubs it, encodes it and
sends it before it decodes the next (`Stages::next_output`, driven from `RelayedBody::poll_frame`), whatever the upstream
chunk size. What a response holds is one piece (`PIECE_SIZE`, 64 KiB), the scrubber's hold-back (the longest pattern minus
one), and the encoder's output for that piece, plus the upstream chunk in flight, which the decoder keeps until it is used
up. The bomb test sends the bomb in a single chunk: the caller receives exactly the 1 MiB the ratio floor allows, in sixteen
64 KiB chunks, and the largest is 65,536 bytes. A valid 10 MiB gzip JSON reply reaches the caller in chunks of at most
65,537 bytes (`measure_gzip_decode_throughput`), where gathering a chunk's output first gave 1.9 MB.

**Latency per gzip SSE event** comes from `measure_gzip_sse_latency_per_event`: 200 events, each coded with a sync flush
and sent only after the caller has the one before, timed from the upstream's write to the moment the caller holds the
event decoded. Median, 95th percentile and maximum on one development machine (Linux 6.8, loopback):

| Build | gzip to identity | gzip to gzip (`identity;q=0`) |
|---|---|---|
| debug | 105 / 113 / 286 us | 127 / 136 / 311 us |
| release | 13 / 16 / 74 us | 15 / 17 / 63 us |

`s3_8_a_gzip_sse_event_reaches_the_caller_decoded_before_the_next_is_sent` and its `..._recompressed_...` twin gate the
upstream on a channel, so they prove the event is relayed before the next exists without a timing threshold.

**Throughput** comes from `measure_gzip_decode_throughput`: a 10 MiB gzip JSON body (2.8 MB compressed) sent in one
write, timed from the caller's request to the end of the response, best of five. Release: 122 ms, 82 MiB/s decoded.
Debug: 3.7 s, 3 MiB/s. It includes TLS to the upstream, decode, scrub and the Unix socket.

**Boundaries.** `s3_8_a_gzip_body_split_at_every_compressed_offset_scrubs_to_the_same_bytes` splits the compressed bytes of a
body holding every pattern of a Basic credential and of a static key at every offset; the `br` test does so at eight.
`s3_8_a_secret_across_two_decoder_output_pieces_is_scrubbed` plants a key across the 64 KiB piece boundary at three
offsets. `s3_8_a_realistic_gzip_json_reply_without_a_secret_decodes_to_the_same_bytes` requires gzip, deflate and br
replies without a secret to decode byte for byte.

## Clearing a vault

`Vault` owns its identity and records by value. The store's production code uses no `Rc`, `Arc`, `OnceLock`,
`LazyLock`, `OnceCell`, `thread_local!` or `static mut`, so no other owner can keep a copy alive after the `Vault` is
dropped. (The service's `ServingSnapshot` shares its vault through an `Arc`: the vault is dropped when the holder has
replaced the snapshot and the last request that loaded it has finished.) `secret_types_tests` checks this by scanning
the store's sources, and asserts `Vault: Send + Sync`, which `Rc` would break.

**Lock** (`ServiceContext::lock`, spec [§3.13](iron-vault-specification.md#313-administration-recovery-and-migration)) drops every owner of a secret in this order. Under the context's mutex,
the holder stops admitting requests and withdraws its snapshots, which cancels the requests running on them, and the
approval state is dropped. The mutex is then released, and the service waits up to the *lock drain* for every
`Arc<ServingSnapshot>` to go. A snapshot has three kinds of holder, and the drain waits for all of them: a request still
running on it, a streaming response body (`RelayedBody`, whose scrubber owns the request's `ScrubPatterns`; the body
wrapper `UntilWithdrawn` holds the snapshot, declared after the body so the patterns drop first), and the holder itself.
Each snapshot ends with a sender that is its last field, so it is released only after the `Vault` and every other field
have been dropped. Everything reachable from `Vault` (the `VaultIdentity`, the `CredentialRecord`s) and from
`ServingSnapshot` clears its buffers on drop, as the inventory shows. The `ActivePolicy` holds caller token hashes and
route policy, and the rate limiter holds counters. The snapshot is the only owner of its upstream clients, so dropping
it closes their idle connections too (next section). The HTTP stack's own copies are in the rows below. `ApprovalState` is not secret-bearing: it holds the vault ID, the generations, the
pinned approver's public key, and the committed version and digest, so dropping it removes a cache, not a secret.

### Upstream connections close with their snapshot

Each upstream connection runs in a task hyper spawns, and that task owns the connection's write buffer, which still
holds the last request's headers, injected credential included, until the connection is dropped. reqwest keeps an idle
connection for reuse for up to 90 seconds. K-131's review recorded these idle connections as able to outlive `lock`;
K-143 checked that and found they close when the snapshot drops or, if a background connect is still running, when it
ends, at most `TransportLimits::connect` later, because of who owns the pool.

**What closes them.** hyper-util's pool (`hyper-util` 0.1.21, `client/legacy/pool.rs`) is one `Arc<Mutex<PoolInner>>`
with three kinds of strong owner: the reqwest `Client`, the futures of requests in flight, and a background connect.
`Client::connect_to` (`client/legacy/client.rs:490`) moves a strong `self.pool.clone()` into the connect future and
holds it until `pool.pooled(...)` (`:655`) inserts the new connection. When an idle connection frees up while a request
is already connecting, the request takes the idle one and `one_connection_for` spawns the started connect as its own
task (`self.exec.execute(bg)`, `:435-446`) so the socket is not wasted. Cancelling the request does not cancel that
task, so it keeps `PoolInner`, and with it every idle credential-bearing connection, alive until the TCP and TLS connect
ends or `TransportLimits::connect` (10 seconds by default; reqwest's `connect_timeout` covers both) expires. Concurrent
HTTP/1 requests to one upstream reach this. The idle-expiry task and the `Connecting` lock, which stops a second HTTP/2
connect, hold only a `Weak`. An idle connection is the pool's handle
to the connection's task (`PoolClient`, a hyper `SendRequest`); while a response body is still streaming, its handle is
held through a `Weak` to the pool and dropped when the body ends. Lock cancels the requests in flight, so once the snapshot drops its clients the last strong owner is a background connect
if one is running, and nothing otherwise. When the last strong owner drops, `PoolInner` drops
every idle handle, and each connection's task, finding its request channel closed, closes the connection and drops its
buffers on its next poll. HTTP/2 connections are held in the same idle list and end the same way.

The service holds each reqwest `Client` inside one `UpstreamClient`, which is not `Clone` and never hands the client
out; the `UpstreamClients` that own them live only in a `ServingSnapshot`. So the pools are dropped when the snapshot is
or, if a background connect is still running, when it ends, at most `TransportLimits::connect` later. The snapshot drops
its clients before the sender it releases last, so without a background connect the lock drain sees the release only
after every idle handle has gone; with one, the drain does not wait for it (residual table below). `after_a_cleared_lock_no_upstream_connection_that_carried_the_credential_is_open`
(`service_context_linux.rs`) and `dropping_the_client_closes_its_idle_connection` (`upstream_client.rs`, and its HTTP/2
twin in `upstream_client_h2.rs`) hold this in place against an upstream that keeps every connection open.

**Decision (K-143): keep the pool, and keep the snapshot its only owner.** The options considered:

- *No idle pooling* (`pool_max_idle_per_host(0)`). The connection's task would then end with its response body, which
  is the same point a pooled connection's task ends on lock: woken when its last handle drops, closed on its next poll.
  It gives no stronger guarantee, and costs every request a new TCP connection and TLS handshake: one round trip for
  TCP and one for TLS 1.3 (two for TLS 1.2), so tens of milliseconds to a nearby provider and 100-300 ms to a distant
  one, and HTTP/2 could no longer multiplex concurrent requests over one connection. Rejected.
- *A short idle timeout plus closing the pools on withdrawal.* Dropping the snapshot already closes them. reqwest
  exposes neither its connection tasks nor its executor, and `connector_layer` cannot wrap the connection it returns
  (`Conn`'s fields are private), so no option can wait for a task to end; a shorter timeout would only narrow the
  copy's life while the service is Ready, when the vault holds the credential anyway. Not needed.
- *Accepting the residual.* What remains is the task's final poll, in the table below.

Anything that adds a second owner of a reqwest `Client` or of `UpstreamClients` (a clone, a cache across reloads, a
client shared between snapshots) breaks this, and must come with a new way to close the pools on lock.

## Known residual copies

| Copy | Why it is accepted, or what removes it |
|---|---|
| The pieces a `ResponseDecoder` yields are plain `Bytes`, and the decoder's compressed-input bit buffers hold a few bytes of upstream data. | A piece is decoded response data not yet scrubbed, the same exposure as an unscrubbed chunk in flight from the upstream client; the scrubber copies it into its own clearing buffer. |
| The gzip and deflate window is wiped with ordinary stores, not volatile ones. | miniz_oxide 0.9.1 zeroes it (`state.dict = [0; ...]`) just before freeing the Box, and nothing in flate2 or miniz_oxide offers a stronger wipe. `Inflate`'s `Drop` passes the state through `black_box` so the compiler keeps the stores, but that is a hint, not a guarantee. The wipe also relies on flate2's `rust_backend` (miniz_oxide): another backend needs the check again. Locked memory (K-45) keeps the window out of swap. |
| `age`'s `StreamWriter` keeps its last 64 KiB plaintext chunk in a buffer it does not wipe (K-33 review). | `age` owns the buffer. Locked memory (K-45) keeps it out of swap. |
| `age`'s `StreamReader` (age 0.12.1, `primitives/stream.rs:410`) keeps the decrypted chunk in a `SecretSlice<u8>`, which is wiped. The AEAD's output `Vec` is 16 bytes larger than the plaintext (room for the tag), so converting it into a `SecretSlice` shrinks it, and the allocator may move it, leaving a freed, unwiped copy of the chunk. | `age` owns the conversion. Locked memory (K-45) keeps it out of swap; the plaintext `sealed::open` returns is in a `Zeroizing` buffer. |
| `age`'s scrypt recipient and identity take a `SecretString` copy of the passphrase (`Passphrase::for_age`), and derive the wrapping key inside `age`. | The copy is a `SecretString` and is wiped; `age`'s internal key derivation is not audited here. Locked memory (K-45) keeps it out of swap. |
| `base64`'s `encode_string`, used by both `CallerToken` constructors, encodes through a 1 KiB stack buffer it does not wipe, leaving a copy of the token's body in a dead stack frame. | The next calls on that thread overwrite it; locked memory (K-45) keeps it out of swap. The 32 raw bytes are held in `Zeroizing` buffers. |
| An upstream connection's task, which owns the connection's write buffer (the last request's headers, the injected credential included), outlives the last handle to it by the task's final poll. The drain waits for the snapshot, not the task, so `lock` can answer `cleared` in that window. | Dropping the snapshot drops its pools, and with them every idle connection's handle, before the drain sees it released ("Upstream connections close with their snapshot" above); a connection still streaming loses its handle when its body drops, which is also before. Each task is woken then and closes on its next poll, normally within microseconds. A TLS `close_notify` that cannot be flushed because the upstream stopped reading keeps it longer, until the kernel accepts the write or the connection fails; reqwest offers no write timeout. A background connect (hyper-util's `one_connection_for` spawning a connect that an idle connection beat, above) holds the pool strongly past the snapshot, so idle connections then lose their handles only when it ends, at most `TransportLimits::connect` (10 seconds by default) after `lock`; the drain does not see this task, so `lock` can answer `cleared` while it runs. The buffer is then freed unwiped, like the next rows. Locked memory (K-45) keeps it out of swap, and core dumps and same-account `ptrace` are off. |
| A request that ignores its cancellation. | `lock` cancels requests where the transport permits ([§3.9](iron-vault-specification.md#39-configuration-approval-and-reload)), but a request blocked in code that never polls its cancellation keeps its `Arc<ServingSnapshot>`, and with it the vault, until it ends. The lock drain bounds the wait and `lock` then answers `cleared` as false and logs the count of snapshots still held, instead of claiming the secrets are gone. |
| The kernel holds owner input outside the CLI: in the terminal's line buffer while the owner types, in the pipe buffer when it is piped, and in the admin socket's buffers in transit. | Outside any process's control. Each buffer is drained by the read that empties it. |
| When SIGINT, SIGQUIT, SIGTERM or SIGHUP arrives after the CLI opened its owner console, its watcher thread restores the terminal if echo is off and calls `process::exit`, which runs no destructors, so a line buffer the main thread is filling is not wiped. | The process exits at once and the kernel frees its memory. Core dumps and same-account `ptrace` are off, so nothing can read the buffer between the signal and the exit. |
| The CLI's memory is not locked, so an owner-input buffer could be swapped out while it lives. | It lives only from the read until the frame is written. The CLI disables core dumps and same-account `ptrace` before connecting; encrypted swap, which the install guide requires, covers the rest. |
| `rustls-pki-types` 1.15.1's `PrivateKeyDer`, which holds a TLS listener's decoded key, implements `Zeroize` but has no `Drop`, so it does not wipe itself on drop. | `ListenerTls::open` moves the decoded key straight into ring's key provider, which wraps it in `Zeroizing` (rustls 0.23.46, `crypto/ring/mod.rs:61`), so the `PrivateKeyDer` buffer itself is wiped as soon as loading returns, whether or not the key loads. Nothing else holds a `PrivateKeyDer`. Copies the loader makes while parsing are the next row. |
| rustls's ring loader converts a SEC1 (`EC PRIVATE KEY`) key to PKCS#8 before ring parses it (rustls 0.23.46, `crypto/ring/sign.rs:245-261`, `convert_sec1_to_pkcs8`). The conversion copies the secret into two `Vec<u8>`s, `sec1_wrap` and `pkcs8` (`x509.rs:12-58`), which are freed without being wiped. `any_ecdsa_type` tries P-256 before P-384, so a P-384 key is converted twice and leaves four such copies. | rustls owns the buffers. When the key loads, it lives on in the listener's signing key (two rows down), so the freed copies expose nothing that row does not. Locked memory (K-45) keeps them out of swap, and core dumps and same-account `ptrace` are off. |
| `rustls-pki-types`' PEM decoder collects a TLS listener key's base64 text in its own buffer (`SliceIter`'s `b64_buf`), which is freed without being wiped. If base64 decoding fails partway through the key's body, the decoder also frees its partly filled `der` output `Vec` without wiping it (rustls-pki-types 1.15.1, `pem.rs:318-323`, the `?` on `Error::Base64Decode` in `read()`), so a key file with a bad character late in its body leaves part of the key in freed memory. | The decoder owns both buffers. A key that decodes lives on in the listener's signing key (next row), so the freed copies expose nothing that row does not; a key that fails to decode stops the listener opening. Locked memory (K-45) keeps both buffers out of swap, and core dumps and same-account `ptrace` are off. |
| A TLS listener's `ServerConfig` holds its signing key (ring's RSA, ECDSA or Ed25519 key pair, in the `CertifiedKey` its certificate resolver holds) for as long as the listener lives, and ring does not wipe it on drop. | The listener must sign every handshake, so the key stays in memory until the listeners are next opened. Locked memory (K-45) keeps it out of swap; core dumps and same-account `ptrace` are off. |
| The `url::Url` inside `UpstreamTarget` and `CheckedRequest` holds a filled query slot and is never wiped, because `Url` owns its buffer. | The service never clones it: it moves from the `UpstreamTarget` into the `CheckedRequest`, and `UpstreamClient::send` moves it out through `CheckedRequest::into_parts` into the `reqwest::Request`. From there it is one of the HTTP stack's copies in the next row, freed unwiped when reqwest drops it. |
| `reqwest`, `hyper` and `http` copy a checked request's URL and header values into their own buffers, which are never wiped: `UpstreamClient::send` moves the URL and copies each header value into a `reqwest::Request`, reqwest keeps a copy of both for the life of the exchange (and the URL in its `Response`), hyper writes them into its connection's write buffer, and HTTP/2 encodes them into HPACK frames. | The libraries own these buffers. Every header value is marked sensitive, so HPACK never adds it to the connection's dynamic table, where it would outlive the request, and `http`'s `Debug` hides it. h2 never adds `:path` to the dynamic table either (`Header::skip_value_index`, h2 0.4.20 `hpack/header.rs:205`), so a filled query slot stays out of it too. No re-send makes another set: reqwest's retry layer would clone the URL and headers before every send in case it retries, but `UpstreamClient::new` sets a policy that never retries and allows zero retries, so it neither re-sends nor clones (reqwest 0.12.28 `retry.rs`, `clone_request`). Errors are classified and dropped without being formatted (`TransportError`). Locked memory (K-45) keeps the copies out of swap. |
