# Admin protocol

The CLI and the service talk only over the admin socket (spec [§3.2](iron-vault-specification.md#32-service-and-cli-boundary)). This document specifies the bytes they exchange:
the **admin protocol**. Terms are defined in the [glossary](glossary.md). The codec is `iron_vault::admin::protocol`;
it is pure and does no I/O. The [admin socket](#admin-socket) section specifies the service's transport:
binding, the peer check and the server loop (`iron_vault::admin::socket` and `iron_vault::admin::server`).

Three properties drive the design:

- **Versioned and deterministic.** Every value has exactly one encoding, so decoding and re-encoding an accepted frame
  reproduces its bytes, and a peer can never be talked into reading one frame two ways.
- **Hostile input is an error, never a crash.** A peer can only make the decoder return a typed error. Nothing it
  sends makes the decoder allocate more than the body bound.
- **Owner input stays out of general-purpose code.** It has its own frame kind, is never parsed as fields, and never
  passes through `serde`, logs or error messages.

## Exchange

One connection carries one exchange:

1. The CLI sends one **admin request**: a command and its arguments.
2. The service sends zero or more **prompts** and **notices**, in any order. The CLI answers each prompt with exactly
   one **owner input** frame before the service sends anything else. A notice is shown to the owner and never answered.
3. The service sends exactly one **admin response**, success or error, and closes the connection.

The service, not the CLI, decides what to prompt for: the service owns the operation ([§3.2](iron-vault-specification.md#32-service-and-cli-boundary)), so a modified CLI cannot
skip a step by not asking for it. A frame of a kind the receiver does not expect at that point in the exchange ends
it: the service answers with an `unexpected-frame` error response and closes; the CLI reports the fault and closes.

```mermaid
sequenceDiagram
    participant CLI
    participant Service
    CLI->>Service: admin request
    loop zero or more times
        alt prompt
            Service->>CLI: prompt (label, secret?)
            CLI->>Service: owner input
        else notice
            Service->>CLI: notice (text)
        end
    end
    Service->>CLI: admin response (success or error)
    Note over Service: closes the connection
```

## Frame

Every frame is a 7-byte header followed by its body. Integers are big-endian.

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 2 | protocol version | `u16`, `1` |
| 2 | 1 | frame kind | `u8`, see below |
| 3 | 4 | body length | `u32`, at most 65 536 |
| 7 | body length | body | depends on the frame kind |

| Kind | Frame | Sent by | Body |
|---|---|---|---|
| `1` | admin request | CLI | fields |
| `2` | prompt | service | fields |
| `3` | owner input | CLI | the value itself |
| `4` | admin response: success | service | no fields (empty) |
| `5` | admin response: error | service | fields |
| `6` | notice | service | fields |

The body bound is 64 KiB (65 536 bytes). It is far above any label, message or typed value an operation needs, and
small enough that a hostile length costs nothing. A body length above the bound is refused as soon as the header is
read, before any body byte is read or any buffer is sized from it.

The decoder checks the header in this order: version, then kind, then length, so a peer speaking a newer version is
always told so, even when its frame kinds are unknown here. A peer may send fewer bytes than a frame needs; the decoder
then asks for more (`NeedMore(n)`: at least `n` more bytes before it can make progress) and the transport reads on.
Bytes after a complete frame belong to the next frame.

## Body encoding

Every body except owner input is a sequence of **fields**:

| Size | Field part |
|---|---|
| 2 | tag, `u16` |
| 4 | value length, `u32` |
| value length | value |

- Tags are **strictly ascending**. A repeated tag, or a tag lower than the one before it, is an error, so field order
  cannot vary and no field can appear twice.
- Every field a frame kind defines is required, and no other tag is allowed: a missing field and an unknown tag are
  both errors. A later version adds optional fields, if it needs them, by bumping the protocol version.
- A field must fit inside the body; a field header or value that runs past the end of the body is an error.
- Integer values have a fixed width; any other length is an error.
- Text values are UTF-8, checked on decode.
- A flag is one byte, `0` (false) or `1` (true); any other byte is an error.
- A byte value is taken as is. The codec checks only its length, against the limit its field defines, and never
  interprets, normalizes or re-encodes it, so the bytes decoded are the bytes sent.

### Admin request (kind 1)

| Tag | Field | Value |
|---|---|---|
| 1 | command | `u16` command ID |

A command's arguments, when it has any, follow at tags 2 and up, defined with the command. An unknown command ID is
an error.

| Command ID | Command | Arguments | Result |
|---|---|---|---|
| `1` | `ping` | none | the deployment profile |
| `2` | `config approve` | the proposed config bytes | the committed version, the config digest and the summary headline |
| `4` | `unlock` | none | none |
| `5` | `lock` | none | whether every cached secret was confirmed cleared |
| `6` | `status` | none | the [status report](#status) |

**No command accepts an external signature** ([§3.2](iron-vault-specification.md#32-service-and-cli-boundary)). The service signs only the pending config of its own approval
transaction, and no command takes a signature, an approval envelope or a signing key as an argument, or as owner
input. Normal loading verifies only the `config.toml.sig` the service itself published. A later command that would
take any of these is out of bounds for this protocol, whatever it is for.

`ping` changes nothing; the service answers it with a success response naming its deployment profile. The response's
frame header already carries the service's protocol version, so the result does not repeat it. `ping` lets the CLI
check that the service is up and which profile it runs before the real commands exist.

#### lock

Clears the vault identity and every cached secret from the service's memory (spec [§3.13](iron-vault-specification.md#313-administration-recovery-and-migration), [§3.11](iron-vault-specification.md#311-recipients-startup-and-memory)) and moves the service
from Ready to Locked. It takes no arguments and no prompt. In order, the service stops admitting requests, withdraws the
serving snapshot so requests running on it stop where the transport permits ([§3.9](iron-vault-specification.md#39-configuration-approval-and-reload)), and drops the approval state. It
then waits for the last holder of the old snapshot, a request or a streaming response body, to release it (the *lock
drain*, at most 10 seconds). The vault, which the snapshot owns, is dropped when that last holder releases it, so during
the drain the vault may still be in memory.

The success result:

| Tag | Field | Value |
|---|---|---|
| 2 | cleared | flag: `1` when every snapshot was released within the drain, `0` when a request still held one |

`cleared` `0` is a success, not an error: the service is Locked and admits nothing, but a request that ignored its
cancellation still holds secrets until it ends, and the service logs how many. The CLI prints `locked` for `1`, and for
`0` also a warning on stderr that secrets may remain in memory; both exit with code `0`. Only a Ready service locks: in
any other state the command fails with `wrong-state`.

#### config approve

Runs the approval transaction (spec [§3.9](iron-vault-specification.md#39-configuration-approval-and-reload); [config-approval.md](config-approval.md#the-transaction)) on the bytes the
owner proposes.

| Tag | Field | Value |
|---|---|---|
| 2 | config | byte value: the exact proposed config, at most `MAX_CONFIG_LEN` (61,440) bytes |

The decoder refuses a longer config as `malformed-frame`, so a request body is never above 61,454 bytes, inside the
frame bound. The bytes are a byte value, not text: the service's config parser reports a non-UTF-8 config as an
invalid config, with its own message, and the digest covers the bytes exactly as sent.

The exchange, after the request:

1. The service writes the pending config and validates it. An invalid config ends the exchange with `config-invalid`
   before any prompt.
2. **Summary.** The service sends the approval summary as one or more notices: the header (vault ID, the version this
   approval will commit, the config digest, the committed version), then the sections in their fixed order. A summary
   longer than one notice continues in the next, and nothing is ever truncated (see [Notice](#notice-kind-6)).
3. **Confirmation.** A prompt, not secret: `Approve this config as version <n>? Type yes to approve`. Any answer other
   than exactly `yes` ends the exchange with `declined`. No version is reserved.
4. **Approval passphrase.** A prompt, secret: `Approval passphrase`. The service opens the approver key with it. A
   wrong passphrase ends the exchange with `approval-denied`, still before any reservation. There is no second try in
   the same exchange. Summary, confirmation, then passphrase is the order of [§3.9](iron-vault-specification.md#39-configuration-approval-and-reload)'s sequence diagram, which its text
   words differently ([open question 6](config-approval.md#open-questions)).
5. The service runs steps 2 to 6 of the transaction, including the config check after the commit, and answers once
   the check has ended, with the result or an error below. A success means the new config is active.

A prompt that gets no owner input cancels the command, as for every command, before a version is reserved. The service
answers within the CLI's 60-second timeout after the passphrase: scrypt, three durable replaces, two renames, a
directory fsync and a signature check take a few seconds.

The success result:

| Tag | Field | Value |
|---|---|---|
| 2 | committed version | `u64` |
| 3 | config digest | byte value, exactly 32 bytes: BLAKE2b-256 of the approved config |
| 4 | summary headline | UTF-8 text: one line of counts per summary section |

The full summary was already shown as notices before the confirmation, and goes to the audit log. The result carries
only the headline, which is bounded whatever the config's size, so the response always fits in one frame. The CLI
prints `approved version <n> (blake2b:<64 hex>)` and the headline to stdout.

Errors specific to `config approve`:

| Code | When | Version consumed |
|---|---|---|
| `busy` | another approval, vault write or reload holds the service-wide lock | no |
| `config-invalid` | the proposed config fails parsing, validation or activation; the message names the rule and the configured names involved, escaped, and never quotes other config bytes | no |
| `declined` | the owner did not answer the confirmation with `yes` | no |
| `approval-denied` | the approval passphrase did not open the approver key, or the key it opened is not the pinned approver | no |
| `approval-unavailable` | the service cannot approve now: its state does not allow it (only Ready and Unavailable with an invalid policy do), the approval state is damaged, the version counter is exhausted, or a write failed before any version was reserved; the message says which | no |
| `approval-failed` | the transaction failed after its reservation and before its commit; the active policy is unchanged | yes; the message names it |
| `committed-not-active` | the commit landed, or may have landed, but it could not be settled, published or activated; the service is Unavailable, and a reload does not leave that state: only an authorized repair (`Repaired`, then Checking) or a restart does | yes; the message names the version |

#### unlock

Opens the vault with the interactive passphrase (spec [§3.11](iron-vault-specification.md#311-recipients-startup-and-memory), [§3.12](iron-vault-specification.md#312-service-states-and-errors), [§3.13](iron-vault-specification.md#313-administration-recovery-and-migration)). It is allowed only while the service is
Locked; in any other state the exchange ends with `wrong-state` before any prompt, and the state is unchanged.

1. **Vault passphrase.** A prompt, secret: `Vault passphrase`. The value is the vault-unlock passphrase, never the
   approval passphrase: the two are separate types, and unlocking never implies authority to approve. Empty or
   non-UTF-8 input cannot be the passphrase and is answered as a wrong one.
2. The service checks the state again under the service context's mutex, so two unlocks never both open the vault,
   and opens `operational.age` with the passphrase, then `identity.age` with the operational identity, which is
   dropped as soon as the vault identity is unwrapped ([§3.10](iron-vault-specification.md#310-vault-structure-and-durable-writes)). A wrong passphrase ends the exchange with
   `unlock-denied`, whose message is only `wrong passphrase`; an envelope that cannot be read or opened ends it with
   `unlock-failed`. Either way the service stays Locked, and no other storage is tried (R-22). There is no second try
   in the same exchange.
3. The service moves to Checking and runs the config check. Ready answers with a success without a result.
   Unavailable answers `unlocked-unavailable`, and the message names the redacted reason (`policy invalid` or
   `recovery needed`), never the check's detail, which goes to the log at WARN.

Each state change is logged at INFO as a lock transition, under the target `iron_vault::lock_transition`, naming the two
states and nothing the owner typed. scrypt and the config check take a few seconds, inside the CLI's 60-second timeout.

### Prompt (kind 2)

| Tag | Field | Value |
|---|---|---|
| 1 | label | UTF-8 text the CLI shows the owner |
| 2 | secret | flag: when `1`, the CLI turns terminal echo off while the owner types |

### Notice (kind 6)

| Tag | Field | Value |
|---|---|---|
| 1 | text | UTF-8 text the CLI shows the owner, continuing the previous notice's text; `\n` ends a line |

A notice carries text the service needs the owner to read before a prompt, such as an approval summary. It is never
answered. Unlike a prompt label, it may hold many lines, and a command may send as many notices as it needs, so text
of any length reaches the owner without changing the frame bound. A single prompt label could not carry it: a label is
one line, because the CLI removes control characters from it, newlines included.

The CLI writes the texts of consecutive notices one after another and adds nothing between them, so a notice
boundary means nothing to the owner. The service may therefore split text anywhere between two UTF-8 characters, even
inside a line, and does so whenever the next piece would make the body longer than the frame bound. A long line, such
as a route's path patterns after escaping, is split this way across notices. It is never truncated, because the owner
must see everything the service will sign.

### Owner input (kind 3)

The body is the value the owner typed, whole and unframed; it may be empty. It is never parsed as fields. The decoder
copies it once, straight from the received bytes into a buffer that clears itself on drop (`Zeroizing<Vec<u8>>`),
and wraps that in `OwnerInput`, a secret-bearing type (`design/secret-handling.md`). The receiving operation turns it
into its own secret type, such as a passphrase.

The encoder writes the frame into a buffer the caller supplies, so a caller sending owner input passes a clearing
buffer. The transport that reads frames off the socket clears its read buffer for the same reason.

### Admin response: success (kind 4)

A command without a result answers with an empty body. A command with a result answers with fields:

| Tag | Field | Value |
|---|---|---|
| 1 | command | `u16` ID of the command this answers |
| 2 and up | result | defined with the command |

`config approve`'s result is defined [with the command](#config-approve).

Naming the command keeps the codec context-free: a success body decodes on its own, without knowing which request it
answers, and the CLI can check that it answers the request it sent. A body that names a command without a result, or
an unknown command, is an error.

`ping`'s result:

| Tag | Field | Value |
|---|---|---|
| 2 | deployment profile | `u8`: `1` protected, `2` development |

#### status

`status` changes nothing and is answered in every state ([§3.12](iron-vault-specification.md#312-service-states-and-errors)), including Locked and Unavailable, so the owner can
diagnose why requests fail. The result is the **status report**: fields, never one preformatted string, so the CLI
renders them and tests assert on values. Every collection is in name order, and the report holds no secret value, record
digest or permitted origin.

| Tag | Field | Value |
|---|---|---|
| 2 | service state | `u8`: `1` starting, `2` locked, `3` checking, `4` ready, `5` unavailable, `6` stopped |
| 3 | unavailable reason | `u8`: `0` none, `1` policy invalid, `2` recovery needed; non-zero exactly when the state is `5` |
| 4 | deployment profile | `u8`: `1` protected, `2` development |
| 5 | vault ID | byte value: empty while the vault is locked, otherwise the 16 raw bytes of the vault ID |
| 6 | committed approval version | `u64`: `0` when none is committed, and while the vault is locked |
| 7 | highest reserved approval version | `u64`: `0` while the vault is locked |
| 8 | memory protection | `u8`: `1` locked against swap, `2` unavailable, `3` unsupported |
| 9 | memory protection detail | UTF-8 text: why memory is not locked; empty when it is locked or unsupported |
| 10 | credentials | byte value: the credential list below; empty while the vault is locked |

The vault ID, both approval versions and the credentials are sealed behind the vault identity (`approval.age`, the
manifest), so they are unknown while the vault is locked. The vault is locked in Starting and Locked, and also in
Unavailable: a failed config check drops the vault and its identity, so the service holds no ID, version or
credential state to report there. The CLI shows these as unknown rather than guessing. An empty vault ID is how the
report says the vault is locked; an unlocked vault with no credentials has a non-empty vault ID and an empty list.

Memory protection is reported from the process hardening report and never claims swap protection unless `mlockall`
succeeded ([§3.11](iron-vault-specification.md#311-recipients-startup-and-memory)).

The credential list is one entry per credential in the vault manifest, in credential-name order:

| Size | Part |
|---|---|
| 1 | name length `n`, 1 to 64 |
| `n` | credential name |
| 1 | standing: `0` healthy, `1` damaged: record missing, `2` damaged: record substituted, `3` damaged: record unreadable |
| 2 | `u16` count `r` of routes this credential makes unavailable |
| `r` times | route name length (1 byte) then the route name, in route-name order |

A healthy credential makes no route unavailable. A needs-login standing joins this table with OAuth (v1).

### Admin response: error (kind 5)

| Tag | Field | Value |
|---|---|---|
| 1 | error code | `u16`, from the table below |
| 2 | message | UTF-8 text the service wrote |

The error code is stable, so scripts can act on it; the message is for the owner and may change. The service writes
the message itself, and neither the code nor the message ever contains owner input. An unknown error code is an error.

| Code | Name | Meaning |
|---|---|---|
| `1` | `unsupported-version` | the request frame's protocol version is not the service's |
| `2` | `malformed-frame` | the frame broke a rule in this document |
| `3` | `unknown-command` | the command ID is not one the service knows |
| `4` | `unexpected-frame` | a well-formed frame arrived out of turn in the exchange |
| `5` | `not-admin-principal` | the connecting account is not an admin principal; nothing it sent was read |
| `6` | `busy` | the service is already serving as many admin connections as it allows, or another operation holds the lock a command needs; try again |
| `7` | `config-invalid` | `config approve`: the proposed config is invalid |
| `8` | `declined` | the owner declined at a confirmation prompt |
| `9` | `approval-denied` | `config approve`: the approval passphrase was wrong |
| `10` | `approval-unavailable` | `config approve`: the service cannot run an approval now |
| `11` | `approval-failed` | `config approve`: failed after reserving a version, before committing it |
| `12` | `committed-not-active` | `config approve`: committed, but not yet published or active |
| `13` | `wrong-state` | the command is not allowed in the service's current state; the message names the state |
| `14` | `unlock-denied` | `unlock`: the vault passphrase was wrong |
| `15` | `unlock-failed` | `unlock`: the vault did not open, for a reason other than the passphrase; the service stays Locked |
| `16` | `unlocked-unavailable` | `unlock`: the vault unlocked, but the config check left the service Unavailable; the message names the redacted reason |

## Versions

This document specifies protocol version 1, the only version the codec reads or writes. A frame of any other version
is refused before its kind or length is read. Version 1 has not been released, so the notice frame, byte values,
`config approve` (command 2), `unlock` (command 4), `lock` (command 5), `status` (command 6) and error codes 7 to 16
join it rather than starting version 2. That is a default for the owner to confirm
([open question 11](config-approval.md#open-questions)).

Only the service sends responses, so the version rule is asymmetric:

- **The service** answers a frame with an unsupported version with one `unsupported-version` error response, encoded
  at its own version, and closes. A newer CLI can still read the header of that response and tell the owner which
  version the service speaks.
- **The CLI** that receives a frame with an unsupported version reports the mismatch, naming both versions, and
  closes.

## Errors

Decoding errors are typed (`FrameError`). They name protocol numbers, such as a version, frame kind, tag or command
ID, and never contain body bytes, so no error can carry owner input into a log or a response message.

## Admin socket

The service serves the admin protocol on `admin.sock` in its runtime directory (spec [§3.2](iron-vault-specification.md#32-service-and-cli-boundary), [§3.4](iron-vault-specification.md#34-caller-authentication-and-listeners)).

**Binding.** A leftover file at the path is removed only when `lstat` shows a socket owned by the service account;
a regular file, a symlink, or a socket another account owns stops startup with an error naming the path. The service
creates the socket and binds it, sets the path's mode to `0600` while the socket is not yet listening, and only then
listens. The kernel refuses a connection to a socket that is not listening, so the socket is never connectable at the
mode it was created with. The process umask is never changed: it is process-wide and would race with other threads.
The result is checked with `lstat`: a socket owned by the service account with mode `0600`, or startup fails.

**One exchange per connection**, in this order:

1. Over the connection cap (4 open exchanges), the service answers `busy` and closes.
2. The service reads the peer identity the kernel recorded at connect and checks it against the admin principals
   before reading a single byte. A refused peer gets one `not-admin-principal` error response and the connection
   closes; the refusal is logged at WARN with the peer's uid and pid.
3. It reads one admin request within the request deadline of 30 seconds. A connection that sends no complete frame
   in time, or closes first, is closed without a response.
4. It dispatches the request to the handler registered for its command, with the admin principal and the exchange,
   through which the handler sends prompts. A frame that does not decode gets the error response its fault maps to
   (`unsupported-version`, `unknown-command`, or `malformed-frame`); a well-formed frame of another kind gets
   `unexpected-frame`.
5. It writes the admin response and closes.

**Prompts.** A handler asks the owner for a value with `Exchange::prompt`. The service writes the prompt within the
request deadline, then waits for the owner input under the prompt deadline of 5 minutes, longer than the request
deadline because a person is typing. A prompt that gets no owner input cancels the command: `prompt` returns an
`ExchangeError`, and the handler returns it, typically with `?`, before it changes anything. How the exchange ends
depends on why:

| What happened at the prompt | The exchange ends |
|---|---|
| The CLI closed, the connection failed, or the prompt deadline passed | closed without a response, as when no admin request arrives |
| The answer does not decode | with the error response its fault maps to, as for a request |
| The answer is a well-formed frame other than owner input | with `unexpected-frame` |

Each cancellation is logged at WARN with the command's name and the reason, which never holds a frame body.

The log names the accepted principal's uid and the command at INFO, and never a frame body. The buffer the service
reads frames into is allocated once at the largest frame size, clears itself on drop, and is cleared after each frame,
because it holds owner input before decoding.

**Shutdown.** On SIGTERM or SIGINT the service stops accepting, gives open exchanges up to 5 seconds to finish,
abandons any still open, and removes the socket file. Once the socket is listening, the service removes the file on
every exit, an early error included, but only while `lstat` still shows the device and inode it bound, so a file
someone else has since put at the path is left alone. A socket that fails the check or `listen` while binding stays at
the path, never connectable, until the next start replaces it as stale.

## CLI client

The CLI (`iron-vault`, module `cli`) runs one exchange per command over a blocking Unix stream. It connects to
`admin.sock` in its deployment profile's runtime directory, or to the path `--admin-socket` names, such as a socket
forwarded over SSH; the service judges whoever arrives either way.

A refused or `busy` connection is answered and closed without the service reading the request, so the CLI's write
may fail with a reset or broken pipe while the answer is already waiting. The CLI always reads for the admin response
and reports a failed write only when no response arrives. It reads no more bytes than the decoder asks for, so a reset
after the last frame does not hide it.

| Exit code | Meaning |
|---|---|
| `0` | the command succeeded |
| `1` | the service answered with an error response |
| `2` | usage error |
| `3` | no admin response: no socket or nothing listening, permission denied, the exchange failed or timed out, or a prompt got no value |
| `4` | `status`: the service answered, and it is not Ready |
| `128 + n` | signal `n` while the CLI had the terminal open for prompting: `130` for SIGINT, `131` for SIGQUIT, `143` for SIGTERM |

A `not-admin-principal` response or a permission-denied connect tells the owner that a protected install needs `sudo`.
Diagnostics name the socket path, the error code and the service's message, never the request's arguments.

**Timeout.** Each read and write on the admin socket gives up after 60 seconds, so a wedged service or a stalled
forwarded socket ends the command with exit code 3 instead of hanging it. The timeout bounds socket calls only. While
the owner types, the CLI is reading the terminal or stdin, not the socket, so time at a prompt never counts against it;
the service's prompt deadline bounds that wait on the other side. 60 seconds is longer than the request deadline,
within which the service writes every prompt and response once it starts writing. It does not bound the handler's own
work after an owner input arrives: that time, until the next frame, counts against the client's 60 seconds. Commands
whose steps after a prompt can be slow, such as scrypt, a TPM, a touch or OAuth, will need a longer client timeout or
a progress frame.

**Hardening.** Before connecting, a client command disables core dumps: `RLIMIT_CORE` 0, and `PR_SET_DUMPABLE` 0,
which also keeps other processes of the same account from attaching with `ptrace` and reading what the owner typed. A
failure is reported on stderr as a warning and the command goes on, because it would hold only what the owner is about
to type. The CLI does not lock memory: it holds a value only until the value is sent, and `mlockall` with future
mappings would make its allocations fail under a finite `RLIMIT_MEMLOCK`. The client is Linux-only for now, like the
service.

### config approve

`iron-vault config approve <file>` reads the file and sends its bytes. The file is required, and `-` is not accepted:
when stdin is not a terminal, it carries the owner's answers to the prompts, so it cannot also carry the config. The
config is not a secret, but the CLI never echoes its bytes in a diagnostic. A file longer than `MAX_CONFIG_LEN` is
refused before anything is sent, with exit code 2. The CLI never computes a summary or a digest of its own: it shows
the service's notices and result. File-only input is a default that conflicts with K-128's spec, which reads stdin
when no file is given ([open question 12](config-approval.md#open-questions)).

### status

`iron-vault status` prints one field per line, in this order, to stdout: `service`, `reason` (only when Unavailable),
`profile`, `vault`, `vault id`, `approval committed`, `approval highest reserved`, `memory protection`, then one
`credential <name>` line per credential (or `credentials` alone when there are none or they are unknown). A value
sealed behind a locked vault prints as `unknown while the vault is locked`. Under the development profile the
profile line is exactly `profile: development — no isolation from malware running as <user>`, with the user the CLI
runs as: in development the service account, the admin principal and the invoking user are the same account. The output
is a function of the report, so two runs on the same state are byte-identical. It exits `0` when the service is Ready
and `4` for any other state.

### unlock

`iron-vault unlock` takes no argument: the passphrase is the answer to the service's secret prompt, read from the
terminal with echo off or as the next line of stdin. On success it prints `the vault is unlocked: the service is
Ready` to stdout. Otherwise it prints the service's error to stderr, which for an Unavailable service names the
redacted reason, and exits with code 1.

### Owner input

The CLI collects each prompted value from its **owner console**, opened at the first prompt or notice, so a command
the service never prompts for touches neither the terminal nor stdin. No argument ever carries a value ([§3.2](iron-vault-specification.md#32-service-and-cli-boundary), [§3.13](iron-vault-specification.md#313-administration-recovery-and-migration)).

- **Stdin is a terminal:** the CLI opens `/dev/tty`, writes the label to it followed by `: `, and reads one line from
  it. For a secret prompt it turns echo off for the read with `tcsetattr`: `ECHO` off and `ECHONL` on, so the owner's
  Enter still moves to a new line, applied with `TCSAFLUSH` so anything typed before the prompt is discarded. A guard
  restores the saved settings on every path out of the read, errors included. The CLI also registers handlers for
  SIGINT, SIGQUIT and SIGTERM before the first read: on any of them a watcher thread restores the saved settings if
  echo is off and exits with status 128 plus the signal number. Turning echo off and the watcher's restore are
  serialised, and the watcher holds off further prompts until the process exits, so a signal never leaves echo off.
  If echo cannot be turned off, nothing is read and the command is cancelled.
- **The terminal's line limit:** in canonical mode Linux keeps at most 4095 bytes of a line and silently discards the
  rest up to the newline, so a longer pasted value would arrive cut short. The CLI refuses a terminal line of 4095
  bytes or more, counted with its line ending, as possibly cut short, without sending or showing it, and says to pipe
  longer values through stdin. A value typed at the terminal is therefore at most 4093 bytes.
- **Stdin is not a terminal:** each value is the next line of stdin, so `pass show fx | sudo iron-vault add fx` works
  from an interactive shell as well as from a script, and several prompts read consecutive lines. The label goes to
  stderr, and only when stderr is a terminal; it never goes to stdout.

The label is the service's text with control characters removed, so a label cannot move the cursor or reprogram the
terminal. A notice's text has every control character except `\n` removed, for the same reason. It is written to
`/dev/tty` when stdin is a terminal, and otherwise to stderr, whether or not stderr is a terminal, so a scripted
approval still records the summary it approved. It never goes to stdout. Every line follows the same rules:

- Exactly one trailing `\n` is stripped, and one `\r` before it. A last line without `\n` is still a value; an empty
  line is an empty value.
- Input that ends before any byte is no value. A value longer than the 64 KiB body bound is refused without being sent
  or shown; the CLI stops reading at the first byte past the bound. A terminal line has the tighter limit above.
- A refused or missing value cancels the command: the CLI reports why on stderr, naming no typed byte, and closes the
  connection, so the service cancels too. The CLI exits with code 3.

**Where the CLI's copies live.** Bytes are read one at a time, straight into a buffer that clears itself on drop
(`Zeroizing<Vec<u8>>`), sized once for the longest line so it never reallocates and leaves a copy behind; reading one
byte at a time also means nothing after the line is consumed. Stdin is read through a duplicate of its descriptor,
never through `io::Stdin`, whose buffer is never cleared. The buffer becomes the `OwnerInput`, which is encoded into a
second clearing buffer sized for the frame. Both are dropped, and so cleared, as soon as the frame is written. The
value never passes through `String`, formatting, `Debug` or a log call, and no CLI error names a byte of it.
