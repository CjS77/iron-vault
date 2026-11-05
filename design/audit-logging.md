# Audit logging

What the service writes to its log, in what shape, and where (specification
[§3.15](iron-vault-specification.md#315-logging-and-v0-acceptance)). Iron Vault cannot stop a caller from misusing a
route it was granted, so it records every request and every administrative and security fact. The log must never
become the leak: it holds names, numbers and fixed codes, never a secret, a body, a header value or a URL. Terms follow
the [glossary](glossary.md).

The log has three kinds of record, all in one stream:

- **Request events:** one per completed or rejected request ([Request event](#request-event)).
- **Audit events:** one per administrative change, approval step, lock transition, corruption, policy failure or
  other security fact ([Audit events](#audit-events)).
- **Diagnostic records:** every other `tracing` event, such as a listener's accept error. They help an administrator
  debug and carry no stable name.

What the owner has not yet decided is listed under [Open questions](#open-questions).

## Owner decisions

The owner made these decisions on 2026-11-05. Each is recorded with the alternatives rejected.

1. **Format: JSON Lines.** One JSON object per line, UTF-8. A record never spans lines: JSON escapes a newline inside a
   string as `\n`, so even a multi-line approval summary stays on one line.
2. **Library: `tracing`**, with `tracing-subscriber`'s `json` feature for the record format and `tracing-appender` for
   the files. The service already logs through `tracing`, and the [dependency caps](#dependency-caps) are a
   `tracing-subscriber` layer. This design departs from the `tracing-appender` half of the decision; see
   [Departure: no `tracing-appender`](#departure-no-tracing-appender).
3. **No journald output, even on Linux.** The service writes files (or stdout, in Docker) and nothing else.
4. **Destination: rolling log files in `/var/log/iron-vault`, or the directory set in configuration.** One file,
   `iron-vault.log`, rotated daily, keeping about 30 files. In Docker, stdout instead. Decisions D1 and D2 below settle
   what "set in configuration" and "rotated" mean.

Rejected:

- **journald.** The owner chose files. JSON inside journald's `MESSAGE` field would also lose journald's own
  field-level queries, so neither tool would read the record well.
- **`log4rs`.** It works through the `log` crate. Installing a `log` backend would start accepting the records that
  `reqwest` and `rustls` emit through `log`, which are discarded today because no backend is installed, so the
  dependency caps would have to be rebuilt in `log4rs`'s file-driven config. Its records are also unstructured text.
- **OpenTelemetry (OTLP) export from inside Iron Vault.** It brings heavy dependencies, possibly another copy of
  `rand`, and a further network path out of the process that holds the secrets. A collector can convert the JSON Lines
  files to OTLP outside the service.

### D1: the log directory is set in `config.toml`

The log directory is a setting of the service config file, `[logging] destination`, with a default per deployment
profile. [Log destination](#log-destination) settles when the setting takes effect and how it is checked.

Rejected:

- **A `serve` flag, `--log-destination`, in the root-owned unit or Compose file.** It keeps the setting out of the
  approval, but it puts a security-relevant setting where the approval summary never shows it, and gives the owner a
  second place to configure the service. The approved config is the one reviewed record of how the service behaves.
- **An environment variable.** Environment variables are inherited and easily set from outside the service's
  definition, and the service already refuses ambient settings such as `RUST_LOG` and `SSL_CERT_FILE`
  ([§3.7](iron-vault-specification.md#37-outbound-tls-and-environment)).

A `serve` flag survives in one narrow role: `--log-to-stdout` chooses stdout before any approved config is active, for
Docker ([Docker](#docker)).

### D2: one file, `iron-vault.log`, rotated by `logrotate`

The service always writes one fixed file, `iron-vault.log`, in the log directory. `logrotate` rotates it, keeps the
old files and compresses them. There are no dated files and no `max_log_files`. [Log file and
rotation](#log-file-and-rotation) gives the rule and how the service follows a rotation without losing a record.

Rejected:

- **`tracing-appender`'s daily rolling files with `max_log_files(30)`.** It names each file by its date
  (`iron-vault.2026-11-05.log`) and keeps no fixed-name current file, it cannot limit size or compress, and
  `logrotate` cannot be pointed at its files, since `max_log_files` counts only names it can parse.
- **`logrotate` with `copytruncate`.** It silently loses every record written between its copy and its truncate.
- **A reopen signal (`SIGUSR1`) sent from `postrotate`.** It adds a signal handler and a way for a root script to find
  the service's process, and still needs the same reopen logic; the inode check below needs neither. `SIGHUP` already
  means "reload the config" ([§3.9](iron-vault-specification.md#39-configuration-approval-and-reload)).

### D3: every refusal Iron Vault's code makes writes a request event

The owner relies on request events to debug bad route and credential setups, so every refusal made by Iron Vault's own
code writes `request.completed`, including the refusals the request server makes before or instead of the request
handler: its request form gate's `400`, its `413` for a declared body over the limit, and its `408` and `413` after it
has dropped the handler. A field the service cannot know at that point, such as the caller or route when the handler
never ran, is left out; `request_id`, `listener` and `http_method` are always present. [Request event](#request-event)
settles who writes the event so that no request yields zero events or two.

The only refusals without a request event are those made before Iron Vault's code sees a request: hyper's `431` and
`414`, and a connection closed unread over `max_connections` ([Known limit](#known-limit)).

Rejected:

- **Leaving the request server's own refusals to a diagnostic record.** A diagnostic record has no stable name or
  shape, so a collector cannot count or alert on it, and the
  [§3.15](iron-vault-specification.md#315-logging-and-v0-acceptance) rule of one event per rejected request would
  have a hole Iron Vault could close.
- **A separate event name for the request server's refusals.** Every dashboard would have to query two names for one
  stream; `reason` already says which check refused.

### Owner notifications come after v0

On 2026-11-05 the owner dropped owner notifications from v0. They are designed and built after v0, in EP-40; this
design has no notification channel, and every fact it records goes to the log only.

### Departure: no `tracing-appender`

**For the owner to confirm.** Decision 2 names `tracing-appender`. With one fixed file rotated by `logrotate` (D2) and
a blocking writer ([Writer behaviour](#writer-behaviour)), it contributes nothing this design uses: no rotation, no
pruning and no non-blocking channel. What the writer needs, an append-mode file that follows a rotation and reports a
failed write, is a small `MakeWriter` wrapper of the binary's own, `logging::LogFile`. `tracing-appender` could not
host those checks, since its `RollingFileAppender` neither reopens a renamed file nor returns a write error to anyone
who can act on it. Dropping it also drops `crossbeam-channel`, `time` and `symlink` from the dependency tree.

## Record shape

Every record is one flat JSON object. These fields are in every record, whatever its kind:

| Field | Type | Form |
|---|---|---|
| `timestamp` | string | RFC 3339 in UTC with fractional seconds, such as `2026-11-05T10:15:30.123456Z` |
| `level` | string | `ERROR`, `WARN`, `INFO`, `DEBUG` or `TRACE` |
| `target` | string | The `tracing` target: `iron-vault.audit`, `iron-vault.request`, or a module path for a diagnostic record |
| `service` | string | Always `"iron-vault"` |
| `service_version` | string | The release version, from `CARGO_PKG_VERSION` |
| `schema_version` | number | The [schema version](#schema-version), `1` for this design |
| `deployment_profile` | string | `protected` or `development` |
| `message` | string | A short fixed phrase; values go in fields, never in the message |

Audit and request events add `event`, their [event name](#event-names), and their own fields. A diagnostic record has
no `event`.

`deployment_profile` is in every record, not only in the startup event, so a reader who sees one record, or a stream
filtered to one route, can never mistake a development run for a protected one. The alternative, recording the profile
only in `service.started`, leaves every other record ambiguous once the startup event has scrolled away or been
filtered out.

`target` is kept, although the owner's field list omits it: it is how a collector tells audit and request events from
diagnostic records without parsing `event`, and `tracing-subscriber`'s JSON formatter writes it by default.

### Targets

Audit events use the target `iron-vault.audit` (`audit::AUDIT_TARGET`) and request events `iron-vault.request`
(`audit::REQUEST_TARGET`). Neither is a module path, nor a prefix of one, nor has one as a prefix.
`tracing-subscriber` matches a filter directive's target against a record's target with `starts_with`, so a target
named like a module would be caught by filters meant for code: `iron_vault::request` would also match the module
`iron_vault::request_server`, `iron_vault::audit` is the planned module's own path, and even `iron_vault_audit` starts
with the crate's own target, `iron_vault`. A hyphen cannot appear in a Rust path, so no module target can start with
`iron-vault.`, and the two audit targets do not prefix each other.

### Constant fields

`service`, `service_version`, `schema_version` and `deployment_profile` are the same in every record. They are added
by a small formatter that wraps `tracing-subscriber`'s JSON formatter (a `FormatEvent` implementation,
`logging::RecordFormat`): it formats the record with the JSON formatter into a buffer, then writes `{`, the constant
fields, and the rest of the buffer after its opening `{`. The constant fields' text is built once at startup.

The alternative, having the typed emitter add the constant fields to each audit and request event, leaves diagnostic
records without them, so a collector's `service` label would be missing from some lines of the same file. The
wrapper also keeps the constant fields out of every emitter, where one could forget them.

### One file

Diagnostic records share the file with audit and request events. Audit records are told apart by their target and
their `event` field. The alternative, a second file for audit records only, doubles the rotation, permission and
collector setup, and splits a request's diagnostic lines from its request event, which an administrator reading one
incident wants side by side.

### Levels

Audit and request events are always written, at their own level, whatever verbosity is set for diagnostic records:
the level filter passes the `iron-vault.audit` and `iron-vault.request` targets at `INFO` and above. The default level
for every other target stays `INFO`, as it is today. A verbosity setting, when one exists, changes diagnostic records
only, so no setting can switch the audit log off.

### Schema version

`schema_version` is a positive integer, `audit::SCHEMA_VERSION`. It increases when a field is removed or renamed, a
field's type or unit changes, an event name is removed or renamed, or a reason code or label changes meaning. Adding an
event, a field, a reason code or a label does not change it: a reader must ignore what it does not know. A dashboard or
alert rule can then pin the version it was written for.

## Field rules

The rules below keep the records readable by Loki, Elastic and other tools without per-tool configuration.

- **Flat records.** The subscriber uses `flatten_event(true)`, with `with_current_span(false)` and
  `with_span_list(false)`, so no record has a `fields`, `span` or `spans` key and every record has the same shape.
- **One meaning and one type per field name, across every event.** A field that is a number in one record is a number
  in all of them, and a field name never means two things. Elastic maps a field from the first record it sees and
  rejects a later record whose `status` is a string. A field with no value is left out, never written as `"n/a"`,
  `null` or an empty string. An `Option` field is recorded through `tracing`'s `Option<T>` value, which records nothing
  for `None`; never as `?option`, which writes `"Some(3)"`.
- **Primitive values only.** Audit and request event fields are recorded as `&str`, `u64` or `bool`, never through
  `Display` (`%version`) or `Debug` (`?kind`). Numbers then stay JSON numbers, and formatting an event cannot fail
  ([Failure behaviour](#failure-behaviour)).
- **Plain snake_case names** such as `http_method`, never dotted names such as `http.method`: Elastic reads a dotted
  name as a nested object, and Loki turns the dots into underscores, so the two would disagree.
- **Fixed labels are snake_case strings.** Every value from a fixed vocabulary, such as `outcome`, `reason`, `step`,
  `refusal`, `unavailable_reason` and `error_kind`, is a lowercase snake_case label (`policy_invalid`,
  `wrong_passphrase`, `not_found`), never a type's `Debug` output, whose form can change with the code. This holds
  even where the same fact has another spelling elsewhere: the admin protocol's wire label `not-admin-principal` is
  logged as `not_admin_principal`, and the unavailable reason that a `503` body spells `policy invalid` is logged as
  `policy_invalid`. Event names are the one exception ([Event names](#event-names)).
- **A list is one string**, its items in a fixed order and separated by `,` with no spaces, since a `tracing` field
  cannot hold an array.
- **Loki labels:** only `service`, `event`, `level` and, if wanted, `route`. Never a field with many distinct values,
  such as `request_id` or `caller`, which Loki would turn into a separate stream each. The
  [operations guide](#operations) gives the collector settings.
- **Elastic:** a collector can rename `timestamp` to `@timestamp`; the service keeps the name `timestamp`.
- **Collectors read the file as it is.** Grafana Alloy (and Promtail), Vector, Fluent Bit and Filebeat each read
  JSON Lines files natively, need no plugin, and follow a file that `logrotate` renames.

### Shared field names

These are the fields more than one event uses:

| Field | Type | Meaning |
|---|---|---|
| `request_id` | string | The request's [request ID](#request-id) |
| `caller` | string | A caller's configured name |
| `route` | string | A route's configured name |
| `credential` | string | A credential's configured name |
| `record_id` | string | A credential record's record ID |
| `version` | number | An approval version |
| `committed_version` | number | The committed approval version, left out when nothing is committed |
| `config_digest` | string | A config digest, as `blake2b:` and 64 lowercase hex digits |
| `file` | string | A state or config file name, never a path |
| `step` | string | A fixed step label, such as an approval step or an init step |
| `refusal` | string | Why an admin connection, request or command was refused: a fixed label |
| `unavailable_reason` | string | An unavailable reason: `locked`, `policy_invalid`, `checking` or `recovery_needed` |
| `detail` | string | A check failure's detail: fixed phrases with versions and configured names only |
| `error_kind` | string | A [library error's](#library-errors) fixed kind label |
| `remediation` | string | A fixed phrase saying what the administrator should do |
| `log_destination` | string | A [log destination](#log-destination): `stdout`, or the log directory's absolute path |

`reason` is the request event's [reason code](#reason-codes) and nothing else. An audit event that records why the
service is unavailable uses `unavailable_reason`. `status` is the request event's HTTP status, a number, and nothing
else.

### Escaping

JSON escapes every control character, so no value can start a new record or forge a field. That is not enough for a
person reading the file or a tool that renders it, so:

- configured names (callers, routes, credentials, listeners) and the log directory reject control characters when the
  config is validated ([§3.15](iron-vault-specification.md#315-logging-and-v0-acceptance)), as the policy crate's name
  types already do;
- a caller-controlled value that must be logged goes through the policy crate's escaping (`display::escaped`), which
  also escapes non-ASCII, so a format character such as U+202E cannot reorder what a reader sees. That function is
  `pub(crate)` today; the first ticket that logs a caller-controlled value from the binary exports it.

The request event logs one caller-controlled value, `http_method`; its other fields are configured names, numbers,
fixed labels and the request ID. hyper's parser admits only RFC 9110 token characters in a method, so it holds no
control character, space or quote, and it still goes through `display::escaped`.

## Never logged

No record contains any of these ([§3.15](iron-vault-specification.md#315-logging-and-v0-acceptance)):

- request or response bodies;
- header values, including `Authorization`, `Proxy-Authorization`, cookies and `Location`;
- URLs, paths and raw query strings of a request or an upstream, since a query slot holds the credential;
- passwords and passphrases, caller tokens, provider tokens and other credential material;
- private keys, the recovery key's text, signature bytes and PINs;
- config bytes (the digest is logged, never the bytes);
- a library error's text ([below](#library-errors)).

The typed events enforce this by construction: each has fixed fields of domain types, so a header value or a URL has
no field to go into. Diagnostic records follow the same list by review. The log directory's path is the one path
logged, in `log_destination`; it is configuration the owner approved, not a request's.

### Library errors

A library error's `Display` and `Debug` may hold a URL with its query, a header value or a path. A `reqwest::Error`
formats the request URL, and its source chain carries `hyper` and `rustls` diagnostics. So the redaction rule is:

> A library error is logged only as a fixed kind label in `error_kind`, chosen by matching the error's variant or
> predicates, and the error is dropped without being formatted.

`TransportError::classify` already does this for upstream errors. An `io::Error` is logged as its `io::ErrorKind`
label in snake_case (`not_found`, `permission_denied`, `storage_full`, …). An error type of this workspace whose
variants carry no library text may be logged by its variant label. No record uses `error = %e` on a library error.
K-175 applies the rule to the existing records.

## Request event

One event, `request.completed`, per request the request server received, whether it was served or refused, at `INFO`
under the target `iron-vault.request`. "Completed" means the service has finished with the request, whatever the
outcome. It is written when the response body ends: cleanly, by a failure, by the caller going away, or at once for a
refusal with a fixed body.

The alternative, two names such as `request.completed` and `request.rejected`, splits one stream across two event
names, so every dashboard and alert would have to query both; `outcome` already tells them apart.

| Field | Type | When present | Meaning |
|---|---|---|---|
| `request_id` | string | always | The [request ID](#request-id) |
| `listener` | string | always | The listener the request arrived on |
| `http_method` | string | always | The request method, as received ([Escaping](#escaping)) |
| `caller` | string | once the caller is identified | The caller's configured name |
| `route` | string | once a route is selected | The route's configured name |
| `credential` | string | once a route is selected | The route's credential's configured name |
| `upstream_host` | string | once a route is selected | The route's upstream host, as configured; never the port, path or query |
| `status` | number | once a response head was sent | The HTTP status sent to the caller |
| `request_bytes` | number | always | Body bytes read from the caller, as counted against `max_request_body_bytes` |
| `response_bytes` | number | always | Body bytes sent to the caller, after scrubbing and any re-encoding |
| `duration_ms` | number | always | Whole milliseconds from the request server receiving the request to the end of the response body |
| `scrubbed` | boolean | once a response head was relayed | Whether any scrub pattern matched in its headers or body |
| `outcome` | string | always | `success` or `failure` |
| `reason` | string | when `outcome` is `failure` | The [reason code](#reason-codes) |

- **`outcome`** is `success` when an upstream response was relayed and its body reached its end, whatever its status:
  an upstream `404` relayed in full is a success of the proxy. It is `failure` when a reason was recorded: the service
  refused the request, could not reach the upstream, refused the upstream's response, or the body did not reach its
  end.
- **`status`** is in every request event but one: a caller that closed its connection before any response head was
  sent (reason `caller_gone`), since no status was sent. For a body that failed after its head was sent, it is the
  status of that head, with `outcome` `failure`.
- **`duration_ms` stops at the end of the streamed response body**, not at the response head, so a long streaming
  response is counted for as long as it streams. It is measured on the monotonic clock and rounded down. It is an
  integer, not a fraction, because Elastic maps a field from its first value, and a first value of `3` would make
  `3.5` a type conflict.
- **`response_bytes`** counts what crossed the wire to the caller, including a fixed refusal body such as the form
  gate's. The response outcome's `decoded_bytes`, the bytes the scrubber screened, is not logged: for a compressed
  response it is not what the caller received, and an operator comparing with the caller's own counts needs the wire
  figure.
- **`scrubbed`** comes from the relayed body's running match count, which the body records as each match is found
  (in the headers when the head is built, and in the body as each piece is screened). So a body that fails or is
  dropped mid-stream still reports whether a pattern matched in what was screened before it stopped. The response
  outcome gives the same flag for a body that ended cleanly; the relayed body must keep its count available after a
  failure too.

### Who writes the event

The request server owns the event, because only it sees every request, including the ones it answers itself and the
ones whose handler it drops. The design:

- **`respond` creates the request record**, `audit::RequestRecord`, as soon as it has a request: the request ID, the
  listener, `http_method` and the start instant. The record is the only thing that can write the event, and it is not
  `Clone`.
- **The handler fills it in** through a `RequestFacts` handle, a shared cell it is given beside the request: the
  caller, the route, the credential, the upstream host, the reason when it refuses, and the scrub match count. The
  handle can set facts but cannot write the event. Because the facts live outside the handler's future, they survive
  when the request server drops that future at the request timeout or the body limit.
- **The record moves into the response body.** `respond` wraps whatever response it sends, its own refusal or the
  handler's, in the outermost body layer, which also counts `response_bytes`. The record writes the event exactly once:
  when that body ends, cleanly or with an error, or when it is dropped. A refusal the request server makes itself sets
  its own reason on the record before the response leaves `respond`. If `respond`'s own future is dropped before a
  response exists, the record's `Drop` writes the event with reason `caller_gone` and no status.
- **One owner, one write.** The event is written from the record's `Drop`, or from the body's end, which consumes the
  facts, so a clean end followed by the drop writes once. `Drop` must not panic: no `unwrap`, indexing or fallible
  call.
- **Facts are read when the event is written**, not when the record moves, so a body failure the relay or the
  request deadline records reaches the event. The scrub match count is recorded as matches are found, so it is
  already in the facts when the outer layer's `Drop` runs before the inner relayed body is dropped.

K-173 builds the record and the handle; K-174 writes the event from the body.

### Request ID

`request_id` is a random version 4 UUID in its hyphenated lowercase form, from the `uuid` crate's `Uuid::new_v4`,
generated when the request server receives the request and held as the value object `audit::RequestId`. `uuid` is
already a workspace dependency (with the `v4` feature) and in the lock file through `iron-vault-store`, so the binary
adding it pulls in no new crate and no new version of `getrandom`. The ID is in the request event and in every audit
event about the same request (`request.defect`, `response.scrubbed`), so they can be joined. It is never sent to the
caller or the upstream.

The alternative, 128 bits from the binary's `OsRng` formatted as hex, needs no extra dependency in the binary but
gives an ID that collectors and log viewers do not recognize as a UUID.

### Reason codes

A reason code is a fixed snake_case label, `audit::ReasonCode`. Every failure the request server or the request
handler can meet maps to exactly one code; the mapping is a single `match` per source, tested to cover every variant.
A code names the check, never the caller's input: `bad_target` does not say which character was refused.

**The request server, before the handler runs** (no caller, route or credential):

| Source | Status | Code |
|---|---|---|
| `FormViolation::Connect` | 400 | `connect_not_supported` |
| `FormViolation::NotOriginForm` | 400 | `not_origin_form` |
| `FormViolation::Upgrade` | 400 | `upgrade_not_supported` |
| `FormViolation::Version` | 400 | `unsupported_version` |
| A declared body (`Content-Length`) over `max_request_body_bytes` | 413 | `request_too_large` |

**The request server, after the handler has the request** (its future is dropped, or its answer replaced; the facts
it recorded are kept):

| Source | Status | Code |
|---|---|---|
| The body passed `max_request_body_bytes` as it streamed (`RequestBodyError::TooLarge`) | 413 | `request_too_large` |
| The handler had not answered by the request timeout | 408 | `request_timeout` |

`request_too_large` is one code for both rows: both refuse the same limit, and whether `caller` and `route` are
present shows whether the handler had run.

**Before a snapshot is used** (the service holds no serving snapshot, and answers with the unavailable reason):

| Source | Status | Code |
|---|---|---|
| `UnavailableReason::Locked` | 503 | `locked` |
| `UnavailableReason::PolicyInvalid` | 503 | `policy_invalid` |
| `UnavailableReason::Checking` | 503 | `checking` |
| `UnavailableReason::RecoveryNeeded` | 503 | `recovery_needed` |

**While a snapshot is held, outside the pipeline:**

| Source | Status | Code |
|---|---|---|
| A request header does not convert (`request_head` gives `None`) | 400 | `bad_header` |
| The snapshot was withdrawn before the response head | 503 | `withdrawn` |
| The snapshot was withdrawn after the response head (the body fails) | head's | `withdrawn` |

**Pipeline refusals** (`PipelineRefusal`):

| Refusal | Status | Code |
|---|---|---|
| `Unauthenticated` | 401 | `unauthenticated` |
| `Target(_)` | 400 | `bad_target` |
| `Method` | 400 | `bad_method` |
| `Authz(NotFound)` | 404 | `no_route` |
| `Authz(Forbidden { reason: NotGranted })` | 403 | `not_granted` |
| `Authz(Forbidden { reason: Method })` | 403 | `method_not_allowed` |
| `Authz(Forbidden { reason: Path })` | 403 | `path_not_allowed` |
| `Authz(Unavailable)` | 503 | `route_unavailable` |
| `Sanitize(_)` | 400 | `ambiguous_framing` |
| `Charge(Limited)` | 429 | `rate_limited` |
| `NoHealthyRecord` | 503 | `credential_unavailable` |
| `Kind(_)` | 503 | `credential_unusable` |
| `Assemble(ForeignMarker)` | 400 | `foreign_marker` |
| `Assemble(MalformedMarker)` | 400 | `malformed_marker` |
| `Charge(UnknownRoute \| NotGranted)`, `Assemble(NonAsciiSlotValue \| HeaderValue \| Header \| Target)`, `FinalCheck(_)` | 500 | `service_defect` |

Every `service_defect` is also a [`request.defect`](#request-defect) audit event.

**Sending** (after the pipeline accepted the request):

| Source | Status | Code |
|---|---|---|
| The route has no upstream client, or no route config in the snapshot | 503 | `route_unavailable` |
| `TransportError::Timeout`, and no response head by the request deadline | 504 | `upstream_timeout` |
| `TransportError::Connect` | 502 | `upstream_connect` |
| `TransportError::Tls` | 502 | `upstream_tls` |
| `TransportError::Protocol` | 502 | `upstream_protocol` |
| `TransportError::Body` | 502 | `upstream_body` |

**The response head** (refused before it is sent):

| Source | Status | Code |
|---|---|---|
| A content coding the service does not decode, a coded `206`, or a transfer coding besides `chunked` | 502 | `unsupported_coding` |
| A `Location` outside the route's upstream base, ambiguous, or repeated | 502 | `redirect_refused` |

**The response body** (`RelayFailure`, after the head was sent; the caller's connection is aborted):

| Source | Status | Code |
|---|---|---|
| `RelayFailure::Corrupt` | head's | `body_corrupt` |
| `RelayFailure::Truncated` | head's | `body_truncated` |
| `RelayFailure::SizeLimit` | head's | `body_size_limit` |
| `RelayFailure::RatioLimit` | head's | `body_ratio_limit` |
| `RelayFailure::Encode` | head's | `body_encode` |
| `RelayFailure::Upstream` | head's | `upstream_body` |
| The request server failed the body at the request deadline | head's | `deadline` |
| The caller closed the connection before the body ended | head's, or none | `caller_gone` |

`upstream_body` is one code for both `TransportError::Body` and `RelayFailure::Upstream`: both mean the upstream's
body stopped before its end, before or after the head.

The `refused an upstream redirect` and `aborted a response body after its head was sent` diagnostic records are
replaced by these codes in the request event, so a request's failure is recorded once.

### Known limit

Some refusals happen before Iron Vault's code sees a request, so they have no request event:

- hyper's own `431` for a head over `max_header_bytes` or `max_header_count`, and its `414` for a request target over
  its URI limit;
- a connection closed unread because `max_connections` connections are already open;
- a connection closed at the header read timeout, or whose TLS handshake failed, before any request arrived.

Each is covered by a connection-level diagnostic record naming the listener, as the request server writes today. The
connection closed over `max_connections` is raised from `DEBUG` to `WARN`, since it is cheap to record and means the
limit is too low or a caller is flooding the service. The others stay at `DEBUG`: hyper reports a `431` or `414` only
as a connection error, and any caller can provoke them at will. A connection error is logged by its fixed kind label
([Library errors](#library-errors)), never by hyper's text.

### Request defect

A final-check failure, or any other refusal only a service defect can cause, is recorded twice: in the request event,
as `outcome` `failure` with reason `service_defect`, and as its own audit event, `request.defect`, at `ERROR`. That
event is the redacted high-severity event [§3.6](iron-vault-specification.md#36-url-header-and-slot-rules) requires.
It carries the `request_id`, the `route`, the `credential` and `defect`, the fixed label of the check that failed
(`PipelineRefusal::report` gives one today, such as `Host` or `AssembleHeader`, written in snake_case), and never the
URL, a header or a library error.

The alternative, a `severity` field on the request event, would add a field that only some request events have, and
would hide the defect inside the request stream: an alert on `event = "request.defect"` cannot be written against a
request event's optional field without scanning every request. The level, `ERROR`, is the severity; no `severity`
field is needed.

## Audit events

Each audit event is a typed struct in the binary's `audit` module, implementing `audit::AuditEvent`, with fixed
fields, emitted under the target `iron-vault.audit`. Its `emit` makes one `tracing` call with its event name, its
level, its fixed message and exactly its own fields. Its fields are domain types (`RouteName`, `CredentialName`,
`ApprovalVersion`, `ConfigDigest`, `ReasonCode`), never a `&str` taken from a request, so a header value or a URL
cannot be added by accident; `emit` turns each into its primitive value. The request event is the same kind of struct,
`audit::RequestEvent`, under the target `iron-vault.request`.

### Where the types live

The binary owns the audit log: its schema, its event structs and every emit. A library crate returns facts and the
binary turns them into events. The store already returns some: `WriteReport` (the unindexed files a write removed and
the superseded file it left), `OpenReport` (damaged records, unindexed files, an unrecorded approval state), the
reserved version of a prepared approval, and the files a recovery discarded. Where the store logs a fact itself today
(`config.version-reserved`, `config.commit-uncertain`, `config.recovery-published`, `config.recovery-discarded`, the
init's `config.approval-completed`, the discarded conflicting staged approval, and its vault and approval-state
warnings), the fact moves into what it returns, and the binary emits the event.

This keeps one published language for the log in one crate: the store does not know the event names, the record
shape or the target, and a test of the binary sees every event. The alternative, letting the store emit audit events
under the audit target itself, puts the schema in two crates, so a field could change type in one and not the other.
A store-side `AuditSink` trait the binary implements was also considered; it works, but it is a second interface for
what a return value already carries.

One fact has an ordering constraint: `config.version-reserved` must be recorded before signing starts, so a signing
failure, or a crash while the signer waits for the owner, follows its reservation in the log
([§3.9](iron-vault-specification.md#39-configuration-approval-and-reload)). The store therefore returns the reserved
version from its own step, before it signs, rather than only in the result of the whole transaction.

### Catalogue

Fields named in [Shared field names](#shared-field-names) have the types given there, and the others are typed in
[Event fields](#event-fields). "Not yet emitted" marks an event whose operation does not exist yet; its ticket emits it
with these fields.

**Service and lock state:**

| Event | Level | When | Fields |
|---|---|---|---|
| `service.started` | INFO | the log destination is open, before the admin socket is bound | `log_destination`, `core_dumps`, `memory_protection` |
| `service.hardening-incomplete` | ERROR | at startup, when core dumps are not disabled or memory is not locked | `core_dumps`, `memory_protection`, `remediation` |
| `service.log-destination-changed` | INFO | an activated config moved the log destination; written to both destinations | `log_destination`, `previous_log_destination`, `version` |
| `service.lock-transition` | INFO | a lock transition: Locked to Checking, the outcome of the check that follows, and Ready or Unavailable to Locked | `from_state`, `to_state`; `unavailable_reason` when `to_state` is `unavailable` |
| `vault.unlock-refused` | WARN | an unlock was refused | `refusal`, such as `wrong_passphrase` |
| `vault.lock-incomplete` | WARN | a lock's drain ended with a serving snapshot or the vault identity still held | `snapshots_held`, `identity_held` |

`service.started` carries the hardening report's outcome as fixed labels, so a run without its protections is visible
in the startup record itself; `service.hardening-incomplete` is the record to alert on, and replaces the `ERROR` lines
the hardening report writes today (`hardening::log_report`), with the same fix in `remediation`. The reason text a
failed core-dump setting carries is not logged, since it is an OS error's text. Every record carries
`deployment_profile` as a constant field, so the startup event needs no profile field of its own. The state labels are
fixed strings, never `ServiceState`'s `Debug` output, which writes `Unavailable(PolicyInvalid)`.
`service.lock-transition` takes over the records written under `LOCK_TRANSITION_TARGET` today; that target is retired
when it moves (K-171).

**Admin commands:**

| Event | Level | When | Fields |
|---|---|---|---|
| `admin.command` | INFO | an admin principal's request was read | `command`, `principal_uid` |
| `admin.refused` | WARN | an admin connection or request was refused before any command ran | `refusal`; `peer_uid` and `peer_pid` when known |
| `caller.token-issued` | INFO | a caller token was issued | none; the token is never logged |
| `caller.token-failed` | ERROR | no caller token could be issued | `error_kind` |

`admin.refused`'s `refusal` is one of `not_admin_principal`, `peer_unreadable` and `busy` for a connection, and
`unsupported_version`, `malformed_frame`, `unknown_command` and `unexpected_frame` for a request frame that was not
read as a command (the frame errors the admin server logs today). A refusal of a command after it was read (`init`'s
`wrong_state`, `already_initialized`, `passphrase_rejected`, `declined`) records only `admin.command`.

**Config approvals and checks** ([config-approval.md](config-approval.md#audit-events) gives when each fires). A
reserved version and a completed approval are distinct events, so a reserved version is never mistaken for a
completed approval ([§3.9](iron-vault-specification.md#39-configuration-approval-and-reload)):

| Event | Level | When | Fields |
|---|---|---|---|
| `config.approval-refused` | WARN | the approval passphrase was wrong or the key is not the pinned approver's; nothing was reserved | `refusal` (`wrong_passphrase` or `key_mismatch`), `config_digest` |
| `config.version-reserved` | INFO | step 2's reservation is durable | `version`, `config_digest` |
| `config.approval-failed` | WARN | the transaction failed after its reservation and before its commit | `version` (consumed), `config_digest`, `step`, `error_kind` |
| `config.commit-uncertain` | WARN | step 5's rename of `approval.age` landed, but its directory fsync failed | `version`, `error_kind` |
| `config.approval-completed` | INFO | the commit is durable | `version`, `config_digest`, `summary` |
| `config.activation-failed` | WARN | the config check after a committed approval failed, or an uncertain commit could not be settled | `version`, `unavailable_reason`, `detail` |
| `config.check-failed` | WARN | any config check failed | `unavailable_reason`, `failure`, `detail` |
| `config.reload-failed` | WARN | the config check of a SIGHUP reload failed | `committed_version`, `unavailable_reason`, `detail` |
| `config.recovery-published` | WARN | a config check finished publishing a committed transaction | `version`, `renames` |
| `config.recovery-discarded` | INFO | a config check removed an uncommitted file | `file`; `signed_for` for a staged approval whose version is known |
| `config.conflicting-approval-discarded` | ERROR | a config check found a staged approval signed for the committed version over another config, and discarded it | `version` |

A staged approval for the committed version with another digest cannot come from a single approval transaction, so
`config.conflicting-approval-discarded` is an `ERROR` audit event rather than a diagnostic record: it means a second
signature over the same version, or a file written by something other than the service. The approval summary goes
into `summary` as one string; `tracing` fields cannot hold nested objects, and the summary is already text the service
built from configured names. When the approval moves the log destination, the summary shows it
([config-approval.md](config-approval.md#approval-summary)).

**Credentials and vault writes:**

| Event | Level | When | Fields |
|---|---|---|---|
| `credential.added` | INFO | an `add` committed | `credential`, `record_id`, `kind`, `origins` |
| `credential.replaced` | INFO | a `replace` committed (not yet emitted, K-152) | `credential`, `old_record_id`, `record_id`, `kind`, `origins`; `old_kind`, `old_origins` for a healthy old record |
| `credential.removed` | INFO | an `rm` committed (not yet emitted, K-151) | `credential`, `record_id` |
| `credential.short-secret` | WARN | a record just written has a short secret | `credential`, `secret_field`, `len` |
| `vault.unindexed-removed` | WARN | a vault write removed an unindexed record file first (from its write report) | `file` |
| `vault.superseded-left` | WARN | a vault write committed but could not remove the record file it superseded (from its write report) | `file`, `error_kind` |
| `vault.commit-uncertain` | ERROR | the vault manifest or approval state was replaced but its directory fsync failed | `file`, `error_kind` |

**Corruption** (from the open report and the vault's errors):

| Event | Level | When | Fields |
|---|---|---|---|
| `vault.record-damaged` | ERROR | a listed record is damaged and was not loaded | `credential`, `record_id`, `file`, `damage`, `error_kind` when a read failed |
| `vault.unindexed-file` | WARN | opening the vault found an unindexed record file | `file` |
| `vault.approval-state-unrecorded` | WARN | the approval state exists but the vault manifest does not record it | none |
| `vault.shared-state-damaged` | ERROR | the vault's shared state is damaged | `file`, `damage` |
| `vault.state-dir-unreadable` | ERROR | the state directory cannot be listed | `error_kind` |
| `vault.foreign-file` | WARN | `unlock` read an Initialized state directory holding a file not on the [lists](vault-initialization.md#initialization-state) | `file`, escaped with `display::escaped`, since the name is not one the service chose |

Each corruption event also carries `remediation`, the fixed phrase the store logs with it today.

**Initialization** ([vault-initialization.md](vault-initialization.md#logging) gives when each fires):

| Event | Level | When | Fields |
|---|---|---|---|
| `vault.init-discarded` | WARN | an unfinished initialization was discarded | `files` |
| `vault.initialized` | INFO | init's last step is durable | `vault_id` |
| `vault.init-failed` | WARN | an init step failed | `step`, `error_kind` |

Init's version 1 also records `config.version-reserved` and `config.approval-completed`, so it is audited like any
other approval.

**Routes and responses:**

| Event | Level | When | Fields |
|---|---|---|---|
| `route.pinned-ca-unavailable` | WARN | a route's pinned CA could not be loaded, so the route is unavailable | `route`, `config_field` (`ca_file`) |
| `response.scrubbed` | WARN | a relayed response ended, cleanly or not, and a scrub pattern matched in its headers or body (the scrub event) | `request_id`, `route`, `credential`, `matches` |
| `request.defect` | ERROR | a request was refused by a service defect | `request_id`, `route`, `credential`, `defect` |

**Recovery** (not yet emitted; the recovery epic's tickets emit them):

| Event | Level | When | Fields |
|---|---|---|---|
| `recovery.checked` | INFO, or WARN when the key fails | `recovery check` finished | `recovery_outcome` (`opened` or `failed`) |
| `recovery.reminder` | INFO | a scheduled recovery reminder fell due | `last_checked`, left out when never checked |

### Event fields

The fields that only one event uses, or that only audit events use:

| Field | Type | Form |
|---|---|---|
| `command` | string | The admin command ID in snake_case, such as `config_approve` or `caller_token` |
| `principal_uid`, `peer_uid`, `peer_pid` | number | The admin peer's uid and pid, as the kernel reported them |
| `core_dumps` | string | `disabled` or `not_disabled` |
| `memory_protection` | string | `locked`, `unavailable` or `unsupported` |
| `previous_log_destination` | string | The log destination before the change, in `log_destination`'s form |
| `from_state`, `to_state` | string | A service state label: `starting`, `locked`, `checking`, `ready`, `unavailable` or `stopped` |
| `snapshots_held` | number | Serving snapshots still held when the lock's drain ended |
| `identity_held` | boolean | Whether the vault identity was still held when the lock's drain ended |
| `summary` | string | The approval summary's text, or `initial config` for version 1 |
| `failure` | string | A config check failure's fixed label, one per check failure variant, never its `Display` text |
| `renames` | string | The publish renames run, as fixed labels in a [list](#field-rules) |
| `signed_for` | number | The approval version a staged approval was signed for |
| `kind`, `old_kind` | string | A credential kind label, such as `static` or `basic` |
| `origins`, `old_origins` | string | A credential's permitted origins as `https://host:port`, in a [list](#field-rules) |
| `old_record_id` | string | The replaced record's record ID |
| `secret_field` | string | The label of a credential kind's secret field, such as `password` |
| `len` | number | A secret's length in bytes |
| `damage` | string | A record damage or shared-state damage label |
| `files` | string | File names, in a [list](#field-rules) |
| `vault_id` | string | The vault ID, a hyphenated lowercase UUID |
| `config_field` | string | The config key a fact is about, such as `ca_file` |
| `matches` | number | Scrub pattern matches in one response |
| `defect` | string | The label of the check a service defect failed |
| `recovery_outcome` | string | `opened` or `failed` |
| `last_checked` | string | An RFC 3339 UTC timestamp |

### Renamed and retyped fields

The `config.*`, `credential.*`, `vault.*`, `caller.token-*` and `route.pinned-ca-unavailable` events keep the names
they have in the code and in the design docs. Their fields change only where the [field rules](#field-rules) require:

- `version`, `signed_for` and `committed_version` become JSON numbers; some are recorded with `%version` or `?option`
  today, which writes strings such as `"3"` and `"Some(3)"`;
- `digest` becomes `config_digest`;
- `config.check-failed`'s `status` becomes `failure`, since `status` is the request event's HTTP status, a number;
- `reason` in the `config.*` events becomes `unavailable_reason`, since `reason` is the request event's reason code;
- the lock transition's `from` and `to` become `from_state` and `to_state`, so neither name means two things;
- `field` becomes `secret_field` in `credential.short-secret` and `config_field` in `route.pinned-ca-unavailable`;
- `error` on a library error becomes `error_kind` ([Library errors](#library-errors));
- `renames` becomes fixed labels, not `PublishSet`'s `Debug` output;
- a label in kebab-case, such as `wrong-passphrase`, becomes snake_case;
- a message that interpolates values, such as ``credential `{name}` added`` or `lock transition: {from:?} to {to:?}`,
  becomes a fixed phrase.

### Diagnostic records, not audit events

These records report a fact the audit log already holds another way, so they stay diagnostic records. Each still
follows the [library error](#library-errors) rule:

| Record | Why it is not an audit event |
|---|---|
| The config directory's fsync failed after a publish (store `approval/transaction.rs` and `approval/recovery.rs`) | The commit was already durable and recorded as `config.approval-completed` or `config.recovery-published`; the approval state, not the config directory, decides the version, and the next config check's read-back settles the files |
| The uncommitted pending config or staged approval could not be removed (store `approval/transaction.rs` and `approval/recovery.rs`) | Nothing uncommitted is ever promoted; the next config check removes the file and records `config.recovery-discarded` |
| An approval committed but its publish failed (`service_context/approval.rs`) | `config.approval-completed` is already written, and the config check that finishes the publish records `config.recovery-published` or `config.activation-failed` |
| An admin connection's accept failed, or an exchange was cancelled or abandoned at shutdown (`admin/server.rs`) | No admin principal was identified, or `admin.command` already records the command |

### Event names

An event name is `<subject>.<name>`: a lowercase subject (`admin`, `caller`, `config`, `credential`, `recovery`,
`request`, `response`, `route`, `service`, `vault`), a dot, and a kebab-case name, matching
`^[a-z]+\.[a-z]+(-[a-z]+)*$`. Event names keep the kebab-case already in use in the code and the design docs; only
field names and label values are snake_case. Names are stable: renaming or removing one changes the schema version.
Each name is defined once, as an `audit::EventName` constant beside its struct.

## Log destination

Where the records go, `logging::LogDestination`: a log directory, or stdout. It is chosen in this order:

1. **The active approved config's `[logging] destination`**, when it sets one: an absolute directory path, or the
   string `"stdout"`. It is a setting of the approved config like any other, so it appears in the approval summary.
2. **The bootstrap destination**, otherwise: stdout when `serve` was started with `--log-to-stdout`, else the deployment
   profile's default directory.

| Deployment | Bootstrap destination |
|---|---|
| Protected install (systemd) | `/var/log/iron-vault` |
| Development build | `$XDG_STATE_HOME/iron-vault-dev-log` (default `~/.local/state/iron-vault-dev-log`) |
| Docker or Compose | stdout: the image's default command is `serve --log-to-stdout` |

The development directory is beside the development state directory (`$XDG_STATE_HOME/iron-vault-dev`), not inside
it: the vault's files stay alone in the state directory, and any other file there is a foreign file that makes `unlock`
refuse.

### Before an approved config is active

The service writes to the bootstrap destination from startup until a config check activates an approved config. In a
passphrase install that lasts until the owner unlocks, which may be indefinitely. The setting is never taken from the
unverified `config.toml`: the provisional listener set reads the unverified file to bind its listeners, but that read
does not apply to the log destination. An unverified file could otherwise move the audit log out of the service's
control before any approval had been checked.

### Switching at activation

The destination switches when a config check activates an approved config whose destination differs from the current
one: after an approval, on an unlock's check, on a SIGHUP reload and on a recovery that publishes a committed config.
It does not wait for a restart, which in a passphrase install would cost an unlock.

- The config check opens the new destination, with every check below, as one of its own checks. If it cannot be
  opened or fails a check, the config check fails (`config.check-failed`, `unavailable_reason` `policy_invalid`, a
  `detail` naming the log destination), the service settles Unavailable as for any other invalid policy, and it keeps
  writing to the current destination. There is no half-switch: until the new destination is open, every record goes
  to the old one.
- `config approve` runs the same checks on the proposed config before it reserves a version, so an approval naming an
  unusable directory is refused as an invalid config and consumes nothing. The check at activation still runs, since
  the directory can change in between.
- The order of records at a switch: `config.approval-completed` is written to the old destination, since the commit
  comes before activation. Then `service.log-destination-changed` is written to the old destination, the writer
  switches, and the same event is written again as the first record of the new one, so each file says where the log
  went or came from. The lock transition into Ready follows in the new destination.
- `lock` does not move the destination. The service keeps writing where it is until a later activation moves it, or
  a restart returns it to the bootstrap destination until the next unlock. A lock is not a config change, and moving
  the log back and forth on every lock would split one session's records across directories.
- A config that removes `[logging] destination` switches back to the bootstrap destination at activation, in the same
  way.

### Trust

A configured log directory must be:

- an absolute path with no control characters, and no `..` component;
- not inside, or equal to, the state directory or the config directory, so log files are never foreign files in the
  state directory and never sit beside `config.toml`;
- a directory that passes the trusted-path rule for a service-owned directory: owned by the service account, not
  readable or writable by others, and no ancestor writable by any account but root and the service account.

The trusted-path check runs before the writer opens the file, at startup for the bootstrap destination and in the
config check for a configured one.

The service creates a missing log directory only in development, as it creates the development state and config
directories: `$XDG_STATE_HOME/iron-vault-dev-log` and any missing parents, at mode `0700`. A protected install's
default directory belongs to the package: the packaged unit's `LogsDirectory=iron-vault` with `LogsDirectoryMode=0750`
makes systemd create it for the service account before the service starts. A configured directory is the
administrator's to create; the service never creates it, and a missing one fails the check above. Creating
directories in an arbitrary place from a config setting would let an approval make the service build paths it was
never given.

### Docker

In Docker the image's default command is `iron-vault serve --log-to-stdout`, so the bootstrap destination is stdout
and the container runtime collects the records. The flag only selects stdout and takes no path, so it cannot point the
log anywhere else. An approved config's `[logging] destination` still wins once it is active; a Docker deployment
normally leaves it unset, or sets `"stdout"` so that removing the flag from the Compose file changes nothing. Rotation
in Docker is the runtime's: its log driver's `max-size` and `max-file` options, which the operations guide (K-177)
gives for Compose.

### Startup order

The bootstrap destination needs the deployment's paths, and in development those come from the invoking user's
environment. So `serve` hardens the process first, as today, then reads the accounts and the profile environment,
then creates the development log directory if needed, checks the bootstrap log directory's trusted path, opens it and
installs the subscriber, then writes `service.started` (and `service.hardening-incomplete` when it applies), and only
then resolves the other service paths and starts the service. An error before the subscriber is installed goes to
stderr, as an error before logging does today.

## Log file and rotation

The service writes one file, `iron-vault.log`, in the log directory, through `logging::LogFile`, a `MakeWriter` of the
binary's own:

- It opens the file with `O_APPEND`, creating it at mode `0640` when it is missing, so each record is appended whole
  even if another process appends too.
- It holds the open file behind a mutex, and writes each record with one `write_all` under it, so records from
  different threads never interleave.
- **It follows a rotation without a signal.** Before it writes a record, it compares the `(dev, inode)` of the path
  with that of its open file. When they differ, or the path is missing, `logrotate` has renamed the file, so it opens
  (and creates) the path again and writes there. A record written between the rename and the reopen lands in the
  renamed file, which `delaycompress` leaves uncompressed until the next rotation, so no record is lost. A reopen that
  fails is a write failure ([Failure behaviour](#failure-behaviour)).
- It reports every failed write ([below](#failure-behaviour)).

The check costs one `stat` per record, which is small beside the write itself.

### The shipped rule

The package ships `/etc/logrotate.d/iron-vault`, owned by root, mode `0644`:

```
/var/log/iron-vault/iron-vault.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 iron-vault iron-vault
    su iron-vault iron-vault
}
```

`create` makes the new file with the service account as owner before the service reopens it; `su` makes `logrotate`
act as the service account in a directory root does not own. No `postrotate` script is needed. Size limits are a
`maxsize` line in the same rule, for an administrator who wants one.

The rule names the default directory only. When an approved config moves the log directory, the shipped rule matches
nothing (`missingok` keeps it quiet), and the administrator adds a rule for the new directory; the approval summary's
entry for the change says so. The service never writes to `/etc/logrotate.d`.

In development nobody rotates the log: the file grows until the developer removes or rotates it, for example with a
user `logrotate` run that keeps its own state file. The reopen check works there too.

## Writer behaviour

The writer is blocking: each record is written to the file (or stdout) by the thread that emits it, before the
emitting call returns. A record therefore reaches the kernel before the event it describes is reported to anyone, and
a crash or abort loses no record already emitted. The records are not fsynced one by one; a power failure may lose
the last records, and the approval state, not the log, is the authority on versions.

The alternative, a non-blocking writer with a channel and a worker thread that never drops a record, keeps disk writes
off the request tasks, but the records still in its channel are lost on a crash or an abort, which is when an audit
trail matters most, and its worker thread can report a write error only on stderr, where the service cannot act on it.
A write takes microseconds and the service serves one host's callers, so the blocking writer's cost is acceptable. A
writer that drops records when its channel is full is ruled out: audit records must never be dropped silently.

## Failure behaviour

- **The destination cannot be opened at startup** (the directory is missing, unwritable or fails its trusted-path
  check): the service writes one line to stderr naming the destination and the error kind, and exits non-zero before
  it binds any socket or unlocks anything. systemd records the failure in the unit's status.
- **A write fails mid-run** (for example, a full disk, a failed reopen, or a closed stdout): after a record fails, the
  service serves and accepts nothing further, then stops as on SIGTERM: it clears its memory and exits non-zero. A
  unit with `Restart=on-failure` ([§3.12](iron-vault-specification.md#312-service-states-and-errors)) restarts it,
  and the restart then succeeds or fails at startup as above.

`tracing-subscriber`'s `fmt::Layer` discards a writer's error: it only prints it to stderr. So the failure is seen in
`LogFile`, the one place that has the error. Its first failed write trips a shared latch, `logging::LogFailure`. The
request server checks the latch as it admits each request and the admin server as it reads each command, and refuses
both once it is tripped; the `serve` loop's stop future completes on it beside SIGTERM.

The subscriber is built with `log_internal_errors(false)`. Otherwise, when an event fails to format, `fmt::Layer`
writes a plain-text "Unable to format the following event" line into the log, which breaks JSON Lines. Audit and
request events record only primitive values ([Field rules](#field-rules)), so their formatting cannot fail; a
diagnostic record whose own `Display` fails is lost, which is acceptable for a diagnostic record and impossible for an
audit record.

A full disk keeps the service down. Each restart opens the file, fails its first write and stops again, until
systemd's start limit leaves the unit failed. That is intended: the service never runs without its audit log, and the
unit's status and stderr say why. Freeing space and restarting the unit recovers it.

Both cases are explicit safe states ([§3.12](iron-vault-specification.md#312-service-states-and-errors)): the service
never serves a request or accepts an admin change it cannot record. The alternative, falling back to stderr and
carrying on, runs the service without its audit log, which is what this design must prevent. A third option, a new
service state that refuses requests with a `503` while the log is unwritable and resumes when it recovers, keeps the
request interface answering, but adds a state, an unavailable reason and a retry loop for a rare fault. Stopping costs
a passphrase-only install one unlock after the disk is fixed. Whether stopping is the safe state §3.12 intends is an
[open question](#open-questions).

## Permissions

In a protected install the log directory is owned by the service account, mode `0750`, and its files `0640`, so
callers cannot read or change the audit log. The group is the service account's own unless the administrator chooses
a group for a collector; a caller's account is never in it. The directory and every ancestor must pass the
trusted-path rule for a service-owned directory ([Trust](#trust)). `LogFile` creates the file at `0640` itself, and
the shipped `logrotate` rule creates each new file at `0640`, so neither depends on the unit's umask.

## Dependency caps

The dependency caps in `logging.rs` stay as they are: `CAPPED_TARGETS` capped at `DEPENDENCY_CAP` (`WARN`) by their
own layer, fixed in code whatever level or setting is in force
([§3.7](iron-vault-specification.md#37-outbound-tls-and-environment)). The new formatter and writer are added beside
that layer, never in place of it. No `log` backend is installed, so the records `reqwest` and `rustls` emit through
`log` stay discarded.

## Dependencies

`tracing-subscriber` is 0.3.23 in `Cargo.lock`, with the features `fmt`, `registry` and `std`. This design adds:

- the `json` feature of `tracing-subscriber`, which brings `tracing-serde` and `serde_json`;
- `uuid` as a dependency of the binary; it is already a workspace dependency used by the store.

It adds no `tracing-appender` ([departure](#departure-no-tracing-appender)). None of these depends on `rand`,
`rand_core` or `getrandom`, except `uuid`, which uses the `getrandom` 0.4 the store already brings. The lock file
already holds two copies of each random crate: `rand` 0.8 and `rand_core` 0.6 with `getrandom` 0.2 come from `age`,
and `rand` 0.10 comes only from `proptest` in development; `getrandom` 0.4 comes from the store and `uuid`. This design
adds no further copy. The ticket that adds each crate checks `Cargo.lock` again.

## Operations

K-177 writes the operations guide: the log directory's setup, the shipped `logrotate` rule and a rule for a moved
directory, Docker's log-driver rotation, and collector settings for Grafana Alloy, Vector, Fluent Bit and Filebeat,
with the Loki labels and the Elastic `@timestamp` rename above.

## Open questions

These are questions about the specification, for the owner. Until the owner answers, the design follows the default
stated for each.

1. **§3.15's "one structured event per … rejected request": does it exempt rejections made before service code
   runs?** hyper's own `431` and `414`, and connections closed unread over `max_connections`, have no request event
   ([Known limit](#known-limit)). Owner decision D3 answers this for the design: these are the accepted exceptions,
   and every refusal Iron Vault's own code makes writes a request event. The specification's wording still reads as
   if it had no exceptions, so the question left is whether §3.15 should name them.
2. **§3.12 keeps the request interface bound so callers receive an explicit status. Is stopping on an audit-log
   failure the intended safe state, or should it be a `503` state?** *Default:* stop, as
   [Failure behaviour](#failure-behaviour) describes; callers then see a refused connection rather than a `503`.
3. **Confirm the departure from decision 2:** no `tracing-appender`
   ([Departure: no `tracing-appender`](#departure-no-tracing-appender)). *Default:* the binary's own `LogFile`
   writer.

## Spec check

Checked against [§3.15](iron-vault-specification.md#315-logging-and-v0-acceptance),
[§3.2](iron-vault-specification.md#32-service-and-cli-boundary),
[§3.6](iron-vault-specification.md#36-url-header-and-slot-rules),
[§3.7](iron-vault-specification.md#37-outbound-tls-and-environment),
[§3.9](iron-vault-specification.md#39-configuration-approval-and-reload),
[§3.12](iron-vault-specification.md#312-service-states-and-errors) and
[§3.14](iron-vault-specification.md#314-docker-remote-servers-and-appliances). The request event carries every field
§3.15 lists (time, caller, route, credential name, upstream host, method, status, sizes, duration, scrubbing), and
every rejected request Iron Vault's code sees writes one. Owner notifications
([§3.2](iron-vault-specification.md#32-service-and-cli-boundary)) come after v0, in EP-40, and this design has none;
K-179 aligns the specification's wording.
