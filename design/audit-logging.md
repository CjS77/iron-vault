# Audit logging

What the service writes to its log, in what shape, and where (specification
[§18](iron-vault-specification.md#18-logging)). Iron Vault cannot stop a caller from misusing a
route it was granted, so it records every request and every administrative and security fact. The log must never
become the leak: it holds names, numbers and fixed codes, never a secret, a body, a header value or a URL. Terms follow
the [glossary](glossary.md).

The log has three kinds of record, all in one stream:

- **Request events:** one per completed or rejected request ([Request event](#request-event)).
- **Audit events:** one per administrative change, approval step, lock transition, corruption, policy failure or
  other security fact ([Audit events](#audit-events)).
- **Diagnostic records:** every other `tracing` event, such as a listener's accept error. They help an administrator
  debug and carry no stable name.

The questions this design raised for the owner, and how each was decided, are under [Open questions](#open-questions).

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
  ([§10](iron-vault-specification.md#10-outbound-tls-and-environment)).

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
  means "reload the config" ([§12](iron-vault-specification.md#12-configuration-approval-and-reload)).

### D3: every refusal Iron Vault's code makes writes a request event

The owner relies on request events to debug bad route and credential setups, so every refusal made by Iron Vault's own
code writes `request.completed`, including the refusals the request server makes before or instead of the request
handler: its request form gate's `400`, its `413` for a declared body over the limit, and its `408` and `413` after it
has dropped the handler. A field the service cannot know at that point, such as the caller or route when the handler
never ran, is left out; `request_id`, `listener` and `http_method` are always present, and so is `status` but for one
case ([`status`](#status)). [Request event](#request-event) settles who writes the event so that no request yields
zero events or two.

The only refusals without a request event are those made before Iron Vault's code sees a request: hyper's `431` and
`414`, and a connection closed unread over `max_connections` ([Known limit](#known-limit)).

Rejected:

- **Leaving the request server's own refusals to a diagnostic record.** A diagnostic record has no stable name or
  shape, so a collector cannot count or alert on it, and the
  [§18](iron-vault-specification.md#18-logging) rule of one event per rejected request would
  have a hole Iron Vault could close.
- **A separate event name for the request server's refusals.** Every dashboard would have to query two names for one
  stream; `reason` already says which check refused.

### Owner notifications come in v1

v0 has no owner notifications: the owner placed them in v1, in EP-40. In v0 this design has no notification channel,
and every fact it records goes to the log only. [owner-notifications.md](owner-notifications.md) designs them for v1,
recording each one as the audit event `owner.notified` ([Catalogue](#catalogue)).

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
  [log operations guide](../book/src/reference/log-operations.md#collectors) gives the collector settings.
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
| `file` | string | A state or config file name, or a migration bundle entry's name; never a path |
| `step` | string | A fixed step label, such as an approval step, an init step, a reset step (`begin`, `remove`, `finish`), an approver change step (`read_back`, `tpm_helper`, `key_file`, `key_check`, `approval_state`), or an export step (`check`, `snapshot`, `seal`, `transfer`) |
| `refusal` | string | Why an admin connection, request, command, migration authorization or host unlock was refused: a fixed label |
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
  config is validated ([§18](iron-vault-specification.md#18-logging)), as the policy crate's name
  types already do;
- a caller-controlled value that must be logged goes through the policy crate's escaping (`display::escaped`), which
  also escapes non-ASCII, so a format character such as U+202E cannot reorder what a reader sees. That function is
  `pub(crate)` today; the first ticket that logs a caller-controlled value from the binary exports it.

The request event logs one caller-controlled value, `http_method`; its other fields are configured names, numbers,
fixed labels and the request ID. hyper's parser admits only RFC 9110 token characters in a method, so it holds no
control character, space or quote, and it still goes through `display::escaped`.

## Never logged

No record contains any of these ([§18](iron-vault-specification.md#18-logging)):

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
| `upstream_host` | string | once a route is selected, unless the answer was replaced | The route's upstream host, as configured; never the port, path or query |
| `status` | number | once `respond` produced a response | The status of the response `respond` produced |
| `request_bytes` | number | always | Body bytes read from the caller, as counted against `max_request_body_bytes` |
| `response_bytes` | number | always | Body bytes handed to hyper for the caller, after scrubbing and any re-encoding |
| `duration_ms` | number | always | Whole milliseconds from the request server receiving the request to the event being written |
| `scrubbed` | boolean | once the handler's relayed response was sent | Whether any scrub pattern matched in its headers or body |
| `outcome` | string | always | `success` or `failure` |
| `reason` | string | when `outcome` is `failure` | The [reason code](#reason-codes) |

- **`outcome`** is `success` when an upstream response was relayed and its body reached its end, whatever its status:
  an upstream `404` relayed in full is a success of the proxy. It is `failure` when a reason was recorded: the service
  refused the request, could not reach the upstream, refused the upstream's response, or the body did not reach its
  end. A body that hyper never polls because it has nothing to send reaches its end too
  ([Bodies hyper never polls](#bodies-hyper-never-polls)).
- **`duration_ms` stops when the record writes the event**: at the end of the streamed response body, or when the body
  is dropped, not at the response head, so a long streaming response is counted for as long as it streams. hyper may
  still be flushing the last bytes then. It is measured on the monotonic clock and rounded down. It is an integer, not
  a fraction, because Elastic maps a field from its first value, and a first value of `3` would make `3.5` a type
  conflict.
- **`response_bytes`** counts the body bytes the outermost body layer handed to hyper, including a fixed refusal body
  such as the form gate's. Bytes still in hyper's or the kernel's buffers when the connection closed are counted,
  though the caller may never have received them. The response outcome's `decoded_bytes`, the bytes the scrubber
  screened, is not logged: for a compressed response it is not what the caller was sent, and an operator comparing
  with the caller's own counts needs the sent figure.
- **`scrubbed`** comes from the relayed body's running match count, which the body records as each match is found
  (in the headers when the head is built, and in the body as each piece is screened). So a body that fails or is
  dropped mid-stream still reports whether a pattern matched in what was screened before it stopped. The response
  outcome gives the same flag for a body that ended cleanly; the relayed body must keep its count available after a
  failure too. It is left out when the handler's answer was replaced ([Which reason wins](#which-reason-wins)).

### `status`

`status` is the status of the response `respond` produced: its own refusal, or the handler's answer, after any
replacement by the request server. The record sets it when `respond` wraps that response, so it does not say whether
the head reached the wire; for a body that failed after its head, it is that head's status with `outcome` `failure`.

Its one absence is a `respond` future dropped before any response existed: the caller closed the connection, or the
service closed it, while the handler was still working. Then no status exists to record, and the reason is
`caller_gone` or `service_closed`. This is this design's reading of D3's "`status` is always present", as decided in
[open question 4](#open-questions); the alternative, a made-up status such as `499`, would be a status no
one sent.

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
  response exists, the record's `Drop` writes the event with no status and the drop's reason
  ([Closes the service makes](#closes-the-service-makes)).
- **One owner, one write.** The event is written from the record's `Drop`, or from the body's end, which consumes the
  facts, so a clean end followed by the drop writes once. `Drop` must not panic: no `unwrap`, indexing or fallible
  call.
- **Facts are read when the event is written**, not when the record moves, so a body failure the relay or the
  request deadline records reaches the event. The scrub match count is recorded as matches are found, so it is
  already in the facts when the outer layer's `Drop` runs before the inner relayed body is dropped.
- **The record writes `response.scrubbed` too**, beside `request.completed`, when the match count is above zero and
  the handler's relayed response is the one sent. The relayed body never writes it, so a relayed body that is
  discarded unsent writes nothing.

K-173 builds the record and the handle; K-174 writes the event from the body.

### Bodies hyper never polls

hyper 1.x drops a response body without polling it in two cases (`proto/h1/dispatch.rs` `poll_write`, and the
`can_have_body` rule in `proto/h1/role.rs`): the body's `is_end_stream()` is already true, or its `size_hint()` is
exactly 0, when the head is written, as for every fixed empty refusal; or the response cannot carry a body: an answer
to `HEAD`, a `204` or a `304`. A drop there is a clean end, not a caller going away. `can_have_body` also covers a
`1xx` and a `2xx` answer to `CONNECT`, but neither reaches the record: the form gate refuses `CONNECT`, and `respond`
never produces a `1xx`. So the outermost body layer:

- forwards `is_end_stream()` and `size_hint()` from the body it wraps, so hyper sees the same body it would have seen
  unwrapped;
- records, when `respond` wraps the response, whether it can carry a body, from the request method and the status, by
  the same rule as the relay's `has_no_body` (`proxy_handler/relay.rs`);
- on a drop before the end, counts it as a clean end when the response cannot carry a body, or the inner body reports
  `is_end_stream()` or a `size_hint()` that is exactly 0. A relayed `HEAD` answer is then a `success`, and a fixed
  refusal keeps the reason it was given. Any other drop before the end is a drop failure, below.

### Closes the service makes

The service closes connections itself: `Connections::close_except` and `close_all` (`request_server.rs`, called from
`service_context/serving.rs`) abort the connections of a listener a rebuild drops, every connection when the limits
change, and every connection at a stop. Each aborted task drops its record. Blaming the caller for those would send an
administrator looking in the wrong place, so a drop failure has two codes:

- `service_closed` when the service closed the connection;
- `caller_gone` otherwise: the caller closed it, or hyper ended it on a connection error.

The record learns which from a flag. Each listener's connection set holds a `ServiceClose` flag, a shared atomic
boolean. Each connection task holds a clone and passes it to `respond` beside the connection's `ConnectionTags`, not
inside them: the tags are the pipeline's value object, compared by value, and a shared mutable flag has no place in
one. `respond` puts the clone in every request record on that connection. `close_except` sets the flag of each set it
is about to close before it aborts the set's tasks, so every record those aborts drop reads `service_closed`.

`Connections` also sets every set's flag in its `Drop`, before its connection sets abort their tasks. A listener task
that panics drops its `Connections` without calling `close_except` (`halt` in `service_context/serving.rs` then
returns an empty set), and that is still the service closing the connections, not the callers.

### Which reason wins

A record holds at most one reason. The rules, in order:

1. **The request server's own refusal after the handler had the request overrides the handler.** Its `413` when the
   body passed the limit (in the `select!`, or by the `overflow.is_tripped()` check that replaces an answer the
   handler gave in the same poll) and its `408` at the request timeout set their reason whatever the handler recorded.
2. **Otherwise the first reason recorded wins.** A later reason is ignored: a body failure the relay records is not
   replaced by the deadline that follows, and a drop never replaces a recorded reason.
3. **A drop with no reason recorded** writes `service_closed` or `caller_gone` ([above](#closes-the-service-makes)),
   unless it is a clean end ([Bodies hyper never polls](#bodies-hyper-never-polls)).

When rule 1 replaces the handler's answer, the facts that describe that answer are discarded, since the caller never
received it: `upstream_host` and `scrubbed` are left out of the event, and no `response.scrubbed` is written for the
discarded relayed body. `caller`, `route` and `credential` are kept, since they say who asked for what. The handle is
sealed at the replacement, so a handler still running cannot set them again.

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

**The request server, after the handler has the request** (its future is dropped, or its answer replaced; these
override the handler's reason, [Which reason wins](#which-reason-wins)):

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
| The caller closed the connection, or hyper ended it on a connection error, before the body ended | head's, or none | `caller_gone` |
| The service closed the connection (`close_except`, `close_all`) before the body ended | head's, or none | `service_closed` |

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
event is the redacted high-severity event [§9](iron-vault-specification.md#9-url-header-and-slot-rules) requires.
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
([§12](iron-vault-specification.md#12-configuration-approval-and-reload)). The store therefore returns the reserved
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
| `service.lock-transition` | INFO | a lock transition: Locked to Checking, or Starting to Checking on a host unlock, the outcome of the check that follows, and Ready or Unavailable to Locked | `from_state`, `to_state`; `unavailable_reason` when `to_state` is `unavailable` |
| `vault.unlock-refused` | WARN | an unlock was refused, or `init` or the host unlock at startup was refused for unprotected memory (`memory_unprotected`) | `refusal`, such as `wrong_passphrase` or `rate_limited`; `memory_protection` when `refusal` is `memory_unprotected`, a protected install whose memory is not locked; `retry_after` (whole seconds) when `refusal` is `rate_limited`, the vault passphrase attempt limit |
| `vault.host-unlock` | INFO, or WARN when `refused` or `unseal_failed` | a Protected or Container service tried the unlock handoff at startup, or skipped it because the owner-lock file is there (`owner_locked`); a Development service never writes it | `host_unlock_outcome`; `refusal` when refused: `memory_unprotected`, `untrusted`, `unreadable`, `not_an_identity`, `not_initialized` or `not_a_recipient` |
| `vault.presence-refused` | WARN | owner presence for `replace`, `rm`, `recipient remove` or an approver command was refused: the approval passphrase was wrong or the key is not the asked approver's; nothing was written | `refusal` (`wrong_passphrase` or `key_mismatch`), `approver_id`, `approver_label`; no `config_digest`, since no config is involved |
| `vault.lock-incomplete` | WARN | a lock's drain ended with a serving snapshot or the vault identity still held | `snapshots_held`, `identity_held` |

`service.started` carries the hardening report's outcome as fixed labels, so a run without its protections is visible
in the startup record itself; `service.hardening-incomplete` is the record to alert on, with the fix for each missing
protection in `remediation`. The reason text a
failed core-dump setting carries is not logged, since it is an OS error's text. Every record carries
`deployment_profile` as a constant field, so the startup event needs no profile field of its own. The state labels are
fixed strings, never `ServiceState`'s `Debug` output, which writes `Unavailable(PolicyInvalid)`.
`service.lock-transition` is the struct `audit::LockTransition`. `vault.host-unlock` is `audit::vault::HostUnlock`; it
never holds the handoff's bytes or its recipient key. `owner_locked` is INFO with no `refusal`: the owner locked the
service, and the startup read the [owner-lock file](tpm-unlock.md#lock-across-restarts) before the memory guard and
before it opened the handoff. A failed write or removal of that file is a plain WARN line carrying only the error kind,
not an audit event. A `memory_unprotected` refusal also writes the
`vault.unlock-refused` record every unlock path's memory guard writes
([docker-compose.md](docker-compose.md#in-the-container)).

**Admin commands:**

| Event | Level | When | Fields |
|---|---|---|---|
| `admin.command` | INFO | an admin principal's request was read | `command`, `principal_uid` |
| `admin.refused` | WARN | an admin connection or request was refused before any command ran | `refusal`; `peer_uid` and `peer_pid` when known; `peer_pid` is absent when the peer is in another PID namespace |
| `caller.token-issued` | INFO | a caller token was issued | none; the token is never logged |
| `caller.token-failed` | ERROR | no caller token could be issued | `error_kind` |

`admin.refused`'s `refusal` is one of `not_admin_principal`, `peer_unreadable` and `busy` for a connection, and
`unsupported_version`, `malformed_frame`, `unknown_command` and `unexpected_frame` for a request frame that was not
read as a command (the frame errors the admin server logs today). A refusal of a command after it was read (`init`'s
`wrong_state`, `already_initialized`, `passphrase_rejected`, `declined`) records only `admin.command`.

**Config approvals and checks** ([config-approval.md](config-approval.md#audit-events) gives when each fires). A
reserved version and a completed approval are distinct events, so a reserved version is never mistaken for a
completed approval ([§12](iron-vault-specification.md#12-configuration-approval-and-reload)):

| Event | Level | When | Fields |
|---|---|---|---|
| `config.approval-refused` | WARN | the approval passphrase was wrong or the key is not the asked approver's; nothing was reserved | `refusal` (`wrong_passphrase` or `key_mismatch`), `config_digest`, `approver_id`, `approver_label` |
| `config.version-reserved` | INFO | step 2's reservation is durable | `version`, `config_digest`, `approver_id`, `approver_label` |
| `config.approval-failed` | WARN | the transaction failed after its reservation and before its commit | `version` (consumed), `config_digest`, `step`, `error_kind` |
| `config.commit-uncertain` | WARN | step 5's rename of `approval.age` landed, but its directory fsync failed | `version`, `error_kind` |
| `config.approval-completed` | INFO | the commit is durable | `version`, `config_digest`, `summary`, `approver_id`, `approver_label` |
| `config.activation-failed` | WARN | the config check after a committed approval failed, or an uncertain commit could not be settled | `version`, `unavailable_reason`, `detail` |
| `config.check-failed` | WARN | any config check failed | `unavailable_reason`, `failure`, `detail`; `log_destination` when the log destination failed |
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
| `credential.replaced` | INFO | a `replace` committed | `credential`, `old_record_id`, `record_id`, `kind`, `origins`; `old_kind`, `old_origins` for a healthy old record |
| `credential.removed` | INFO | an `rm` committed | `credential`, `record_id` |
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

Each corruption event also carries `remediation`, a fixed phrase the service holds with the event.

**Initialization** ([vault-initialization.md](vault-initialization.md#logging) gives when each fires):

| Event | Level | When | Fields |
|---|---|---|---|
| `vault.init-discarded` | WARN | an unfinished initialization was discarded | `files` |
| `vault.initialized` | INFO | init's last step is durable | `vault_id`, `recipients`: the enrolled roles' names, comma-separated (kinds, never keys) |
| `vault.init-failed` | WARN | an init step failed | `step`, `error_kind` |

Init's version 1 also records `config.version-reserved` and `config.approval-completed`, so it is audited like any
other approval.

**Reset** ([reset.md](reset.md#logging) gives when each fires):

| Event | Level | When | Fields |
|---|---|---|---|
| `vault.reset-confirmed` | WARN | the owner confirmed, before `reset.unfinished` is written | `vault_id` (an Initialized vault only), `verified`, `initialization` (`initialized`, `unfinished`, `unfinished_import`, `unfinished_reset` or `unrecognized`), `from_state`, `resumes` |
| `vault.reset` | WARN | the vault is discarded and `reset.unfinished` is removed | `vault_id`, `files`, `foreign` (escaped names, in a [list](#field-rules)), `finish_uncertain` |
| `vault.reset-failed` | WARN | writing `reset.unfinished` or a removal failed | `step` (`begin`, `remove` or `finish`), `file`, `error_kind`, `removed` |

The lock from Ready or Unavailable raises the existing `service.lock-transition`.

**Routes and responses:**

| Event | Level | When | Fields |
|---|---|---|---|
| `route.pinned-ca-unavailable` | WARN | a route's pinned CA could not be loaded, so the route is unavailable | `route`, `config_field` (`ca_file`) |
| `response.scrubbed` | WARN | a relayed response ended, cleanly or not, and a scrub pattern matched in its headers or body (the scrub event) | `request_id`, `route`, `credential`, `matches` |
| `request.defect` | ERROR | a request was refused by a service defect | `request_id`, `route`, `credential`, `defect` |

**Recovery** ([recovery.md](recovery.md#logging) gives when each fires):

| Event | Level | When | Fields |
|---|---|---|---|
| `recovery.checked` | INFO when opened, WARN otherwise | `recovery check` ended with `invalid` at its prompt, or with any other outcome after the key parsed and the lock was taken; `busy` and the re-check's `wrong-state` and `recovery-check-unavailable` record only `admin.command` | `recovery_outcome`; for `opened`, `vault_id` and `recorded`, with `error_kind` when not recorded; for `failed`, `recovery_failure`; for `unavailable`, `file` and `error_kind` |
| `recovery.reminder` | INFO | a reminder evaluation found a recovery reminder due | `recovery_record`; `last_checked` when `checked`; `reminders_since` when `never_checked`; `error_kind` when `unusable`; `reminder_days`; `remediation` |

**Recipients** ([recipients.md](recipients.md#audit-events) gives the whole family; the inventory check writes
`recipient.inventory-damaged` and `recipient.change-recovered`; `recipient add` and `recipient remove` write the others):

| Event | Level | When | Fields |
|---|---|---|---|
| `recipient.added` | INFO | a recipient change that adds committed | `recipient`, `recipient_role`, `recipient_label`, `recipients` |
| `recipient.inventory-damaged` | WARN | the inventory check found the recipient inventory missing or damaged | `inventory_damage` |
| `recipient.change-recovered` | WARN | the inventory check finished a committed recipient change or removed a staged inventory | `recovery` |
| `recipient.removed` | INFO | a recipient change that removes a recipient committed | `recipient`, `recipient_role`, `recipient_label`, `recipients` |
| `recipient.change-failed` | WARN | an add or a removal was refused at its own step 3 (`already_enrolled`, `unknown_recipient`, `set_invalid`), or its recipient change failed (`write_failed`) | `change`, `recipient`, `failure`; `step`, `error_kind` and `committed` for `write_failed` |

The `recipient.forget-checked` event ([forget-machine.md](forget-machine.md#audit-event)) is written by `forget-machine`:

| Event | Level | When | Fields |
|---|---|---|---|
| `recipient.forget-checked` | INFO when the key is not a recipient, the independence rule holds and the recovery path is verified (a check ran, no reminder due), else WARN | `forget-machine` parsed the key and ran the inventory check | `recipient`, `forget_outcome` (`forgotten` or `still_enrolled`), `recipient_role` (`still_enrolled` only), `independence` (`holds` or `broken`) and `recovery` (`verified` or `unverified`), `forgotten` only |

**Approvers** ([approval-signers.md](approval-signers.md#audit-events); `approver add` and `approver remove` write these):

| Event | Level | When | Fields |
|---|---|---|---|
| `approver.enrolled` | INFO | an approver change that enrolls committed (`signer_kind` is `software` or `tpm`) | `approver_id`, `approver_label`, `signer_kind`, `approvers`, `authorizing_approver_id`, `authorizing_approver_label` |
| `approver.removed` | INFO | an approver change that removes committed | as `approver.enrolled`, and `key_file` (`removed` or `left`) |
| `approver.change-failed` | WARN | `approver add` was refused at step 3 (`set_invalid`, `write_failed`) or step 6 (`passphrase_rejected`); `approver remove` was refused at step 3 (`unknown_approver`, `set_invalid`, `in_use`, `write_failed`); or either command's approver change failed (`write_failed`) | `change`, `failure`; `approver_id` when known; `step`, `error_kind` and `committed` for `write_failed` |
| `approver.orphan-removed` | WARN | step 3 of an approver command removed an orphan key file | `approver_id`, the ID in the file's name |

**Migration authorization** ([migration-authorization.md](migration-authorization.md#audit-events) gives the order of the records of one exchange):

| Event | Level | When | Fields |
|---|---|---|---|
| `migration.challenge-issued` | INFO | a migration challenge was issued | `operation`, `method`; `destination_recipient` for `add_recipient` |
| `migration.authorized` | INFO | a source-owner method proved the challenge | `operation`, `method`; `destination_recipient` for `add_recipient` |
| `migration.authorization-refused` | WARN | the challenge was refused or its prompt cancelled, or the authorization was refused when consumed | `operation`, `method`, `refusal`; `destination_recipient` for `add_recipient`; `retry_after` for `rate_limited` |

**Migration bundle** ([migration-bundle.md](migration-bundle.md#audit-events) gives when each is written):

| Event | Level | When | Fields |
|---|---|---|---|
| `migration.exported` | INFO | the last bundle data frame of an export was written | `vault_id`, `records`, `approvers`, `committed_version`, `highest_reserved` |
| `migration.export-failed` | WARN | an export failed at its snapshot checks, or after its authorization was consumed | `step` (`check`, `snapshot`, `seal` or `transfer`), `error_kind` (`locked` for a `lock`, `deadline` for a missed deadline); `file` when a file failed |
| `migration.import-refused` | WARN | an import was refused at steps 2 to 4 | `refusal` (`bundle_invalid` or `wrong_passphrase`); `detail`, the fixed name of the failed rule or check, for `bundle_invalid` |
| `migration.import-discarded` | WARN | an unfinished import was discarded, by `import` or `init` | `files` |
| `migration.imported` | INFO | the import's step 10 is durable | `vault_id`, `records`, `approvers`, `committed_version`, `highest_reserved`, `recipients`: the enrolled roles' names |
| `migration.import-failed` | WARN | an import write step failed | `step`, `error_kind` |

**Owner notifications** (v1; not emitted in v0.
[owner-notifications.md](owner-notifications.md#which-events-notify) gives which events raise one):

| Event | Level | When | Fields |
|---|---|---|---|
| `owner.notified` | INFO | right after the record of an audit event that notifies the owner | `topic`, `source_event`, `urgency`, `title`, `body`, `remediation` |

### Event fields

The fields that only one event uses, or that only audit events use:

| Field | Type | Form |
|---|---|---|
| `command` | string | The admin command ID in snake_case, such as `config_approve` or `caller_token` |
| `principal_uid`, `peer_uid`, `peer_pid` | number | The admin peer's uid and pid, as the kernel reported them; `peer_pid` is left out when the peer is in another PID namespace, such as the host CLI in the Container profile |
| `core_dumps` | string | `disabled` or `not_disabled` |
| `memory_protection` | string | `locked`, `unavailable` or `unsupported` |
| `previous_log_destination` | string | The log destination before the change, in `log_destination`'s form |
| `from_state`, `to_state` | string | A service state label: `starting`, `locked`, `checking`, `ready`, `unavailable` or `stopped` |
| `snapshots_held` | number | Serving snapshots still held when the lock's drain ended |
| `identity_held` | boolean | Whether the vault identity was still held when the lock's drain ended |
| `summary` | string | The approval summary's text, or `initial config` for version 1 |
| `failure` | string | A config check failure's fixed label, one per check failure variant, never its `Display` text; for `recipient.change-failed`, `already_enrolled`, `unknown_recipient`, `set_invalid` or `write_failed`; for `approver.change-failed`, `set_invalid`, `passphrase_rejected` or `write_failed` |
| `renames` | string | The publish renames run, as fixed labels in a [list](#field-rules) |
| `signed_for` | number | The approval version a staged approval was signed for |
| `kind`, `old_kind` | string | A credential kind label, such as `static` or `basic` |
| `origins`, `old_origins` | string | A credential's permitted origins as `https://host:port`, in a [list](#field-rules) |
| `old_record_id` | string | The replaced record's record ID |
| `secret_field` | string | The label of a credential kind's secret field, such as `password` |
| `len` | number | A secret's length in bytes |
| `damage` | string | A record damage or shared-state damage label |
| `files` | string | File names, in a [list](#field-rules) |
| `foreign` | string | Foreign file names, escaped, in a [list](#field-rules) |
| `initialization` | string | The initialization state reset read: `initialized`, `unfinished`, `unfinished_import`, `unfinished_reset` or `unrecognized` |
| `verified`, `resumes`, `finish_uncertain` | boolean | Whether a reset's vault ID came from an open vault; whether it finishes an interrupted reset; whether the removal of `reset.unfinished` may not survive a power loss |
| `removed` | string | The files a failed reset removed before it stopped, in a [list](#field-rules) |
| `vault_id` | string | The vault ID, a hyphenated lowercase UUID |
| `config_field` | string | The config key a fact is about, such as `ca_file` |
| `matches` | number | Scrub pattern matches in one response |
| `defect` | string | The label of the check a service defect failed |
| `host_unlock_outcome` | string | `unlocked`, `absent` (no unlock handoff), `unseal_failed` (no handoff, and the handoff unit left the [unseal-failure file](tpm-unlock.md#reporting-a-failed-unseal)), `owner_locked` (the owner-lock file is there, so the handoff was not opened) or `refused` |
| `recovery_outcome` | string | `opened`, `failed` (the key does not open this vault), `invalid` (the text is not a recovery key) or `unavailable` (the check could not run) |
| `recovery_failure` | string | Why a recovery key failed: `not_a_recipient` or `identity_unverified` |
| `recorded` | boolean | Whether a successful recovery check's record was written |
| `inventory_damage` | string | What the recipient inventory check found: `envelope_unreadable`, `missing`, `unreadable`, `mac`, `malformed`, `unknown_role`, `other_vault`, `envelope_mismatch` or `count_mismatch` |
| `recovery` | string | How the inventory check settled a staged recipient change: `completed` or `discarded` |
| `recipient` | string | A recipient key's `age1…` text, which is public |
| `recipient_role` | string | A recipient role's name: `operational`, `recovery`, `added` or `host-unlock` |
| `recipient_label` | string | A recipient label, escaped |
| `approver_id` | string | The approver asked for, or that signed, or that an approver command enrolls or finds orphaned: its approver ID, a hyphenated UUID |
| `approver_label` | string | That approver's label, escaped |
| `authorizing_approver_id` | string | The approver that gave owner presence for an approver change: its approver ID, a hyphenated UUID |
| `authorizing_approver_label` | string | That approver's label, escaped |
| `signer_kind` | string | `software`, `tpm` or `hardware` |
| `approvers` | number | The approver count after an approver change, or that a migration bundle carries |
| `records` | number | The number of credential records a migration bundle carries |
| `highest_reserved` | number | The highest reserved approval version |
| `recipients` | number | The recipient count after a recipient change |
| `change` | string | `add` or `remove` |
| `committed` | string | `no`, `unknown` or `yes`: whether a failed recipient change committed; `no` or `unknown` for a failed approver change, always `no` when `step` is `read_back` |
| `recovery_record` | string | The recovery check record's form: `checked`, `never_checked` or `unusable` |
| `last_checked` | string | The record's last successful recovery check, an RFC 3339 UTC timestamp to the second |
| `reminders_since` | string | When the reminder schedule started counting, an RFC 3339 UTC timestamp to the second |
| `reminder_days` | number | The reminder interval in force, in days |
| `operation` | string | A migration operation: `export` or `add_recipient` |
| `method` | string | A source-owner method's label: `vault_passphrase` in v0 |
| `destination_recipient` | string | The recipient key a migration adds, in its `age1…` text, which is public |
| `retry_after` | number | Whole seconds left in the passphrase attempt limit's cooldown, rounded up |
| `topic` | string | A notification topic label, such as `vault_changed` |
| `source_event` | string | The event name of the audit event an owner notification was made from |
| `urgency` | string | `normal` or `critical` |
| `title` | string | An owner notification's title, a fixed phrase per topic |
| `body` | string | An owner notification's body, built from its source event's fields; at most 1024 bytes |

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
| An approval or config check task panicked or was cancelled (`service_context.rs` `log_task_crash`) | It reports a service defect, not an administrative or security fact, and the task fails closed; it stays an `ERROR` diagnostic record for the developer |

### Event names

An event name is `<subject>.<name>`: a lowercase subject (`admin`, `approver`, `caller`, `config`, `credential`,
`migration`, `owner`, `recipient`, `recovery`, `request`, `response`, `route`, `service`, `vault`), a dot, and a kebab-case name,
matching `^[a-z]+\.[a-z]+(-[a-z]+)*$`. Event names keep the kebab-case already in use in the code and the design
docs; only field names and label values are snake_case. Names are stable: renaming or removing one changes the schema
version. Each name is defined once, as an `audit::EventName` constant beside its struct.

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

### Stdout is never the journal

Under systemd a service's stdout is normally a stream into journald, so `stdout` there would break owner decision 3 ("no
journald output, even on Linux"), and the journal's readers are not bound by the log directory's mode. So `stdout` is
refused when stdout is the journal: systemd sets `JOURNAL_STREAM` to the `<dev>:<inode>` of the stream it connects to
stdout or stderr (`systemd.exec(5)`), and the service refuses `stdout` when that variable is set and file descriptor 1's
device and inode match it. A `JOURNAL_STREAM` that is set but cannot be parsed as two decimal numbers joined by a colon
is refused as if it matched: systemd never writes one, so the service cannot rule out the journal, and failing closed
costs only an administrator clearing a stray variable. The check runs at startup for `--log-to-stdout`, which then exits
as for a destination that cannot be opened, and in the config check for `destination = "stdout"`, which then fails as
for an unusable directory ([Switching at activation](#switching-at-activation)). The variable is read only to refuse; it
can never select or move a destination, so it is not an ambient setting in the sense of
[§10](iron-vault-specification.md#10-outbound-tls-and-environment).

The alternatives were rejected. Detecting a container (`/.dockerenv`, `/run/.containerenv`, cgroup names) depends on
each runtime's conventions and would refuse stdout piped to a collector outside one. Setting `StandardOutput=null` in
the packaged unit would turn `stdout` into a destination that silently discards every record, since writes to
`/dev/null` succeed. An administrator who points the container runtime's `journald` log driver at the container's stdout
makes that choice in the runtime, outside the service; the [log operations guide](../book/src/reference/log-operations.md#docker) says not to.
Podman uses that driver by default on Fedora and RHEL, so the guide names it.

Stderr is not a log destination. Only the one line a startup failure writes before the subscriber is installed goes
there ([Startup order](#startup-order)), as today; under systemd that line reaches the journal and the unit's status.

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

- The config check opens the new destination, verifying the directory's descriptor and the log file's as [Trust](#trust)
  and [Log file and rotation](#log-file-and-rotation) describe, as one of its own checks. If it cannot be opened or
  fails a check, the config check fails and writes `config.check-failed` with `unavailable_reason` `policy_invalid`,
  `failure` `log_destination_unusable`, a `detail` that is the fixed phrase of the check that refused (such as
  `not owned by the service account`), and the path in `log_destination`; `detail` never carries the path. The
  service settles Unavailable as for any other invalid policy, and it keeps writing to the current destination.
- The writer switches only after every other part of the config check has passed, as the check's last step before
  activation. There is no half-switch: a check that fails for any reason leaves the writer where it was, and until the
  new destination is open, every record goes to the old one.
- `config approve` checks the proposed destination before it reserves a version: the directory, verified through a
  descriptor it opens and closes ([Trust](#trust)); the journal check for `stdout`; and, when `iron-vault.log` exists,
  the [log file rule](#log-file-and-rotation), read with `fstatat` through that descriptor. It creates nothing, opens
  no file for writing and does not switch the writer. An approval naming an unusable destination is refused as an
  invalid config and consumes nothing. The check at activation still runs, since the directory can change in between.
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
- a directory that passes the trusted-path rule for a log directory, `TrustedPathRule::LogDir`, below.

The same rule applies to the bootstrap directory.

**The log directory rule** (`TrustedPathRule::LogDir`, in `trusted_path.rs`):

- **The leaf** is a directory, not a symlink, owned by the service account, with no write permission for its group
  and no permission at all for others: `0750` or stricter.
- **Each ancestor** is a directory owned by root or the service account. Nobody but its owner may write it, except
  that a root-owned ancestor may be writable by its group. No ancestor may be writable by others, sticky or not.
- **A symlink above the leaf** is allowed only when root controls it, as for the state directory: the link and the
  directory holding it are root-owned, and its target passes the same rule. A symlinked `/home`, as on Fedora Atomic,
  then passes in development.

Two rules differ from the state directory's. Its `require_not_writable` refuses any ancestor its group can write; the
log directory admits a root-owned one, because stock Debian and Ubuntu ship `/var/log` as `drwxrwxr-x root syslog`,
so the protected default `/var/log/iron-vault` could never pass the stricter rule. And the state directory's
`is_shared_sticky` test does not apply: it decides only whether a root-owned sticky directory that others or its group
can write, such as `/tmp`, is refused, while the log directory's rule already settles both cases without the sticky
bit. A root-owned ancestor its group can write passes whether or not it is sticky, since the sticky bit only narrows
what the group can do; one that others can write is refused whether or not it is sticky, since any local account,
callers included, could create entries in it.

**The check verifies the descriptor it keeps.** A walk of the path by name and a later open by name would leave a gap:
a member of a group that can write an ancestor (`syslog` on stock `/var/log`) could rename the directory away between
the two and plant one of their own. So the check, at startup for the bootstrap directory and in the config check for
a configured one, runs in this order:

1. walk the path with `lstat`, applying the rule above to every ancestor and recording the leaf's `(dev, inode)`;
2. open the leaf once, with `O_DIRECTORY | O_NOFOLLOW`;
3. `fstat` that descriptor, require its `(dev, inode)` to be the one the walk recorded, and apply the leaf rule to its
   own metadata;
4. keep the descriptor: `LogFile` writes only through it ([Log file and rotation](#log-file-and-rotation)), and never
   resolves the directory's path again.

This is the pattern `admin_file::read` already follows for an administrator-installed file: open the leaf the walk
checked without following a symlink, and refuse it unless `fstat` shows the same device, inode, owner and mode.

`config approve`'s check of a proposed directory ([Switching at activation](#switching-at-activation)) verifies it the
same way, then looks at `iron-vault.log` through the descriptor with `fstatat` and `AT_SYMLINK_NOFOLLOW`, and closes
the descriptor. It opens nothing for writing.

Residual risk, accepted: members of a group that can write an ancestor (`syslog` on Debian and Ubuntu) can rename the
log directory's entry in that ancestor, or plant a directory in its place once it is renamed away. That cannot
redirect the writer: `LogFile` holds the directory descriptor the check verified, and every file it writes is opened
through that descriptor and verified by `fstat` in turn, so records keep going to the service's own directory under
whatever name it now has. They cannot read or change the log either, since the directory is the service account's at
`0750`, with no group write, and its files `0640`. A planted directory is theirs, so the next startup or config check
refuses it and the service stops rather than writing into it. What they can do is move the log out of the
collector's view or stop the next start: a denial of service by accounts that already administer the system log.

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
in Docker is the runtime's: its log driver's `max-size` and `max-file` options, which the
[log operations guide](../book/src/reference/log-operations.md#docker) gives for Compose.

### Startup order

The bootstrap destination needs the deployment's paths, and in development those come from the invoking user's
environment. So `serve` hardens the process first, as today, then reads the accounts and the profile environment, then
creates the development log directory if needed, opens and verifies the bootstrap log directory and its log file
([Trust](#trust)), or for `--log-to-stdout` checks that stdout is not the journal, and installs the subscriber, then
writes `service.started` (and `service.hardening-incomplete` when it applies), and only then resolves the other service
paths and starts the service. An error before the subscriber is installed goes to stderr, as an error before logging
does today.

## Log file and rotation

The service writes one file, `iron-vault.log`, in the log directory, through `logging::LogFile`, a `MakeWriter` of the
binary's own:

- It holds the directory descriptor the trust check opened and verified ([Trust](#trust)), and opens
  `iron-vault.log` relative to it with `openat`, never by path, so renaming or replacing the directory cannot redirect
  it.
- It opens the file with `O_APPEND | O_NOFOLLOW`, creating it at mode `0640` when it is missing, so each record is
  appended whole even if another process appends too, and a symlink planted as `iron-vault.log` is refused rather than
  followed.
- **It verifies every file it opens.** After each `openat`, the first and every reopen, it `fstat`s the new descriptor
  and applies the log file rule: a regular file, owned by the service account, with no write permission for its group
  or for others. A file that fails is closed unused, and the open is a failure: at startup the service exits, in the
  config check the check fails, and mid-run it is a write failure ([Failure behaviour](#failure-behaviour)). The
  directory's own rule leaves nobody else able to create the name, so a failure means the directory was tampered
  with by its owner or by root, and the service stops rather than append to a file it did not create.
- It holds the open file behind a mutex, and writes each record with one `write_all` under it, so records from
  different threads never interleave.
- **It follows a rotation without a signal.** Before it writes a record, it compares the `(dev, inode)` of
  `iron-vault.log` in the directory (`fstatat` with `AT_SYMLINK_NOFOLLOW`) with that of its open file. When they differ,
  or the name is missing, `logrotate` has renamed the file, so it opens (and, when missing, creates) the name again,
  verifies it as above, and writes there. A record written between the rename and the reopen lands in the renamed file,
  which `delaycompress` leaves uncompressed until the next rotation, so no record is lost. A reopen that fails is a
  write failure ([Failure behaviour](#failure-behaviour)).
- It reports every failed write ([below](#failure-behaviour)).

The check costs one `fstatat` per record, which is small beside the write itself.

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
    nocreate
    su iron-vault iron-vault
}
```

`nocreate` overrides the global `create` in `/etc/logrotate.conf`, so `logrotate` only renames the file and the
service creates the new one at its next record. A `create` rule would race the service: `logrotate` renames the file,
then creates the new one with `O_EXCL`, and a record arriving between those steps makes `LogFile` create it first.
`logrotate` then moves the service's new file aside as a `.backup` file it never compresses or prunes, and exits with
an error. With `nocreate` nobody but the service creates `iron-vault.log`. `su` makes `logrotate` act as the service
account in a directory root does not own. No `postrotate` script is needed. Size limits are a `maxsize` line in the
same rule, for an administrator who wants one.

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
  unit with `Restart=on-failure` ([§15](iron-vault-specification.md#15-service-states-and-errors)) restarts it,
  and the restart then succeeds or fails at startup as above.

`tracing-subscriber`'s `fmt::Layer` discards a writer's error: it only prints it to stderr. So the failure is seen in
the writer, the one place that has the error. Both writers are the binary's own `MakeWriter` wrappers: `LogFile` for a
log directory and `logging::LogStdout` for stdout, which writes each record with one `write_all` to a locked stdout.
Rust ignores `SIGPIPE`, so a closed stdout returns `EPIPE` rather than killing the process, and `LogStdout` treats it
as any other failed write. Either writer's first failed write trips a shared latch, `logging::LogFailure`. The
request server checks the latch as it admits each request and the admin server as it reads each command, and refuses
both once it is tripped: the request server closes the connection without a response, as it does over `max_connections`
(stopping was decided in [open question 2](#open-questions), so callers see no `503`), and the admin server
answers `wrong-state`. The `serve` loop's stop future completes on it beside SIGTERM.

The subscriber is built with `log_internal_errors(false)`. Otherwise, when an event fails to format, `fmt::Layer`
writes a plain-text "Unable to format the following event" line into the log, which breaks JSON Lines. Audit and
request events record only primitive values ([Field rules](#field-rules)), so their formatting cannot fail; a
diagnostic record whose own `Display` fails is lost, which is acceptable for a diagnostic record and impossible for an
audit record.

A full disk keeps the service down. Each restart opens the file, fails its first write and stops again. The packaged
unit has no start limit and restarts it once a second ([linux-package.md](linux-package.md#service-unit)), so that
the listener sockets keep their ports. That is intended: the service never runs without its audit log, and the
unit's status and stderr say why. Once space is freed, the next restart succeeds and the service starts Locked.

Both cases are explicit safe states ([§15](iron-vault-specification.md#15-service-states-and-errors)): the service
never serves a request or accepts an admin change it cannot record. The alternative, falling back to stderr and
carrying on, runs the service without its audit log, which is what this design must prevent. A third option, a new
service state that refuses requests with a `503` while the log is unwritable and resumes when it recovers, keeps the
request interface answering, but adds a state, an unavailable reason and a retry loop for a rare fault. Stopping costs
a passphrase-only install one unlock after the disk is fixed. Stopping is the safe state, as decided in
[open question 2](#open-questions).

## Permissions

In a protected install the log directory is owned by the service account, mode `0750`, and its files `0640`, so callers
cannot read or change the audit log. The group is the service account's own unless the administrator chooses a group for
a collector, and that group may only read: the directory is `0750` and its files `0640`, never `0770` or `0660`, since a
group that could write the directory could plant `iron-vault.log` after a rotation, and the service refuses such a
directory or file ([Trust](#trust), [Log file and rotation](#log-file-and-rotation)). A caller's account is never in the
group. The directory and every ancestor must pass the log directory rule ([Trust](#trust)). `LogFile` creates every log
file itself, at `0640` whatever the unit's umask; the shipped `logrotate` rule creates none.

## Dependency caps

The dependency caps in `logging.rs` stay as they are: `CAPPED_TARGETS` capped at `DEPENDENCY_CAP` (`WARN`) by their
own layer, fixed in code whatever level or setting is in force
([§10](iron-vault-specification.md#10-outbound-tls-and-environment)). The new formatter and writer are added beside
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

The [log operations guide](../book/src/reference/log-operations.md) covers: the log directory's setup, the shipped `logrotate` rule and a rule for a moved
directory, Docker's log-driver rotation, a warning against the `journald` log driver in Docker and in Podman, whose
default log driver on Fedora and RHEL is `journald`, so a Podman deployment must select another driver (such as
`k8s-file`) explicitly, and collector settings for Grafana Alloy, Vector, Fluent Bit and Filebeat, with the Loki labels
and the Elastic `@timestamp` rename above.

## Open questions

These are questions about the specification, for the owner. The owner has decided questions 2 to 4 by accepting their
defaults, and the design stands on them; only question 1 is open.

1. **§18's "one structured event per … rejected request": does it exempt rejections made before service code
   runs?** hyper's own `431` and `414`, and connections closed unread over `max_connections`, have no request event
   ([Known limit](#known-limit)). Owner decision D3 answers this for the design: these are the accepted exceptions,
   and every refusal Iron Vault's own code makes writes a request event. The specification's wording still reads as
   if it had no exceptions, so the question left is whether §18 should name them.
2. **§15 keeps the request interface bound so callers receive an explicit status. Is stopping on an audit-log failure
   the intended safe state, or should it be a `503` state?** *Decided: default accepted (2026-11-09).* *Default:* stop,
   as [Failure behaviour](#failure-behaviour) describes; callers then see a refused connection rather than a `503`.
3. **Confirm the departure from decision 2:** *Decided: default accepted (2026-11-09).* no `tracing-appender`
   ([Departure: no `tracing-appender`](#departure-no-tracing-appender)). *Default:* the binary's own `LogFile`
   writer.
4. **D3 says `status` is always present. Is a request event without `status` acceptable when the connection closed
   before any response existed?** *Decided: default accepted (2026-11-09).* No status was produced then, so none can be
   recorded ([`status`](#status)). *Default:* leave `status` out in that one case, with reason `caller_gone` or
   `service_closed`.

## Spec check

Checked against [§18](iron-vault-specification.md#18-logging),
[§5](iron-vault-specification.md#5-service-and-cli-separation-of-concerns),
[§9](iron-vault-specification.md#9-url-header-and-slot-rules),
[§10](iron-vault-specification.md#10-outbound-tls-and-environment),
[§12](iron-vault-specification.md#12-configuration-approval-and-reload),
[§15](iron-vault-specification.md#15-service-states-and-errors) and
[§17](iron-vault-specification.md#17-docker-remote-servers-and-appliances). The request event carries every field
§18 lists (time, caller, route, credential name, upstream host, method, status, sizes, duration, scrubbing), and
every rejected request Iron Vault's code sees writes one. Owner notifications
([§5](iron-vault-specification.md#5-service-and-cli-separation-of-concerns)) come in v1, in EP-40, as the specification's release
plan places them; in v0 this design has none, and v1 adds the audit event `owner.notified`
([owner-notifications.md](owner-notifications.md)).
