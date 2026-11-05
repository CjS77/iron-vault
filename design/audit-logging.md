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

Every default this design takes where the owner has not decided is listed under [Open questions](#open-questions).

## Owner decisions

The owner decided these on 2026-11-05. Each is recorded with the alternatives rejected.

1. **Format: JSON Lines.** One JSON object per line, UTF-8. A record never spans lines: JSON escapes a newline inside a
   string as `\n`, so even a multi-line approval summary stays on one line.
2. **Library: `tracing`**, with `tracing-subscriber`'s `json` feature for the record format and `tracing-appender` for
   the rolling files. The service already logs through `tracing`, and the [dependency caps](#dependency-caps) are a
   `tracing-subscriber` layer.
3. **No journald output, even on Linux.** The service writes files (or stdout, in Docker) and nothing else.
4. **Destination: rolling log files** in `/var/log/iron-vault`, or the directory the service manager names, rotated
   daily, keeping about 30 files (`max_log_files`). In Docker, stdout instead. See [Log destination](#log-destination).

Rejected:

- **journald.** The owner chose files. JSON inside journald's `MESSAGE` field would also lose journald's own
  field-level queries, so neither tool would read the record well.
- **`log4rs`.** It works through the `log` crate. Installing a `log` backend would start accepting the records that
  `reqwest` and `rustls` emit through `log`, which are discarded today because no backend is installed, so the
  dependency caps would have to be rebuilt in `log4rs`'s file-driven config. Its records are also unstructured text.
- **OpenTelemetry (OTLP) export from inside Iron Vault.** It brings heavy dependencies, possibly another copy of
  `rand`, and a further network path out of the process that holds the secrets. A collector can convert the JSON Lines
  files to OTLP outside the service.

## Record shape

Every record is one flat JSON object. These fields are in every record, whatever its kind:

| Field | Type | Form |
|---|---|---|
| `timestamp` | string | RFC 3339 in UTC with fractional seconds, such as `2026-11-05T10:15:30.123456Z` |
| `level` | string | `ERROR`, `WARN`, `INFO`, `DEBUG` or `TRACE` |
| `target` | string | The `tracing` target: `iron_vault::audit`, `iron_vault::request`, or a module path for a diagnostic record |
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

### Constant fields

`service`, `service_version`, `schema_version` and `deployment_profile` are the same in every record. They are added
by a small formatter that wraps `tracing-subscriber`'s JSON formatter (a `FormatEvent` implementation,
`logging::RecordFormat`): it formats the record with the JSON formatter into a buffer, then writes `{`, the constant
fields, and the rest of the buffer after its opening `{`. The constant fields' text is built once at startup.

The alternative, having the typed emitter add the constant fields to each audit and request event, leaves diagnostic
records without them, so a collector's `service` label would be missing from some lines of the same file. The
wrapper also keeps the constant fields out of every emitter, where one could forget them.

### One file

Diagnostic records share the file with audit and request events. Audit records are told apart by their target
(`iron_vault::audit` or `iron_vault::request`) and their `event` field. The alternative, a second file for audit
records only, doubles the rotation, permission and collector setup, and splits a request's diagnostic lines from its
request event, which an administrator reading one incident wants side by side.

### Levels

Audit and request events are always written, at their own level, whatever verbosity is set for diagnostic records:
the level filter passes the `iron_vault::audit` and `iron_vault::request` targets at `INFO` and above. The default
level for every other target stays `INFO`, as it is today. A verbosity setting, when one exists, changes diagnostic
records only, so no setting can switch the audit log off.

### Schema version

`schema_version` is a positive integer, `audit::SCHEMA_VERSION`. It increases when a field is removed or renamed, a
field's type or unit changes, an event name is removed or renamed, or a reason code changes meaning. Adding an event,
a field or a reason code does not change it: a reader must ignore what it does not know. A dashboard or alert rule can
then pin the version it was written for.

## Field rules

The rules below keep the records readable by Loki, Elastic and other tools without per-tool configuration.

- **Flat records.** The subscriber uses `flatten_event(true)`, with `with_current_span(false)` and
  `with_span_list(false)`, so no record has a `fields`, `span` or `spans` key and every record has the same shape.
- **One type per field name, across every event.** A field that is a number in one record is a number in all of them.
  Elastic maps a field from the first record it sees and rejects a later record whose `status` is a string. A field
  with no value is left out, never written as `"n/a"`, `null` or an empty string. An `Option` field is recorded through
  `tracing`'s `Option<T>` value, which records nothing for `None`; never as `?option`, which writes `"Some(3)"`.
- **Numbers are JSON numbers.** Versions, sizes, counts, durations and statuses are recorded as integers, never through
  `Display` (`%version`), which writes a string.
- **Plain snake_case names** such as `http_method`, never dotted names such as `http.method`: Elastic reads a dotted
  name as a nested object, and Loki turns the dots into underscores, so the two would disagree.
- **Fixed vocabularies are strings of fixed labels**, such as `outcome`, `reason`, `step` and `error_kind`, never a
  type's `Debug` output, whose form can change with the code.
- **Loki labels:** only `service`, `event`, `level` and, if wanted, `route`. Never a field with many distinct values,
  such as `request_id` or `caller`, which Loki would turn into a separate stream each. The
  [operations guide](#operations) gives the collector settings.
- **Elastic:** a collector can rename `timestamp` to `@timestamp`; the service keeps the name `timestamp`.
- **Collectors read the files as they are.** Grafana Alloy (and Promtail), Vector, Fluent Bit and Filebeat each read
  JSON Lines files natively and need no plugin.

### Shared field names

A field name means one thing in every event. These are the fields more than one event uses:

| Field | Type | Meaning |
|---|---|---|
| `request_id` | string | The request's [request ID](#request-id) |
| `caller` | string | A caller's configured name |
| `route` | string | A route's configured name |
| `credential` | string | A credential's configured name |
| `record_id` | string | A credential record's record ID |
| `version` | number | An approval version |
| `committed_version` | number | The committed approval version, left out when nothing is committed |
| `config_digest` | string | A config digest, in lowercase hex |
| `file` | string | A state or config file name, never a path |
| `step` | string | A fixed step label, such as an approval step or an init step |
| `unavailable_reason` | string | An unavailable reason's text: `locked`, `policy invalid`, `checking` or `recovery needed` |
| `detail` | string | A check failure's detail: fixed phrases with versions and configured names only |
| `error_kind` | string | A [library error's](#library-errors) fixed kind label |
| `remediation` | string | A fixed phrase saying what the administrator should do |

`reason` is the request event's [reason code](#reason-codes) and nothing else. An audit event that records why the
service is unavailable uses `unavailable_reason`.

### Escaping

JSON escapes every control character, so no value can start a new record or forge a field. That is not enough for a
person reading the file or a tool that renders it, so:

- configured names (callers, routes, credentials, listeners) reject control characters when the config is validated
  ([§3.15](iron-vault-specification.md#315-logging-and-v0-acceptance)), as the policy crate's name types already do;
- a caller-controlled value that must be logged goes through the policy crate's escaping (`display::escaped`), which
  also escapes non-ASCII, so a format character such as U+202E cannot reorder what a reader sees. That function is
  `pub(crate)` today; the first ticket that logs a caller-controlled value from the binary exports it.

The request event logs no caller-controlled value: every field is a configured name, a number, a fixed label or the
request ID. A request whose method is not one a route may allow has no `http_method` at all (reason `bad_method`).

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
no field to go into. Diagnostic records follow the same list by review.

### Library errors

A library error's `Display` and `Debug` may hold a URL with its query, a header value or a path. A `reqwest::Error`
formats the request URL, and its source chain carries `hyper` and `rustls` diagnostics. So the redaction rule is:

> A library error is logged only as a fixed kind label in `error_kind`, chosen by matching the error's variant or
> predicates, and the error is dropped without being formatted.

`TransportError::classify` already does this for upstream errors. An `io::Error` is logged as its `io::ErrorKind`
label (`not-found`, `permission-denied`, `storage-full`, …). An error type of this workspace whose variants carry no
library text may be logged by its variant label. No record uses `error = %e` on a library error. K-175 applies the rule
to the existing records.

## Request event

One event, `request.completed`, per request the request server handed to the request handler, whether it was served
or refused. "Completed" means the service has finished with the request, whatever the outcome. It is written at `INFO`
under the target `iron_vault::request`, when the response body ends: cleanly, by a failure, by the caller going away,
or at once for a refusal with a fixed body.

The alternative, two names such as `request.completed` and `request.rejected`, splits one stream across two event
names, so every dashboard and alert would have to query both; `outcome` already tells them apart.

| Field | Type | When present | Meaning |
|---|---|---|---|
| `request_id` | string | always | The [request ID](#request-id) |
| `listener` | string | always | The listener the request arrived on |
| `caller` | string | once the caller is identified | The caller's configured name |
| `route` | string | once a route is selected | The route's configured name |
| `credential` | string | once a route is selected | The route's credential's configured name |
| `upstream_host` | string | once a route is selected | The route's upstream host, as configured; never the port, path or query |
| `http_method` | string | when the method is one a route may allow | The request method |
| `status` | number | always | The HTTP status sent to the caller |
| `request_bytes` | number | always | Body bytes read from the caller, as counted against `max_request_body_bytes` |
| `response_bytes` | number | always | Body bytes sent to the caller, after scrubbing and any re-encoding; `0` for a fixed refusal body |
| `duration_ms` | number | always | Whole milliseconds from the request handler receiving the request to the end of the response body |
| `scrubbed` | boolean | once a response head was relayed | Whether any scrub pattern matched in its headers or body (the response outcome) |
| `outcome` | string | always | `success` or `failure` |
| `reason` | string | when `outcome` is `failure` | The [reason code](#reason-codes) |

- **`outcome`** is `success` when an upstream response was relayed and its body reached its end, whatever its status:
  an upstream `404` relayed in full is a success of the proxy. It is `failure` when the service refused the request,
  could not reach the upstream, refused the upstream's response, or the body did not reach its end.
- **`duration_ms` stops at the end of the streamed response body**, not at the response head, so a long streaming
  response is counted for as long as it streams. It is measured on the monotonic clock and rounded down. It is an
  integer, not a fraction, because Elastic maps a field from its first value, and a first value of `3` would make
  `3.5` a type conflict.
- **`response_bytes`** counts what crossed the wire to the caller. The response outcome's `decoded_bytes`, the bytes
  the scrubber screened, is not logged: for a compressed response it is not what the caller received, and an operator
  comparing with the caller's own counts needs the wire figure.
- **`status`** for a body that failed after its head was sent is the status of that head, with `outcome` `failure`.
- A request the request server answers itself, before the handler (the request form gate's `400`, an over-limit head's
  `431`), and a connection closed unread over `max_connections`, have no request event: no caller, route or listener
  decision was made, and the request server's diagnostic record covers it. A `413` for an over-limit body and the
  request server's `408` at the request timeout come after the handler has the request, so they do have one.

### Request ID

`request_id` is a random version 4 UUID in its hyphenated lowercase form, from the `uuid` crate's `Uuid::new_v4`,
generated when the request handler receives the request and held as the value object `audit::RequestId`. `uuid` is already a workspace dependency (with the `v4`
feature) and in the lock file through `iron-vault-store`, so the binary adding it pulls in no new crate and no new
version of `getrandom`. The ID is in the request event and in every audit event about the same request
(`request.defect`, `response.scrubbed`), so they can be joined. It is never sent to the caller or the upstream.

The alternative, 128 bits from the binary's `OsRng` formatted as hex, needs no extra dependency in the binary but
gives an ID that collectors and log viewers do not recognize as a UUID.

### Reason codes

A reason code is a fixed snake_case label, `audit::ReasonCode`. Every failure the request handler can meet maps to
exactly one code; the mapping is a single `match`, tested to cover every variant.

**Before a snapshot is used** (the service holds no serving snapshot, and answers with the unavailable reason):

| Source | Status | Code |
|---|---|---|
| `UnavailableReason::Locked` | 503 | `locked` |
| `UnavailableReason::PolicyInvalid` | 503 | `policy_invalid` |
| `UnavailableReason::Checking` | 503 | `checking` |
| `UnavailableReason::RecoveryNeeded` | 503 | `recovery_needed` |
| The snapshot was withdrawn before the response head | 503 | `withdrawn` |
| The snapshot was withdrawn after the response head (the body fails) | head's | `withdrawn` |
| A request header does not convert (`request_head` gives `None`) | 400 | `bad_header` |

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

Every `service_defect` is also a [`request.defect`](#request-defect) audit event. The codes for a refusal name the
check, never the caller's input: `bad_target` does not say which character was refused.

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
| The caller closed the connection before the body ended | head's | `caller_gone` |

**The request server, after the handler has the request:**

| Source | Status | Code |
|---|---|---|
| The caller's body passed `max_request_body_bytes` (`RequestBodyError::TooLarge`) | 413 | `request_too_large` |
| The handler had not answered by the request timeout | 408 | `request_timeout` |

`upstream_body` is one code for both `TransportError::Body` and `RelayFailure::Upstream`: both mean the upstream's
body stopped before its end, before or after the head.

The `refused an upstream redirect` and `aborted a response body after its head was sent` diagnostic records are
replaced by these codes in the request event, so a request's failure is recorded once.

### Request defect

A final-check failure, or any other refusal only a service defect can cause, is recorded twice: in the request event,
as `outcome` `failure` with reason `service_defect`, and as its own audit event, `request.defect`, at `ERROR`. That
event is the redacted high-severity event [§3.6](iron-vault-specification.md#36-url-header-and-slot-rules) requires.
It carries the `request_id`, the `route`, the `credential` and `defect`, the fixed label `PipelineRefusal::report`
gives today (such as `Host` or `AssembleHeader`), and never the URL, a header or a library error.

The alternative, a `severity` field on the request event, would add a field that only some request events have, and
would hide the defect inside the request stream: an alert on `event = "request.defect"` cannot be written against a
request event's optional field without scanning every request. The level, `ERROR`, is the severity; no `severity`
field is needed.

## Audit events

Each audit event is a typed struct in the binary's `audit` module, implementing `audit::AuditEvent`, with fixed fields, emitted under the target
`iron_vault::audit` (`audit::AUDIT_TARGET`). Its `emit` makes one `tracing` call with its event name, its level, its
fixed message and exactly its own fields. Its fields are domain types (`RouteName`, `CredentialName`,
`ApprovalVersion`, `ConfigDigest`, `ReasonCode`), never a `&str` taken from a request, so a header value or a URL
cannot be added by accident. The request event is the same kind of struct, `audit::RequestEvent`, under the target
`iron_vault::request` (`audit::REQUEST_TARGET`).

### Where the types live

The binary owns the audit log: its schema, its event structs and every emit. A library crate returns facts and the
binary turns them into events. The store already returns some: `WriteReport` (the unindexed files a write removed and
the superseded file it left), `OpenReport` (damaged records, unindexed files, an unrecorded approval state), the
reserved version of a prepared approval, and the files a recovery discarded. Where the store logs a fact itself today
(`config.version-reserved`, `config.commit-uncertain`, `config.recovery-published`, `config.recovery-discarded`, the
init's `config.approval-completed`, and its vault and approval-state warnings), the fact moves into what it returns,
and the binary emits the event.

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

Fields named in [Shared field names](#shared-field-names) have the types given there. "Not yet emitted" marks an
event whose operation does not exist yet; its ticket emits it with these fields.

**Service and lock state:**

| Event | Level | When | Fields |
|---|---|---|---|
| `service.started` | INFO | the log destination is open, before the admin socket is bound | `log_destination` (`directory` or `stdout`) |
| `service.lock-transition` | INFO | a lock transition: Locked to Checking, the outcome of the check that follows, and Ready or Unavailable to Locked | `from`, `to` (state labels `starting`, `locked`, `checking`, `ready`, `unavailable`, `stopped`); `unavailable_reason` when `to` is `unavailable` |
| `vault.unlock-refused` | WARN | an unlock was refused | `refusal`: a fixed label, such as `wrong-passphrase` |
| `vault.lock-incomplete` | WARN | a lock's drain ended with a serving snapshot or the vault identity still held | `snapshots_held` (number), `identity_held` (boolean) |

`service.started` and every other record carry `deployment_profile` as a constant field, so the startup event needs no
profile field of its own. The state labels are fixed strings, never `ServiceState`'s `Debug` output, which writes
`Unavailable(PolicyInvalid)`. `service.lock-transition` takes over the records written under `LOCK_TRANSITION_TARGET`
today; that target is retired when it moves (K-171).

**Admin commands:**

| Event | Level | When | Fields |
|---|---|---|---|
| `admin.command` | INFO | an admin principal's request was read | `command` (the command ID), `principal_uid` (number) |
| `admin.refused` | WARN | an admin connection was refused | `refusal` (`not-admin-principal`, `peer-unreadable` or `too-many-exchanges`); `peer_uid` and `peer_pid` (numbers) when known |
| `caller.token-issued` | INFO | a caller token was issued | none; the token is never logged |
| `caller.token-failed` | ERROR | no caller token could be issued | `error_kind` |

A refusal before any write (`init`'s `wrong-state`, `already-initialized`, `passphrase-rejected`, `declined`) records
only `admin.command`.

**Config approvals and checks** ([config-approval.md](config-approval.md#audit-events) gives when each fires). A
reserved version and a completed approval are distinct events, so a reserved version is never mistaken for a
completed approval ([§3.9](iron-vault-specification.md#39-configuration-approval-and-reload)):

| Event | Level | When | Fields |
|---|---|---|---|
| `config.version-reserved` | INFO | step 2's reservation is durable | `version`, `config_digest` |
| `config.approval-failed` | WARN | the transaction failed after its reservation and before its commit | `version` (consumed), `config_digest`, `step`, `error_kind` |
| `config.commit-uncertain` | WARN | step 5's rename of `approval.age` landed, but its directory fsync failed | `version`, `error_kind` |
| `config.approval-completed` | INFO | the commit is durable | `version`, `config_digest`, `summary` (the approval summary's text, or `initial config` for version 1) |
| `config.activation-failed` | WARN | the config check after a committed approval failed, or an uncertain commit could not be settled | `version`, `unavailable_reason`, `detail` |
| `config.check-failed` | WARN | any config check failed | `unavailable_reason`, `failure` (the check failure's fixed status text), `detail` |
| `config.reload-failed` | WARN | the config check of a SIGHUP reload failed | `committed_version`, `unavailable_reason`, `detail` |
| `config.recovery-published` | WARN | a config check finished publishing a committed transaction | `version`, `renames` (fixed labels of the renames it ran, comma-separated) |
| `config.recovery-discarded` | INFO | a config check removed an uncommitted file | `file`; `signed_for` (number) for a staged approval whose version is known |

The approval summary goes into `summary` as one JSON string; `tracing` fields cannot hold nested objects, and the
summary is already text the service built from configured names.

**Credentials and vault writes:**

| Event | Level | When | Fields |
|---|---|---|---|
| `credential.added` | INFO | an `add` committed | `credential`, `record_id`, `kind`, `origins` |
| `credential.replaced` | INFO | a `replace` committed (not yet emitted, K-152) | `credential`, `old_record_id`, `record_id`, `kind`, `origins`; `old_kind`, `old_origins` for a healthy old record |
| `credential.removed` | INFO | an `rm` committed (not yet emitted, K-151) | `credential`, `record_id` |
| `credential.short-secret` | WARN | a record just written has a short secret | `credential`, `field` (the secret field's label), `len` (number) |
| `vault.unindexed-removed` | WARN | a vault write removed an unindexed record file first (from its write report) | `file` |
| `vault.superseded-left` | WARN | a vault write committed but could not remove the record file it superseded (from its write report) | `file`, `error_kind` |
| `vault.commit-uncertain` | ERROR | the vault manifest or approval state was replaced but its directory fsync failed | `file`, `error_kind` |

**Corruption** (from the open report and the vault's errors):

| Event | Level | When | Fields |
|---|---|---|---|
| `vault.record-damaged` | ERROR | a listed record is damaged and was not loaded | `credential`, `record_id`, `file`, `damage` (the record damage's label), `error_kind` when a read failed |
| `vault.unindexed-file` | WARN | opening the vault found an unindexed record file | `file` |
| `vault.approval-state-unrecorded` | WARN | the approval state exists but the vault manifest does not record it | none |
| `vault.shared-state-damaged` | ERROR | the vault's shared state is damaged | `file`, `damage` (the shared-state damage's label) |
| `vault.state-dir-unreadable` | ERROR | the state directory cannot be listed | `error_kind` |
| `vault.foreign-file` | WARN | `unlock` read an Initialized state directory holding a file not on the [lists](vault-initialization.md#initialization-state) | `file`, escaped with `display::escaped`, since the name is not one the service chose |

Each corruption event also carries `remediation`, the fixed phrase the store logs with it today.

**Initialization** ([vault-initialization.md](vault-initialization.md#logging) gives when each fires):

| Event | Level | When | Fields |
|---|---|---|---|
| `vault.init-discarded` | WARN | an unfinished initialization was discarded | `files` (the file names removed, comma-separated) |
| `vault.initialized` | INFO | init's last step is durable | `vault_id` |
| `vault.init-failed` | WARN | an init step failed | `step`, `error_kind` |

Init's version 1 also records `config.version-reserved` and `config.approval-completed`, so it is audited like any
other approval.

**Routes and responses:**

| Event | Level | When | Fields |
|---|---|---|---|
| `route.pinned-ca-unavailable` | WARN | a route's pinned CA could not be loaded, so the route is unavailable | `route`, `field` (`ca_file`) |
| `response.scrubbed` | WARN | a relayed response ended, cleanly or not, and a scrub pattern matched in its headers or body (the scrub event) | `request_id`, `route`, `credential`, `matches` (number) |
| `request.defect` | ERROR | a request was refused by a service defect | `request_id`, `route`, `credential`, `defect` |

**Recovery** (not yet emitted; the recovery epic's tickets emit them):

| Event | Level | When | Fields |
|---|---|---|---|
| `recovery.checked` | INFO, or WARN when the key fails | `recovery check` finished | `outcome` (`opened` or `failed`) |
| `recovery.reminder` | INFO | a scheduled recovery reminder fell due | `last_checked` (RFC 3339 string), left out when never checked |

The `config.*`, `credential.*`, `vault.*`, `caller.token-*` and `route.pinned-ca-unavailable` events keep the names
they have in the code and in the design docs. Their fields change only where the [field rules](#field-rules) require:

- `version`, `signed_for` and `committed_version` become JSON numbers; some are recorded with `%version` or `?option`
  today, which writes strings such as `"3"` and `"Some(3)"`;
- `digest` becomes `config_digest`;
- `config.check-failed`'s `status` becomes `failure`, since `status` is the request event's HTTP status, a number;
- `reason` in the `config.*` events becomes `unavailable_reason`, since `reason` is the request event's reason code;
- `error` on a library error becomes `error_kind` ([Library errors](#library-errors));
- `renames` becomes fixed labels, not `PublishSet`'s `Debug` output;
- a message that interpolates values, such as ``credential `{name}` added`` or `lock transition: {from:?} to {to:?}`,
  becomes a fixed phrase.

### Event names

An event name is `<subject>.<name>`: a lowercase subject (`admin`, `caller`, `config`, `credential`, `recovery`,
`request`, `response`, `route`, `service`, `vault`), a dot, and a kebab-case name, matching
`^[a-z]+\.[a-z]+(-[a-z]+)*$`. Names are stable: renaming or removing one changes the schema version. Each name is
defined once, as an `audit::EventName` constant beside its struct.

## Log destination

Where the records go, `logging::LogDestination`. One setting selects it, given by the service manager (see [open question 1](#open-questions)):
a directory, or stdout.

| Deployment | Destination |
|---|---|
| Protected install (systemd) | Files in `/var/log/iron-vault` |
| Development build | Files in `$XDG_STATE_HOME/iron-vault-dev-log` (default `~/.local/state/iron-vault-dev-log`) |
| Docker or Compose | stdout, which the container runtime collects |
| Any, with the setting given | The directory it names, or stdout |

The development directory is beside the development state directory (`$XDG_STATE_HOME/iron-vault-dev`), not inside
it: the vault's files stay alone in the state directory, and any other file there is a foreign file that makes `unlock`
refuse. A Docker deployment uses the same build as a protected install and selects stdout through the setting, in the
Compose file's `command`.

### Rolling files

`tracing-appender`'s `RollingFileAppender`, built with `Rotation::DAILY`, the filename prefix `iron-vault`, the
suffix `log`, and `max_log_files(30)`. It rotates at midnight UTC and names each file by its UTC date:
`iron-vault.2026-11-05.log`. When it opens a new file it deletes the oldest beyond 30. The current file is the one for
today's date; there is no fixed-name `iron-vault.log` (see [open question 2](#open-questions)). Collectors read
`iron-vault.*.log` with a glob, and each of the four named above follows a new file as it appears.

### Writer behaviour

The writer is blocking: each record is written to the file (or stdout) by the thread that emits it, before the
emitting call returns. A record therefore reaches the kernel before the event it describes is reported to anyone, and
a crash or abort loses no record already emitted. The records are not fsynced one by one; a power failure may lose
the last records, and the approval state, not the log, is the authority on versions.

The alternative, `tracing-appender`'s non-blocking writer with `lossy(false)`, keeps disk writes off the request
tasks, but the records still in its channel are lost on a crash or an abort, which is when an audit trail matters
most, and its worker thread reports a write error only on stderr, where the service cannot see it. A write takes
microseconds and the service serves one host's callers, so the blocking writer's cost is acceptable. The default
non-blocking writer, which drops records when its channel is full, is ruled out: audit records must never be dropped
silently.

### Failure behaviour

- **The destination cannot be opened at startup** (the directory is missing, unwritable or fails its trusted-path
  check): the service writes one line to stderr naming the destination and the error kind, and exits non-zero before
  it binds any socket or unlocks anything. systemd records the failure in the unit's status.
- **A write fails mid-run** (for example, a full disk, or a closed stdout): the writer records the failure and the
  service stops, as on SIGTERM: it clears its memory and exits non-zero. A unit with
  `Restart=on-failure` ([§3.12](iron-vault-specification.md#312-service-states-and-errors)) restarts it, and the restart then succeeds or fails at startup as above.

Both are explicit safe states ([§3.12](iron-vault-specification.md#312-service-states-and-errors)): the service never
serves a request or accepts an admin change it cannot record. The alternative, falling back to stderr and carrying
on, runs the service without its audit log, which is what this design must prevent. A third option, a new service
state that refuses requests with a `503` while the log is unwritable and resumes when it recovers, keeps the request
interface answering, but adds a state, an unavailable reason and a retry loop for a rare fault; stopping costs a
passphrase-only install one unlock after the disk is fixed.

### Startup order

The log destination needs the deployment's paths, and in development those come from the invoking user's environment.
So `serve` hardens the process first, as today, then reads the accounts and the profile environment, then opens the
log destination and installs the subscriber, then logs the hardening report and `service.started`, and only then
resolves the other service paths and starts the service. An error before the subscriber is installed goes to stderr,
as an error before logging does today.

### Permissions

In a protected install the log directory is owned by the service account, mode `0750`, and its files `0640`, so
callers cannot read or change the audit log. The group is the service account's own unless the administrator chooses
a group for a collector; a caller's account is never in it. The directory and every ancestor must pass the
trusted-path rule for a service-owned directory: no account but root and the service account can write any of them.
The packaged systemd unit must set `UMask=0027`, so the files `tracing-appender` creates are not world-readable.

### Size limits and compression

`tracing-appender` rotates by time only: it has no size limit and does not compress old files. A deployment that
needs either uses `logrotate` with `copytruncate`, which copies and truncates the file in place and so never signals
the service; that matters because SIGHUP already means "reload the config". `copytruncate` has a known window: a
record written between the copy and the truncate is lost. And `logrotate` cannot be pointed at `tracing-appender`'s
dated files, since `max_log_files` counts only files it can parse and a renamed or compressed copy escapes it. So a
size limit or compression changes how the files are named; see [open question 2](#open-questions).

### Dependency caps

The dependency caps in `logging.rs` stay as they are: `CAPPED_TARGETS` capped at `DEPENDENCY_CAP` (`WARN`) by their
own layer, fixed in code whatever level or setting is in force
([§3.7](iron-vault-specification.md#37-outbound-tls-and-environment)). The new formatter and writer are added beside
that layer, never in place of it. No `log` backend is installed, so the records `reqwest` and `rustls` emit through
`log` stay discarded.

## Dependencies

`tracing-subscriber` is 0.3.23 in `Cargo.lock`, with the features `fmt`, `registry` and `std`. This design adds:

- the `json` feature of `tracing-subscriber`, which brings `tracing-serde` and `serde_json`;
- `tracing-appender` 0.2, which brings `crossbeam-channel` and `time`. `time` is in the lock file already, as a
  development dependency through `rcgen`; it becomes a normal one;
- `uuid` as a dependency of the binary; it is already a workspace dependency used by the store.

None of them depends on `rand`, `rand_core` or `getrandom`, except `uuid`, which uses the `getrandom` 0.4 the store
already brings. The lock file already holds two copies of each random crate: `rand` 0.8 and `rand_core` 0.6 with
`getrandom` 0.2 come from `age`, and `rand` 0.10 comes only from `proptest` in development; `getrandom` 0.4 comes from
the store and `uuid`. This design adds no further copy. The ticket that adds each crate checks `Cargo.lock` again.

## Operations

K-177 writes the operations guide: the log directory's setup, the `logrotate` rule if one is used, and collector
settings for Grafana Alloy, Vector, Fluent Bit and Filebeat, with the Loki labels and the Elastic `@timestamp`
rename above.

## Open questions

The default stated for each question below stands until the owner decides.

1. **Where "the directory set in configuration" comes from.** `config.toml` is approval-gated and read only after
   logging has started, and a log destination chosen by an approved config would let an approval redirect the audit
   log of the approval itself. *Default:* a `serve` flag, `--log-destination <absolute directory | stdout>`, written
   in the root-owned systemd unit's `ExecStart` or the Compose file's `command`. A directory it names must pass the
   trusted-path check as a service-owned directory; `stdout` selects stdout, which is how a Docker deployment chooses
   it. Without the flag, the profile's directory above is used. An environment variable in the same unit or Compose
   file would work as well, but environment variables are inherited and easily set from outside the service's
   definition, and the service already refuses to take ambient settings such as `RUST_LOG` or `SSL_CERT_FILE` from
   its environment ([§3.7](iron-vault-specification.md#37-outbound-tls-and-environment)), so a flag keeps the setting
   in one reviewed place.
2. **File naming against size limits.** The owner asked for one file, `iron-vault.log`, rotated daily by
   `tracing-appender` with `max_log_files`, and `logrotate` with `copytruncate` for size limits and compression. These
   do not combine: `tracing-appender`'s daily rotation writes a dated file and keeps no fixed-name current file, and
   `logrotate` must not rename the dated files that `max_log_files` prunes. *Default:* `tracing-appender`'s dated
   daily files and `max_log_files(30)`, with no size limit and no compression; this loses no record. The alternative,
   for a deployment that needs a size limit or compression, is `Rotation::NEVER` on a fixed `iron-vault.log`, with
   `logrotate` doing the daily rotation, the 30-file retention, the size limit and the compression under
   `copytruncate`, and accepting that records written during the copy are lost.

## Spec check

Checked against [§3.15](iron-vault-specification.md#315-logging-and-v0-acceptance),
[§3.2](iron-vault-specification.md#32-service-and-cli-boundary), [§3.6](iron-vault-specification.md#36-url-header-and-slot-rules),
[§3.7](iron-vault-specification.md#37-outbound-tls-and-environment),
[§3.9](iron-vault-specification.md#39-configuration-approval-and-reload),
[§3.12](iron-vault-specification.md#312-service-states-and-errors) and
[§3.14](iron-vault-specification.md#314-docker-remote-servers-and-appliances). The request event carries every field
§3.15 lists (time, caller, route, credential name, upstream host, method, status, sizes, duration, scrubbing). Owner
notifications ([§3.2](iron-vault-specification.md#32-service-and-cli-boundary)) are out of this design; K-178 designs
their adapter.
