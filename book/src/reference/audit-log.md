# Audit log

The log is JSON Lines: one flat JSON object per line, in one file, `iron-vault.log`
([where it is](files.md#the-log)). A line is one of three things:

- a **request event**, `request.completed`: one per request the service received, served or refused;
- an **audit event**: an administrative or security fact, such as an approval, a lock transition or a damaged record;
- a **diagnostic record**: anything else, for a developer. It has no `event` field.

No record holds a secret, a caller token, a passphrase, a header value, a request or response body, a raw query string
or a library error's text ([§18](../../../design/iron-vault-specification.md#18-logging)).

This page lists what the records hold. The [log operations guide](log-operations.md) covers rotation, permissions,
Docker, collectors and more queries; [Investigate with the audit log](../cookbook/investigate-audit-log.md) walks
through an investigation. The design is [audit-logging.md](../../../design/audit-logging.md).

## Record envelope

Every record has these fields:

| Field | Type | Value |
|---|---|---|
| `timestamp` | string | RFC 3339 in UTC with fractional seconds, such as `2026-11-05T10:15:30.123456Z` |
| `level` | string | `ERROR`, `WARN`, `INFO`, `DEBUG` or `TRACE` |
| `target` | string | `iron-vault.request` for the request event, `iron-vault.audit` for audit events, a module path for a diagnostic record |
| `service` | string | always `iron-vault` |
| `service_version` | string | the release version |
| `schema_version` | number | `1`. It rises when a field or event is renamed or removed, or a label changes meaning; additions do not change it |
| `deployment_profile` | string | `protected`, `development` or `container` |
| `message` | string | a short fixed phrase; values are in fields, never in the message |
| `event` | string | the event name; request and audit events only |

Request and audit events are always written, whatever level is set for diagnostic records, so no setting can turn
the audit log off. A field with no value is left out, never written as `null` or `""`. Fixed labels are snake_case
(`policy_invalid`, `wrong_passphrase`); event names are kebab-case after the dot. A list is one string with its items
separated by `,`.

## Shared fields

These mean the same, with the same type, in every event that has them:

| Field | Type | Meaning |
|---|---|---|
| `request_id` | string | A random UUID per request; joins `request.completed` to `response.scrubbed` and `request.defect` |
| `caller`, `route`, `credential` | string | Configured names |
| `record_id` | string | A credential record's ID |
| `approver_id` | string | The approver that was asked for the approval passphrase, or that signed: its ID, a hyphenated UUID |
| `approver_label` | string | That approver's label, escaped; `init` labels the approval passphrase's approver `approval passphrase` |
| `version` | number | An approval version |
| `committed_version` | number | The committed approval version; absent when none is committed |
| `config_digest` | string | `blake2b:` and 64 hex digits |
| `file` | string | A state or config file name, never a path |
| `step` | string | A fixed step label |
| `refusal` | string | Why something was refused: a fixed label |
| `unavailable_reason` | string | `locked`, `policy_invalid`, `checking` or `recovery_needed` |
| `detail` | string | A check failure's detail: fixed phrases with versions and configured names only |
| `error_kind` | string | A library error's fixed kind label, never its text |
| `remediation` | string | A fixed phrase saying what to do |
| `log_destination` | string | `stdout`, or the log directory's absolute path |

## The request event

`request.completed`, at `INFO`, target `iron-vault.request`. It is written when the service has finished with the
request: when the response body ends, fails or is dropped, or at once for a fixed refusal.

| Field | Type | Present | Meaning |
|---|---|---|---|
| `request_id` | string | always | The request ID |
| `listener` | string | always | The listener it arrived on |
| `http_method` | string | always | The method as received, escaped |
| `caller` | string | once the caller is identified | The caller's name |
| `route` | string | once a route is selected | The route's name |
| `credential` | string | once a route is selected | The route's credential |
| `upstream_host` | string | once a route is selected, unless the answer was replaced | The upstream host; never the port, path or query |
| `status` | number | once a response existed | The HTTP status sent |
| `request_bytes` | number | always | Body bytes read from the caller |
| `response_bytes` | number | always | Body bytes sent to the caller, after scrubbing |
| `duration_ms` | number | always | Whole milliseconds from receipt to the end of the response body |
| `scrubbed` | boolean | once a relayed response was sent | Whether a scrub pattern matched |
| `outcome` | string | always | `success` (an upstream response was relayed in full, whatever its status) or `failure` |
| `reason` | string | when `outcome` is `failure` | The reason code. The [errors reference](errors.md#proxy-refusals) lists every one with its status |

## Audit events

Every audit event has the target `iron-vault.audit`. The fields are those beyond the envelope.

### Service and lock state

| Event | Level | When | Fields |
|---|---|---|---|
| `service.started` | INFO | The log is open, before the admin socket is bound | `log_destination`, `core_dumps` (`disabled` or `not_disabled`), `memory_protection` (`locked`, `unavailable` or `unsupported`) |
| `service.hardening-incomplete` | ERROR | At startup, when core dumps are not disabled or memory is not locked | `core_dumps`, `memory_protection`, `remediation` |
| `service.log-destination-changed` | INFO | An approved config moved the log; written to both the old and the new destination | `log_destination`, `previous_log_destination`, `version` |
| `service.lock-transition` | INFO | Locked to Checking on an unlock, or Starting to Checking on a host unlock, the check's outcome, and Ready or Unavailable to Locked | `from_state`, `to_state` (`starting`, `locked`, `checking`, `ready`, `unavailable` or `stopped`); `unavailable_reason` when `to_state` is `unavailable` |
| `vault.unlock-refused` | WARN | An unlock was refused | `refusal`: `wrong_passphrase`, `rate_limited`, `memory_unprotected`, `wrong_state`, `state_read`, `passphrase_envelope`, `identity_envelope`, `initialization_unfinished`, `not_initialized`, `unrecognized_files`, `state_unreadable` or `interrupted`; `memory_protection` for `memory_unprotected`; `retry_after` (whole seconds) for `rate_limited` |
| `vault.host-unlock` | INFO when `unlocked` or `absent`, WARN when `refused` | A Container-profile service tried the unlock handoff at startup; other profiles never write it | `host_unlock_outcome` (`unlocked`, `absent` or `refused`); `refusal` when refused: `memory_unprotected`, `untrusted`, `unreadable`, `not_an_identity`, `not_initialized` or `not_a_recipient`. Never the handoff's bytes or its recipient key. A `memory_unprotected` refusal also writes `vault.unlock-refused`. |
| `vault.foreign-file` | WARN | `unlock` found a file beside the manifest that the vault does not use; the file is never read, and the unlock goes on | `file`, escaped |
| `vault.presence-refused` | WARN | The approval passphrase for `replace`, `rm`, `recipient remove` or `approver add` was refused; nothing was written | `refusal` (`wrong_passphrase` or `key_mismatch`), `approver_id`, `approver_label` |
| `vault.lock-incomplete` | WARN | A lock finished while a request still held a snapshot or the vault identity | `snapshots_held` (number), `identity_held` (boolean) |

### Admin commands and caller tokens

| Event | Level | When | Fields |
|---|---|---|---|
| `admin.command` | INFO | An admin principal's command was read | `command` (`config_approve`, `caller_token`, `unlock` and so on), `principal_uid` |
| `admin.refused` | WARN | An admin connection or request was refused before any command ran | `refusal`: `not_admin_principal`, `peer_unreadable`, `busy`, `unsupported_version`, `malformed_frame`, `unknown_command` or `unexpected_frame`; `peer_uid` and `peer_pid` when known; `peer_pid` is absent when the peer is in another PID namespace, such as the host CLI in the Container profile |
| `caller.token-issued` | INFO | A caller token was issued | none; the token is never logged |
| `caller.token-failed` | ERROR | No caller token could be issued | `error_kind` |

A command refused after it was read, such as `init` in the wrong state, records only `admin.command`.

### Config approvals and checks

| Event | Level | When | Fields |
|---|---|---|---|
| `config.approval-refused` | WARN | The approval passphrase was wrong or opened the wrong key; nothing was reserved | `refusal` (`wrong_passphrase` or `key_mismatch`), `config_digest`, `approver_id`, `approver_label` |
| `config.version-reserved` | INFO | A version was reserved, before signing | `version`, `config_digest`, `approver_id`, `approver_label` |
| `config.approval-failed` | WARN | The approval failed after its reservation and before its commit; the version is used up | `version`, `config_digest`, `step`, `error_kind` |
| `config.commit-uncertain` | WARN | The commit's rename landed but its directory fsync failed | `version`, `error_kind` |
| `config.approval-completed` | INFO | The commit is durable | `version`, `config_digest`, `summary` (the approval summary's text, or `initial config` for version 1), `approver_id`, `approver_label` |
| `config.activation-failed` | WARN | The config check after a committed approval failed | `version`, `unavailable_reason`, `detail` |
| `config.check-failed` | WARN | Any config check failed | `unavailable_reason`, `failure` (a fixed label), `detail`; `log_destination` when the log destination failed |
| `config.reload-failed` | WARN | The config check of a SIGHUP reload failed | `committed_version`, `unavailable_reason`, `detail` |
| `config.recovery-published` | WARN | A config check finished publishing a committed approval | `version`, `renames` |
| `config.recovery-discarded` | INFO | A config check removed an uncommitted file | `file`; `signed_for` for a staged approval whose version is known |
| `config.conflicting-approval-discarded` | ERROR | A staged approval for the committed version but another config was found and discarded. Only a second signature or a file the service did not write can cause it | `version` |

A reserved version is never a completed approval: look for `config.approval-completed`.

### Credentials and vault writes

| Event | Level | When | Fields |
|---|---|---|---|
| `credential.added` | INFO | An `add` committed | `credential`, `record_id`, `kind`, `origins` |
| `credential.replaced` | INFO | A `replace` committed | `credential`, `old_record_id`, `record_id`, `kind`, `origins`; `old_kind` and `old_origins` when the old record was healthy |
| `credential.removed` | INFO | An `rm` committed | `credential`, `record_id` |
| `credential.short-secret` | WARN | A record just written has a short secret, which the scrubber may also match in innocent text | `credential`, `secret_field`, `len` |
| `vault.unindexed-removed` | WARN | A vault write first removed a record file the manifest does not list | `file` |
| `vault.superseded-left` | WARN | A write committed but could not remove the file it replaced; the next write removes it | `file`, `error_kind` |
| `vault.commit-uncertain` | ERROR | A state file was replaced but the directory fsync failed, so the change may not survive power loss | `file`, `error_kind` |

`kind` is `static` or `basic`. `origins` lists `https://host:port` values.

### Corruption

Each of these also has `remediation`.

| Event | Level | When | Fields |
|---|---|---|---|
| `vault.record-damaged` | ERROR | A listed record is damaged and was not loaded; its routes answer `503` | `credential`, `record_id`, `file`, `damage` (`missing`, `substituted` or `unreadable`); `error_kind` when a read failed |
| `vault.unindexed-file` | WARN | Opening the vault found a record file the manifest does not list; it was not loaded | `file` |
| `vault.approval-state-unrecorded` | WARN | The approval state exists but the manifest does not record it | none beyond `remediation` |
| `vault.shared-state-damaged` | ERROR | The vault's shared state is damaged | `file`, `damage` |
| `vault.state-dir-unreadable` | ERROR | The state directory cannot be listed | `error_kind` |

### Initialization

| Event | Level | When | Fields |
|---|---|---|---|
| `vault.init-discarded` | WARN | An unfinished initialization was discarded | `files` |
| `vault.initialized` | INFO | `init`'s last step is durable | `vault_id`, `recipients` (the enrolled roles' names, such as `operational,recovery`) |
| `vault.init-failed` | WARN | An `init` step failed | `step`, `error_kind` |

`init` also writes `config.version-reserved` and `config.approval-completed` for version 1.

### Routes and responses

| Event | Level | When | Fields |
|---|---|---|---|
| `route.pinned-ca-unavailable` | WARN | A route's pinned CA could not be loaded, so the route is unavailable | `route`, `config_field` (`ca_file`) |
| `response.scrubbed` | WARN | A relayed response had a scrub pattern match in its headers or body | `request_id`, `route`, `credential`, `matches` |
| `request.defect` | ERROR | A request was refused by a service defect (`reason` `service_defect`) | `request_id`, `route`, `credential`, `defect` (the label of the check that failed) |

### Recovery

| Event | Level | When | Fields |
|---|---|---|---|
| `recovery.checked` | INFO when the key opened the vault, WARN otherwise | `recovery check` finished | `recovery_outcome`: `opened` with `vault_id` and `recorded` (and `error_kind` when the record was not written); `failed` with `recovery_failure` (`not_a_recipient` or `identity_unverified`); `invalid`; or `unavailable` with `file` and `error_kind` |
| `recovery.reminder` | INFO | A recovery check is due | `recovery_record` (`checked` with `last_checked`, `never_checked` with `reminders_since`, `unusable` with `error_kind`), `reminder_days`, `remediation` |

### Recipients

The first two are written by the inventory check that every recipient command, `recipient list` included, runs first;
neither carries a recipient key or label. `recipient add` and `recipient remove` write the other three, which name the public
recipient key; `recipient.added` and `recipient.removed` also carry the label, escaped.

| Event | Level | When | Fields |
|---|---|---|---|
| `recipient.added` | INFO | A `recipient add` committed | `recipient`, `recipient_role` (`added`, `recovery` for `recipient add --recovery`, or `host-unlock` for `recipient add --host-unlock`), `recipient_label` (escaped), `recipients` (the count after the change) |
| `recipient.inventory-damaged` | WARN | The inventory check found the recipient inventory missing or damaged, and wrote nothing | `inventory_damage`: `envelope_unreadable`, `missing`, `unreadable`, `mac`, `malformed`, `unknown_role`, `other_vault`, `envelope_mismatch` or `count_mismatch` |
| `recipient.change-recovered` | WARN | The inventory check finished a committed recipient change or removed a staged inventory | `recovery`: `completed` or `discarded` |
| `recipient.removed` | INFO | A removal committed | `recipient`, `recipient_role`, `recipient_label`, `recipients` (the count after the removal) |
| `recipient.change-failed` | WARN | An add or a removal was refused because the key is already enrolled, is not enrolled or would break the independence rule, or it failed while written | `change` (`add` or `remove`), `recipient`, `failure`: `already_enrolled`, `unknown_recipient`, `set_invalid` or `write_failed`; for `write_failed` also `step`, `error_kind` and `committed` (`no`, `unknown` or `yes`) |

### Approvers

`approver add` and `approver remove` write these. They name approvers by their public approver ID and label (escaped); no passphrase or key
file byte is logged.

| Event | Level | When | Fields |
|---|---|---|---|
| `approver.enrolled` | INFO | An `approver add` committed | `approver_id`, `approver_label`, `signer_kind` (`software`), `approvers` (the count after the change), `authorizing_approver_id` and `authorizing_approver_label` (the approver whose passphrase authorized it) |
| `approver.removed` | INFO | An `approver remove` committed | as `approver.enrolled`, for the approver removed, and `key_file`: `removed`, or `left` when the key file could not be deleted (the next approver command removes it) |
| `approver.change-failed` | WARN | An `approver add` or `approver remove` was refused (16 approvers pinned, the new passphrase broke a rule, no such approver, the last approver or the active approval's signer), the approval state did not read back, or the change failed | `change` (`add` or `remove`), `failure`: `set_invalid`, `passphrase_rejected`, `unknown_approver`, `in_use` or `write_failed`; `approver_id` when known; for `write_failed` also `step` (`read_back`, `key_file`, `key_check` or `approval_state`), `error_kind` and `committed` (`no` or `unknown`) |
| `approver.orphan-removed` | WARN | Before its prompts, `approver add` or `approver remove` removed a key file no pinned approver has, left by an enrollment that failed or a removal that could not delete it | `approver_id`, the ID in the file's name |

### Migration authorization

`recipient add` writes these events, and `export` will: they come from the authorization step the two share.

| Event | Level | When | Fields |
|---|---|---|---|
| `migration.challenge-issued` | INFO | A migration challenge was issued | `operation` (`export` or `add_recipient`), `method` (`vault_passphrase`); `destination_recipient` for `add_recipient` |
| `migration.authorized` | INFO | The owner proved the challenge | `operation`, `method`; `destination_recipient` for `add_recipient` |
| `migration.authorization-refused` | WARN | The challenge was refused or cancelled, or the authorization was refused when used | `operation`, `method`, `refusal`; `destination_recipient` for `add_recipient`; `retry_after` for `rate_limited` |

## `jq` recipes

These run against a development log (`tee` of `serve --log-to-stdout`). In a protected install set
`LOG=/var/log/iron-vault/iron-vault.log` and run them with `sudo`. [Investigate with the audit
log](../cookbook/investigate-audit-log.md) works through more.

```sh
LOG=~/iron-vault-dev.log

# one line per request: who asked, which route, and what happened
jq -c 'select(.event == "request.completed")
       | {caller, route, http_method, status, outcome, reason, scrubbed, duration_ms}' $LOG

# refusals, counted by reason: unauthenticated, method_not_allowed, rate_limited, ...
jq -r 'select(.event == "request.completed" and .outcome == "failure") | .reason' $LOG | sort | uniq -c

# the administrative trail: commands, credential changes and config approvals (the strings filter handles null values)
jq -c 'select(.event | strings | test("^(admin|credential|config|caller)\\."))
       | {timestamp, event, command, credential, version}' $LOG

# responses the scrubber had to clean, and how many matches it removed
jq -c 'select(.event == "response.scrubbed") | {request_id, route, credential, matches}' $LOG

# the test secret from getting started never reaches the log: this prints 0
grep -c -F 'not-a-real-key-123' $LOG
```

The [log operations guide](log-operations.md#querying) has more, and the queries for Loki and Elastic.
