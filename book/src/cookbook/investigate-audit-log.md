# Investigate with the audit log

*Checked with `iron-vault 0.2.0-alpha (features: dev-mode)`, built from `main` at `378d57d`.*

At the end of this recipe you can answer three questions from the audit log: which requests were refused and why,
which responses had a secret scrubbed from them, and who changed what, and when. The log is JSON
Lines, one record per line, and `jq` answers each question in one command. No record holds a secret, a token or a
header value, so you can share the output.

Every query below was run on the log of a development service that had worked through the other recipes. Long
outputs are cut to their last lines.

## Prerequisites

- `jq`.
- The log. Set `LOG` to its path:

  | Install | Log | Read it as |
  |---|---|---|
  | Development, as in [getting started](getting-started.md) | `~/iron-vault-dev.log` (the `tee` copy) | you |
  | Development, without `--log-to-stdout` | `$XDG_STATE_HOME/iron-vault-dev-log/iron-vault.log` | you |
  | [Protected Linux install](protected-linux.md) | `/var/log/iron-vault/iron-vault.log` | root (`sudo jq …`) |

  ```sh
  LOG=~/iron-vault-dev.log
  ```

  Rotated files have the same format. Read `iron-vault.log.1` with `jq` and the older `iron-vault.log.*.gz` with
  `zcat … | jq`. The [log operations guide](../reference/log-operations.md) covers locations, permissions, rotation and
  shipping the log to a collector.

## Steps

### 1. Count refusals by reason

Every request ends in one `request.completed` record. A refused one has `"outcome":"failure"` and a `reason`:

```sh
jq -r 'select(.event == "request.completed" and .outcome == "failure") | .reason' $LOG | sort | uniq -c | sort -rn
```

```text
      4 rate_limited
      3 unauthenticated
      2 path_not_allowed
      2 locked
      1 policy_invalid
      1 no_route
      1 method_not_allowed
```

What each one points at:

| Reason | Status | Look at |
|---|---|---|
| `unauthenticated` | 401 | a missing, wrong or [revoked](caller-token.md) caller token; such records name no caller |
| `not_granted`, `method_not_allowed`, `path_not_allowed` | 403 | the caller's `routes`, or the route's `methods` and `paths` ([widen or narrow a route](change-route.md)) |
| `no_route` | 404 | a base URL missing the route prefix |
| `rate_limited` | 429 | the route's `rate_limit`; a burst of these straight after an unlock, approval, reload, `replace` or `rm` is the bucket [starting empty](getting-started.md#rate-limits-start-empty) |
| `locked` | 503 | the service is Locked: [unlock it](lock-unlock-restart.md) |
| `policy_invalid` | 503 | the config check failed: see [tamper detection](tamper-detection.md) |

The [audit log reference](../reference/audit-log.md) lists every reason.

### 2. Narrow it down

Who was refused, on which route, and when:

```sh
jq -c 'select(.event == "request.completed" and .reason == "rate_limited") | {timestamp, caller, route}' $LOG
```

```text
…
{"timestamp":"2026-11-07T10:22:50.927407Z","caller":"me","route":"httpbin"}
{"timestamp":"2026-11-07T10:23:53.745995Z","caller":"me","route":"httpbin"}
{"timestamp":"2026-11-07T10:24:37.662668Z","caller":"me","route":"httpbin"}
```

Swap the `select` for `.route == "brave" and .outcome == "failure"` to see one route's failures, or add
`and .timestamp >= "2026-11-07T10:20"` to bound the time. Timestamps are UTC RFC 3339, so they compare correctly as
strings.

### 3. Find scrubbed responses

A `response.scrubbed` record means the upstream sent a credential back and Iron Vault removed it before it reached
the caller. An echo service like httpbin does that on every request. A real API that does it may be logging or
reflecting your key, so report it to the provider. To list them:

```sh
jq -c 'select(.event == "response.scrubbed") | {timestamp, request_id, route, credential, matches}' $LOG
```

```text
…
{"timestamp":"2026-11-07T10:22:50.919167Z","request_id":"0589c90c-…","route":"httpbin","credential":"httpbin_key","matches":1}
{"timestamp":"2026-11-07T10:24:00.060540Z","request_id":"5e34a829-…","route":"httpbin","credential":"httpbin_key","matches":1}
```

### 4. Follow one request

A `request_id` joins every record about one request:

```sh
jq -c 'select(.request_id == "5e34a829-…") | {event, caller, route, status, scrubbed, matches}' $LOG
```

```text
{"event":"request.completed","caller":"me","route":"httpbin","status":200,"scrubbed":true,"matches":null}
{"event":"response.scrubbed","caller":null,"route":"httpbin","status":null,"scrubbed":null,"matches":1}
```

Use the full ID from the log.

### 5. Read the admin trail

Credential changes, issued tokens, approvals, config checks, recovery checks, refused passphrases and lock changes,
with only the fields each one has:

```sh
jq -c 'select(.event | strings | test("^(credential|caller|vault|recovery)\\.|^admin\\.refused|^config\\.(approval|reload|check)|^service\\.lock"))
       | {timestamp, event}
         + ({credential, version, refusal, peer_uid, recovery_outcome, unavailable_reason, from_state, to_state}
            | with_entries(select(.value != null)))' $LOG
```

```text
…
{"timestamp":"2026-11-07T10:20:14.997205Z","event":"credential.added","credential":"httpbin_key"}
{"timestamp":"2026-11-07T10:20:14.999235Z","event":"caller.token-issued"}
{"timestamp":"2026-11-07T10:20:15.436819Z","event":"config.approval-completed","version":2}
{"timestamp":"2026-11-07T10:20:34.208637Z","event":"credential.replaced","credential":"httpbin_key"}
{"timestamp":"2026-11-07T10:20:56.809548Z","event":"vault.presence-refused","refusal":"wrong_passphrase"}
{"timestamp":"2026-11-07T10:21:03.864703Z","event":"credential.replaced","credential":"httpbin_key"}
…
{"timestamp":"2026-11-07T10:24:16.625579Z","event":"recovery.checked","recovery_outcome":"failed"}
{"timestamp":"2026-11-07T10:24:23.474827Z","event":"config.check-failed","unavailable_reason":"policy_invalid"}
{"timestamp":"2026-11-07T10:24:23.474848Z","event":"config.reload-failed","unavailable_reason":"policy_invalid"}
{"timestamp":"2026-11-07T10:24:32.584363Z","event":"config.approval-completed","version":10}
```

Things to look for:

- an `admin.refused` with refusal `not_admin_principal`: an account that is not the admin tried the admin socket, and
  `peer_uid` names it;
- a `vault.presence-refused` or `vault.unlock-refused` you didn't cause: someone tried the vault passphrase;
- a `config.approval-refused` you didn't cause: someone tried the approval passphrase;
- an approval or `credential.replaced` you didn't make;
- a `config.reload-failed`: someone changed the published config.

Every admin connection also writes an `admin.command` record with the command and the connecting account's
`principal_uid`. A declined or invalid approval writes only that record.

### 6. See what an approval changed

Each `config.approval-completed` carries the approval summary that was shown before `yes`:

```sh
jq -r 'select(.event == "config.approval-completed" and .version == 9) | "version \(.version), \(.timestamp)\n\(.summary)"' $LOG
```

```text
version 9, 2026-11-07T10:22:20.790368Z
routes:
  ~ httpbin: paths /anything/**, /gzip, /headers, /stream/* -> /anything/**, /gzip, /headers; rate limit 30 per 60s burst 5 -> 10 per 60s burst 2
```

### 7. Check that no secret reached the log

Search for a test secret you stored. This prints `0`:

```sh
grep -c -F 'not-a-real-key-123' $LOG
```

```text
0
```

Don't do this with a real secret on the command line: it would land in your shell history.

## What can go wrong

- **`jq: error (at …): null (null) cannot be matched, as it is not a string`.** Diagnostic records have no
  `event` field. Keep the `.event | strings` guard in filters that test the event name.
- **`Permission denied` on `/var/log/iron-vault`.** The protected log directory belongs to the service account, mode
  `0750`. Use `sudo`, and don't add a login or caller account to its group.
- **Nothing since a restart.** In development with `--log-to-stdout`, the log is wherever stdout went. Without the
  `tee`, it is gone.

## Reference

- [Audit log](../reference/audit-log.md): every event, its fields and level, and every `reason`.
- [Log operations](../reference/log-operations.md): location, permissions, rotation, collectors and more queries.
- The [audit logging design](../../../design/audit-logging.md).
