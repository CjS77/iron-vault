# Errors

Iron Vault refuses things in two places, and each has its own vocabulary:

- **Admin commands** (`init`, `unlock`, `config approve`, `add` and the rest) talk to the service over the admin
  socket. A refused command ends with an **error code**: a stable number and name that scripts can act on, and a
  message for you that may change between releases.
- **Proxied requests** get an **HTTP status** with a short fixed body. The audit log records the same request with a
  `reason` that says exactly which check refused it.

Terms follow the [glossary](../glossary.md). The [audit log reference](audit-log.md) lists every log field, and the
[service states](states.md) page explains Locked, Checking, Ready and Unavailable, which many of these errors name.

## Admin error codes

The CLI prints a refused command as one line on stderr and exits with status `1`:

```text
iron-vault: the service answered error 13 (wrong-state): ...
```

The number and the name are fixed; the text after them is the service's message. A message never repeats a secret or
passphrase you typed, so it is safe to paste into a ticket, though it may name routes, credentials and hosts. For
three codes the CLI adds a line saying what to do: `not-admin-principal`, `unsupported-version` and
`memory-unprotected`.

The other exit statuses are `0` for success, `2` for a usage error caught before anything was sent, `3` when no answer
came back (the service is not running, this account may not connect, the exchange failed, a prompt got no value, or a
secret value the service sent could not be shown on a terminal), and `4` when `status` found the service in a state
other than Ready, or `list` found no vault open.

### Protocol and connection

These can happen on any command.

| Code | Name | Meaning | What to do |
|---|---|---|---|
| `1` | `unsupported-version` | The CLI and the service speak different admin protocol versions. | Install the same release of the CLI and the service. In a protected install both are `/usr/bin/iron-vault`, so this means a service still running the old binary: restart it. |
| `2` | `malformed-frame` | A message on the admin socket broke the protocol's rules. | This is a bug, or something other than the `iron-vault` CLI is talking to the socket. Report it with the command you ran. |
| `3` | `unknown-command` | The service does not know the command. | The CLI is newer than the service. Restart the service on the new binary. |
| `4` | `unexpected-frame` | A message arrived out of turn in the exchange. | As for `malformed-frame`. |
| `5` | `not-admin-principal` | The account you ran the command as may not use the admin socket. Nothing it sent was read. | In a protected install, run the command with `sudo`: only root is an admin principal. In a container, that is root on the host: run `sudo iron-vault …` on the host, against the bind-mounted admin socket. A plain `docker exec` arrives as the service's own uid and is refused. In development, run it as the account that runs `iron-vault serve`. |
| `6` | `busy` | The service is already serving as many admin connections as it allows, or another command holds the lock this one needs. | Wait for the other command to finish, then try again. |
| `13` | `wrong-state` | The command is not allowed in the service's current state. The message names the state. | See [which commands run in which state](states.md#admin-commands-by-state). For example, `unlock` needs Locked, `add` needs Ready, and `init` needs Locked with no vault. |

### `init`

| Code | Name | Meaning | What to do |
|---|---|---|---|
| `8` | `declined` | You did not type `yes` when asked to confirm you saved the recovery key. Nothing was written. | Run `init` again when you are ready to store the key. |
| `17` | `already-initialized` | The state directory already holds a vault, or files `init` did not write. Nothing was changed. | `init` never overwrites a vault. If you meant to start over, see [Start over in development mode](../cookbook/start-over.md). If the key was already shown, discard it: it opens nothing. |
| `18` | `passphrase-rejected` | A passphrase broke a rule: it is under 12 characters, the two copies differ, or the vault and approval passphrases are the same. The message names the rule. | Choose a passphrase that meets the rule. |
| `19` | `init-failed` | A write failed. The message names the step. | Fix the cause the message names, then run `init` again: it discards the unfinished vault first. Discard the recovery key shown, unless the message says to keep it until the re-run decides. |
| `27` | `memory-unprotected` | A protected or container install's memory is not locked against swap, so `init` would put the new keys and passphrases in swappable memory. Nothing was written, and no prompt was shown. | Raise the memory-lock limit as for `unlock` (see [`unlock`](#unlock)), restart the service and run `init` again. |

### `unlock`

| Code | Name | Meaning | What to do |
|---|---|---|---|
| `14` | `unlock-denied` | The vault passphrase was wrong. | Try again. After 5 wrong passphrases the attempt limit applies (`unlock-rate-limited`). |
| `15` | `unlock-failed` | The vault did not open for a reason other than the passphrase, such as a damaged or unreadable file. The service stays Locked. | Read the message and the log's `vault.*` events. `iron-vault recovery check` tells you whether the recovery key still opens the vault. |
| `16` | `unlocked-unavailable` | The vault opened, but the config check failed, so the service is Unavailable. The message names the redacted reason. | Run `status`, and read the `config.check-failed` event in the log. For `policy invalid`, approve a good config with `config approve`. |
| `27` | `memory-unprotected` | A protected or container install's memory is not locked against swap, so the vault was not opened. The service stays Locked. `recovery check` refuses with this code too. | Raise the memory-lock limit: `LimitMEMLOCK=infinity` on the systemd unit, or `ulimits: memlock: -1` under Docker Compose. Then restart the service and unlock again. |
| `34` | `unlock-rate-limited` | Too many wrong vault passphrases, here or in migration authorization. No prompt was sent. The message gives the seconds to wait. | Wait that long. The cooldown starts at 30 seconds and doubles up to 15 minutes. `lock` does not clear it. |

### `config approve`

| Code | Name | Meaning | What to do |
|---|---|---|---|
| `7` | `config-invalid` | The proposed config does not parse, does not validate, or would not activate. Nothing was reserved, and the active config is unchanged. | Fix what the message names and approve again. A common case: a route sends a credential to a host its record does not permit, which only `replace` can change. |
| `8` | `declined` | You did not type `yes` at the summary. | Nothing was changed. |
| `9` | `approval-denied` | The approval passphrase did not open the approver key, or the key it opened is not the vault's pinned approver. Nothing was reserved. | Type the approval passphrase, not the vault passphrase. |
| `10` | `approval-unavailable` | The service cannot run an approval now, or a `lock` cancelled the approval at its prompt. No version was reserved. | Read the message; the service may be in a state that cannot approve. Try again once `status` shows Ready, or Unavailable with `policy invalid`. |
| `11` | `approval-failed` | The approval failed after it reserved a version and before it committed. That version number is used up. | Read `config.approval-failed` in the log for the step, fix it and approve again. The next approval gets a higher version. |
| `12` | `committed-not-active` | The approval committed, but it was not published or did not activate, so the service is Unavailable. | Run `status` and read `config.activation-failed` in the log. Approve a corrected config to recover. |

### Credentials: `add`, `replace`, `rm`, `list`

| Code | Name | Meaning | What to do |
|---|---|---|---|
| `20` | `name-taken` | `add`: a credential of that name exists, healthy or damaged. `add` never overwrites. | Use `replace` to change it, or choose another name. |
| `21` | `credential-invalid` | `add`, `replace`, `rm`: the name, an origin or the secret breaks its rule. The message names the rule, never what you typed. | Fix the argument. Names are what routes reference; origins are `host` or `host:port`, without a scheme. |
| `22` | `vault-write-failed` | `add`, `replace`, `rm`, `recipient remove`: writing the vault failed. The message says whether the change may have committed. | Run `list` to see what the vault now holds, fix the cause (often disk space or permissions) and retry. |
| `23` | `unknown-credential` | `replace`, `rm`: no credential of that name. | Check the name with `list`. |
| `24` | `credential-in-use` | `replace`, `rm`: a route of the active config uses the credential and would not activate after the change. For `rm` the message names each route; for `replace`, each route and why. | For `rm`, approve a config without those routes first. For `replace`, give origins that still suit the routes. |
| `9` | `approval-denied` | `replace`, `rm`, `recipient remove`: the approval passphrase was wrong, or opened a key that is not the asked approver's. Nothing was written. | Type the approval passphrase. |
| `10` | `approval-unavailable` | `replace`, `rm`, `recipient remove`: owner presence could not be checked, or a `lock` cancelled the change at its passphrase prompt. Nothing was written. | Unlock if needed, and run the command again. |
| `12` | `committed-not-active` | `replace`, `rm`: the change committed, but the config check after it left the service Unavailable. | Run `status` and read the log's `config.check-failed`. |
| `26` | `list-too-large` | `list`: the credential list does not fit one admin message. The message gives the count. | Remove credentials you no longer need. |

### `caller-token`

| Code | Name | Meaning | What to do |
|---|---|---|---|
| `25` | `random-source-failed` | The operating system's random source failed, so no token was made. | This points to a broken host. Check the kernel log; do not work around it. |

### `recovery check`

| Code | Name | Meaning | What to do |
|---|---|---|---|
| `30` | `recovery-key-invalid` | The text is not a recovery key: it does not look like `AGE-SECRET-KEY-1...`. | Check you pasted the whole key from where you stored it. |
| `31` | `recovery-check-failed` | The key does not open this vault. | This is not the key for this vault. Find the right one; if you cannot, the vault has no working recovery key. See [Check and store your recovery key](../cookbook/recovery-key.md). |
| `32` | `recovery-check-unavailable` | The vault is not initialized, or a file the check reads could not be read or is malformed, so the key was not judged. | Read the message, which names the file and error kind. |

### `recipient list`, `recipient add` and `recipient remove`

| Code | Name | Meaning | What to do |
|---|---|---|---|
| `8` | `declined` | `recipient add --recovery`: you did not type `yes` when asked to confirm you saved the new recovery key. Nothing was changed, and the key shown opens nothing. | Discard the key shown, and run the command again when you are ready to store a new one. |
| `35` | `recipient-invalid` | The key is not an `age1...` X25519 recipient key, or (for `recipient add`) the label breaks its rule. The message names the rule. | Copy the key from `recipient list`, or check the key and the label you typed. |
| `36` | `recipient-enrolled` | `recipient add`: the key is already enrolled. It was refused before any prompt. Nothing was changed. | Run `recipient list` to see the enrolled keys. |
| `37` | `unknown-recipient` | `recipient remove`: no enrolled recipient has this key. Nothing was changed. | Run `recipient list` and copy the key from it. |
| `38` | `recipient-set-invalid` | `recipient add`: the set after the change would break the independence rule or hold more than 64 recipients. `recipient remove`: the vault would be left without its operational recipient or without a recovery recipient, or, in a Protected or Container service, the key is the `host-unlock` recipient whose identity the unlock handoff holds. The message names which part. Nothing was changed. | Read the message. The vault always needs its operational recipient and one recovery recipient. To replace the host unlock identity, enrol the new one with `recipient add --host-unlock` and restart until the stack reaches Ready with no `unlock`, then remove the old one. To retire host unlock, stop and disable the handoff unit and remove its credential first. |
| `39` | `recipient-inventory-damaged` | The recipient inventory (`recipients.age`) is missing or damaged, or does not describe the `identity.age` on disk. The message names the damage. Nothing was changed, and the service stays Ready. | Do not delete or rewrite either file. A vault initialized before recipient commands has no inventory, and the message says so. Keep your recovery key, which opens the vault without the inventory. |

All three commands also answer `wrong-state` outside Ready, `busy` while another command holds the service-wide lock, and
`vault-write-failed` when settling a staged recipient change failed or, for `recipient add` and `recipient remove`, the
change itself did; the message says whether it may have committed.

### `approver add` and `approver remove`

| Code | Name | Meaning | What to do |
|---|---|---|---|
| `40` | `approver-invalid` | `approver add`: the label breaks its rule. `approver remove`: the ID is not a version 4 UUID. The message names the rule. Nothing was changed. | Give a label of 1 to 64 bytes with no control characters, or copy the approver ID from `approver list`. |
| `41` | `unknown-approver` | `approver remove`: no pinned approver has this ID. It was refused before any prompt. Nothing was changed. | Run `approver list` and copy the ID from it. |
| `42` | `approver-set-invalid` | `approver add`: 16 approvers are already pinned. `approver remove`: it is the last approver. Either was refused before any prompt. Nothing was changed. | For `add`, remove an approver you no longer use first. The last approver stays: enroll another one before you remove it. |
| `43` | `approver-in-use` | `approver remove`: this approver signed the active approval, and removing it would stop the active config verifying and take every route down. It was refused before any prompt. Nothing was changed. | Approve the config again with another approver (switch to it at the prompt), then remove this one. |
| `44` | `approver-kind-unavailable` | This install does not offer that signer kind yet. Only `software` is offered. Nothing was changed. | Leave out `--kind`, or use `--kind software`. |
| `9` | `approval-denied` | The passphrase did not open the asked approver's key. The vault passphrase and a recovery key never authorize an approver change. Any pinned approver may authorize a removal, the one being removed included. Nothing was written. | Type the approval passphrase of the approver the prompt names, or switch to another approver. |
| `10` | `approval-unavailable` | Owner presence could not be checked, or a `lock` cancelled the change at its passphrase prompt. Nothing was written. | Unlock if needed, and run the command again. |
| `18` | `passphrase-rejected` | The new approval passphrase is under 12 characters, or the two copies differ. Nothing was written. | Run the command again and choose a passphrase that meets the rule, different from the vault passphrase. |
| `22` | `vault-write-failed` | The approval state (`approval.age`) did not read back before any prompt, or the enrollment or removal failed. The message says whether it may have committed. | When the message says nothing was changed, read the log's `approver.change-failed` and fix its cause. When it may have committed, check the approvers before trying again. |

Both also answer `wrong-state` outside Ready (`approver add` also when a `lock` cancels it at the new passphrase prompt), and `busy` while
another command holds the service-wide lock.

### `reset`

| Code | Name | Meaning | What to do |
|---|---|---|---|
| `49` | `nothing-to-reset` | No vault file is there, at the request or after you confirmed. The message says to run `init`, or names the first file that is there and says to move it aside first. Nothing was removed. | Run `iron-vault init`, or move the named file aside. |
| `50` | `reset-failed` | Writing the reset marker or removing a file failed. The message says whether the vault is intact (the marker was not written) or the next `reset` finishes the job. | Fix the cause the message names, then run `iron-vault reset` again. `status` shows `reset unfinished` until it ends. |

`reset` also answers `wrong-state` in Starting, Checking and Stopped, and `declined` when what you typed does not match, or when
the vault changed between the summary and your confirmation. When stdin is not a terminal or `/dev/tty` cannot be opened,
the CLI exits with `3` before it connects.

### Migration authorization

`recipient add` and `export` share these codes. `export` is not a CLI command yet.

| Code | Name | Meaning | What to do |
|---|---|---|---|
| `28` | `migration-denied` | Migration authorization was refused: the vault passphrase was wrong, the envelopes it opened are not this vault's, or the authorization expired, was used already or is for another operation. Nothing was exported or rewrapped. | Start the command again with the right vault passphrase. |
| `29` | `migration-unavailable` | Migration authorization could not be checked, or a `lock` cancelled the command at its prompt. Nothing was exported or rewrapped. | Read the message and try again. |
| `33` | `migration-rate-limited` | Too many wrong vault passphrases in a row. The message gives the seconds to wait. | Wait that long. The limit is the one `unlock` shares. |

## Proxy refusals

A refused request gets one of these statuses. Every body is a short fixed string, the same whatever caused it, so a
caller learns nothing about other callers' routes. The `reason` is in the log's `request.completed` record, never in
the response. A refusal before the route's credential is added sends nothing upstream.

| Status | Body | `reason` values |
|---|---|---|
| `400` | `bad request`, or for a request form the service does not accept, the rule broken (below) | `connect_not_supported`, `not_origin_form`, `upgrade_not_supported`, `unsupported_version`, `bad_target`, `bad_method`, `bad_header`, `ambiguous_framing`, `foreign_marker`, `malformed_marker` |
| `401` | `unauthorized` | `unauthenticated` |
| `403` | `forbidden` | `not_granted`, `method_not_allowed`, `path_not_allowed` |
| `404` | `not found` | `no_route` |
| `408` | empty | `request_timeout` |
| `413` | empty | `request_too_large` |
| `429` | `too many requests`, with `Retry-After` in whole seconds | `rate_limited` |
| `500` | `internal error` | `service_defect` |
| `502` | `bad gateway` | `upstream_connect`, `upstream_tls`, `upstream_protocol`, `upstream_body`, `unsupported_coding`, `redirect_refused` |
| `503` | the unavailable reason (`locked`, `policy invalid`, `checking` or `recovery needed`), or `service unavailable` | `locked`, `policy_invalid`, `checking`, `recovery_needed`, `withdrawn`, `route_unavailable`, `credential_unavailable`, `credential_unusable` |
| `504` | `gateway timeout` | `upstream_timeout` |

### 400: the request is malformed

| `reason` | Cause | What to do |
|---|---|---|
| `connect_not_supported` | A `CONNECT` request. The body is `CONNECT is not supported`. | Iron Vault is a base-URL proxy, not a forward proxy. Point the application's base URL at the route prefix instead of setting `HTTPS_PROXY`. |
| `not_origin_form` | The request target is not a path such as `/route/...`, for example a full URL. The body is `the request target must be origin-form`. | As above: use the route prefix as the base URL. |
| `upgrade_not_supported` | A protocol upgrade, such as WebSocket. The body is `protocol upgrades are not supported`. | Not supported in v0. |
| `unsupported_version` | Not HTTP/1.0 or HTTP/1.1. The body is `only HTTP/1.0 and HTTP/1.1 are supported`. | Configure the client for HTTP/1.1. |
| `bad_target` | The path or query broke a rule, such as a `..` segment or an encoded separator. | Fix the URL the application builds. |
| `bad_method` | The method is not one a route may allow. | Use a standard method. |
| `bad_header` | A request header could not be read. | Fix the client. |
| `ambiguous_framing` | The request's length is ambiguous, for example both `Content-Length` and `Transfer-Encoding`. | Fix the client. |
| `foreign_marker`, `malformed_marker` | The request holds a credential placeholder that is not this route's, or is malformed. | Check the placeholder the application sends where its API key goes. |

### 401, 403, 404: who may use what

| Status and `reason` | Cause | What to do |
|---|---|---|
| `401` `unauthenticated` | No caller token, a wrong one, or a peer account no caller names. | Send the token in `Proxy-Authorization: Bearer <token>`, or in the listener's `token_header`. After a token rotation, the old one stops working at once. |
| `403` `not_granted` | The caller is known but its `routes` do not include this route. | Grant the route in the caller's table and approve. |
| `403` `method_not_allowed` | The route's `methods` do not allow this method. | Widen `methods`, or call it differently. See [Widen or narrow a route](../cookbook/change-route.md). |
| `403` `path_not_allowed` | The route's `paths` do not match. Patterns match the path after the route prefix, as the provider documents it, without the upstream's base path. | Check `paths` against the path you call after the prefix; leave the upstream's base path out. |
| `404` `no_route` | No route has this prefix. The same answer whatever other callers may use. | Check the prefix in the URL. |

### 413, 408 and 429: limits

| Status and `reason` | Cause | What to do |
|---|---|---|
| `413` `request_too_large` | The request body is over `max_request_body_bytes`, declared or as it streamed. | Send less, or raise the limit in `[limits]` and approve. |
| `408` `request_timeout` | The service had not answered by its request timeout. | Check the upstream's latency. |
| `429` `rate_limited` | The route's or caller's token bucket is empty. `Retry-After` says when a request will pass. | Wait, or raise `rate_limit` and approve. |

### 500: a service defect

`service_defect` means a final check that should never fail did. Nothing was sent upstream. It is also logged as
`request.defect` at `ERROR`, with the label of the check. Report it as a bug with that record.

### 502 and 504: the upstream

| Status and `reason` | Cause | What to do |
|---|---|---|
| `502` `upstream_connect` | The service could not connect to the upstream. | Check DNS and the network from the service's host. |
| `502` `upstream_tls` | The upstream's TLS certificate did not verify. | Iron Vault never skips verification. For a private CA, set the route's `ca_file`. |
| `502` `upstream_protocol` | The upstream broke the HTTP protocol. | Check the upstream URL is an HTTPS API. |
| `502` `upstream_body` | The upstream's body stopped before its end. | Usually the upstream's problem; retry. |
| `502` `unsupported_coding` | The response uses a content coding the scrubber cannot decode, so it could not be screened for secrets. | The service decodes `gzip`, `deflate` and `br`. Ask the upstream for one of those, or for none. |
| `502` `redirect_refused` | The upstream redirected outside the route's upstream base path, or sent an ambiguous `Location`. | Expected for a redirect that could land in another route. A redirect to another site is passed through instead. |
| `504` `upstream_timeout` | No response head by the request deadline. | Check the upstream. |

### 503: not available now

When the service is not Ready, every request gets `503` before any caller is identified, and the body is the reason
itself:

| Body | `reason` | Meaning | What to do |
|---|---|---|---|
| `locked` | `locked` | The service is Starting or Locked. | `iron-vault unlock`. |
| `checking` | `checking` | A config check is running: after an unlock, a reload, an approval or a credential change. | Retry in a moment. |
| `policy invalid` | `policy_invalid` | The config or its approval did not verify, for example after a hand edit. | Approve a good config: see [Tamper detection and recovery](../cookbook/tamper-detection.md). |
| `recovery needed` | `recovery_needed` | Shared vault state is damaged, or a committed change is unfinished. | Read `vault.shared-state-damaged` or `config.activation-failed` in the log, and its `remediation`. |

When the service is Ready but this request cannot be served, the body is `service unavailable`:

| `reason` | Meaning | What to do |
|---|---|---|
| `route_unavailable` | The route cannot serve: its pinned CA did not load, or it has no upstream client. | `status` lists route faults; the log has `route.pinned-ca-unavailable`. |
| `credential_unavailable` | The route's credential record is damaged. Other routes keep working. | `status` shows the credential as damaged; repair it with `replace`. |
| `credential_unusable` | The record loaded but its kind could not produce the request's credential. | Replace the credential with one of the right kind. |
| `withdrawn` | The policy changed while the request waited, and its snapshot was withdrawn. | Retry. |

### Failures after the response started

Some failures happen after the status line has gone to the caller. The status in the log is then that head's, the
caller's connection is cut, and the `reason` says why:

| `reason` | Meaning |
|---|---|
| `body_corrupt` | The upstream's compressed body did not decode. |
| `body_truncated` | The upstream's body ended early. |
| `body_size_limit`, `body_ratio_limit` | The decoded body passed the size limit or the decompression ratio limit. |
| `body_encode` | Re-encoding the scrubbed body failed. |
| `upstream_body` | The upstream's body stopped. |
| `deadline` | The request deadline passed while the body streamed. |
| `caller_gone` | The caller closed the connection. |
| `service_closed` | The service closed the connection: a lock, a stop, or a config change that dropped the listener. |

### Refusals with no log record

A few refusals happen before Iron Vault's code sees a request, so they write no `request.completed`: hyper's own `431`
for oversized headers and `414` for an oversized target, a connection closed because `max_connections` are open (a
`WARN` diagnostic record), and a TLS handshake or header read that timed out.
