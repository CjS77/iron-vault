# Tamper detection and recovery

*Checked with `iron-vault 0.2.0-alpha (features: dev-mode)`, built from `main` at `378d57d`.*

At the end of this recipe you will have seen what the service does when its published config is changed without an
approval, and brought it back. The service publishes each approved config as `config.toml` with its signature,
`config.toml.sig`, beside it. When it reloads, it checks the pair against the approved version. A config that nobody
approved is refused, and the service stops proxying rather than run it.

Every command below was run as shown, against the real httpbin.org. Step 1 plays the attacker. Don't do it to a
service that holds real keys.

## Prerequisites

- The service running and Ready, with the `me` caller and `httpbin` route from [getting started](getting-started.md),
  and the route's rate limit set to `burst = 2` as in [widen or narrow a route](change-route.md#2-narrow-it).
- Your own config file, `dev-config.toml`, holding the config you last approved, and the approval passphrase.

## Steps

### 1. Change the published config

Raise the rate limit directly in the published copy, as malware that could write the file might, then ask the
service to reload:

```sh
CONFIG="${XDG_CONFIG_HOME:-$HOME/.config}/iron-vault-dev/config.toml"
sed -i 's/burst = 2 }/burst = 500 }/' "$CONFIG"
kill -HUP "$(pgrep -x iron-vault)"
```

### 2. See what the service does

```sh
iron-vault status
```

```text
service: unavailable
reason: policy invalid
profile: development — no isolation from malware running as code
vault: locked
vault id: unknown
approval committed: unknown while the vault is locked
approval highest reserved: unknown while the vault is locked
memory protection: NOT protected, swap protection unavailable (RLIMIT_MEMLOCK soft limit is 8315834368 bytes, not unlimited)
recovery last checked: 2026-11-07 (today)
credentials: unknown while the vault is locked
```

Every request is refused, before anything leaves the machine:

```sh
curl -si -H "Proxy-Authorization: Bearer $(cat ~/.iron-vault-tokens/me)" http://127.0.0.1:7878/httpbin/headers
```

```text
HTTP/1.1 503 Service Unavailable
content-type: text/plain; charset=utf-8
content-length: 14

policy invalid
```

The log says what happened:

```sh
jq -c 'select(.event == "config.reload-failed")' ~/iron-vault-dev.log
```

```json
{"service":"iron-vault","service_version":"0.2.0-alpha","schema_version":1,"deployment_profile":"development","timestamp":"2026-11-07T10:24:23.474848Z","level":"WARN","message":"the reload failed, the service stops proxying","event":"config.reload-failed","committed_version":9,"unavailable_reason":"policy_invalid","detail":"the published config is not committed version 9: the config has changed since it was approved; approve it again","target":"iron-vault.audit"}
```

A `config.check-failed` record with the same `detail` comes just before it. The service keeps none of the old route
policy: it would rather serve nothing than guess which config is real.

### 3. Find out how it happened

In development mode the published config is in your own config directory, so anything running as you can write it.
In a protected install only the `iron-vault` service account and root can, so a changed file there means something
ran as one of them. Look at what else changed, and [read the admin trail](investigate-audit-log.md#5-read-the-admin-trail)
for approvals and credential changes you didn't make.

### 4. Approve your config again

Never fix the published copy by hand. Approve your own copy, after checking it is the one you mean:

```sh
iron-vault config approve dev-config.toml
```

The service lists everything as added, because no config is active:

```text
Approval summary
vault: 8c597c79-…
version to commit: 10
config digest: blake2b:f8020a2b…
committed version: 9
no active config
callers:
  + me: listener loopback, auth token, rate limits none
route grants:
  + me: granted httpbin
routes:
  + httpbin: prefix /httpbin, upstream https://httpbin.org/, credential httpbin_key, slot header Authorization format "Bearer {}", ca file none, methods GET, paths /anything/**, /gzip, /headers, rate limit 10 per 60s burst 2, confirm none
listeners:
  + loopback: endpoint tcp 127.0.0.1:7878, no tls, token header default
Approve this config as version 10? Type yes to approve: yes
Approval passphrase:
approved version 10 (blake2b:f8020a2b…)
callers: 1 added; route grants: 1 added; routes: 1 added; listeners: 1 added; limits: none; logging: none; recovery: none
```

Read every line of it: this is the whole policy, not a diff. Here the digest is the same as version 9's, because the
file is the same as the one last approved.

```sh
iron-vault status | head -6
```

```text
service: ready
profile: development — no isolation from malware running as code
vault: unlocked
vault id: 8c597c79-…
approval committed: 10
approval highest reserved: 10
```

The service is Ready again. Its rate limit [starts empty](getting-started.md#rate-limits-start-empty), so the first
request may get `429`.

## What can go wrong

- **`status` shows `vault: locked` while Unavailable.** That is how `status` reports an Unavailable service; the
  approval above still worked without an `unlock`.
- **You don't have the config you last approved.** Write a new one from scratch and approve it. The summary lists it
  all as added either way.

## Reference

- [Files and locations](../reference/files.md): the published config, its signature, and why never to edit them.
- [Service states](../reference/states.md): Unavailable.
- [Config approval design](../../../design/config-approval.md#reload): reload and the config check.
