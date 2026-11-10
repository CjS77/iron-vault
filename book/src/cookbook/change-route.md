# Widen or narrow a route

*Checked with `iron-vault 0.2.0-alpha (features: dev-mode)`, built from `main` at `378d57d`.*

At the end of this recipe a route allows more, or less, than it did, and you will have read the approval summary
before agreeing to it. Every change to a route is an approval of the whole config file. The **approval summary** is
the service's own account of what that approval changes, so read it, not your editor, before you type `yes`: if
something else edited the file, the summary is where you see it.

Every command below was run as shown, against the real httpbin.org.

## Prerequisites

- The service running and Ready, with the `me` caller and `httpbin` route from [getting started](getting-started.md).
- Your config file, `dev-config.toml`, and the approval passphrase.

## Steps

### 1. Widen the route

Allow httpbin's compressed and streamed echoes too. In `[routes.httpbin]`:

```toml
paths = ["/anything/**", "/headers", "/gzip", "/stream/*"]
```

`*` matches exactly one path segment, and `**` any number.

```sh
iron-vault config approve dev-config.toml
```

```text
Approval summary
vault: 8c597c79-…
version to commit: 8
config digest: blake2b:e540c2d8…
committed version: 7
routes:
  ~ httpbin: paths /anything/**, /headers -> /anything/**, /gzip, /headers, /stream/*
Approve this config as version 8? Type yes to approve: yes
Approval passphrase:
approved version 8 (blake2b:e540c2d8…)
callers: none; route grants: none; routes: 1 changed; listeners: none; limits: none; logging: none; recovery: none
```

The new paths work at once, with no restart:

```sh
AUTH="Proxy-Authorization: Bearer $(cat ~/.iron-vault-tokens/me)"
curl -s -H "$AUTH" http://127.0.0.1:7878/httpbin/stream/2
```

```text
{"id":0,"args":{},"headers":{"Accept":"*/*","Accept-Encoding":"gzip, deflate, br","Authorization":"Bearer [iron-vault:scrubbed]","Host":"httpbin.org","User-Agent":"curl/8.5.0"},"origin":"…","url":"https://httpbin.org/stream/2"}
{"id":1,"args":{},"headers":{"Accept":"*/*","Accept-Encoding":"gzip, deflate, br","Authorization":"Bearer [iron-vault:scrubbed]","Host":"httpbin.org","User-Agent":"curl/8.5.0"},"origin":"…","url":"https://httpbin.org/stream/2"}
```

### 2. Narrow it

Take `/stream/*` away again and slow the route down:

```toml
paths = ["/anything/**", "/headers", "/gzip"]
rate_limit = { requests = 10, per_seconds = 60, burst = 2 }
```

```text
Approval summary
vault: 8c597c79-…
version to commit: 9
config digest: blake2b:f8020a2b…
committed version: 8
routes:
  ~ httpbin: paths /anything/**, /gzip, /headers, /stream/* -> /anything/**, /gzip, /headers; rate limit 30 per 60s burst 5 -> 10 per 60s burst 2
Approve this config as version 9? Type yes to approve: yes
Approval passphrase:
approved version 9 (blake2b:f8020a2b…)
callers: none; route grants: none; routes: 1 changed; listeners: none; limits: none; logging: none; recovery: none
```

```sh
curl -si -H "$AUTH" http://127.0.0.1:7878/httpbin/stream/2 | head -1
```

```text
HTTP/1.1 403 Forbidden
```

The log gives the reason `path_not_allowed`. Each approval makes the service Ready again, so the route's rate limit
[starts empty](getting-started.md#rate-limits-start-empty).

### 3. Read the summary, and say no when it's wrong

Suppose the file now holds a change you didn't make, or one bigger than you meant:

```text
Approval summary
vault: 8c597c79-…
version to commit: 10
config digest: blake2b:869e704b…
committed version: 9
routes:
  ~ httpbin: methods GET -> DELETE, GET, POST; paths /anything/**, /gzip, /headers -> /**
Approve this config as version 10? Type yes to approve: no
iron-vault: the service answered error 8 (declined): the config was not approved: the confirmation was not `yes`
```

Anything but `yes` declines. Nothing changes, and no version is used up: `status` still shows `approval committed: 9`
and `approval highest reserved: 9`. Fix the file and approve again.

What to check in a summary:

- **Header.** `vault` is your vault, and `committed version` is the one `status` shows. `no active config`, which
  appears after [tamper detection](tamper-detection.md) or a failed check, means every table is listed as added.
- **`callers`** (`+` added, `-` removed, `~` changed). A new caller, a changed listener or `token changed` you didn't
  expect means someone else can now use routes.
- **`route grants`**: which caller gains or loses which route.
- **`routes`**: each changed field as old `->` new: prefix, upstream, credential, slot, CA file, methods, paths, rate
  limit and confirmation. Watch `upstream` and `slot` most: they decide where a credential goes and where it sits in
  the request. A credential still can't go to a host its record doesn't permit; that check runs before the summary.
- **`listeners`**: a new address changes who can reach every route on it.
- **The last line** counts every section, so `none` in a section confirms nothing changed there.

## What can go wrong

- **``iron-vault: the service answered error 8 (declined): the config was not approved: the confirmation was not
  `yes` ``.** You typed something other than `yes`. Nothing changed.
- **`iron-vault: the service answered error 7 (config-invalid): the proposed config is invalid: …`.** The service
  refuses before the summary, and uses no version. The message names the problem, such as a caller granted a route the
  config doesn't define. A listener moved to `192.0.2.10:8443` without `tls_certificate` and `tls_key` gives
  `the proposed config is invalid: listener public on 192.0.2.10:8443 needs tls_certificate and tls_key: plain HTTP is
  allowed only on loopback`. Check the [configuration reference](../reference/configuration.md) for that table.
- **`403` with `path_not_allowed` after widening.** Patterns match the path after the route prefix, as the provider
  documents it, without the upstream's base path.
- **`429` straight after the approval.** The bucket [starts empty](getting-started.md#rate-limits-start-empty).

## Reference

- [Configuration](../reference/configuration.md): routes, path patterns, methods and rate limits.
- [CLI](../reference/cli.md#iron-vault-config-approve): `config approve`.
- The [approval summary's design](../../../design/config-approval.md#approval-summary).
- Related: [rotate or revoke a caller token](caller-token.md), [tamper detection and recovery](tamper-detection.md).
