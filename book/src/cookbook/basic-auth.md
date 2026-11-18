# Basic authentication upstreams

*Checked with `iron-vault 0.2.0-alpha (features: dev-mode)`, built from `main` at `cc59b80`.*

Store a username and password and have Iron Vault send them upstream as `Authorization: Basic …`. The test endpoint,
httpbin's `/basic-auth/<user>/<password>`, puts both values in its path; a real upstream's caller knows neither.
Every command below was run against httpbin.org.

## Prerequisites

- The service running and Ready, with the `me` caller and loopback listener from
  [getting started](getting-started.md). This recipe adds to that recipe's `dev-config.toml`.

## Steps

### 1. Store the username and password

`--kind basic` makes `add` ask for two values, neither echoed:

```sh
iron-vault add httpbin_basic --kind basic --origin httpbin.org
```

```text
Username for httpbin_basic:
Password for httpbin_basic:
added httpbin_basic (basic) as record 5c4cd8bd-…
```

This run used `alice` and `test-basic-pass-77`. Piped in, the first line is the username and the second the password.

```sh
iron-vault list
```

```text
…
httpbin_basic  basic  httpbin.org:443  healthy
httpbin_key  static  httpbin.org:443  healthy
…
```

### 2. Add a route with the Basic slot

The Basic slot is the bare string `"basic"`. Add the route to `dev-config.toml`, and grant it to `me`:

```toml
[callers.me]
listener = "loopback"
token_hash = "blake2b:<me's hash>"
routes = ["httpbin", "httpbin-basic"]

[routes.httpbin-basic]
prefix = "/httpbin-basic"
upstream = "https://httpbin.org"
credential = "httpbin_basic"
slot = "basic"
methods = ["GET"]
paths = ["/basic-auth/alice/*", "/headers"]
rate_limit = { requests = 30, per_seconds = 60, burst = 5 }
```

```sh
iron-vault config approve dev-config.toml
```

```text
Approval summary
vault: 4b3faa85-…
version to commit: 5
config digest: blake2b:6d193719…
committed version: 4
route grants:
  ~ me: granted httpbin-basic
routes:
  + httpbin-basic: prefix /httpbin-basic, upstream https://httpbin.org/, credential httpbin_basic, slot basic, ca file none, methods GET, paths /basic-auth/alice/*, /headers, rate limit 30 per 60s burst 5, confirm none
Approve this config as version 5? Type yes to approve: yes
Approval passphrase for "approval passphrase":
approved version 5 (blake2b:6d193719…)
callers: none; route grants: 1 changed; routes: 1 added; listeners: none; limits: none; logging: none; recovery: none
```

### 3. Send requests

```sh
AUTH="Proxy-Authorization: Bearer $(cat ~/.iron-vault-tokens/me)"
curl -s -H "$AUTH" http://127.0.0.1:7878/httpbin-basic/basic-auth/alice/test-basic-pass-77
```

httpbin accepted the username and password Iron Vault sent:

```json
{
  "authenticated": true,
  "user": "alice",
  "authorized": true
}
```

Ask httpbin to echo the headers it received:

```sh
curl -s -H "$AUTH" http://127.0.0.1:7878/httpbin-basic/headers
```

```json
{
  "headers": {
    "Accept": "*/*",
    "Accept-Encoding": "gzip, deflate, br",
    "Authorization": "[iron-vault:scrubbed]",
    "Host": "httpbin.org",
    "User-Agent": "curl/8.5.0"
  }
}
```

The whole `Basic …` value is scrubbed, and the log has a `response.scrubbed` record with `"matches":1`. A caller's own
`Authorization` header, such as `curl -u placeholder:placeholder`, is replaced by the stored one.

A wrong password in the path is refused by httpbin, not by Iron Vault:

```sh
curl -si -H "$AUTH" http://127.0.0.1:7878/httpbin-basic/basic-auth/alice/wrong
```

```text
HTTP/1.1 401 Unauthorized
www-authenticate: Basic realm="Fake Realm"
…
```

## What can go wrong

- **The username is not scrubbed from bodies.** `"user": "alice"` comes back unchanged. The username alone is scrubbed only
  when the password is empty.
- **`403` with `path_not_allowed`.** This route allows only `alice`'s path; `/basic-auth/bob/x` is refused before
  anything leaves the machine.
- **`429` right after the approval.** The route's token bucket
  [starts empty](../reference/configuration.md#rate_limit-the-token-bucket) and refills at one request every 2 seconds;
  wait a few seconds.
- **`401` from the upstream.** The stored username or password is wrong. `replace httpbin_basic --kind basic
  --origin httpbin.org` stores new ones.

## Reference

- [Configuration](../reference/configuration.md): the `"basic"` slot.
- [CLI](../reference/cli.md): `add --kind basic`, and `replace --kind` to change kind.
- [Audit log](../reference/audit-log.md): `response.scrubbed`.
