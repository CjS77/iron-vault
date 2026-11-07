# Basic authentication upstreams

*Checked with `iron-vault 0.2.0-alpha (features: dev-mode)`, built from `main` at `cc59b80`.*

At the end of this recipe Iron Vault holds a username and password and sends them to an upstream as
`Authorization: Basic …`. With a real upstream the caller holds neither. The recipe uses httpbin's
`/basic-auth/<user>/<password>` endpoint, which answers `200` only when the request carries exactly that username and
password. That demo endpoint needs both in its own path, so here the caller does know them; a real upstream checks
the header alone, and the caller's requests carry neither value.

Every command below was run against the real httpbin.org.

## Prerequisites

- The service running and Ready, with the `me` caller and loopback listener from
  [getting started](getting-started.md). This recipe adds to that recipe's `dev-config.toml`.

## Steps

### 1. Store the username and password

`--kind basic` makes `add` ask for two values. Both are secret, so neither is echoed:

```sh
iron-vault add httpbin_basic --kind basic --origin httpbin.org
```

```text
Username for httpbin_basic:
Password for httpbin_basic:
added httpbin_basic (basic) as record 5c4cd8bd-…
```

This run used the username `alice` and the password `test-basic-pass-77`. Piped in, the first line is the username
and the second the password.

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

The Basic slot is the bare string `"basic"`: it takes no header name or format, because it always writes
`Authorization`. Add the route to `dev-config.toml`, and grant it to `me`:

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

Two routes may share an upstream; each needs its own prefix.

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
Approval passphrase:
approved version 5 (blake2b:6d193719…)
callers: none; route grants: 1 changed; routes: 1 added; listeners: none; limits: none; logging: none; recovery: none
```

### 3. Send requests

```sh
AUTH="Proxy-Authorization: Bearer $(cat ~/.iron-vault-tokens/me)"
curl -s -H "$AUTH" http://127.0.0.1:7878/httpbin-basic/basic-auth/alice/test-basic-pass-77
```

httpbin checked the username and password Iron Vault sent:

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

The whole `Basic …` value was scrubbed, and the log has a `response.scrubbed` record with `"matches":1`.

If the caller sends an `Authorization` header of its own, such as a client that insists on a username and password,
Iron Vault removes it and writes the stored one. With `curl -u placeholder:placeholder`, the echo is the same as
above.

A password that doesn't match is refused by httpbin, not by Iron Vault:

```sh
curl -si -H "$AUTH" http://127.0.0.1:7878/httpbin-basic/basic-auth/alice/wrong
```

```text
HTTP/1.1 401 Unauthorized
www-authenticate: Basic realm="Fake Realm"
…
```

## What can go wrong

- **The username is not scrubbed from bodies.** In the first response, `"user": "alice"` came back unchanged. For a
  Basic credential the scrubber watches for the Basic token, the complete `Basic <token>` value, `username:password`
  and the password, each with its encoded forms. It watches for the username alone only when the password is empty,
  because the username is then the secret.
- **`403` with `path_not_allowed`.** This route allows only `alice`'s path; `/basic-auth/bob/x` is refused before
  anything leaves the machine.
- **`429` right after the approval.** The route's token bucket
  [starts empty](getting-started.md#rate-limits-start-empty) each time the service becomes Ready, and refills at one
  request every 2 seconds. In this run the wrong-password request, sent straight after the other two, got
  `429` and went through a few seconds later.
- **`401` from the upstream.** The stored username or password is wrong. `replace httpbin_basic --kind basic
  --origin httpbin.org` stores new ones.

## Reference

- [Configuration](../reference/configuration.md): the `"basic"` slot.
- [CLI](../reference/cli.md): `add --kind basic`, and `replace --kind` to change kind.
- [Audit log](../reference/audit-log.md): `response.scrubbed`.
