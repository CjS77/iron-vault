# Scrubbing and redirects

*Checked with `iron-vault 0.2.0-alpha (features: dev-mode)`, built from `main` at `e10f09e`. The streamed Venice chat
in step 2 needs a real Venice key and was not run, so no output is shown for it.*

At the end of this recipe you will have seen the scrubber remove a credential from compressed and streamed responses,
and seen what Iron Vault does with an upstream's redirect.

## Prerequisites

- The service running and Ready, with the `me` caller and `httpbin` route from [getting started](getting-started.md),
  and `AUTH` set as in that recipe.
- For the streamed chat, the `chat` caller and `venice-chat` route from [two keys, two callers](two-callers.md), and
  `CHAT` set as in that recipe.

## Steps

### 1. Allow the paths

In `dev-config.toml`, widen the httpbin route's paths:

```toml
paths = ["/anything/**", "/headers", "/gzip", "/stream/*", "/redirect-to"]
```

`*` matches exactly one path segment, and `**` any number. Approve it:

```sh
iron-vault config approve dev-config.toml
```

The summary shows only the changed route. Your vault ID, digest and versions will differ:

```text
Approval summary
vault: 7e3c6dfe-3a89-49ee-9f54-1e538dbfc4ed
version to commit: 3
config digest: blake2b:d5c63bfb9766ff1cbf98328c7c50f8e0fd4aeff2c1ce9f897567a59e361a6b5a
committed version: 2
routes:
  ~ httpbin: paths /anything/**, /headers -> /anything/**, /gzip, /headers, /redirect-to, /stream/*
Approve this config as version 3? Type yes to approve: yes
Approval passphrase:
approved version 3 (blake2b:d5c63bfb9766ff1cbf98328c7c50f8e0fd4aeff2c1ce9f897567a59e361a6b5a)
callers: none; route grants: none; routes: 1 changed; listeners: none; limits: none; logging: none; recovery: none
```

[Widen or narrow a route](change-route.md) shows how to read the approval summary. The route's bucket starts empty
after the approval, so wait a few seconds before the next step or the first request may get `429`.

### 2. Scrub compressed and streamed responses

The scrubber removes the credential from compressed and streamed responses too. httpbin's `/gzip` answers with a
gzip-compressed echo of the request, and `/stream/3` with three echoes sent as they are produced:

```sh
curl -si -H "$AUTH" http://127.0.0.1:7878/httpbin/gzip
```

```text
HTTP/1.1 200 OK
access-control-allow-credentials: true
access-control-allow-origin: *
access-control-expose-headers: Retry-After, RateLimit, RateLimit-Policy
date: Sun, 08 Nov 2026 12:11:08 GMT
x-content-type-options: nosniff
content-type: application/json
transfer-encoding: chunked

{
  "args": {},
  "headers": {
    "Accept": "*/*",
    "Accept-Encoding": "gzip, deflate, br",
    "Authorization": "Bearer [iron-vault:scrubbed]",
    "Host": "httpbin.org",
    "User-Agent": "curl/8.5.0"
  },
  "method": "GET",
  "origin": "203.0.113.7",
  "url": "",
  "gzipped": true
}
```

```sh
curl -sN -H "$AUTH" http://127.0.0.1:7878/httpbin/stream/3
```

```text
{"id":0,"args":{},"headers":{"Accept":"*/*","Accept-Encoding":"gzip, deflate, br","Authorization":"Bearer [iron-vault:scrubbed]","Host":"httpbin.org","User-Agent":"curl/8.5.0"},"origin":"203.0.113.7","url":"https://httpbin.org/stream/3"}
{"id":1,"args":{},"headers":{"Accept":"*/*","Accept-Encoding":"gzip, deflate, br","Authorization":"Bearer [iron-vault:scrubbed]","Host":"httpbin.org","User-Agent":"curl/8.5.0"},"origin":"203.0.113.7","url":"https://httpbin.org/stream/3"}
{"id":2,"args":{},"headers":{"Accept":"*/*","Accept-Encoding":"gzip, deflate, br","Authorization":"Bearer [iron-vault:scrubbed]","Host":"httpbin.org","User-Agent":"curl/8.5.0"},"origin":"203.0.113.7","url":"https://httpbin.org/stream/3"}
```

httpbin's `origin` is your public address; it is shown here as `203.0.113.7`. In both, the echoed `Authorization` header reads `Bearer [iron-vault:scrubbed]`. The `/gzip` response arrives without
`Content-Encoding`: Iron Vault decompressed the body to scrub it and compresses it again only when the caller's
`Accept-Encoding` demands it. Each response also produces a `response.scrubbed` record in the log, with one match
per echo. This one is from `/stream/3`:

```json
{"service":"iron-vault","service_version":"0.2.0-alpha","schema_version":1,"deployment_profile":"development","timestamp":"2026-11-08T12:11:11.628275Z","level":"WARN","message":"scrubbed a secret from a response","event":"response.scrubbed","request_id":"4efad803-1ac8-413e-9ad0-221632213ea0","route":"httpbin","credential":"httpbin_key","matches":3,"target":"iron-vault.audit"}
```

Venice's chat route streams the same way. Add `"stream": true` and the answer arrives as server-sent events, each
scrubbed as it passes. This example was not run (see the note at the top), so no output is shown:

```sh
curl -sN -H "$CHAT" -H 'Content-Type: application/json' \
  http://127.0.0.1:7878/venice-chat/chat/completions \
  -d '{"model": "google-gemma-3-27b-it", "stream": true, "messages": [{"role": "user", "content": "Count to five."}]}'
```

### 3. See a redirect come back

Iron Vault never follows a redirect itself, so the credential is never sent anywhere the route doesn't name. It
passes the redirect back to the caller:

```sh
# a redirect within httpbin is rewritten under the route prefix
curl -si -H "$AUTH" 'http://127.0.0.1:7878/httpbin/redirect-to?url=/headers' | grep -i '^location'
# location: /httpbin/headers

# a redirect to another site is passed through unchanged; following it sends no credential
curl -si -H "$AUTH" 'http://127.0.0.1:7878/httpbin/redirect-to?url=https://example.com/' | grep -i '^location'
# location: https://example.com/
```

A redirect to the same host but outside the upstream's base path, such as `/other` from an upstream at `/api/v1`, is
refused with `502`, so it can't land in another route.

## What can go wrong

- **`403` with `path_not_allowed`.** The route's `paths` don't include the path; step 1 adds them.
- **`502` with reason `redirect_refused`.** The upstream redirected outside its base path, as above.

## Reference

- [Audit log](../reference/audit-log.md): `response.scrubbed`.
- [Errors](../reference/errors.md): the `502` reasons.
- Related: [Basic authentication upstreams](basic-auth.md), which shows what the scrubber matches for a Basic
  credential.
