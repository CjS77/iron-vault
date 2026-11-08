# Scrubbing and redirects

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

[Widen or narrow a route](change-route.md) shows how to read the approval summary.

### 2. Scrub compressed and streamed responses

The scrubber removes the credential from compressed and streamed responses too. httpbin's `/gzip` answers with a
gzip-compressed echo of the request, and `/stream/3` with three echoes sent as they are produced:

```sh
curl -si -H "$AUTH" http://127.0.0.1:7878/httpbin/gzip
curl -sN -H "$AUTH" http://127.0.0.1:7878/httpbin/stream/3
```

In both, the echoed `Authorization` header reads `Bearer [iron-vault:scrubbed]`. The `/gzip` response arrives without
`Content-Encoding`: Iron Vault decompressed the body to scrub it and compresses it again only when the caller's
`Accept-Encoding` demands it. Each response also produces a `response.scrubbed` record in the log.

Venice's chat route streams the same way. Add `"stream": true` and the answer arrives as server-sent events, each
scrubbed as it passes:

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
# Location: /httpbin/headers

# a redirect to another site is passed through unchanged; following it sends no credential
curl -si -H "$AUTH" 'http://127.0.0.1:7878/httpbin/redirect-to?url=https://example.com/' | grep -i '^location'
# Location: https://example.com/
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
