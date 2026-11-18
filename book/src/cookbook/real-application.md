# Point a real application at Iron Vault

*Checked with `iron-vault 0.2.0-alpha (features: dev-mode)`, built from `main` at `cc59b80`.*

Configure an application to reach its API through Iron Vault in **base-URL mode**, send its caller token, and check
that it sends every request through the route. The application must let you change the address it sends to. The
examples use `curl` against httpbin.org; no particular application was tested.

## Prerequisites

- The service running and Ready, with the `me` caller, the loopback listener and the `httpbin` route from
  [getting started](getting-started.md).
- A route for the application's API, such as those in
  [give an AI agent or MCP server an API key](agent-api-key.md).

## Steps

### 1. Set the base URL

Set the application's API address to the listener plus the route's prefix, for example
`http://127.0.0.1:7878/venice` for a route with `prefix = "/venice"`. A request whose path matches no route prefix is refused:

```sh
curl -si -H "Proxy-Authorization: Bearer $(cat ~/.iron-vault-tokens/me)" http://127.0.0.1:7878/headers
```

```text
HTTP/1.1 404 Not Found
…
not found
```

The log reason is `no_route`: the application dropped the prefix.

### 2. Give it a placeholder key

Where the application wants its API key, give it any placeholder, such as `placeholder`:

```sh
AUTH="Proxy-Authorization: Bearer $(cat ~/.iron-vault-tokens/me)"
curl -s -H "$AUTH" -H 'Authorization: Bearer placeholder' http://127.0.0.1:7878/httpbin/headers | grep Authorization
```

```text
    "Authorization": "Bearer [iron-vault:scrubbed]",
```

httpbin received the stored key, not `placeholder`.

Or use a **marker**, `{iv:<credential name>}`, naming the route's own credential. A marker naming another credential
is refused:

```sh
curl -s  -H "$AUTH" -H 'Authorization: Bearer {iv:httpbin_key}' http://127.0.0.1:7878/httpbin/headers | grep Authorization
curl -si -H "$AUTH" -H 'Authorization: Bearer {iv:brave}'       http://127.0.0.1:7878/httpbin/headers
```

```text
    "Authorization": "Bearer [iron-vault:scrubbed]",
HTTP/1.1 400 Bad Request
…
bad request
```

The second is logged with `"reason":"foreign_marker"`. Outside the slot a marker is passed on unchanged:

```sh
curl -s -H "$AUTH" 'http://127.0.0.1:7878/httpbin/anything/x?note=%7Biv:httpbin_key%7D' | grep -E 'note|Authorization'
```

```text
    "note": "{iv:httpbin_key}"
    "Authorization": "Bearer [iron-vault:scrubbed]",
```

### 3. Send the caller token

Every request needs the caller's token, in one of two places:

- **`Proxy-Authorization: Bearer <token>`**, the default.
- **The listener's `token_header`**, for an application that can add a custom header but not `Proxy-Authorization`.
  The token goes in it bare, with no `Bearer`.

Issue the application its own token:

```sh
iron-vault caller-token > ~/.iron-vault-tokens/app
```

Add a listener and a caller to `dev-config.toml`, with the `token_hash` line that printed:

```toml
[listeners.app]
address = "127.0.0.1:7879"
token_header = "X-Iron-Vault-Token"

[callers.app]
listener = "app"
token_hash = "blake2b:<app's hash>"
routes = ["httpbin"]
```

The application gets a listener of its own, because `token_header` is set per listener. Approve it:

```sh
iron-vault config approve dev-config.toml
```

```text
Approval summary
vault: 4b3faa85-…
version to commit: 6
config digest: blake2b:2dbc74a7…
committed version: 5
callers:
  + app: listener app, auth token, rate limits none
route grants:
  + app: granted httpbin
listeners:
  + app: endpoint tcp 127.0.0.1:7879, no tls, token header X-Iron-Vault-Token
Approve this config as version 6? Type yes to approve: yes
Approval passphrase for "approval passphrase":
approved version 6 (blake2b:2dbc74a7…)
callers: 1 added; route grants: 1 added; routes: none; listeners: 1 added; limits: none; logging: none; recovery: none
```

Then send a request with the token in `X-Iron-Vault-Token`, and one with it in `Proxy-Authorization`:

```sh
APP_TOKEN=$(cat ~/.iron-vault-tokens/app)
curl -s  -H "X-Iron-Vault-Token: $APP_TOKEN" -H 'Authorization: Bearer placeholder' http://127.0.0.1:7879/httpbin/headers
curl -si -H "Proxy-Authorization: Bearer $APP_TOKEN" http://127.0.0.1:7879/httpbin/headers | head -1
```

```json
{
  "headers": {
    "Accept": "*/*",
    "Accept-Encoding": "gzip, deflate, br",
    "Authorization": "Bearer [iron-vault:scrubbed]",
    "Host": "httpbin.org",
    "User-Agent": "curl/8.5.0"
  }
}
```

```text
HTTP/1.1 401 Unauthorized
```

On this listener only `X-Iron-Vault-Token` carries the token, and it never reaches httpbin.

### 4. Check that a client supports base-URL mode

Don't assume an application uses the base URL for every request. Before you rely on it:

1. Give it a route whose upstream echoes requests, as httpbin does, or watch the log while you use it.
2. Use every feature you need. Each request through Iron Vault ends in one `request.completed` record naming your
   caller and route:

   ```sh
   jq -c 'select(.event == "request.completed") | {caller, route, http_method, status, outcome, reason}' ~/iron-vault-dev.log
   ```

3. Look for what is missing. A feature that works but leaves no record sent its request somewhere else.
4. Look for `no_route` and `path_not_allowed` refusals: the application calls paths you haven't allowed, or dropped
   the prefix.

### 5. Don't rely on `HTTPS_PROXY`

Setting `HTTPS_PROXY` does not make Iron Vault inject credentials. Iron Vault refuses the `CONNECT` tunnel:

```sh
HTTPS_PROXY=http://127.0.0.1:7878 curl -sv https://httpbin.org/headers
```

```text
> CONNECT httpbin.org:443 HTTP/1.1
< HTTP/1.1 400 Bad Request
< connection: close
< content-type: text/plain; charset=utf-8
< content-length: 24
* CONNECT tunnel failed, response 400
```

The body is `CONNECT is not supported`, and the log reason is `connect_not_supported`. Tools such as `gh`, `npm` and
`cargo` count as supported only once an end-to-end check covers their whole workflow in base-URL mode.

## What can go wrong

- **`404` with `no_route`.** The application dropped the route prefix from the base URL.
- **`401` from Iron Vault.** No token, a wrong one, or the token in the wrong header for this listener.
- **`400` with `foreign_marker`.** The placeholder names another credential.
- **`400 CONNECT is not supported`.** The application is using Iron Vault as a forward proxy. Set its base URL
  instead.
- **The application needs HTTPS to its API.** The loopback listener is plain HTTP. A TCP listener on any address but
  loopback must have `tls_certificate` and `tls_key`; see the [configuration reference](../reference/configuration.md).

## Reference

- [Configuration](../reference/configuration.md): listeners, `token_header`, slots and markers. Its
  [example](../reference/configuration.md#the-example) has routes for Brave Search (a header slot), Venice (a Bearer
  token) and OpenExchangeRates (a query parameter).
- [Audit log](../reference/audit-log.md): `request.completed` and its `reason` values.
- [Errors](../reference/errors.md).
- The [use cases in the README](../../../README.md#use-cases), and the
  [security boundary](../../../README.md#security-boundary): a program holding a caller token can use that caller's
  routes.
