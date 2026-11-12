# Point a real application at Iron Vault

*Checked with `iron-vault 0.2.0-alpha (features: dev-mode)`, built from `main` at `cc59b80`.*

At the end of this recipe you will know how to configure an application to reach its API through Iron Vault, how to
send its caller token, and how to tell whether the application really sends every request through the route. The
examples use `curl` against the real httpbin.org; no particular application was tested.

Iron Vault works in **base-URL mode**: the application sends plain HTTP requests to Iron Vault's listener as if it
were the API, and Iron Vault forwards them over HTTPS. An application can use it only if it lets you change the
address it sends to.

## Prerequisites

- The service running and Ready, with the `me` caller, the loopback listener and the `httpbin` route from
  [getting started](getting-started.md).
- A route for the application's API, such as those in
  [give an AI agent or MCP server an API key](agent-api-key.md).

## Steps

### 1. Set the base URL

Set the application's API address to the listener plus the route's prefix, for example
`http://127.0.0.1:7878/venice` for a route with `prefix = "/venice"`. The application appends its usual paths, and
Iron Vault maps the prefix to the route's `upstream`.

A request whose path matches no route prefix is refused:

```sh
curl -si -H "Proxy-Authorization: Bearer $(cat ~/.iron-vault-tokens/me)" http://127.0.0.1:7878/headers
```

```text
HTTP/1.1 404 Not Found
…
not found
```

The log records it with `"reason":"no_route"`. If you see these, the application dropped the prefix, for example by
replacing the base URL's path rather than appending to it.

### 2. Give it a placeholder key

Where the application wants its API key, give it any placeholder, such as `placeholder`. Iron Vault removes every copy
of the route's slot header or query parameter and writes the real credential once. A placeholder in the slot is
fine:

```sh
AUTH="Proxy-Authorization: Bearer $(cat ~/.iron-vault-tokens/me)"
curl -s -H "$AUTH" -H 'Authorization: Bearer placeholder' http://127.0.0.1:7878/httpbin/headers | grep Authorization
```

```text
    "Authorization": "Bearer [iron-vault:scrubbed]",
```

httpbin received the stored key, not `placeholder`.

You may also use a **marker** naming the route's own credential, `{iv:<credential name>}`, which shows in the
application's configuration which credential it stands for. A marker naming another credential is refused:

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

The second is logged with `"reason":"foreign_marker"`. A marker never selects a credential; the route does. Outside
the slot a marker is plain text, passed on unchanged:

```sh
curl -s -H "$AUTH" 'http://127.0.0.1:7878/httpbin/anything/x?note=%7Biv:httpbin_key%7D' | grep -E 'note|Authorization'
```

```text
    "note": "{iv:httpbin_key}"
    "Authorization": "Bearer [iron-vault:scrubbed]",
```

### 3. Send the caller token

Every request needs the caller's token, in one of two places:

- **`Proxy-Authorization: Bearer <token>`**, the default. Iron Vault strips it before forwarding.
- **A header of the listener's choosing**, for an application that can add a custom header but not
  `Proxy-Authorization`. Name it on the listener with `token_header`; the token goes in it bare, with no `Bearer`.

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

`token_header` is set per listener and a caller arrives on exactly one, so the application gets a listener of its own
on another port. Approve it:

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

On a listener with `token_header`, only that header carries the token, and the token header never reaches httpbin.

### 4. Check that a client supports base-URL mode

Don't assume an application uses the base URL for every request. Before you rely on it:

1. Give it a route whose upstream echoes requests, as httpbin does, or watch the log while you use it.
2. Use every feature you need. Each request through Iron Vault ends in one `request.completed` record naming your
   caller and route:

   ```sh
   jq -c 'select(.event == "request.completed") | {caller, route, http_method, status, outcome, reason}' ~/iron-vault-dev.log
   ```

3. Look for what is missing. A feature that works but leaves no record went somewhere else, with whatever key the
   application had. With a placeholder key it fails instead, which is what you want.
4. Look for `no_route` and `path_not_allowed` refusals: the application calls paths you haven't allowed, or dropped
   the prefix.

### 5. Don't rely on `HTTPS_PROXY`

Setting `HTTPS_PROXY` does not make Iron Vault inject credentials. An HTTPS proxy client opens a `CONNECT` tunnel,
and Iron Vault refuses it:

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

The body is `CONNECT is not supported`, and the log reason is `connect_not_supported`. Iron Vault must see the
request to add the credential, and a tunnel hides it. Setting `HTTPS_PROXY` alone does not enable credential
injection in base-URL mode. Integrations with `gh`, `npm` and `cargo` need end-to-end compatibility checks before
anyone claims they work.

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
