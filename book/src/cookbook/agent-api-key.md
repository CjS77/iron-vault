# Give an AI agent or MCP server an API key

*Checked with `iron-vault 0.2.0-alpha (features: dev-mode)`, built from `main`.*

At the end of this recipe an agent or MCP server can call Brave Search, Venice and an FX API through Iron Vault. Its
configuration holds a base URL, a placeholder key and a caller token, never a provider key. The three routes show the
three slot shapes:

| Provider     | Slot                                                         | The agent's base URL            |
|--------------|--------------------------------------------------------------|---------------------------------|
| Brave Search | a header: `X-Subscription-Token`                             | `http://127.0.0.1:7878/brave`   |
| Venice       | a header with a format: `Authorization: Bearer {}`           | `http://127.0.0.1:7878/venice`  |
| An FX API    | a query parameter: `access_key`                              | `http://127.0.0.1:7878/fx`      |

The routes are the ones in the [specification's example config](../../../design/iron-vault-specification.md#33-credential-records-and-configuration),
with one change: the spec's FX upstream, `api.fx.example`, is a placeholder that doesn't resolve, so this recipe uses
[exchangerate.host](https://exchangerate.host), which takes its key in an `access_key` query parameter.

**What was really run.** Every command below was run, but with dummy keys, because no real Brave, Venice or FX key was
at hand. So each request reached the real provider, carrying a dummy key, and the provider's real refusal is shown.
With a real key in the vault, the same request gets the provider's answer instead.

## Prerequisites

- The service running and Ready, with the loopback listener from
  [getting started](getting-started.md). This recipe adds to that recipe's `dev-config.toml`.
- A key for each provider you want. Each step stands alone, so skip a provider you don't use.

## Steps

### 1. Store the keys

Pipe each key in from your password manager, so it never reaches your shell history. Each `--origin` names the only
host its key may ever be sent to:

```sh
pass show brave  | iron-vault add brave  --origin api.search.brave.com
pass show venice | iron-vault add venice --origin api.venice.ai
pass show fx     | iron-vault add fx_key --origin api.exchangerate.host
iron-vault list
```

```text
added brave (static) as record 8a6c0dd9-…
added venice (static) as record 469b5ab8-…
added fx_key (static) as record c8653d1f-…
brave  static  api.search.brave.com:443  healthy
fx_key  static  api.exchangerate.host:443  healthy
httpbin_key  static  httpbin.org:443  healthy
venice  static  api.venice.ai:443  healthy
```

### 2. Issue the agent a caller token

```sh
iron-vault caller-token > ~/.iron-vault-tokens/agent
```

```text
token_hash = "blake2b:2c3b325980a405f812d41b70987be2f655dd5901800661867224821271ec6a02"
This token is shown once and the service keeps no copy of it.
…
```

### 3. Add the caller and routes

Add these tables to `dev-config.toml`, with your own `token_hash`:

```toml
[callers.agent]
listener = "loopback"
token_hash = "blake2b:<the agent's hash>"
routes = ["brave", "venice", "fx"]

[routes.brave]
prefix = "/brave"
upstream = "https://api.search.brave.com"
credential = "brave"
slot = { header = "X-Subscription-Token" }
methods = ["GET"]
paths = ["/res/v1/web/search"]
rate_limit = { requests = 60, per_seconds = 60, burst = 10 }

[routes.venice]
prefix = "/venice"
upstream = "https://api.venice.ai/api/v1"
credential = "venice"
slot = { header = "Authorization", format = "Bearer {}" }
methods = ["POST"]
paths = ["/api/v1/chat/completions"]
rate_limit = { requests = 120, per_seconds = 60, burst = 20 }

[routes.fx]
prefix = "/fx"
upstream = "https://api.exchangerate.host"
credential = "fx_key"
slot = { query = "access_key" }
methods = ["GET"]
paths = ["/live", "/historical"]
rate_limit = { requests = 60, per_seconds = 60, burst = 10 }
```

- A header slot with no `format` sends the key as the whole header value.
- `paths` match the path sent upstream, including the upstream's base path. The Venice upstream ends in `/api/v1`, so
  the agent's `/venice/chat/completions` reaches Venice as `/api/v1/chat/completions`, and that is what `paths` names.
- Each route allows only the methods and paths the agent needs. Widen them when it needs more.

Approve it:

```sh
iron-vault config approve dev-config.toml
```

```text
Approval summary
vault: 4b3faa85-…
version to commit: 3
config digest: blake2b:ce35d419…
committed version: 2
callers:
  + agent: listener loopback, auth token, rate limits none
route grants:
  + agent: granted brave, fx, venice
routes:
  + brave: prefix /brave, upstream https://api.search.brave.com/, credential brave, slot header X-Subscription-Token format "{}", ca file none, methods GET, paths /res/v1/web/search, rate limit 60 per 60s burst 10, confirm none
  + fx: prefix /fx, upstream https://api.exchangerate.host/, credential fx_key, slot query access_key, ca file none, methods GET, paths /historical, /live, rate limit 60 per 60s burst 10, confirm none
  + venice: prefix /venice, upstream https://api.venice.ai/api/v1, credential venice, slot header Authorization format "Bearer {}", ca file none, methods POST, paths /api/v1/chat/completions, rate limit 120 per 60s burst 20, confirm none
Approve this config as version 3? Type yes to approve: yes
Approval passphrase:
approved version 3 (blake2b:ce35d419…)
callers: 1 added; route grants: 1 added; routes: 3 added; listeners: none; limits: none; logging: none; recovery: none
```

### 4. Try each route

```sh
AG="Proxy-Authorization: Bearer $(cat ~/.iron-vault-tokens/agent)"
```

**Brave Search.** The agent sends no `X-Subscription-Token`; Iron Vault adds it.

```sh
curl -s -H "$AG" -H 'Accept: application/json' 'http://127.0.0.1:7878/brave/res/v1/web/search?q=iron+vault'
```

With a dummy key, Brave answers:

```json
{"error":{"code":"SUBSCRIPTION_TOKEN_INVALID","detail":"The provided subscription token is invalid.","meta":{"component":"authentication"},"status":422},"type":"ErrorResponse"}
```

**Venice.**

```sh
curl -s -H "$AG" -H 'Content-Type: application/json' http://127.0.0.1:7878/venice/chat/completions \
  -d '{"model": "google-gemma-3-27b-it", "messages": [{"role": "user", "content": "hi"}]}'
```

With a dummy key, Venice answers `401 Unauthorized` with:

```json
{"error":"Authentication failed"}
```

**FX.** Iron Vault appends `access_key=<key>` to the query and removes any `access_key` the agent sent.

```sh
curl -s -H "$AG" 'http://127.0.0.1:7878/fx/live?source=USD&currencies=EUR'
```

With a dummy key, exchangerate.host answers `401 Unauthorized` with:

```json
{
  "success": false,
  "error": {
    "code": 101,
    "type": "invalid_access_key",
    "info": "You have not supplied a valid API Access Key. [Technical Support: support@apilayer.com]"
  }
}
```

Each of these answers came from the provider, so each request left Iron Vault with a key in its slot. The log agrees
(fields trimmed):

```json
{"event":"request.completed","caller":"agent","route":"brave","status":422,"outcome":"success"}
{"event":"request.completed","caller":"agent","route":"venice","status":401,"outcome":"success"}
{"event":"request.completed","caller":"agent","route":"fx","status":401,"outcome":"success"}
```

`outcome` is about Iron Vault's part: `success` means it forwarded the request and relayed the answer, whatever status
the provider chose.

### 5. Configure the agent

Give the agent three things:

- **Base URL:** the route's prefix on the listener, from the table at the top. The agent appends its usual API path.
  For Venice, an OpenAI-compatible client sets its base URL to `http://127.0.0.1:7878/venice`.
- **API key:** any placeholder, such as `placeholder`. Many SDKs refuse to start without a key. Iron Vault removes
  every copy of the slot's header or query parameter and writes the real one.
- **Caller token:** sent as `Proxy-Authorization: Bearer <token>` on every request. If the agent can only add a header
  with a fixed name, see [point a real application at Iron Vault](real-application.md#send-the-caller-token).

The client settings above were not tried with a particular agent or MCP server; the `curl` requests in step 4 were.
Before relying on an agent, check that it really uses the base URL for every request, as
[point a real application at Iron Vault](real-application.md#check-that-a-client-supports-base-url-mode) describes.

In a [protected install](../installation/linux-install.md), run the agent as its own OS account and make it a peer
caller on the Unix socket. The kernel then identifies it, and there is no token file to steal:

```toml
[callers.fx-mcp]
listener = "local"
auth = "peer"
user = "fx-mcp"
routes = ["fx"]
```

## What can go wrong

- **`error 7 (config-invalid): the proposed config is invalid: route fx sends credential fx_key to an origin its
  record does not permit`.** The route's upstream is not one of the credential's origins; this is what the spec's
  `https://api.fx.example` upstream gets against a key added for `api.exchangerate.host`. Fix the upstream, or
  `replace` the credential with the right `--origin`. No version is used up.
- **`403 Forbidden` from Iron Vault.** The method or path is not in the route. The log's `reason` says which:
  `method_not_allowed` or `path_not_allowed`. Remember that `paths` include the upstream's base path.
- **`401` or `422` from the provider.** The request reached the provider with the stored key, and the provider refused
  it. Check the key, or `replace` it.
- **`400 Bad Request` with `foreign_marker` in the log.** The agent sent a marker such as `{iv:brave}` in a route
  whose credential is another one.
- **`429 Too Many Requests` right after an approval.** Every approval starts each route's token bucket empty; wait a
  few seconds.

## Reference

- [Configuration](../reference/configuration.md): slots, `format`, path patterns and rate limits.
- [CLI](../reference/cli.md): `add`, `list` and `caller-token`.
- [Audit log](../reference/audit-log.md): `request.completed` and its `reason` values.
- [Errors](../reference/errors.md).
