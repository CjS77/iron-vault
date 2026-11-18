# Two keys, two callers, different permissions

*Checked with `iron-vault 0.2.0-alpha (features: dev-mode)`, built from `main` at `cc59b80`.*

Give two Venice API keys one job each, each used by its own caller:

| Credential    | Caller | Route         | Allows                                                        |
|---------------|--------|---------------|---------------------------------------------------------------|
| `venice_chat` | `chat` | `venice-chat` | `POST` to chat completions only, at most 6 requests a minute  |
| `venice_dev`  | `dev`  | `venice-dev`  | `GET` or `POST` anywhere under `/api/v1`, up to 600 a minute  |

The output below was captured with a dummy Venice key in place of each `pass show`, so forwarded chat requests show
Venice's `401`. With real keys they get answers.

## Prerequisites

- The service running and Ready, with the loopback listener from [getting started](getting-started.md). This recipe
  adds to that recipe's `dev-config.toml`.
- Two Venice API keys.

## Steps

### 1. Store both keys

```sh
pass show venice-chat | iron-vault add venice_chat --origin api.venice.ai
pass show venice-dev  | iron-vault add venice_dev  --origin api.venice.ai
```

```text
added venice_chat (static) as record 6e15ff12-…
added venice_dev (static) as record 850eba14-…
```

### 2. Issue a token for each caller

Each command prints its own `token_hash` line, so keep them apart:

```sh
iron-vault caller-token > ~/.iron-vault-tokens/chat 2> chat.hash
iron-vault caller-token > ~/.iron-vault-tokens/dev  2> dev.hash
head -1 chat.hash dev.hash
```

```text
==> chat.hash <==
token_hash = "blake2b:…"

==> dev.hash <==
token_hash = "blake2b:…"
```

The hash files hold no secret; delete them once the config holds the hashes.

### 3. Add the callers and routes

`config approve` replaces the whole config, so add these tables to `dev-config.toml` and keep what is there:

```toml
[callers.chat]
listener = "loopback"
token_hash = "blake2b:<chat's hash>"
routes = ["venice-chat"]

[callers.dev]
listener = "loopback"
token_hash = "blake2b:<dev's hash>"
routes = ["venice-dev"]

[routes.venice-chat]
prefix = "/venice-chat"
upstream = "https://api.venice.ai/api/v1"
credential = "venice_chat"
slot = { header = "Authorization", format = "Bearer {}" }
methods = ["POST"]
paths = ["/chat/completions"]
rate_limit = { requests = 6, per_seconds = 60, burst = 6 }

[routes.venice-dev]
prefix = "/venice-dev"
upstream = "https://api.venice.ai/api/v1"
credential = "venice_dev"
slot = { header = "Authorization", format = "Bearer {}" }
methods = ["GET", "POST"]
paths = ["/**"]
rate_limit = { requests = 600, per_seconds = 60, burst = 100 }
```

`chat` reaches only the routes it lists. `paths` leave out the upstream's base path, so `/chat/completions`, not
`/api/v1/chat/completions`. The chat route allows 6 at once, then one every 10 seconds. See
[configuration](../reference/configuration.md) for path patterns and rate limits.

Approve it:

```sh
iron-vault config approve dev-config.toml
```

```text
Approval summary
vault: 4b3faa85-…
version to commit: 4
config digest: blake2b:731e570b…
committed version: 3
callers:
  + chat: listener loopback, auth token, rate limits none
  + dev: listener loopback, auth token, rate limits none
route grants:
  + chat: granted venice-chat
  + dev: granted venice-dev
routes:
  + venice-chat: prefix /venice-chat, upstream https://api.venice.ai/api/v1, credential venice_chat, slot header Authorization format "Bearer {}", ca file none, methods POST, paths /chat/completions, rate limit 6 per 60s burst 6, confirm none
  + venice-dev: prefix /venice-dev, upstream https://api.venice.ai/api/v1, credential venice_dev, slot header Authorization format "Bearer {}", ca file none, methods GET, POST, paths /**, rate limit 600 per 60s burst 100, confirm none
Approve this config as version 4? Type yes to approve: yes
Approval passphrase for "approval passphrase":
approved version 4 (blake2b:731e570b…)
callers: 2 added; route grants: 2 added; routes: 2 added; listeners: none; limits: none; logging: none; recovery: none
```

### 4. Use each caller for its job

```sh
CHAT="Proxy-Authorization: Bearer $(cat ~/.iron-vault-tokens/chat)"
DEV="Proxy-Authorization: Bearer $(cat ~/.iron-vault-tokens/dev)"
```

Chat with the `chat` token:

```sh
curl -s -H "$CHAT" -H 'Content-Type: application/json' \
  http://127.0.0.1:7878/venice-chat/chat/completions \
  -d '{"model": "google-gemma-3-27b-it", "messages": [{"role": "user", "content": "hi"}]}'
```

With a dummy key, Venice answers `401` with `{"error":"Authentication failed"}`. With a real key you get the
completion.

List models with the `dev` token:

```sh
curl -s -H "$DEV" http://127.0.0.1:7878/venice-dev/models | head -c 120
```

```text
{"data":[{"context_length":1000000,"created":1791849600,"id":"gemini-4-argon","model_spec":{"pricing":{"input":{"usd":2.5,
```

### 5. Check what `chat` may not do

```sh
# GET is not an allowed method on chat's route
curl -si -H "$CHAT" http://127.0.0.1:7878/venice-chat/models
# chat's caller is not granted dev's route
curl -si -H "$CHAT" http://127.0.0.1:7878/venice-dev/models
```

Both answer the same way, before anything leaves the machine:

```text
HTTP/1.1 403 Forbidden
content-type: text/plain; charset=utf-8
content-length: 9

forbidden
```

The log says why (fields trimmed):

```json
{"caller":"chat","route":"venice-chat","http_method":"GET","status":403,"outcome":"failure","reason":"method_not_allowed"}
{"caller":"chat","route":"venice-dev","http_method":"GET","status":403,"outcome":"failure","reason":"not_granted"}
```

### 6. Check the rate limit

The route's bucket [starts empty](../reference/configuration.md#rate_limit-the-token-bucket), so wait a minute for it to
fill, then send seven requests at once:

```sh
sleep 60
for i in 1 2 3 4 5 6 7; do
  curl -s -o /dev/null -w '%{http_code}\n' \
    -H "$CHAT" -H 'Content-Type: application/json' \
    http://127.0.0.1:7878/venice-chat/chat/completions \
    -d '{"model": "google-gemma-3-27b-it", "messages": [{"role": "user", "content": "hi"}]}' &
done
wait
```

```text
429
401
401
401
401
401
401
```

Six reach Venice (`401` with a dummy key); the seventh gets `429` without leaving the machine, often first. Its log
record has `"reason":"rate_limited"`.

## What can go wrong

- **All seven requests get `429`.** The bucket was not full: it
  [starts empty](../reference/configuration.md#rate_limit-the-token-bucket). Wait the full minute.
- **`401 Unauthorized` from Iron Vault, `unauthorized` in the body.** The token is missing, wrong, or was replaced
  by a newer approval (`reason`: `unauthenticated`).
- **`iron-vault: the service answered error 7 (config-invalid): the proposed config is invalid: caller chat is
  granted route venice-admin, which is not defined`.** A caller's `routes` names a route the config does not define.
  Add the route or take it out of the list.
- **`403` with `path_not_allowed` on the chat route.** `paths` leave out the upstream's base path: `/chat/completions`,
  not `/api/v1/chat/completions`.

## Reference

- [Configuration](../reference/configuration.md): callers, routes, path patterns and rate limits.
- [Audit log](../reference/audit-log.md): `request.completed` and its `reason` values.
- [Errors](../reference/errors.md).
- Related: [rotate or revoke a caller token](caller-token.md), [widen or narrow a route](change-route.md).
