# Iron Vault

A small local proxy that holds API credentials so the programs that use them never do.

Point an application's base URL at Iron Vault and give it a placeholder instead of a provider key. Iron Vault
authenticates the caller, checks its route, adds the credential, and forwards the request over verified TLS.
The application holds at most a local caller token that grants specific routes; it never needs the provider secret.

**Status:** v0 in progress, Linux only. The proxy works end to end in [development mode](#development-mode): you
can create a vault, store credentials, approve a config and send requests through it. The Debian package for a
[protected Linux installation](#protected-installation-linux) is built from this repository, but it has not had a release
check on a real machine yet, so don't rely on it to protect real secrets. The
[product specification](design/iron-vault-specification.md) defines the requirements, roadmap, threat mitigations, and
release checks.

## Features

Done in v0:

- **Credential injection:** static API keys and Basic authentication, placed in a header or query parameter that the
  route names.
- **Restricted routes:** callers authenticate by Unix peer account, caller token, or isolated-network listener. Each
  route is limited by credential, HTTP method, path and request rate. Permitted destinations are stored with the
  encrypted credential, so a route edit cannot send an existing secret to another host.
- **Listeners:** Unix sockets and TCP. A non-loopback TCP listener requires TLS, and a protected install takes TCP
  sockets from systemd socket activation.
- **Outbound requests:** HTTPS only, with verified TLS. Upstream redirects are never followed with credentials attached.
- **Encrypted storage:** credential records are encrypted with `age` and unlocked with an interactive passphrase.
  `init` creates an offline recovery key.
- **Versioned configuration approval:** each config change is signed and checked against a strictly increasing
  approval version. Old config/signature pairs are rejected after a newer approval, and an approved config takes
  effect without a restart.
- **Credential commands:** `add`, `replace`, `rm` and `list`; `replace` and `rm` need the approval passphrase.
- **Response scrubbing:** removes the credential's known forms from response headers, compressed bodies and streamed
  responses.
- **Recovery key check:** `recovery check` proves the offline recovery key still opens the vault, in Locked or Ready, and
  records when.
- **Audit logging:** typed JSON records of request and administrative events, which never log secret values. See the
  [log operations guide](design/log-operations.md).

Still to come in v0:

- vault passphrase attempt limits;
- recipient add and remove, migration, and reset;
- TPM unlock and TPM approval signing;
- a Docker Compose profile;
- the v0 release acceptance suite.

Later phases add OAuth login and refresh, owner notifications, more credential kinds
(JWT, GitHub App, HMAC, AWS Signature Version 4), YubiKey recipients with PIN/touch policies, and macOS and Windows
services.

## Use cases

| Use case                        | What Iron Vault provides                                                                                                                                  |
|---------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| AI agents and MCP servers       | Use FX, Brave, Venice, and other configured APIs without real keys in agent-readable configuration or environment variables                               |
| Naomi back-office applications  | Share installation credentials through isolated routes; add Google consent and token refresh in the OAuth phase                                           |
| Shared Linux workstations       | Give each OS account only its own routes, recognised from the connecting account, with no keys in any home directory ([guide](design/multiuser-linux.md)) |
| Server and Compose applications | Keep credentials in one protected service while application containers receive only the proxy access they need                                            |
| Developer CLI tools             | Avoid provider credentials in application files where a tested base-URL integration supports the complete workflow                                        |

## Roadmap

| Phase       | Scope                                                                                                                                                                                                                                             |
|-------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| v0          | Base-URL proxy; static and Basic credentials; caller authentication; route restrictions and rate limits; encrypted storage; versioned approval; vault passphrase attempt limits; scrubbing; recovery and migration                                |
| v1          | Service-owned OAuth consent, account identity, access-token caching, and safe refresh-token rotation; owner notifications; request-content restrictions (allow-lists on query parameters and JSON body fields, such as the models a key may call) |
| Later       | YubiKey unlock/signing and per-request touch confirmation; additional credential kinds; password-manager sync                                                                                                                                     |
| Conditional | Forward-proxy interception if required callers cannot use base-URL mode                                                                                                                                                                           |

Integrations with `gh`, `npm`, and `cargo` require end-to-end compatibility checks. Setting `HTTPS_PROXY` alone does
not enable credential injection in base-URL mode. Routes that require touch must stay unavailable until a supported
confirmation provider exists.

## Security boundary

Iron Vault aims to prevent callers from extracting provider credentials. Malware that can read a caller's local
token can still use that caller's granted routes. Restrictions and rate limits bound that access; response
scrubbing reduces accidental disclosure but cannot recognize every transformed secret.

The host and runtime administrators remain trusted. Anyone who controls Iron Vault's Docker daemon can replace or
inspect it; TPM encryption does not protect secrets after the service unwraps them into memory. Protected deployments
must keep vault storage, unlock material, and deployment files outside ordinary callers' control. See the
[security requirements](design/iron-vault-specification.md#12-security-promise-and-limits) and
[deployment requirements](design/iron-vault-specification.md#314-docker-remote-servers-and-appliances).

## Protected installation (Linux)

On Linux the `.deb` package runs Iron Vault as the `iron-vault` system service, with its vault in `/var/lib/iron-vault`
out of reach of ordinary accounts:

```sh
cargo install cargo-deb --locked       # once; scripts/build-deb.sh then checks the package
cargo deb -p iron-vault --locked
sudo apt install ./target/debian/iron-vault_*.deb
sudo iron-vault init
sudo iron-vault unlock
```

The [installation guide](design/linux-install.md) covers what the protection depends on: `sudo` credential caching and a
second factor, encrypted swap and hibernation storage. It also covers adding a TCP listener, upgrading (the service
restarts Locked, so run `unlock` again), and uninstalling and purging (the vault is kept unless you say otherwise). The
[multi-user guide](design/multiuser-linux.md) shows a complete setup.

## Development mode

Development mode runs Iron Vault as your own user, with its files in your XDG directories. It is for trying Iron
Vault out and for development. It gives **no isolation from malware running as you**, and the service says so when
it starts and in `status`. It relaxes nothing else: callers still authenticate, routes are still checked, TLS is
still verified, responses are still scrubbed, the vault is still encrypted, and configs still need approval.

Development mode is compiled in only with the `dev-mode` Cargo feature, so a release build can't be switched into
it. It refuses to run as root.

This tutorial has two parts. First it sends requests to [httpbin.org](https://httpbin.org), which echoes back each
request it receives, so you can see the credential Iron Vault adds and see it scrubbed from the response. Then it
gives two [Venice.ai](https://venice.ai) API keys to two callers with different permissions. Steps 10 to 16 then try
the rest: reading the audit log, changing routes and callers, scrubbing and redirects, the limits on where a key can
go, replacing and removing keys, locking, and tamper detection. It needs Linux, a Rust toolchain, `curl` and `jq`. The
Venice parts also need two Venice API keys.

### 1. Build and install

```sh
cargo install --path crates/iron-vault --features dev-mode --root ~/.local/iron-vault-dev
export PATH="$HOME/.local/iron-vault-dev/bin:$PATH"
iron-vault --version    # iron-vault 0.2.0-alpha (features: dev-mode)
```

The service refuses to run a binary that another account could replace. The binary and every directory above it
must be owned by you or root, and none may be writable by group or others. A build inside a group-writable directory (such as `target/`
under a `0775` checkout) is refused with a message naming the directory. Installing under
`~/.local` usually avoids this.

### Harden the install

THe vault service won't start unless the executable chain is owner-only, so remove group write access to the vault chain:

```bash
$ chmod -R g-w ~/.local/iron-vault-dev
```

### Shell completion

Bash completion is generated from the same command definitions the CLI parses, and needs no running service:

```sh
mkdir -p ~/.local/share/bash-completion/completions
iron-vault completions bash > ~/.local/share/bash-completion/completions/iron-vault
```

or add `source <(iron-vault completions bash)` to `~/.bashrc`.

### 2. Start the service

Development mode keeps its files here:

| What         | Where                                                                    |
|--------------|--------------------------------------------------------------------------|
| Config       | `$XDG_CONFIG_HOME/iron-vault-dev/config.toml` (default `~/.config/...`)  |
| Vault        | `$XDG_STATE_HOME/iron-vault-dev/` (default `~/.local/state/...`)         |
| Log          | `$XDG_STATE_HOME/iron-vault-dev-log/`, unless you pass `--log-to-stdout` |
| Admin socket | `$XDG_RUNTIME_DIR/iron-vault-dev/admin.sock`                             |

`XDG_RUNTIME_DIR` must be set, as it is in a normal desktop or SSH login. A Unix socket path must be under 108
bytes, so keep these directories short.

In a terminal of its own, run:

```sh
iron-vault serve --log-to-stdout | tee -a ~/iron-vault-dev.log
```

The log is JSON, one record per line. `tee` keeps a copy for [step 10](#10-read-the-audit-log). Two complaints are
expected in development:

- the development-mode banner (WARN);
- `process hardening is incomplete` (ERROR), because memory can't be locked against swap unless you raised
  `RLIMIT_MEMLOCK`.

In a second terminal, check the service:

```sh
iron-vault ping      # the service is running: development profile, ...
iron-vault status    # service: locked / vault: not initialized (run iron-vault init)
```

Nothing is configured yet, so you should see something like this:

```
service: locked
profile: development — no isolation from malware running as alice
vault: not initialized (run iron-vault init)
vault id: unknown
approval committed: unknown while the vault is locked
approval highest reserved: unknown while the vault is locked
memory protection: NOT protected, swap protection unavailable (RLIMIT_MEMLOCK soft limit is 8315834368 bytes, not unlimited)
credentials: unknown while the vault is locked
```

### 3. Create the vault

```sh
iron-vault init
```

`init` asks for two passphrases, each twice:

- **Vault passphrase:** unlocks the vault each time the service starts.
- **Approval passphrase:** approves config changes and confirms `replace` and `rm`.

Each must be at least 12 characters, and the two must differ.

The service then shows the **recovery key** once. Save it somewhere offline, then type `yes`. `init` writes the vault
and approves an empty config as version 1, and the service stays Locked.

### 4. Unlock

```sh
$ iron-vault unlock    # prompts for the vault passphrase
$ iron-vault status    # service: ready

service: ready
profile: development — no isolation from malware running as alice
vault: unlocked
vault id: 2a682de7-b14d-4900-9ea9-0c968e1a6589
approval committed: 1
approval highest reserved: 1
memory protection: NOT protected, swap protection unavailable (RLIMIT_MEMLOCK soft limit is 8315834368 bytes, not unlimited)
credentials: none
```

Run `unlock` again each time you restart the service. `iron-vault lock` clears the secrets from memory.

#### Check the recovery key

Once the vault exists, prove that the offline recovery key you saved still opens it. The service asks for the key with
echo off, or reads it from stdin, and the check works whether the service is Locked or Ready:

```sh
iron-vault recovery check    # prompts for the recovery key
# the recovery key opens vault 2a682de7-b14d-4900-9ea9-0c968e1a6589: checked 2026-11-06T09:49:13Z
```

The check changes nothing in the vault. It records only the time, in `recovery.toml` beside the vault, and logs a
`recovery.checked` event that never holds the key. Run it again after you move the key to a new place.

### 5. Store a credential

`add` takes the credential's name and the origins it may ever be sent to. The secret is prompted for, never given as
an argument. httpbin doesn't check keys, so any value works:

```sh
iron-vault add httpbin_key --origin httpbin.org    # type any test value, e.g. not-a-real-key-123
iron-vault list                                    # httpbin_key  static  httpbin.org:443  healthy
```

For a real secret, pipe it in so it never reaches your shell history: `pass show brave | iron-vault add brave
--origin api.search.brave.com`.

### 6. Issue a caller token

In this tutorial, access control is by bearer token. Each caller gets its own caller token, and each token grants only
the routes that the config gives its caller. Keep the tokens in a directory only you can read:

```sh
mkdir -m 700 -p ~/.iron-vault-tokens
iron-vault caller-token > ~/.iron-vault-tokens/me
```

The token goes to the file. The line to put in the config, `token_hash = "blake2b:..."`, goes to the terminal. The
service keeps only the hash, so this is the only time the token is shown. Anyone who can read a token file can use its
routes, so the file's permissions are what restrict a token to your account.

**How this changes in a protected installation.** Development mode runs the service as your own account, and a caller
may never be the service's own account. So in development every caller needs a token. A protected installation runs
the service as the `iron-vault` system account, and then your account can be a caller identified by the kernel, with
no token file to steal:

```toml
[listeners.local]
unix_socket = "/run/iron-vault/proxy.sock"

[callers.dev]
listener = "local"
auth = "peer"
user = "alice"            # the account the calling process runs as
routes = ["venice-dev"]
```

The kernel reports the connecting process's account, so only processes running as `alice` get those routes. That
includes malware running as `alice`, but no other account's processes. A protected installation also takes the admin
socket away from your login account: you administer it with `sudo`.

### 7. Write and approve a config

Create a config file, `dev-config.toml`. It can live anywhere, because after approval, the service writes its own copy
and signature to `~/.config/iron-vault-dev/config.toml`. Don't edit that published copy by hand. The service treats a
change without approval as tampering (Step 16). Keep editing `dev-config.toml` and approve it after each change (Step 9 and 11).

Save this as `dev-config.toml`, with your `token_hash` line in place of the placeholder:

```toml
schema_version = 1

[listeners.loopback]
address = "127.0.0.1:7878"

[callers.me]
listener = "loopback"
token_hash = "blake2b:<the 64 hex digits caller-token printed>"
routes = ["httpbin"]

[routes.httpbin]
prefix = "/httpbin"
upstream = "https://httpbin.org"
credential = "httpbin_key"
slot = { header = "Authorization", format = "Bearer {}" }
methods = ["GET"]
paths = ["/anything/**", "/headers"]
rate_limit = { requests = 30, per_seconds = 60, burst = 5 }
```

Each part does this:

- **The listener** is plain HTTP on loopback. A TCP listener on any other address requires `tls_certificate` and
  `tls_key`.
- **The caller** `me` arrives on that listener with the token.
- **The route** maps `/httpbin/...` to `https://httpbin.org/...`. It puts the credential in the `Authorization` header
  and allows only `GET` on the listed paths, at no more than 30 requests a minute.

Then approve it:

```sh
iron-vault config approve dev-config.toml
```

The service shows its own summary of what changes, asks you to confirm, and asks for the approval passphrase. It then
commits the config as version 2, publishes it to the config path above, and starts the listener without a restart.

```
Approval summary
vault: 2a682de7-b14d-4900-9ea9-0c968e1a6589
version to commit: 2
config digest: blake2b:fb3cab486064ce8f6e556725607e2f096cdfe1c917d4e6c4c6e6d54f4736cba6
committed version: 1
callers:
  + me: listener loopback, auth token, rate limits none
route grants:
  + me: granted httpbin
routes:
  + httpbin: prefix /httpbin, upstream https://httpbin.org/, credential httpbin_key, slot header Authorization format "Bearer {}", ca file none, methods GET, paths /anything/**, /headers, rate limit 30 per 60s burst 5, confirm none
listeners:
  + loopback: endpoint tcp 127.0.0.1:7878, no tls, token header default
Approve this config as version 2? Type yes to approve: yes
Approval passphrase: *******
approved version 2 (blake2b:fb3cab486064ce8f6e556725607e2f096cdfe1c917d4e6c4c6e6d54f4736cba6)
callers: 1 added; route grants: 1 added; routes: 1 added; listeners: 1 added; limits: none; logging: none; recovery: none
```

### 8. Send requests

```sh
TOKEN=$(cat ~/.iron-vault-tokens/me)
curl -s -H "Proxy-Authorization: Bearer $TOKEN" http://127.0.0.1:7878/httpbin/headers
```

If everything is set up correctly, you'll see that **httpbin got the credential**, httpbin echoed it back, and the scrubber took it out
of the response before it reached you. Note that:

* The `Authorization` header httpbin received is in the echoed headers, as `Bearer ` followed by `[iron-vault:scrubbed]`.
* **Your token never reached httpbin:** the `Proxy-Authorization` header is missing from the echo, because Iron Vault strips it.

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

The corresponding log entries look like:

```json lines
{
  "service": "iron-vault",
  "service_version": "0.2.0-alpha",
  "schema_version": 1,
  "deployment_profile": "development",
  "timestamp": "2026-11-06T09:49:13.984094Z",
  "level": "INFO",
  "message": "request completed",
  "event": "request.completed",
  "request_id": "9f57ada0-323c-40a2-82ba-04fc999c559e",
  "listener": "loopback",
  "http_method": "GET",
  "caller": "me",
  "route": "httpbin",
  "credential": "httpbin_key",
  "upstream_host": "httpbin.org",
  "status": 200,
  "request_bytes": 0,
  "response_bytes": 199,
  "duration_ms": 308,
  "scrubbed": true,
  "outcome": "success",
  "target": "iron-vault.request"
}
{
  "service": "iron-vault",
  "service_version": "0.2.0-alpha",
  "schema_version": 1,
  "deployment_profile": "development",
  "timestamp": "2026-11-06T09:49:13.984112Z",
  "level": "WARN",
  "message": "scrubbed a secret from a response",
  "event": "response.scrubbed",
  "request_id": "9f57ada0-323c-40a2-82ba-04fc999c559e",
  "route": "httpbin",
  "credential": "httpbin_key",
  "matches": 1,
  "target": "iron-vault.audit"
}
```

Now try requests the policy refuses:

```sh
AUTH="Proxy-Authorization: Bearer $TOKEN"
curl -si http://127.0.0.1:7878/httpbin/headers | head -1                       # no token
curl -si -H "$AUTH" -X POST http://127.0.0.1:7878/httpbin/anything | head -1   # method not allowed
curl -si -H "$AUTH" http://127.0.0.1:7878/httpbin/ip | head -1                 # path not allowed
```

Each one is refused before anything leaves the machine. The service's terminal shows each request and refusal as an
audit record, with no secret, token or header value in it.

### 9. Two Venice keys for two callers

This part gives each Venice key one job, through its own caller:

| Credential    | Caller | Route         | Allows                                                       |
|---------------|--------|---------------|--------------------------------------------------------------|
| `venice_chat` | `chat` | `venice-chat` | `POST` to chat completions only, at most 6 requests a minute |
| `venice_dev`  | `dev`  | `venice-dev`  | `GET` or `POST` anywhere under `/api/v1`, up to 600 a minute |

Store both keys. Typing each at the prompt works, or pipe them from a password manager:

```sh
iron-vault add venice_chat --origin api.venice.ai
iron-vault add venice_dev  --origin api.venice.ai
```

Issue a token for each caller. Each command prints its own `token_hash` line, so note which hash belongs to which
caller:

```sh
iron-vault caller-token > ~/.iron-vault-tokens/chat
iron-vault caller-token > ~/.iron-vault-tokens/dev
```

`config approve` replaces the whole config, so add these tables to `dev-config.toml`, keeping the httpbin ones:

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
paths = ["/api/v1/chat/completions"]
rate_limit = { requests = 6, per_seconds = 60, burst = 6 }

[routes.venice-dev]
prefix = "/venice-dev"
upstream = "https://api.venice.ai/api/v1"
credential = "venice_dev"
slot = { header = "Authorization", format = "Bearer {}" }
methods = ["GET", "POST"]
paths = ["/api/v1/**"]
rate_limit = { requests = 600, per_seconds = 60, burst = 100 }
```

Points to note:

- **Paths include the upstream's base path.** Path patterns match the full path sent upstream. So
  `/venice-chat/chat/completions` becomes `/api/v1/chat/completions` at Venice, and that is what `paths` names.
- **Every route needs a rate limit.** A route that should be effectively unlimited gets a generous one.
- **The rate limit is a token bucket.** The bucket holds up to `burst` requests and refills at `requests` every
  `per_seconds`. The chat route can send 6 at once, then one every 10 seconds.

Approve it with `iron-vault config approve dev-config.toml`. The summary lists the new callers and routes, and the
config becomes version 3.

Chat with the `chat` token:

```sh
CHAT="Proxy-Authorization: Bearer $(cat ~/.iron-vault-tokens/chat)"
curl -s -H "$CHAT" -H 'Content-Type: application/json' \
  http://127.0.0.1:7878/venice-chat/chat/completions \
  -d '{"model": "google-gemma-3-27b-it", "messages": [{"role": "user", "content": "Say hello in portuguese, german and japanese."}]}'
```

It returns something like:

```json
{
  "service_tier": "default",
  "id": "chatcmpl-R34HfL17nNlchhUBz4xmMFbp",
  "object": "chat.completion",
  "created": 1793959965,
  "model": "google-gemma-3-27b-it",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "Olá! (Portuguese)\n\nHallo! (German)\n\nこんにちは！(Konnichiwa!) (Japanese)\n\nIs there anything specific you would like to discuss or any questions you have for me? I'm Google Gemma 3 27B Instruct, running on Venice.ai, and ready to assist.",
        "reasoning_content": null,
        "name": null,
        "tool_calls": []
      },
      "finish_reason": "stop",
      "logprobs": null
    }
  ],
  "usage": {
    "prompt_tokens": 1754,
    "completion_tokens": 59,
    "total_tokens": 1813
  },
  "cost": {
    "usd": 0,
    "diem": 0.00022228
  },
  "venice_parameters": {
    "strip_thinking_response": false,
    "disable_thinking": false,
    "enable_e2ee": true,
    "enable_web_search": "off",
    "enable_web_scraping": false,
    "enable_web_citations": false,
    "include_search_results_in_stream": false,
    "include_venice_system_prompt": true,
    "enable_x_search": false,
    "web_search_citations": [],
    "return_search_results_as_documents": false
  }
}
```

Use the `dev` token for anything else in the API, such as listing models:

```sh
DEV="Proxy-Authorization: Bearer $(cat ~/.iron-vault-tokens/dev)"
curl -s -H "$DEV" http://127.0.0.1:7878/venice-dev/models | head -c 400
```

You can verify that only the `dev` account can make this call:

```sh
# chat may not list models: GET is not an allowed method on its route
curl -si -H "$CHAT" http://127.0.0.1:7878/venice-chat/models
# chat may not use dev's route: its caller isn't granted it
curl -si -H "$CHAT" http://127.0.0.1:7878/venice-dev/models
# the rate limit: seven simultaneous chat requests (with &). The last should return immediately with 429
for i in 1 2 3 4 5 6 7; do
  curl -s -o /dev/null -w '%{http_code}\n' \
    -H "$CHAT" -H 'Content-Type: application/json' \
    http://127.0.0.1:7878/venice-chat/chat/completions \
    -d '{"model": "google-gemma-3-27b-it", "messages": [{"role": "user", "content": "hi"}]}' &
done
wait
```

### 10. Read the audit log

Every request ends in one `request.completed` record, and every admin command, approval and state change has its own
event. Records never hold a secret, a token or a header value. `jq` turns the log into answers:

```sh
LOG=~/iron-vault-dev.log

# one line per request: who asked, which route, and what happened
jq -c 'select(.event == "request.completed")
       | {caller, route, http_method, status, outcome, reason, scrubbed, duration_ms}' $LOG

# refusals, counted by reason: unauthenticated, method_not_allowed, rate_limited, ...
jq -r 'select(.event == "request.completed" and .outcome == "failure") | .reason' $LOG | sort | uniq -c

# the administrative trail: commands, credential changes and config approvals (the strings filter handles null values)
jq -c 'select(.event | strings | test("^(admin|credential|config|caller)\\."))
       | {timestamp, event, command, credential, version}' $LOG

# responses the scrubber had to clean, and how many matches it removed
jq -c 'select(.event == "response.scrubbed") | {request_id, route, credential, matches}' $LOG

# the test secret from step 5 never reaches the log: this prints 0
grep -c -F 'not-a-real-key-123' $LOG
```

Each record also carries `level`, `service_version` and `deployment_profile`. A `request_id` joins a
`response.scrubbed` record to its `request.completed` record.

### 11. Change routes and callers

A config change is always a new approval of the whole file. This step widens the httpbin route for the next step and
rotates the `me` caller's token.

Issue a new token for `me`, keeping the old one for a moment:

```sh
OLD="Proxy-Authorization: Bearer $(cat ~/.iron-vault-tokens/me)"
iron-vault caller-token > ~/.iron-vault-tokens/me.new
```

In `dev-config.toml`, put the new `token_hash` in `[callers.me]` and widen the httpbin route's paths:

```toml
paths = ["/anything/**", "/headers", "/gzip", "/stream/*", "/redirect-to"]
```

`*` matches exactly one path segment, and `**` any number. Approve it:

```sh
iron-vault config approve dev-config.toml
```

The summary shows the changed caller and route before you confirm, and the config becomes version 4. 

```text
Approval summary
vault: 2a682de7-b14d-4900-9ea9-0c968e1a6589
version to commit: 4
config digest: blake2b:d6e2499b5a240bded34e0806751f1f5c4722cb190d8f6e9519f1b5171b54e5b4
committed version: 3
callers:
  ~ me: token changed
routes:
  ~ httpbin: paths /anything/**, /headers -> /anything/**, /gzip, /headers, /redirect-to, /stream/*
Approve this config as version 4? Type yes to approve: yes
Approval passphrase:
approved version 4 (blake2b:d6e2499b5a240bded34e0806751f1f5c4722cb190d8f6e9519f1b5171b54e5b4)
callers: 1 changed; route grants: none; routes: 1 changed; listeners: none; limits: none; logging: none; recovery: none
```

The old token stopped working at that moment:

```sh
mv ~/.iron-vault-tokens/me.new ~/.iron-vault-tokens/me
AUTH="Proxy-Authorization: Bearer $(cat ~/.iron-vault-tokens/me)"
curl -si -H "$OLD"  http://127.0.0.1:7878/httpbin/headers | head -1   # 401
curl -si -H "$AUTH" http://127.0.0.1:7878/httpbin/headers | head -1   # 200
```

To revoke a caller instead, delete its table and approve. To remove a route, delete its table and take it out of
every caller's `routes`: a config that grants a route it doesn't define is refused.

### 12. Scrubbing and redirects

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

### 13. A route can't send a key to another host

The origins given to `add` are stored inside the encrypted credential record, and only `replace` can change them.
Approving a config can't. Try pointing the httpbin route somewhere else in `dev-config.toml`:

```toml
upstream = "https://postman-echo.com"
```

```sh
iron-vault config approve dev-config.toml
```

The service refuses before asking anything, with `config-invalid` and the reason:

```text
route httpbin sends credential httpbin_key to postman-echo.com:443, which its record does not permit
```

No version is used up, and the active config doesn't change. Put the upstream back to `https://httpbin.org`.

The same check guards `replace`. Replacing the key with a record that permits only another host is refused while a
route still sends it to httpbin:

```sh
iron-vault replace httpbin_key --origin postman-echo.com    # refused: credential-in-use
```

### 14. Replace and remove credentials

To rotate a key, `replace` it. It asks for the approval passphrase first, then the new secret; the old origins are
not kept, so name them again:

```sh
iron-vault replace httpbin_key --origin httpbin.org
iron-vault list
```

Requests on the route use the new key as soon as the command finishes, with no config change. While the service
switches over, requests get `503` with reason `checking`.

`rm` refuses to remove a credential that a route uses. Remove the route, approve, then remove the credential:

```sh
iron-vault rm httpbin_key    # refused: credential-in-use

iron-vault add scratch --origin example.com    # any value
iron-vault rm scratch                          # asks for the approval passphrase, then removes it
iron-vault list
```

Each change appears in the log as `credential.added`, `credential.replaced` or `credential.removed`, with the name,
kind and origins but never the secret.

### 15. Lock, unlock and restart

`lock` clears the vault identity and every secret from the service's memory:

```sh
iron-vault lock
iron-vault status                                                     # service: locked
curl -si -H "$AUTH" http://127.0.0.1:7878/httpbin/headers | head -1   # 503
```

The listener stays open, but every request is refused with `503` and reason `locked` until you run `iron-vault
unlock`. The log records each change of state as `service.lock-transition`, with `from_state` and `to_state`.

A restart is the same. Stop the service with Ctrl-C and start it again with the command from step 2. It opens its
listeners from the last published config and answers `503` until you unlock it. The secrets are never written
anywhere unencrypted, so nothing survives the restart but the encrypted vault.

### 16. Tamper detection

The service publishes the approved config as `config.toml` with its signature, `config.toml.sig`, beside it. On
SIGHUP it reloads the pair, and a config changed without approval is refused. Change the published config directly,
as an attacker who could write the file might:

```sh
CONFIG="${XDG_CONFIG_HOME:-$HOME/.config}/iron-vault-dev/config.toml"
sed -i 's/burst = 5 }/burst = 500 }/' "$CONFIG"
pkill -HUP -f 'iron-vault serve'

iron-vault status                                                     # service: unavailable / reason: policy invalid
curl -si -H "$AUTH" http://127.0.0.1:7878/httpbin/headers | head -1   # 503
jq -c 'select(.event == "config.reload-failed")' ~/iron-vault-dev.log
```

The service stops proxying rather than run a policy nobody approved. Approve a config to recover:

```sh
iron-vault config approve dev-config.toml    # version 5; the service is ready again
```

In a protected installation only the service account can write these files. Development mode keeps them in your own
config directory, which is why the attack is this easy to try.

### 17. Point a real application at it

Give the application `http://127.0.0.1:7878/<prefix>` as its base URL, with a placeholder where its API key goes.
Configure it to send the caller token, either in `Proxy-Authorization: Bearer <token>` or in a header the listener
names with `token_header = "X-Iron-Vault-Token"`. The route's `upstream`, `slot`, `methods` and `paths` must match what
the API expects. The [specification's example config](design/iron-vault-specification.md#33-credential-records-and-configuration)
shows routes for Brave Search (a header slot), Venice (a Bearer token) and an FX API (a query parameter).

### Starting over

Stop the service, then remove its files:

```sh
rm -rf "${XDG_CONFIG_HOME:-$HOME/.config}/iron-vault-dev" \
       "${XDG_STATE_HOME:-$HOME/.local/state}/iron-vault-dev" \
       "${XDG_STATE_HOME:-$HOME/.local/state}/iron-vault-dev-log" \
       ~/.iron-vault-tokens ~/iron-vault-dev.log
```

## How the vault is locked

Iron Vault encrypts with [`age`](https://age-encryption.org). You don't need to know any cryptography to follow
this section.

### One vault identity opens everything

Each vault has one secret key, its **vault identity**. Every stored credential is locked with it, along with the
vault's list of which credentials exist. When the service starts, it unlocks the vault identity once and keeps it in
memory. It never needs a key per credential.

### Several people or devices can unlock the vault identity

The vault identity lives in one file, `identity.age`. Think of that file as a safe with one copy of the vault
identity inside. Fixed to the outside of the safe are several small lockboxes, one for each **recipient**: this
machine, your offline recovery key, and later a TPM or YubiKey. Every lockbox holds the same thing, the combination to
the safe.

- Each lockbox opens only with its own recipient's private key.
- Any one recipient can open their lockbox, read the combination, open the safe and take out the vault identity.
- The recipients never share a secret with each other. Each has their own lockbox.
- A seal over all the lockboxes catches any damage to them, or a lockbox added, removed or swapped, when the safe is
  opened. The seal is made with the combination itself, so it doesn't stop someone who can already open a lockbox
  from building a new safe. That is why only the service may write the vault's files.

Adding or removing a recipient only rebuilds `identity.age` with a different set of lockboxes. The stored
credentials don't change.

Every vault has at least two recipients, so losing one device or forgetting one passphrase doesn't lose the vault.

### How a lockbox is locked for one recipient

Each recipient has a key pair: a public key that anyone may see, and a private key only they hold. To lock a
lockbox for a recipient, Iron Vault:

1. makes a brand-new, single-use key pair of its own;
2. combines its single-use private key with the recipient's public key to get a shared secret;
3. uses that shared secret to lock the combination inside the lockbox;
4. stores its single-use public key on the outside of the lockbox, then throws away the single-use private key.

To open the lockbox, the recipient combines their own private key with the single-use public key stored on it. The
maths gives them the same shared secret, which opens the lockbox. Nobody else can work it out from the public parts.

For readers who want the names: the key pairs are X25519, the shared secret goes through HKDF-SHA256, the
locking is ChaCha20-Poly1305, and the seal over the lockboxes is HMAC-SHA256.

### Unlocking with a passphrase

`age` won't put a passphrase lockbox on the same safe as key-pair lockboxes. So for passphrase unlock, Iron Vault
makes one extra key pair, the **operational identity**:

- its public half gets an ordinary lockbox on `identity.age`;
- its private half is kept in a separate file, `operational.age`, locked only by your passphrase.

Unlocking goes: passphrase → operational identity → vault identity.

### What this doesn't protect against

- **Removing a recipient doesn't reach old copies.** It only changes future versions of `identity.age`. A backup
  made earlier can still be opened with the removed key. If a machine is lost, rotate the provider credentials it
  could reach.
- **Encryption doesn't say who wrote a file.** Anyone with the vault's public key can create a file that looks like
  a stored credential. So the vault keeps its own list of which credential files are real, sealed with a code that
  only the holder of the vault identity can produce. A file missing from that list is never trusted.
