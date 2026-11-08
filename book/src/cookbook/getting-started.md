# Getting started in development mode

*Checked with `iron-vault 0.2.0-alpha (features: dev-mode)`, built from `main` at `cc59b80`.*

At the end of this recipe you will have Iron Vault running as your own user, with a vault, one stored credential and
one route to [httpbin.org](https://httpbin.org). You will send a request through it, see that httpbin received the
credential, and see the credential scrubbed from the echo before it reached you.

Development mode gives **no isolation from malware running as you**. Use it to learn Iron Vault, never to protect
real secrets. For that, use the [protected Linux install](../installation/linux-install.md).

## Prerequisites

- Linux, with `XDG_RUNTIME_DIR` set, as it is in a normal desktop or SSH login.
- A Rust toolchain, `curl` and network access to `httpbin.org`.
- About 15 minutes.

## Steps

### 1. Build and install

```sh
cargo install --path crates/iron-vault --features dev-mode --root ~/.local/iron-vault-dev
chmod -R go-w ~/.local/iron-vault-dev
export PATH="$HOME/.local/iron-vault-dev/bin:$PATH"
iron-vault --version
```

```text
iron-vault 0.2.0-alpha (features: dev-mode)
```

The service refuses to run a binary that another account could replace, so the binary and every directory above it
must be owned by you or root and not writable by group or others. That is what the `chmod` is for.

### 2. Start the service

In a terminal of its own:

```sh
iron-vault serve --log-to-stdout | tee -a ~/iron-vault-dev.log
```

The log is JSON, one record per line. Three of the first records are expected in development mode: `service started`,
`process hardening is incomplete` (ERROR, because memory can't be locked against swap unless you raised
`RLIMIT_MEMLOCK`) and the development-mode warning:

```json
{"service":"iron-vault","service_version":"0.2.0-alpha","schema_version":1,"deployment_profile":"development","level":"WARN","message":"development mode: no isolation from malware running as alice","target":"iron_vault"}
```

In a second terminal, check the service:

```sh
iron-vault ping
iron-vault status
```

```text
the service is running: development profile, admin protocol version 1
service: locked
profile: development — no isolation from malware running as alice
vault: not initialized (run iron-vault init)
vault id: unknown
approval committed: unknown while the vault is locked
approval highest reserved: unknown while the vault is locked
memory protection: NOT protected, swap protection unavailable (RLIMIT_MEMLOCK soft limit is 8315834368 bytes, not unlimited)
recovery last checked: unknown (the vault is not initialized)
credentials: unknown while the vault is locked
```

`status` exits with 4 while the service is not Ready. That is expected here.

### 3. Create the vault

```sh
iron-vault init
```

`init` asks for two passphrases, each twice. Each must be at least 12 characters, and the two must differ:

- the **vault passphrase** unlocks the vault each time the service starts;
- the **approval passphrase** approves config changes and confirms `replace` and `rm`.

It then shows the **recovery key** once, as text and as a QR code. Save it somewhere offline, then type `yes`:

```text
Vault passphrase:
Repeat the vault passphrase:
Approval passphrase:
Repeat the approval passphrase:
The recovery key follows. It is shown this once, and the service keeps no copy.
It is the second way into the vault if the vault passphrase or this machine is lost.
Store it in an independent password manager or on paper, never beside the vault.
You may also keep it in a passphrase-encrypted file of your own.
AGE-SECRET-KEY-1…
(QR code)
Type yes once you have saved the recovery key: yes
initialized vault 4b3faa85-…: approval version 1 committed
run iron-vault unlock to start serving
```

`init` refuses to run without a controlling terminal, because it shows the recovery key there. With one, the
passphrases may also be piped in on stdin, one per line. The service stays Locked.

### 4. Unlock

```sh
iron-vault unlock
```

```text
Vault passphrase:
the vault is unlocked: the service is Ready
```

```sh
iron-vault status
```

```text
service: ready
profile: development — no isolation from malware running as alice
vault: unlocked
vault id: 4b3faa85-…
approval committed: 1
approval highest reserved: 1
memory protection: NOT protected, swap protection unavailable (RLIMIT_MEMLOCK soft limit is 8315834368 bytes, not unlimited)
recovery last checked: never (reminders counting since 2026-11-07)
credentials: none
```

Run `unlock` again each time you restart the service.

### 5. Check the recovery key

Prove that the key you saved opens the vault. The service asks for it with echo off, or reads it from stdin:

```sh
iron-vault recovery check
```

```text
Recovery key:
the recovery key opens vault 4b3faa85-…: checked 2026-11-07T09:43:48Z
```

The check changes nothing in the vault. It records only the time, which `status` then shows under
`recovery last checked`.

### 6. List the recipients and rotate the recovery key

The vault's identity is wrapped for each recipient: your vault passphrase and the recovery key. `recipient list`
shows them:

```sh
iron-vault recipient list
```

```text
age10dvnun…  operational  2026-11-08T14:54:27Z  vault passphrase
age1vhncy4…  recovery     2026-11-08T14:54:27Z  recovery key
```

To replace the recovery key, have the service generate a new one. It shows the key once, like `init`; save it, type
`yes`, then authorize with the vault passphrase:

```sh
iron-vault recipient add --recovery --label "recovery key 2026"
```

```text
add a new recovery key to the vault
  vault: 4b3faa85-…
  recipient: age1lvqkl6…
  role: recovery
  label: recovery key 2026
  recipients after the change: 3 (operational 1, recovery 2)
  next: the new recovery key is shown once; save it, then type yes
  authorize with: the vault passphrase
The recovery key follows. It is shown this once, and the service keeps no copy.
…
AGE-SECRET-KEY-1…
…
Type yes once you have saved the recovery key: yes
Vault passphrase:
enrolled age1lvqkl6… as recovery; the vault has 3 recipients.
Removing a recipient protects future copies of identity.age only.
Old copies of identity.age, and backups, still open with a removed key.
If a machine was lost, rotate the provider credentials it could reach.
Check the new key with iron-vault recovery check, then remove the old recovery key with iron-vault recipient remove.
```

Check the new key as in step 5, then remove the old one by the `age1…` key that `recipient list` printed for it. The
service asks for the approval passphrase:

```sh
iron-vault recipient remove age1vhncy4…
```

```text
remove a recipient from the vault
  vault: 4b3faa85-…
  recipient: age1vhncy4…
  role: recovery
  label: recovery key
  enrolled: 2026-11-08T14:54:27Z
  recipients after the change: 2 (operational 1, recovery 1)
  removing a recipient protects future copies of identity.age only; copies made before still open with this key
  authorize with: the approval passphrase
Approval passphrase:
removed age1vhncy4…; the vault has 2 recipients.
Removing a recipient protects future copies of identity.age only.
Old copies of identity.age, and backups, still open with a removed key.
If a machine was lost, rotate the provider credentials it could reach.
Check the recovery key you keep with iron-vault recovery check.
```

The old key now fails `recovery check` with `the recovery key does not open this vault`. Removal does not revoke
copies of `identity.age` or backups made before it: anyone holding one and the old key can still open it. If the old key
or a machine was lost, rotate the provider credentials too.

### 7. Store a credential

`add` takes the credential's name and the origins it may ever be sent to. It prompts for the secret; no argument ever
takes one. httpbin checks no keys, so use a test value such as `not-a-real-key-123`:

```sh
iron-vault add httpbin_key --origin httpbin.org
iron-vault list
```

```text
Secret for httpbin_key:
added httpbin_key (static) as record 531d79af-…
httpbin_key  static  httpbin.org:443  healthy
```

For a real secret, pipe it in so it never reaches your shell history: `pass show brave | iron-vault add brave
--origin api.search.brave.com`.

### 8. Issue a caller token

A TCP caller proves who it is with a caller token. Keep tokens in a directory only you can read:

```sh
mkdir -m 700 -p ~/.iron-vault-tokens
iron-vault caller-token > ~/.iron-vault-tokens/me
```

The token goes to the file. The terminal shows the line the config needs:

```text
token_hash = "blake2b:…"
This token is shown once and the service keeps no copy of it.
Put the token_hash line on the caller's [callers.<name>] table and run `iron-vault config approve <file>`.
The token works only once that config is approved and active; the caller's old token, if any, keeps working until then.
```

Anyone who can read the token file can use its routes.

### 9. Write and approve a config

Save this as `dev-config.toml`, anywhere you like, with your own `token_hash` line:

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

- The **listener** is plain HTTP on loopback.
- The **caller** `me` arrives on that listener and presents the token.
- The **route** maps `/httpbin/...` to `https://httpbin.org/...`, puts the credential in `Authorization`, and allows
  only `GET` on the listed paths, at no more than 30 requests a minute.

Approve it:

```sh
iron-vault config approve dev-config.toml
```

```text
Approval summary
vault: 4b3faa85-…
version to commit: 2
config digest: blake2b:f08dc490…
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
Approval passphrase:
approved version 2 (blake2b:f08dc490…)
callers: 1 added; route grants: 1 added; routes: 1 added; listeners: 1 added; limits: none; logging: none; recovery: none
```

The service publishes its own signed copy of the config to `~/.config/iron-vault-dev/config.toml` and opens the
listener without a restart. Keep editing `dev-config.toml`, never the published copy.

### 10. Send a request

```sh
TOKEN=$(cat ~/.iron-vault-tokens/me)
curl -s -H "Proxy-Authorization: Bearer $TOKEN" http://127.0.0.1:7878/httpbin/headers
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

httpbin received `Authorization: Bearer not-a-real-key-123` and echoed it back. Iron Vault replaced the secret with
`[iron-vault:scrubbed]` before the response reached you. Your caller token never reached httpbin: there is no
`Proxy-Authorization` in the echo.

The service's terminal shows the request and the scrub, trimmed here to the useful fields:

```json
{"level":"INFO","message":"request completed","event":"request.completed","listener":"loopback","http_method":"GET","caller":"me","route":"httpbin","credential":"httpbin_key","upstream_host":"httpbin.org","status":200,"request_bytes":0,"response_bytes":199,"duration_ms":308,"scrubbed":true,"outcome":"success","target":"iron-vault.request"}
{"level":"WARN","message":"scrubbed a secret from a response","event":"response.scrubbed","route":"httpbin","credential":"httpbin_key","matches":1,"target":"iron-vault.audit"}
```

### 11. See the policy refuse

```sh
AUTH="Proxy-Authorization: Bearer $TOKEN"
curl -si http://127.0.0.1:7878/httpbin/headers                          # no token
curl -si -H "$AUTH" -X POST http://127.0.0.1:7878/httpbin/anything      # method not allowed
curl -si -H "$AUTH" http://127.0.0.1:7878/httpbin/ip                    # path not allowed
```

```text
HTTP/1.1 401 Unauthorized
content-type: text/plain; charset=utf-8
content-length: 12

unauthorized
HTTP/1.1 403 Forbidden
content-type: text/plain; charset=utf-8
content-length: 9

forbidden
HTTP/1.1 403 Forbidden
content-type: text/plain; charset=utf-8
content-length: 9

forbidden
```

Each one is refused before anything leaves the machine. The response says only `unauthorized` or `forbidden`; the
log says why, in the `reason` field: `unauthenticated`, `method_not_allowed` and `path_not_allowed`.

## Rate limits start empty

Each route's token bucket starts **empty** every time the service becomes Ready: when you unlock, after each
`config approve`, after a reload on SIGHUP, and after `replace` or `rm`. (`add` doesn't reset it.) The bucket then
refills at `requests / per_seconds` up to `burst`. The `httpbin` route above refills at one request every 2 seconds, so
straight after an approval its first request may get `429 Too Many Requests`, and its full burst of 5 is there after
10 seconds. This stops a restart or a reload from handing out a fresh allowance.

## What can go wrong

- **``iron-vault: refusing to start: /home/alice/projects/iron-vault/target/debug/iron-vault is not trusted:
  /home/alice/projects is writable by group 1001; run `chmod g-w /home/alice/projects` ``.** The binary, or a directory above it, could be replaced by
  another account. A build run straight from `target/` in a group-writable checkout gets this. Install under
  `~/.local` and run the `chmod` in step 1. A group with a name is shown quoted, as in `group 'alice'`.
- **`iron-vault: refusing to start: … is not trusted: /tmp is a shared directory other users can write; move the state
  directory, config, TLS key or certificate out of /tmp rather than changing its permissions`.** `XDG_CONFIG_HOME` or
  `XDG_STATE_HOME` points under `/tmp`. Use directories in your home.
- **`iron-vault: the Iron Vault service is not running: there is no admin socket at …`.** The service is not running,
  or it was started with a different `XDG_RUNTIME_DIR`.
- **`iron-vault: the service answered error 14 (unlock-denied): wrong passphrase`.** After 5 wrong vault passphrases,
  `unlock` is refused for a cooldown that starts at 30 s and doubles up to 15 min.
- **``iron-vault: the service answered error 20 (name-taken): credential httpbin_key already exists, healthy or
  damaged; `add` never overwrites``.** Use `replace` to change an existing credential.
- **`429 Too Many Requests` on the first requests after an approval.** The route's bucket
  [starts empty](#rate-limits-start-empty).
- **`503` from the proxy.** The service is Locked: run `iron-vault unlock`.

## Reference

- [CLI](../reference/cli.md): every command and its exit codes.
- [Configuration](../reference/configuration.md): listeners, callers, routes, slots and rate limits.
- [Errors](../reference/errors.md) and [service states](../reference/states.md).
- [Audit log](../reference/audit-log.md) and [files and locations](../reference/files.md).
- Next: [give an AI agent or MCP server an API key](agent-api-key.md).
