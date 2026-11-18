# Rotate or revoke a caller token

*Checked with `iron-vault 0.2.0-alpha (features: dev-mode)`, built from `main` at `378d57d`.*

Give a caller a new caller token, or remove the caller. Both are a config change: the old token stops working when
the new config is approved, not before.

## Prerequisites

- The service running and Ready, with the `me` caller and `httpbin` route from [getting started](getting-started.md).
- Your config file, `dev-config.toml`, and the approval passphrase.

A peer caller (`auth = "peer"`) has no token; to revoke it, [revoke the caller](#revoke-a-caller).

## Rotate a token

### 1. Issue a new token

Keep the old token's header, to check later that it is refused:

```sh
OLD="Proxy-Authorization: Bearer $(cat ~/.iron-vault-tokens/me)"
iron-vault caller-token > ~/.iron-vault-tokens/me.new
```

```text
token_hash = "blake2b:675b97bb…"
This token is shown once and the service keeps no copy of it.
Put the token_hash line on the caller's [callers.<name>] table and run `iron-vault config approve <file>`.
The token works only once that config is approved and active; the caller's old token, if any, keeps working until then.
```

The old token still works:

```sh
curl -si -H "$OLD" http://127.0.0.1:7878/httpbin/headers | head -1
```

```text
HTTP/1.1 200 OK
```

### 2. Put the new hash in the config and approve it

Replace the `token_hash` line in `[callers.me]` with the one just printed:

```sh
iron-vault config approve dev-config.toml
```

```text
Approval summary
vault: 8c597c79-…
version to commit: 5
config digest: blake2b:3671b247…
committed version: 4
callers:
  ~ me: token changed
Approve this config as version 5? Type yes to approve: yes
Approval passphrase for "approval passphrase":
approved version 5 (blake2b:3671b247…)
callers: 1 changed; route grants: none; routes: none; listeners: none; limits: none; logging: none; recovery: none
```

If the summary shows anything but `token changed`, answer anything but `yes` and check the file.

### 3. Move the new token into place

```sh
mv ~/.iron-vault-tokens/me.new ~/.iron-vault-tokens/me
AUTH="Proxy-Authorization: Bearer $(cat ~/.iron-vault-tokens/me)"
curl -si -H "$OLD"  http://127.0.0.1:7878/httpbin/headers | head -1
curl -si -H "$AUTH" http://127.0.0.1:7878/httpbin/headers | head -1
```

```text
HTTP/1.1 401 Unauthorized
HTTP/1.1 200 OK
```

Give the new token to the program that uses it, and restart the program if it reads the token only at startup. Until
then its requests get `401`.

## Revoke a caller

Delete the caller's whole `[callers.<name>]` table from `dev-config.toml` and approve. Here the caller is `ci`, which
was granted the `httpbin` route:

```sh
iron-vault config approve dev-config.toml
```

```text
Approval summary
vault: 8c597c79-…
version to commit: 7
config digest: blake2b:afe3d6c6…
committed version: 6
callers:
  - ci
route grants:
  - ci: revoked httpbin
Approve this config as version 7? Type yes to approve: yes
Approval passphrase for "approval passphrase":
approved version 7 (blake2b:afe3d6c6…)
callers: 1 removed; route grants: 1 removed; routes: none; listeners: none; limits: none; logging: none; recovery: none
```

Its token is refused from then on:

```sh
curl -si -H "Proxy-Authorization: Bearer $(cat ~/.iron-vault-tokens/ci)" http://127.0.0.1:7878/httpbin/headers | head -1
rm ~/.iron-vault-tokens/ci
```

```text
HTTP/1.1 401 Unauthorized
```

The log shows the last request that worked and the first refused one (fields trimmed):

```json
{"caller":"ci","route":"httpbin","status":200,"outcome":"success","reason":null}
{"caller":null,"route":null,"status":401,"outcome":"failure","reason":"unauthenticated"}
```

To take one route away from a caller without revoking it, remove the route from its `routes` instead. The summary
shows `~ <caller>: revoked <route>`.

## What can go wrong

- **The old token still works.** The new config was not approved, or the approval was declined. `iron-vault status`
  shows the committed version; it should have gone up by one.
- **Both tokens get `401`.** The `token_hash` line in the file is not the one `caller-token` printed for the new
  token, or the program still sends the old token.
- **You lost the new token before saving it.** The service keeps no copy. Issue another and approve again.

## Reference

- [CLI](../reference/cli.md#iron-vault-caller-token): `caller-token`.
- [Configuration](../reference/configuration.md): callers and `token_hash`.
- Related: [widen or narrow a route](change-route.md), [investigate with the audit log](investigate-audit-log.md).
