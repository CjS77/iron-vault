# Rotate a provider key

*Checked with `iron-vault 0.2.0-alpha (features: dev-mode)`, built from `main` at `378d57d`.*

At the end of this recipe a stored credential holds a new secret, and every route that uses it sends the new one, with
no config change and no restart. Do this when a provider issues you a new key, when you think the old one leaked, or
on your own rotation schedule. Revoke the old key at the provider afterwards: Iron Vault stops sending it, but the
provider still accepts it until you do.

Every command below was run against the real httpbin.org. Each `pass show` was replaced by a test value; every
other command was run as shown.

## Prerequisites

- The service running and Ready, with the `httpbin_key` credential and `httpbin` route from
  [getting started](getting-started.md).
- The approval passphrase. `replace` asks for it, so a program that can reach the admin socket can't swap your key
  for one of its own.
- The new key from the provider.

## Steps

### 1. Replace the secret

`replace` takes the same `--origin` options as `add`. The old origins are not kept, so name every one again:

```sh
iron-vault replace httpbin_key --origin httpbin.org
```

The service first shows what changes and which routes and callers use the credential, then asks for the approval
passphrase, then the new secret:

```text
replace credential httpbin_key
  record: f40ebf97-… -> a new record ID, assigned when the change is written
  kind: static -> static
  origins: httpbin.org:443 -> httpbin.org:443
  routes using httpbin_key: httpbin (callers: me)
Approval passphrase for "approval passphrase":
Secret for httpbin_key:
replaced httpbin_key (static) as record 22327b62-…
```

From a script, put the approval passphrase on the first line of stdin and the secret after it. Neither is echoed and
neither reaches your shell history if both come from a password manager:

```sh
{ pass show iron-vault-approval; pass show httpbin; } | iron-vault replace httpbin_key --origin httpbin.org
```

```text
replace credential httpbin_key
  record: 22327b62-… -> a new record ID, assigned when the change is written
  kind: static -> static
  origins: httpbin.org:443 -> httpbin.org:443
  routes using httpbin_key: httpbin (callers: me)
replaced httpbin_key (static) as record 21f505bb-…
```

### 2. Check that the route uses the new key

```sh
iron-vault list
curl -s -H "Proxy-Authorization: Bearer $(cat ~/.iron-vault-tokens/me)" http://127.0.0.1:7878/httpbin/headers
```

```text
httpbin_key  static  httpbin.org:443  healthy
```

```json
{
  "headers": {
    "Accept": "*/*",
    "Authorization": "Bearer [iron-vault:scrubbed]",
    …
```

httpbin echoed the new secret, and the scrubber, which now knows the new secret, removed it. The service becomes
Ready again after a `replace`, so the route's rate limit [starts empty](getting-started.md#rate-limits-start-empty)
and the first request may get `429`. While the switch is in progress, requests get `503` with reason `checking`.

### 3. Find the change in the log

```sh
jq -c 'select(.event == "credential.replaced")' ~/iron-vault-dev.log
```

```json
{"service":"iron-vault","service_version":"0.2.0-alpha","schema_version":1,"deployment_profile":"development","timestamp":"2026-11-07T10:20:34.208637Z","level":"INFO","message":"credential replaced","event":"credential.replaced","credential":"httpbin_key","old_record_id":"f40ebf97-…","record_id":"22327b62-…","kind":"static","origins":"https://httpbin.org:443","old_kind":"static","old_origins":"https://httpbin.org:443","target":"iron-vault.audit"}
```

The record names the credential, its kind and its origins, old and new, but never a secret.

### 4. Revoke the old key at the provider

Do it in the provider's console, now that nothing sends the old key.

## Changing the origins or the kind

`replace` also changes where a key may go and what kind it is. The new record must still suit every route that uses
the credential, or nothing changes:

```sh
iron-vault replace httpbin_key --origin postman-echo.com
```

```text
iron-vault: the service answered error 24 (credential-in-use): routes use credential httpbin_key and would stop working: route httpbin sends credential httpbin_key to postman-echo.com:443, which its record does not permit; approve a config without them first
```

To move a key to another host, change one side at a time, so that at every step the route's upstream is one of the
record's origins:

1. `replace` with the new origin alongside the old one: `--origin httpbin.org --origin postman-echo.com`.
2. Approve a config that points the route at the new host.
3. `replace` again with only the new origin.

```text
                          the record's origins              the route's upstream
before                    httpbin.org                       https://httpbin.org
1. replace                httpbin.org, postman-echo.com     https://httpbin.org
2. config approve         httpbin.org, postman-echo.com     https://postman-echo.com
3. replace                postman-echo.com                  https://postman-echo.com
```

## What can go wrong

- **`iron-vault: the service answered error 9 (approval-denied): the approval passphrase does not open the approver
  key`.** The approval passphrase was wrong. Nothing changed; the old key is still in use. The log has a
  `vault.presence-refused` record with `"refusal":"wrong_passphrase"`.
- **`iron-vault: the service answered error 24 (credential-in-use): …`.** The new origins or kind don't suit a route
  that uses the credential, as [above](#changing-the-origins-or-the-kind).
- **`429` on the first request afterwards.** The bucket [starts empty](getting-started.md#rate-limits-start-empty)
  after a `replace`.
- **The provider refuses the new key.** Iron Vault sends what you typed. Check for a stray space or a truncated paste,
  then `replace` again.

## Reference

- [CLI](../reference/cli.md#iron-vault-replace): `replace` and its stdin layout.
- [Audit log](../reference/audit-log.md): `credential.replaced`.
- Related: [remove a credential safely](remove-credential.md), [rotate or revoke a caller token](caller-token.md).
