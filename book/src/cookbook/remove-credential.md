# Remove a credential safely

*Checked with `iron-vault 0.2.0-alpha (features: dev-mode)`, built from `main` at `378d57d`.*

Remove a credential you no longer need: first approve a config without the routes that use it, then `rm` it. The
example credential is `old_key`, used by a route `old` granted to the `me` caller.

## Prerequisites

- The service running and Ready, with the `me` caller from [getting started](getting-started.md).
- The approval passphrase: `rm` asks for it.
- Your config file, `dev-config.toml`.

To follow along, store a credential and give it a route first:

```sh
echo old-test-key-000 | iron-vault add old_key --origin httpbin.org
```

```text
added old_key (static) as record b3d9440b-…
```

Add `"old"` to `[callers.me]`'s `routes`, add this route, and approve the config:

```toml
[routes.old]
prefix = "/old"
upstream = "https://httpbin.org"
credential = "old_key"
slot = { header = "Authorization", format = "Bearer {}" }
methods = ["GET"]
paths = ["/headers"]
rate_limit = { requests = 30, per_seconds = 60, burst = 5 }
```

## Steps

### 1. See what uses the credential

`rm` tells you, by refusing:

```sh
iron-vault rm old_key
```

```text
iron-vault: the service answered error 24 (credential-in-use): credential old_key is used by route old; approve a config without that route, then run `rm` again
```

Nothing was removed.

### 2. Approve a config without those routes

In `dev-config.toml`, delete the `[routes.old]` table **and** take `"old"` out of every caller's `routes`. Deleting only
the table gets:

```text
iron-vault: the service answered error 7 (config-invalid): the proposed config is invalid: caller me is granted route old, which is not defined
```

With both changes made:

```sh
iron-vault config approve dev-config.toml
```

```text
Approval summary
vault: 8c597c79-…
version to commit: 4
config digest: blake2b:ab7050b8…
committed version: 3
route grants:
  ~ me: revoked old
routes:
  - old
Approve this config as version 4? Type yes to approve: yes
Approval passphrase for "approval passphrase":
approved version 4 (blake2b:ab7050b8…)
callers: none; route grants: 1 changed; routes: 1 removed; listeners: none; limits: none; logging: none; recovery: none
```

Check that the summary removes only the routes you meant to remove before you type `yes`.

### 3. Remove the credential

```sh
iron-vault rm old_key
iron-vault list
```

It shows the record, then asks for the approval passphrase:

```text
remove credential old_key
  record: b3d9440b-…
  kind: static
  origins: httpbin.org:443
  routes using old_key: none
Approval passphrase for "approval passphrase":
removed old_key
httpbin_key  static  httpbin.org:443  healthy
```

The log records it:

```json
{"level":"INFO","message":"credential removed; no active route used it","event":"credential.removed","credential":"old_key","record_id":"b3d9440b-…","target":"iron-vault.audit"}
```

### 4. Revoke the key at the provider

`rm` deletes Iron Vault's copy only. Revoke the key in the provider's console, so a copy in an old backup is useless
too.

## What can go wrong

- **`iron-vault: the service answered error 24 (credential-in-use): …`.** A route of the active config still uses the
  credential. Do [step 2](#2-approve-a-config-without-those-routes) first, and approve it.
- **`iron-vault: the service answered error 7 (config-invalid): … caller me is granted route old, which is not
  defined`.** You deleted the route but left it in a caller's `routes`.
- **`iron-vault: the service answered error 9 (approval-denied): the approval passphrase does not open the approver
  key`.** Nothing was removed.
- **You removed the wrong credential.** There is no undo. `add` it again with the secret from the provider, or a
  reissued one, and approve its routes again.

## Reference

- [CLI](../reference/cli.md#iron-vault-rm): `rm`.
- [Audit log](../reference/audit-log.md): `credential.removed`.
- Related: [rotate a provider key](rotate-key.md), [widen or narrow a route](change-route.md).
