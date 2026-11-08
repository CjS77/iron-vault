# A route can't send a key to another host

*Checked with `iron-vault 0.2.0-alpha (features: dev-mode)`, built from `main` at `e10f09e`.*

At the end of this recipe you will have seen Iron Vault refuse to send a stored key anywhere its credential record
doesn't permit, whether the change comes from a config approval or a `replace`.

## Prerequisites

- The service running and Ready, with the `httpbin_key` credential and `httpbin` route from
  [getting started](getting-started.md).
- Your config file, `dev-config.toml`.

## Steps

### 1. Point the route at another host

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
iron-vault: the service answered error 7 (config-invalid): the proposed config is invalid: route httpbin sends credential httpbin_key to an origin its record does not permit
```

The command exits with status 1. No version is used up, and the active config doesn't change: `iron-vault status`
still shows the same `approval committed` version. Put the upstream back to `https://httpbin.org`.

### 2. Try it with `replace`

The same check guards `replace`. Replacing the key with a record that permits only another host is refused while a
route still sends it to httpbin:

```sh
iron-vault replace httpbin_key --origin postman-echo.com
```

It is refused before it asks for anything:

```text
iron-vault: the service answered error 24 (credential-in-use): routes use credential httpbin_key and would stop working: route httpbin sends credential httpbin_key to httpbin.org:443, which its record does not permit; approve a config without them first
```

`iron-vault list` still shows `httpbin_key  static  httpbin.org:443  healthy`.

To move a key to another host on purpose, follow
[changing the origins or the kind](rotate-key.md#changing-the-origins-or-the-kind).

## Reference

- [Configuration](../reference/configuration.md#credential-and-where-it-may-go): `credential`, and where it may go.
- [Errors](../reference/errors.md): `config-invalid` and `credential-in-use`.
- Related: [rotate a provider key](rotate-key.md).
