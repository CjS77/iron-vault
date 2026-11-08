# Configuration

This page lists every table and key of Iron Vault's configuration file. For each key it gives the type, whether the
key is required, its default, the rule it must meet and the refusal you get when it doesn't. The `iron-vault-policy`
crate checks the config, and every refusal below is copied from its code. Terms follow the [glossary](../glossary.md),
and the [specification](../../../design/iron-vault-specification.md#33-credential-records-and-configuration) is the
source of the rules.

## How approval works

You never edit the config the service runs. You edit your own copy, anywhere you like, and approve it:

```sh
iron-vault config approve my-config.toml
```

The CLI sends the file's bytes to the service. The service then:

1. writes them beside the active config as `config.toml.pending`, and checks them as described on this page;
2. shows its own approval summary of what changes, and asks you to type `yes`;
3. asks for the approval passphrase;
4. reserves the next approval version, signs the config with it, and commits it to the vault;
5. publishes the config as `config.toml`, with its signature `config.toml.sig`, in the config directory, and puts it
   into force without a restart.

The config directory is `/etc/iron-vault` in a protected install and `$XDG_CONFIG_HOME/iron-vault-dev` in development.
[config-approval.md](../../../design/config-approval.md) describes the transaction step by step.

**Never edit the published copy.** The signature covers every byte, comments and whitespace included. On SIGHUP the
service reloads the published pair, and only from Ready. A published config that doesn't match its signature is
refused: the service stops proxying and reports `policy invalid` until you approve a config again. To change anything,
edit your own copy and approve it again.

A config that fails a check uses up no approval version, and the active config doesn't change. The CLI refuses a file
longer than 61440 bytes before sending it:

```text
the config file {path} is longer than 61440 bytes
```

## Reading a refusal

A refused config ends `config approve` with one line on stderr:

```text
iron-vault: the service answered error 7 (config-invalid): the proposed config is invalid: <detail>
```

The checks run in four stages, and the detail depends on which stage refused the config.

1. **Parsing** reads each table and checks each key on its own: its type, its value, and that no key is unknown. The
   detail gives only the position of the first fault, because the parser's message may quote a value from your file:

   ```text
   config is invalid at line 12, column 7
   ```

   Look at that line and check it against the rules below. The parser's own message for each rule is listed in this
   page's tables so that you can tell which rule a value breaks. Two parse faults are named in the detail:

   ```text
   config has no schema_version at line 1, column 1
   config schema_version 2 is unsupported at line 1, column 18
   ```

2. **Validation** checks the tables against each other, for example that every route a caller is granted is defined.
   It reports every fault it finds, joined by `; `, in full.

3. **Activation** checks the config against the vault and the host: that each credential exists and permits the
   route's upstream, and that each peer caller's account exists. It also reports every fault in full.

4. **Serving checks** run last. The service builds the upstream HTTP clients the routes need and, when the config moves
   the log, checks the new [log destination](#logging). A failure here gives one fixed phrase, such as
   `the upstream HTTP client could not be built` or `the log directory does not exist`, and never a path.

## The example

This config uses every table, and every kind of listener, caller and slot. A test in `iron-vault-policy` parses and
validates this exact file, so it stays valid as the schema changes. To approve it you would still need the credentials
in your vault and the accounts on your host.

```toml
{{#include configuration-example.toml}}
```

## The file

The config is one TOML file in UTF-8. Its top level holds `schema_version` and these tables:

| Table               | Required | What it holds                                          |
|---------------------|----------|--------------------------------------------------------|
| `[listeners.<name>]` | no      | where callers connect                                  |
| `[callers.<name>]`   | no      | who may connect, how they are identified, which routes |
| `[routes.<name>]`    | no      | where requests go, and with which credential           |
| `[limits]`           | no      | operational limits for the whole service               |
| `[logging]`          | no      | where the log goes                                     |
| `[recovery]`         | no      | how often to remind you to check the recovery key      |

An empty config with only `schema_version = 1` is valid: `init` approves one as version 1. It opens no listener.

**Unknown keys are refused** in every table, so a misspelt key is an error rather than a silently ignored setting:

```text
unknown field `backlog`, expected one of `unix_socket`, `address`, `tls_certificate`, `tls_key`, `token_header`
```

**Names.** Listener, caller, route and credential names are 1 to 64 bytes of `a-z`, `0-9`, `_` and `-`, starting with
a lowercase letter. A caller's `routes` and a route's `credential` refer to these names.

```text
invalid listener name: must start with a lowercase ASCII letter, found 'L'
```

**Paths.** Every file or socket path (`unix_socket`, `tls_certificate`, `tls_key`, `ca_file`) must be absolute, with no
`..` component and no NUL byte:

```text
path "run/a.sock" must be absolute
path "/run/../a.sock" must not contain a '..' component
```

## `schema_version`

| Type    | Required | Default | Rule                     |
|---------|----------|---------|--------------------------|
| integer | yes      | none    | must be `1` this release |

The version of the config's format. It is the only top-level key. (The glossary's *schema version* is the field of the
same name in a log record; it is a different number.)

```toml
schema_version = 1
```

| Fault           | Parser message                                                                                |
|-----------------|-----------------------------------------------------------------------------------------------|
| missing         | `configuration has no schema_version at line 1, column 1; expected schema_version = 1`         |
| any other value | `unsupported schema version 2 at line 1, column 18; this release reads schema_version = 1`    |

## `[listeners.<name>]`

A listener is one socket or address where callers connect. Each caller names the listener it arrives on.

| Key               | Type   | Required                                   | Default               |
|-------------------|--------|--------------------------------------------|-----------------------|
| `unix_socket`     | path   | exactly one of `unix_socket` and `address` | none                  |
| `address`         | string | exactly one of `unix_socket` and `address` | none                  |
| `tls_certificate` | path   | with `tls_key`; required off loopback      | none (plain HTTP)     |
| `tls_key`         | path   | with `tls_certificate`                     | none                  |
| `token_header`    | string | no                                         | `Proxy-Authorization` |

```toml
[listeners.local]
unix_socket = "/run/iron-vault/proxy.sock"

[listeners.backoffice]
address = "10.20.0.2:7878"
tls_certificate = "/etc/iron-vault/tls/server.crt"
tls_key = "/etc/iron-vault/tls/server.key"
```

**`address`** is an IP address and port, `127.0.0.1:7878` or `[::1]:7878`. A host name is refused, and so is port 0.

**TLS off loopback.** A listener on any address outside loopback must have `tls_certificate` and `tls_key`, so that
caller tokens never cross a network in clear. Loopback means `127.0.0.0/8` or `::1`. `::ffff:127.0.0.1` is not
loopback. A Unix socket never takes TLS. Approval refuses a listener without them and names it:
`listener public on 192.0.2.10:8443 needs tls_certificate and tls_key: plain HTTP is allowed only on loopback`.

**Socket activation.** In a protected install, systemd opens TCP listeners and passes them to the service. Adding an
`address` listener there also needs a systemd socket unit:
see [Add a TCP listener](../installation/linux-install.md#add-a-tcp-listener).

**`token_header`** is the header from which callers on this listener send their caller token:

- Not set, or set to `Proxy-Authorization`: the caller sends `Proxy-Authorization: Bearer <token>`. The scheme may be in
  any case, followed by exactly one space.
- Any other header, such as `X-Iron-Vault-Token`: the whole header value is the token, and `Proxy-Authorization` is not
  read. Use this for a client that can add a fixed header but can't send `Proxy-Authorization`.

A missing token, an unknown one, or the header sent more than once is refused with `401`. The service strips the token
header before forwarding, so the upstream never sees it. The header must not be a
[reserved header](#reserved-headers), apart from `Proxy-Authorization` itself, and must not be the slot header of a
route that this listener's callers can use.

| Fault                                  | Parser message                                                                                                 |
|----------------------------------------|----------------------------------------------------------------------------------------------------------------|
| neither `unix_socket` nor `address`    | `listener needs exactly one of unix_socket or address; neither is set`                                         |
| both                                   | `listener needs exactly one of unix_socket or address; both are set`                                           |
| not an IP address and port             | `listener address "localhost:7878" is not an IP address and port such as 127.0.0.1:7878 or [::1]:7878`         |
| port 0                                 | `listener address 127.0.0.1:0 uses port 0`                                                                     |
| one TLS file                           | `listener sets only one of tls_certificate and tls_key; set both or neither`                                   |
| TLS on a Unix socket                   | `tls_certificate and tls_key apply only to an address listener, not a unix_socket`                             |
| reserved `token_header`                | `token_header X-Forwarded-Token is a reserved header; choose a dedicated header such as X-Iron-Vault-Token`    |
| malformed header name                  | `header name "X Token" contains ' ', which is not allowed in an HTTP token`                                    |

One validation refusal, shown in full:

```text
listener loopback token_header x-key is the credential slot of route brave, which its callers can use
```

## `[callers.<name>]`

A caller is one program, or one group of programs, that Iron Vault recognises and grants routes to.

| Key           | Type             | Required                     | Default   |
|---------------|------------------|------------------------------|-----------|
| `listener`    | listener name    | yes                          | none      |
| `auth`        | string           | no                           | `"token"` |
| `token_hash`  | string           | with `auth = "token"` only   | none      |
| `user`        | account name     | with `auth = "peer"` only    | none      |
| `routes`      | array of names   | yes, at least one            | none      |
| `rate_limits` | table            | no                           | none      |

```toml
[callers.brave-cli]
listener = "loopback"
token_hash = "blake2b:0123456789abcdef00112233445566778899aabbccddeeff0f1e2d3c4b5a6978"
routes = ["brave", "venice"]
```

### How a caller is identified: `auth`

`auth` is one of three values. Each listener uses one of them for all its callers.

**`"token"`**, the default. The caller sends a caller token, and `token_hash` holds its hash.
`iron-vault caller-token` makes a token, writes it to stdout and prints the `token_hash = "blake2b:..."` line for the
config. The service keeps only the hash. A token is `ivt_` followed by 43 base64url characters, and its hash is
`blake2b:` followed by 64 lowercase hex digits. Anyone who can read the token can use the caller's routes, so keep it in
a file only the caller's account can read. To rotate it, put the new hash in the config and approve: the old token
stops working at that moment. Token callers on one listener must have different hashes.

**`"peer"`.** The caller is recognised by the OS account of the connecting process, which the kernel reports on a Unix
socket. There is no token to steal. `user` names the account: `a-z` or `_`, then `a-z`, `0-9`, `_` or `-`, with an
optional trailing `$`, at most 32 bytes. Peer callers need a `unix_socket` listener, and every caller on that listener
must be a peer caller with a different account. Activation checks the account on the host: it must exist, and must not
be root, the service account or the overflow uid, and no two peer callers on one listener may resolve to the same uid.
Development mode runs the service as your own account, which is never a peer account, so peer callers are for a
protected install.

**`"isolated-network"`.** The caller is recognised by the listener alone: it is the only caller on a TLS address
listener bound to an address only it can reach, such as its own container network. The address must be dedicated, so
neither loopback nor a wildcard address such as `0.0.0.0`.

```toml
[callers.fx-mcp]
listener = "local"
auth = "peer"
user = "fx-mcp"
routes = ["fx"]

[callers.backoffice]
listener = "backoffice"
auth = "isolated-network"
routes = ["venice", "tickets"]
```

### `routes` and `rate_limits`

`routes` lists the routes the caller may use. It must not be empty or repeat a route, and every route it names must be
defined.

`rate_limits` sets a [rate limit](#rate_limit-the-token-bucket) for this caller on one of its routes. It applies on top
of the route's own limit, which all the route's callers share. It may be stricter than the route's limit but never
looser, in rate or in burst.

```toml
[callers.code.rate_limits]
github = { requests = 30, per_seconds = 60, burst = 5 }
```

### Refusals

Parser messages:

| Fault                                   | Parser message                                                                                                   |
|-----------------------------------------|------------------------------------------------------------------------------------------------------------------|
| token caller without `token_hash`       | `caller uses token authentication but has no token_hash`                                                         |
| hash without the prefix                 | `token hash must start with "blake2b:"`                                                                          |
| hash of the wrong length                | `token hash digest is 3 characters long; it must be 64 lowercase hex digits`                                     |
| hash with another character             | `token hash digest has a character other than 0-9 or a-f at byte 10`                                             |
| peer caller without `user`              | `caller uses auth = "peer" but has no user`                                                                      |
| `token_hash` on a peer caller           | `caller sets token_hash but uses auth = "peer"; token_hash applies only to auth = "token"`                       |
| `user` on a token caller                | `caller sets user but uses auth = "token"; user applies only to auth = "peer"`                                   |
| unknown `auth`                          | `` unknown variant `password`, expected one of `token`, `isolated-network`, `peer` ``                             |
| empty `routes`                          | `caller must be granted at least one route`                                                                      |
| repeated route                          | `caller lists route fx more than once`                                                                           |
| limit for a route not granted           | `caller sets a rate limit for route brave, which is not in its routes`                                           |
| malformed account                       | `invalid account name "Alice": must be a-z or '_', then a-z, 0-9, '_' or '-', with an optional trailing '$'`     |

Validation messages, shown in full:

```text
caller code is granted route gitlab, which is not defined
caller code names listener lan, which is not defined
caller code rate limit for route github allows a higher request rate than the route's own limit
caller code rate limit for route github allows a larger burst than the route's own limit
caller fx-mcp uses auth = "peer", which needs a unix_socket listener; listener loopback is not one
caller backoffice uses auth = "isolated-network", which needs an address listener with TLS; listener local is not one
caller backoffice needs listener backoffice to bind a dedicated address
caller backoffice uses auth = "isolated-network", so it must be the only caller on listener backoffice, which brave-cli also use; callers that share a TCP listener must use tokens
listener local has peer callers, so every caller on it must use auth = "peer"; brave-cli do not
callers code, fx-mcp on listener local share user alice, so one account would identify more than one caller
callers brave-cli, chat on listener loopback share a token_hash, so one token would identify more than one caller
```

Activation messages:

```text
caller fx-mcp names user fx-mcp, which is not an account on this host
caller fx-mcp names user root, which is root or the service account; neither may be a peer account
caller fx-mcp names user nobody, the overflow uid; the kernel reports this uid for processes outside this user namespace
callers code, fx-mcp on listener local name accounts with uid 1001, so one account would identify more than one caller
```

## `[routes.<name>]`

A route maps requests under a path prefix to one upstream, with one credential in one slot.

| Key          | Type             | Required | Default  |
|--------------|------------------|----------|----------|
| `prefix`     | string           | yes      | none     |
| `upstream`   | string           | yes      | none     |
| `credential` | credential name  | yes      | none     |
| `slot`       | string or table  | yes      | none     |
| `methods`    | array of strings | yes      | none     |
| `paths`      | array of strings | yes      | none     |
| `rate_limit` | table            | yes      | none     |
| `confirm`    | string           | no       | `"none"` |
| `ca_file`    | path             | no       | none     |

```toml
[routes.venice]
prefix = "/venice"
upstream = "https://api.venice.ai/api/v1"
credential = "venice"
slot = { header = "Authorization", format = "Bearer {}" }
methods = ["POST"]
paths = ["/api/v1/chat/completions"]
rate_limit = { requests = 120, per_seconds = 60, burst = 20 }
```

### `prefix`

The path under which the caller sends requests for this route. The service takes the prefix off and sends the rest of
the path to the upstream. A prefix matches whole segments: `/fx` matches `/fx` and `/fx/latest`, never `/fx.evil` or
`/fxx`. No two routes' prefixes may overlap, so `/fx` and `/fx/v2` can't both be used.

A prefix is made of literal segments, with the same characters as a [path pattern](#paths-and-the-base-path). It must
not be `/`, contain a wildcard, end in a slash or contain `%`.

| Fault          | Parser message                                                                                              |
|----------------|-------------------------------------------------------------------------------------------------------------|
| `/`            | `route prefix must not be "/"; it would match every request path`                                           |
| trailing slash | `route prefix breaks a path-pattern literal rule: path pattern "/r/" contains an empty segment or trailing slash` |
| wildcard       | `route prefix "/r/*" must not contain a wildcard segment`                                                   |
| overlap (a validation message) | `route fx prefix overlaps route fx-v2 prefix`                                                  |

### `upstream`

The HTTPS URL that requests are sent to, with an optional base path. It must start with `https://` in lowercase, and has
no user-info, query or fragment. An IP address host must be written in its canonical form, and the base path has no
dot segments. A trailing slash is dropped. The port defaults to 443.

| Fault             | Parser message                                                                                                                 |
|-------------------|--------------------------------------------------------------------------------------------------------------------------------|
| not HTTPS         | `upstream URL must start with "https://"`                                                                                      |
| user-info         | `upstream URL must not contain user-info`                                                                                      |
| query             | `upstream URL must not contain a query`                                                                                        |
| fragment          | `upstream URL must not contain a fragment`                                                                                     |
| dot segment       | `upstream URL base path segment ".." is a dot segment`                                                                         |
| non-canonical IP  | `upstream URL host is invalid: host denotes an IP address but is not written as a canonical IPv4 or bracketed IPv6 literal`    |
| port 0            | `upstream URL port is invalid: port 0 is not allowed`                                                                          |

### `credential`, and where it may go

`credential` names a credential in the vault, which you stored with `iron-vault add`. The origins given to `add` are
kept inside the encrypted credential record. Activation refuses a route whose upstream is not one of them, so a config
change can never send an existing key to a new host. Only `iron-vault replace` changes the origins.

```text
route venice uses credential venice, which the vault does not hold
route brave sends credential brave to an origin its record does not permit
route tickets uses a static credential, tickets, on a slot that kind cannot fill
```

### `methods`

The HTTP methods the route allows: any of `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE` and `OPTIONS`, in upper
case. `CONNECT` and `TRACE` are never allowed. The list must not be empty or repeat a method. A request with another
method is refused before anything is sent.

| Fault         | Parser message                                                                         |
|---------------|----------------------------------------------------------------------------------------|
| empty         | `route must allow at least one method`                                                 |
| repeated      | `route lists method GET more than once`                                                |
| not supported | `unsupported method "get"; expected one of GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS` |
| never allowed | `method TRACE is never allowed`                                                        |

### `paths` and the base path

The path patterns the route allows. A request whose path matches none of them is refused before anything is sent.

**Patterns match the full path sent upstream**, which is the upstream's base path followed by the rest of the request
path. With `upstream = "https://api.venice.ai/api/v1"` and `prefix = "/venice"`, a request for
`/venice/chat/completions` is sent to `/api/v1/chat/completions`, and that is what `paths` must name. Patterns never
see the query string.

**Wildcards stand for whole segments.**

- `*` matches exactly one segment: `/repos/*/*/issues` matches `/repos/octo/demo/issues`, not `/repos/octo/issues`.
- `**` matches zero or more segments: `/historical/**` matches `/historical`, `/historical/2024` and
  `/historical/2024/01/02`.
- `/` alone has no segments and matches only the root path.
- `["/**"]` allows every path. It must be written out; an empty list is refused.

A pattern starts with `/`, has no empty segment or trailing slash, and no dot segment. A wildcard must be the whole
segment, so `a*` is refused. Literal segments may hold letters, digits and `- . _ ~ ! $ & ' ( ) + , ; = : @`; `%` and
other characters are refused. Each pattern may be listed only once.

| Fault             | Parser message                                                                |
|-------------------|-------------------------------------------------------------------------------|
| empty list        | `path patterns must not be empty; use ["/**"] to allow every path explicitly` |
| repeated          | `path pattern "/v1" is listed more than once`                                 |
| no leading slash  | `path pattern "v1" must start with '/'`                                       |
| trailing slash    | `path pattern "/v1/" contains an empty segment or trailing slash`             |
| partial wildcard  | `path pattern "/v1/a*" has a partial wildcard segment "a*"`                   |
| dot segment       | `path pattern "/v1/../x" contains a dot segment`                              |
| other character   | `path pattern "/v1/a%20b" contains disallowed character '%'`                  |

### `slot`: where the credential goes

The slot is the one place the service writes the credential. It first removes whatever the caller sent there, so a
placeholder key in the application is replaced, never forwarded. There are three kinds:

| Slot                                              | Credential kind | What the upstream gets                     |
|---------------------------------------------------|-----------------|--------------------------------------------|
| `{ header = "X-Subscription-Token" }`             | static          | `X-Subscription-Token: <key>`              |
| `{ header = "Authorization", format = "Bearer {}" }` | static       | `Authorization: Bearer <key>`              |
| `{ query = "access_key" }`                        | static          | `?access_key=<key>`, added to the query    |
| `"basic"`                                         | basic           | `Authorization: Basic <base64 of user:password>` |

- **`header`** is an HTTP header name that is not a [reserved header](#reserved-headers). `Authorization` is allowed.
- **`format`** applies only to a header slot, and defaults to `{}`. It is printable ASCII with exactly one `{}`, where
  the key goes, and no other braces.
- **`query`** is a parameter name made only of `A-Z a-z 0-9 - . _ ~`.
- **`"basic"`** is for a credential added with a username and password.

| Fault                          | Parser message                                                                                                  |
|--------------------------------|-----------------------------------------------------------------------------------------------------------------|
| reserved header                | `header Host is reserved for caller authentication or transport control and cannot be a slot`                   |
| format without `{}`            | `slot format "Bearer" has no {} substitution point`                                                             |
| format with two `{}`           | `slot format "{} {}" must contain exactly one {} and no other braces`                                           |
| format not printable ASCII     | `slot format "B\u{e9} {}" contains '\u{e9}'; only printable ASCII is allowed`                                   |
| `format` on a query slot       | `` `format` applies only to header slots ``                                                                        |
| both or neither of header, query | `` a slot table must name exactly one of `header` or `query` ``                                                |
| query name with another character | `query parameter name "api key" contains ' '; only A-Z a-z 0-9 - . _ ~ are allowed`                          |
| empty query name               | `query parameter name is empty`                                                                                 |
| any other string               | `` invalid value: string "bearer", expected "basic" or a table with `header` (and optional `format`) or `query` `` |

### `rate_limit`: the token bucket

Every route has a rate limit, written as three nonzero whole numbers:

```toml
rate_limit = { requests = 60, per_seconds = 60, burst = 10 }
```

The limit is a token bucket. The bucket holds at most `burst` tokens and refills at `requests` tokens every
`per_seconds` seconds. Each request takes one token, and a request that finds the bucket empty gets `429`. The example
above allows one request a second on average, and up to 10 at once after a quiet spell.

**Every bucket starts empty** each time the service becomes Ready, and fills from there: after `unlock`, an approval, a
SIGHUP reload, a repair, or a `replace` or `rm`. Each of these runs a config check, and every config check builds new
buckets. A service that has just started is Locked, so in practice its buckets begin at `unlock`. Neither a restart nor
a reload ever hands out a fresh burst. In the example, the first request is allowed one second after the service
becomes Ready, and the full burst of 10 only after ten quiet seconds.

All the route's callers share its bucket. A caller's `rate_limits` entry adds a second bucket of its own, and a request
needs a token from both. A route that should be effectively unlimited still gets a limit, a generous one.

| Fault       | Parser message                                     |
|-------------|----------------------------------------------------|
| zero        | ``invalid value: integer `0`, expected a nonzero u32`` |
| missing key | `` missing field `burst` ``                         |

### `confirm`

`"none"`, the default, or `"touch"`. A touch route will need confirmation on a security key for each request. No
confirmation provider exists in v0, so a config with a touch route is refused at activation:

```text
route github sets confirm = "touch", but no touch confirmation provider is available
```

Any other value: `` unknown variant `always`, expected `none` or `touch` ``.

### `ca_file`

A PEM file of CA certificates that the route trusts instead of the built-in roots, for a self-hosted upstream with its
own CA. Install it where only an administrator can write. If the file can't be read or parsed, the config is still
approved, but the routes that pin it are unavailable until it is fixed.

```toml
ca_file = "/etc/iron-vault/ca/tickets.pem"
```

## Reserved headers

The service removes these headers from every request before forwarding, and controls `Host` itself. None of them may be
a route's slot, and none but `Proxy-Authorization` may be a listener's `token_header`. Names are compared without
regard to case.

- Hop-by-hop: `Connection`, `Keep-Alive`, `Proxy-Connection`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`,
  `Trailer`, `Transfer-Encoding`, `Upgrade`.
- Transport and routing: `Host`, `Content-Length`, `Forwarded`, `Via`, `X-Real-IP`, `True-Client-IP`, `X-Client-IP`,
  `CF-Connecting-IP`, `X-Host`, `X-Original-Host`, `X-HTTP-Host-Override`.
- Method override and URL rewrite: `X-HTTP-Method-Override`, `X-Method-Override`, `X-HTTP-Method`, `X-Original-URL`,
  `X-Rewrite-URL`.
- Any header starting with `X-Forwarded-`.

The service also strips the listener's own `token_header` and any header that `Connection` names.

## `[limits]`

Service-wide limits. Every key is optional; a key left out keeps its default. Zero is refused, and so is a value above
the ceiling.

| Key                               | Type    | Default             | Ceiling        | What it bounds                                   |
|-----------------------------------|---------|---------------------|----------------|--------------------------------------------------|
| `max_header_bytes`                | integer | 65536 (64 KiB)      | 1048576 (1 MiB) | a request line and headers, in bytes            |
| `max_header_count`                | integer | 100                 | 1000           | a request's headers, in count                    |
| `max_request_body_bytes`          | integer | 10485760 (10 MiB)   | 1073741824 (1 GiB) | a request body                               |
| `max_decompressed_response_bytes` | integer | 67108864 (64 MiB)   | 4294967296 (4 GiB) | a response body after decompression for scrubbing |
| `max_decompression_ratio`         | integer | 100                 | 10000          | decompressed size over compressed size           |
| `request_timeout_secs`            | integer | 300                 | 3600           | a whole request, in seconds                      |
| `upstream_timeout_secs`           | integer | 300                 | 600            | waiting for the upstream's response headers; at most `request_timeout_secs` |
| `max_connections`                 | integer | 256                 | 65536          | concurrent caller connections                    |

```toml
[limits]
max_request_body_bytes = 1048576
request_timeout_secs = 120
upstream_timeout_secs = 60
```

| Fault             | Parser message                                                                           |
|-------------------|------------------------------------------------------------------------------------------|
| zero              | `limits.max_connections must not be zero`                                                |
| above the ceiling | `limits.max_connections is 70000; the maximum is 65536`                                  |
| timeouts crossed  | `limits.upstream_timeout_secs (400) must not exceed limits.request_timeout_secs (300)`  |

## `[logging]`

| Key           | Type   | Required | Default                    |
|---------------|--------|----------|----------------------------|
| `destination` | string | no       | the bootstrap destination  |

Where the log goes: `"stdout"`, or an absolute directory in which the service writes `iron-vault.log`. When it is not
set, the bootstrap destination applies: `/var/log/iron-vault` in a protected install,
`$XDG_STATE_HOME/iron-vault-dev-log` in development, or stdout when `serve` has `--log-to-stdout`.

A directory must be absolute, with no control characters and no `..`, and outside the state and config directories.
It must also pass the log directory's trusted-path rule; the
[log operations guide](log-operations.md#location-and-permissions) gives the owner and modes. Create it before you
approve. A development build creates its missing bootstrap log directory at `0700` when `serve` starts, but never a
directory that a config names.

**Checked at approval.** When the config changes the destination, `config approve` checks the new one before it
reserves a version: that the directory exists, resolves to a canonical path outside the state and config directories,
and passes the trusted-path rule. It creates and writes nothing. A failure is `config-invalid` with a fixed phrase,
for example:

```text
the log directory is, or is inside, the state directory
the log directory does not exist
the log directory, or a directory above it, is writable by others
```

```toml
[logging]
destination = "/var/log/iron-vault"
```

```text
log destination must be "stdout" or an absolute directory: path "logs" must be absolute
```

**Switching.** When the service becomes Ready with a config that moves the log, it checks the destination again,
then switches to it. It writes `service.log-destination-changed` to the old destination and then to the new one, so
each file records where the log went. Removing the key moves the log back to the bootstrap destination the same way.
If the check fails at that point, the service stays Unavailable (`policy invalid`) and keeps writing where it was.

## `[recovery]`

| Key             | Type    | Required | Default |
|-----------------|---------|----------|---------|
| `reminder_days` | integer | no       | 90      |

How many days may pass after the last `iron-vault recovery check` before the service reminds you to run another. It is
a whole number from 7 to 365. It is part of the approved config, so silencing the reminders needs the approval
passphrase. When the key is absent, the approval summary shows the interval as `default`.

```toml
[recovery]
reminder_days = 30
```

```text
recovery.reminder_days must be a whole number of days from 7 to 365, not 3
```
