# Development mode

Development mode runs Iron Vault as your own user, with its files in your XDG directories. It is for trying Iron
Vault out and for development. It gives **no isolation from malware running as you**, and the service says so when
it starts and in `status`. It relaxes nothing else: callers still authenticate, routes are still checked, TLS is
still verified, responses are still scrubbed, the vault is still encrypted, and configs still need approval.

Development mode is compiled in only with the `dev-mode` Cargo feature, so a release build can't be switched into
it. It refuses to run as root.

## Build and install

Build and install the `dev-mode` binary as in
[step 1 of getting started](../cookbook/getting-started.md#1-build-and-install). It needs Linux and a Rust toolchain.

The service refuses to run a binary that another account could replace, so make the binary and every directory above
it writable only by you. A build inside a group-writable directory (such as `target/` under a `0775` checkout) is
refused with a message naming the directory. Installing under `~/.local` usually avoids this.

### Shell completion

Bash completion is generated from the same command definitions the CLI parses, and needs no running service:

```sh
mkdir -p ~/.local/share/bash-completion/completions
iron-vault completions bash > ~/.local/share/bash-completion/completions/iron-vault
```

or add `source <(iron-vault completions bash)` to `~/.bashrc`.

## Where the files are

Development mode keeps its files here:

| What         | Where                                                                    |
|--------------|--------------------------------------------------------------------------|
| Config       | `$XDG_CONFIG_HOME/iron-vault-dev/config.toml` (default `~/.config/...`)  |
| Vault        | `$XDG_STATE_HOME/iron-vault-dev/` (default `~/.local/state/...`)         |
| Log          | `$XDG_STATE_HOME/iron-vault-dev-log/`, unless you pass `--log-to-stdout` |
| Admin socket | `$XDG_RUNTIME_DIR/iron-vault-dev/admin.sock`                             |

`XDG_RUNTIME_DIR` must be set, as it is in a normal desktop or SSH login. A Unix socket path must be under 108
bytes, so keep these directories short. [Files and locations](../reference/files.md) lists every file and its
permissions.

## Callers need a token

Development mode runs the service as your own account, and a caller may never be the service's own account. So in
development every caller needs a token. A protected installation runs the service as the `iron-vault` system account,
and then your account can be a caller identified by the kernel, with no token file to steal:

```toml
[listeners.local]
unix_socket = "/run/iron-vault/proxy.sock"

[callers.dev]
listener = "local"
auth = "peer"
user = "alice"            # the account the calling process runs as
routes = ["httpbin"]      # the route from getting started
```

The kernel reports the connecting process's account, so only processes running as `alice` get those routes. That
includes malware running as `alice`, but no other account's processes. A protected installation also takes the admin
socket away from your login account: you administer it with `sudo`.

## A tour through the cookbook

These recipes, in this order, start the service and try each part of Iron Vault against
[httpbin.org](https://httpbin.org), which echoes back each request it receives, and two [Venice.ai](https://venice.ai)
API keys. The tour needs `curl` and `jq`, and the Venice recipe needs two Venice API keys.

1. [Getting started in development mode](../cookbook/getting-started.md): start the service, create and unlock the
   vault, store a credential, approve a route and send a request.
2. [Two keys, two callers, different permissions](../cookbook/two-callers.md).
3. [Investigate with the audit log](../cookbook/investigate-audit-log.md).
4. [Rotate or revoke a caller token](../cookbook/caller-token.md) and [widen or narrow a route](../cookbook/change-route.md).
5. [Scrubbing and redirects](../cookbook/scrubbing-redirects.md).
6. [A route can't send a key to another host](../cookbook/key-origins.md).
7. [Rotate a provider key](../cookbook/rotate-key.md) and [remove a credential safely](../cookbook/remove-credential.md).
8. [Lock, unlock and restart](../cookbook/lock-unlock-restart.md).
9. [Tamper detection and recovery](../cookbook/tamper-detection.md).
10. [Point a real application at Iron Vault](../cookbook/real-application.md).
11. [Start over in development mode](../cookbook/start-over.md).
