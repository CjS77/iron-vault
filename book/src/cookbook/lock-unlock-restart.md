# Lock, unlock and restart

*Checked with `iron-vault 0.2.0-alpha (features: dev-mode)`, built from `main` at `378d57d`.*

At the end of this recipe you will have locked the service, seen what callers get while it is Locked, unlocked it
again, and restarted it. Lock the service when you step away from a machine that holds real keys, or when you think
something on it is misbehaving: `lock` clears the vault identity and every secret from the service's memory, and
nothing is proxied until someone with the vault passphrase unlocks it.

Every command below was run as shown, against the real httpbin.org.

## Prerequisites

- The service running and Ready, with the `me` caller and `httpbin` route from [getting started](getting-started.md).
- The vault passphrase.

## Steps

### 1. Lock

```sh
iron-vault lock
iron-vault status
```

```text
locked
service: locked
profile: development — no isolation from malware running as alice
vault: locked
vault id: unknown
approval committed: unknown while the vault is locked
approval highest reserved: unknown while the vault is locked
memory protection: NOT protected, swap protection unavailable (RLIMIT_MEMLOCK soft limit is 8315834368 bytes, not unlimited)
recovery last checked: never (reminders counting since 2026-11-07)
credentials: unknown while the vault is locked
```

`status` exits with 4, as it does whenever the service is not Ready.

### 2. See what callers get

The listener stays open, so a caller gets a clear answer rather than a refused connection:

```sh
AUTH="Proxy-Authorization: Bearer $(cat ~/.iron-vault-tokens/me)"
curl -si -H "$AUTH" http://127.0.0.1:7878/httpbin/headers
```

```text
HTTP/1.1 503 Service Unavailable
content-type: text/plain; charset=utf-8
content-length: 6

locked
```

The log records it as `"status":503,"outcome":"failure","reason":"locked"`.

### 3. Unlock

```sh
iron-vault unlock
```

```text
Vault passphrase:
the vault is unlocked: the service is Ready
```

A wrong passphrase changes nothing:

```text
iron-vault: the service answered error 14 (unlock-denied): wrong passphrase
```

After 5 wrong vault passphrases, `unlock` is refused for a cooldown that starts at 30 s and doubles up to 15 min,
before any prompt. `lock` does not clear the count.

The log shows each change of state, and the refused attempt (fields trimmed):

```json
{"event":"service.lock-transition","from_state":"ready","to_state":"locked"}
{"event":"vault.unlock-refused","refusal":"wrong_passphrase"}
{"event":"service.lock-transition","from_state":"locked","to_state":"checking"}
{"event":"service.lock-transition","from_state":"checking","to_state":"ready"}
```

### 4. Restart

Stop the service with Ctrl-C in its terminal. It logs `stopping on SIGINT`, then `stopped`. Start it again with the
command from [getting started](getting-started.md#2-start-the-service):

```sh
iron-vault serve --log-to-stdout | tee -a ~/iron-vault-dev.log
```

It comes back Locked, with its listeners open from the last published config:

```sh
iron-vault status | head -3
curl -si -H "$AUTH" http://127.0.0.1:7878/httpbin/headers | head -1
```

```text
service: locked
profile: development — no isolation from malware running as alice
vault: locked
HTTP/1.1 503 Service Unavailable
```

Nothing survives a restart but the encrypted vault, so unlock it:

```sh
iron-vault unlock
iron-vault status
```

```text
Vault passphrase:
the vault is unlocked: the service is Ready
service: ready
profile: development — no isolation from malware running as alice
vault: unlocked
vault id: 8c597c79-…
approval committed: 9
approval highest reserved: 9
memory protection: NOT protected, swap protection unavailable (RLIMIT_MEMLOCK soft limit is 8315834368 bytes, not unlimited)
recovery last checked: never (reminders counting since 2026-11-07)
credential httpbin_key: healthy
```

### 5. Expect `429` for a moment

The rate limit [starts empty](getting-started.md#rate-limits-start-empty) on every unlock. Straight after it:

```sh
curl -si -H "$AUTH" http://127.0.0.1:7878/httpbin/headers | head -1
sleep 6
curl -si -H "$AUTH" http://127.0.0.1:7878/httpbin/headers | head -1
```

```text
HTTP/1.1 429 Too Many Requests
HTTP/1.1 200 OK
```

## A lock survives a restart

`lock` leaves an empty file, `locked-by-owner`, in the [state directory](../reference/files.md#the-state-directory),
and a passphrase `unlock` removes it. While it is there, a restart, a crash or a reboot leaves the service Locked, even
where a host unlock would otherwise open the vault with no one present (the Docker Compose install, or a protected Linux
install with [TPM unlock](tpm-unlock.md)). The service logs it as `vault.host-unlock`
with `host_unlock_outcome` `owner_locked`.

If the service cannot write the file, `lock` still locks and clears the vault, and says on stderr that the lock will not
survive a restart. If a later `unlock` cannot remove it, `unlock` still succeeds and says on stderr that the next start
will stay Locked; `lock`, then `unlock` again once the state directory is writable, clears it.

## In a protected install

The same commands run through `sudo`: `sudo iron-vault lock`, `sudo iron-vault unlock`. The service is restarted by
systemd, with `sudo systemctl restart iron-vault`, and by every package upgrade; each time it comes back Locked and
needs `sudo iron-vault unlock`, unless [TPM unlock](tpm-unlock.md) is set up. See [protected Linux install](protected-linux.md).

## What can go wrong

- **`iron-vault: the service answered error 14 (unlock-denied): wrong passphrase`.** Type the vault passphrase, not
  the approval passphrase. After 5 wrong ones the cooldown starts.
- **`iron-vault: the Iron Vault service is not running: there is no admin socket at …`.** The service is stopped, or
  it was started with a different `XDG_RUNTIME_DIR`.
- **`503` with `policy invalid` after unlocking.** The published config failed its check. See
  [tamper detection and recovery](tamper-detection.md).
- **`unlock` is refused with `memory-unprotected`** (protected install only). The service could not lock its memory.
  The [installation guide](../installation/linux-install.md#install) says how to fix the limit.

## Reference

- [Service states](../reference/states.md): Locked, Checking, Ready and Unavailable.
- [CLI](../reference/cli.md#iron-vault-lock): `lock`, `unlock` and `status`.
- Related: [check and store your recovery key](recovery-key.md).
