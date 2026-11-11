# CLI

Every `iron-vault` command and option, with what each one does. The sections after the introduction are generated
from the same definitions the CLI parses, the way `iron-vault completions` is, so they say what
`iron-vault COMMAND --help` says.

## Secrets are never arguments

No argument or option ever takes a secret value. Arguments end up in shell history, process listings and error
messages, where a passphrase or a provider key must never appear
([§5](../../../design/iron-vault-specification.md#5-service-and-cli-separation-of-concerns)). A command that needs one has the
service prompt for it, and the CLI reads the answer in one of two ways:

- **From a terminal**, with echo off.
- **From stdin**, one line per prompt, when stdin is not a terminal. Pipe a secret in from a password manager, so it
  never reaches your shell history: `pass show fx | iron-vault add fx --origin api.fx.example`.

`init` is the exception: it shows the recovery key, so it needs a controlling terminal and refuses to run without
one.

## Host unlock

`iron-vault init --host-unlock` also enrols the host unlock identity from the unlock handoff as a recipient of the new
vault. The packaged and Container builds accept it; a `dev-mode` build rejects it as an unexpected argument
([design](../../../design/docker-compose.md#enrollment)).

## The admin socket

The CLI is a thin client. It opens nothing itself: each command sends one admin request to the service over the
**admin socket** and shows the answer
([admin protocol](../../../design/admin-protocol.md)). The service decides what to prompt for, and judges whoever
connects by the account the connection comes from. `serve` is the only command that runs the service; `completions`
is the only one that never contacts it.

The socket is `admin.sock` in the service's runtime directory: `/run/iron-vault/` in a protected installation, and
`$XDG_RUNTIME_DIR/iron-vault-dev/` in development mode ([Files and locations](files.md)). `--admin-socket PATH`
connects to another one, such as a socket forwarded over SSH; the service at the other end still judges the account
the connection arrives as.

## `sudo` in a protected installation

In a protected installation your login account is never an admin principal, so malware running as you cannot reach
the admin socket. Only root may connect, not even the `iron-vault` service account, so a compromised service cannot lock the vault or
spend your passphrase attempts. You run every client command through `sudo`:

```sh
sudo iron-vault unlock
sudo iron-vault status
```

That barrier is only as strong as your `sudo` setup; the [installation guide](../installation/linux-install.md)
covers credential caching and a second factor. In development mode the service runs as you, and you run the same
commands without `sudo`.

## Build features

Every build has the same commands and options. The `dev-mode` and `container` Cargo features change the deployment
profile, and with it the paths, the service account and which accounts may administer the service, but no command
or option. `iron-vault --version` lists the features a binary was built with.

`--help` (`-h` for a summary) works on every command and is not repeated below.

<!-- Generated from the CLI definition below this line. Do not edit by hand. -->

## `iron-vault`

```text
iron-vault [OPTIONS] <COMMAND>
```

Iron Vault: a local proxy that holds API credentials so the programs that use them never do.

- `--admin-socket <PATH>`: Use the admin socket at PATH instead of this installation's, for example one forwarded over SSH. Every client command takes it; `serve` refuses it, because the service always binds its own installation's socket.
  - global: it may also follow the command

```text
Exit codes:
  0  success
  1  the service answered with an error
  2  usage error
  3  no answer from the service: it is not running, this account may not connect, the exchange failed, a prompt
     got no value, or a secret value the service sent could not be shown on a terminal; `reset` also exits 3,
     before it connects, when stdin is not a terminal or /dev/tty cannot be opened; `export` also exits 3 when
     the bundle it received is incomplete or cannot be kept
  4  `status`: the service answered, and it is not Ready; `list`: no vault is open, so the credentials are unknown
```

## `iron-vault serve`

```text
iron-vault serve [OPTIONS]
```

Run the service until SIGTERM or SIGINT.

In a protected installation systemd starts it as the `iron-vault` service account, so you never run it yourself. It starts Locked: run `unlock` after each start.

- `--log-to-stdout`: Write the log to stdout until an approved config names a destination, as the Docker image does. The service refuses it when stdout is the systemd journal.

## `iron-vault ping`

```text
iron-vault ping [OPTIONS]
```

Check that the service is running and show its deployment profile.

## `iron-vault status`

```text
iron-vault status [OPTIONS]
```

Show the service, vault, approval, memory protection, host unlock outcome and credential states, without secrets. It exits 4 when the service answers and is not Ready.

## `iron-vault list`

```text
iron-vault list [OPTIONS]
```

List every credential with its kind, permitted origins and standing, never a secret. It needs an open vault, and exits 4 while none is open.

## `iron-vault unlock`

```text
iron-vault unlock [OPTIONS]
```

Open the vault: the service prompts for the vault passphrase, read with echo off or from stdin.

## `iron-vault lock`

```text
iron-vault lock [OPTIONS]
```

Clear the vault identity and every cached secret from the service's memory, leaving it Locked.

The lock lasts across restarts: run `unlock` to end it.

## `iron-vault init`

```text
iron-vault init [OPTIONS]
```

Create the vault: the service prompts for the vault and approval passphrases, shows the recovery key once on the controlling terminal, and once you confirm you saved it, writes the vault and approves the initial config as version 1. It needs a controlling terminal, and leaves the service Locked.

- `--host-unlock`: Also enrol the identity in the unlock handoff as a recipient, so a restart unlocks with no owner present. The service refuses to start `init` if the handoff is absent or untrusted. A dev-mode build does not accept this flag.

## `iron-vault reset`

```text
iron-vault reset [OPTIONS]
```

Discard the vault and the config, so `init` can make a new vault: the way out when no passphrase, recovery key or approver works. It asks for no owner factor, only a confirmation typed at a terminal, which is the vault ID, or the state directory's path when no vault is Initialized. It refuses a pipe, a file or a missing `/dev/tty` with exit code 3 before it connects. The service locks first, then removes the store's files and the config, keeps any foreign file, and ends Locked. Nothing can be recovered afterwards: keep your own copy of the config.

## `iron-vault export`

```text
iron-vault export [OPTIONS] <BUNDLE>
```

Write the vault as a migration bundle to BUNDLE, for `import` on another machine. The service checks the vault, prompts for the vault passphrase to authorize the export, then for a new export passphrase, typed twice, which seals the bundle; `import` asks for it. The bundle arrives in `.<BUNDLE name>.partial` beside BUNDLE, created with mode 0600 before anything is sent, and takes BUNDLE's name only once it is whole. An existing BUNDLE or a leftover partial file is refused before anything is sent. The source vault keeps serving afterwards.

- `<BUNDLE>`: Where to write the bundle; it must not exist.
  - required

## `iron-vault caller-token`

```text
iron-vault caller-token [OPTIONS]
```

Issue a fresh caller token: it goes to stdout once, and its token_hash line to stderr. The service keeps no copy; the token works once a config naming the hash is approved with `config approve`.

## `iron-vault add`

```text
iron-vault add [OPTIONS] --origin <ORIGIN> <NAME>
```

Enrol a new credential under NAME; the service prompts for the secret, read with echo off or from stdin, so `pass show fx | iron-vault add fx --origin api.fx.example` works. It never overwrites an existing name.

- `<NAME>`: The credential name, which routes reference.
  - required
- `--kind <KIND>`: The credential's kind: a static key, or a Basic username and password.
  - default: `static`
  - possible values:
    - `static`: A provider key, sent as is.
    - `basic`: A username and password, sent as `Authorization: Basic`.
- `--origin <ORIGIN>`: A permitted origin: `host`, `host:port`, `[v6]` or `[v6]:port`, without a scheme (HTTPS is implied); the port defaults to 443. Repeat for each origin, up to 32.
  - required
  - repeatable

## `iron-vault replace`

```text
iron-vault replace [OPTIONS] --origin <ORIGIN> <NAME>
```

Replace NAME's record with a new one, and with it the kind and the origins; the old record need not be readable, so this also repairs a damaged one. The service shows what changes, asks for the approval passphrase as owner presence, then prompts for the new secret. On stdin, the first line is the approval passphrase and the rest the secret. Routes that use NAME keep working only if the new kind and origins suit them; otherwise nothing changes.

- `<NAME>`: The credential name.
  - required
- `--kind <KIND>`: The new kind: a static key, or a Basic username and password.
  - default: `static`
  - possible values:
    - `static`: A provider key, sent as is.
    - `basic`: A username and password, sent as `Authorization: Basic`.
- `--origin <ORIGIN>`: A new permitted origin, as for `add`. Repeat for each origin, up to 32; the old origins are not kept.
  - required
  - repeatable

## `iron-vault rm`

```text
iron-vault rm [OPTIONS] <NAME>
```

Remove the credential NAME after you type the approval passphrase. It refuses while a route of the active config uses the name: approve a config without those routes first.

- `<NAME>`: The credential name to remove.
  - required

## `iron-vault config`

```text
iron-vault config [OPTIONS] <COMMAND>
```

Change the approved configuration.

## `iron-vault config approve`

```text
iron-vault config approve [OPTIONS] <FILE>
```

Propose FILE as the new config: the service shows its summary, asks for confirmation and the approval passphrase, then commits, publishes and activates it. Stdin is not read for the config, because it carries the answers to the prompts when it is not a terminal.

- `<FILE>`: The proposed config file.
  - required

## `iron-vault recovery`

```text
iron-vault recovery [OPTIONS] <COMMAND>
```

Check the owner's offline recovery key.

## `iron-vault recovery check`

```text
iron-vault recovery check [OPTIONS]
```

Prove that your offline recovery key opens this vault: the service prompts for the key, read with echo off or from stdin, so `pass show iron-vault-recovery | sudo iron-vault recovery check` works. It works while the service is Locked or Ready, changes nothing but the time it records, and keeps no copy of the key.

## `iron-vault recipient`

```text
iron-vault recipient [OPTIONS] <COMMAND>
```

Manage the keys that can open the vault.

## `iron-vault recipient list`

```text
iron-vault recipient list [OPTIONS]
```

List every enrolled recipient, one line each: its `age1...` key, role, enrolment time and label. It works while the service is Ready, and refuses a missing or damaged recipient inventory without changing it.

## `iron-vault recipient add`

```text
iron-vault recipient add [OPTIONS] --label <LABEL> [RECIPIENT]
```

Enroll RECIPIENT, an `age1...` public key, as another way to open the vault. This is the alternate migration path: whoever holds the key can open the vault identity, and with it every credential. The service shows what changes, then asks for the vault passphrase, which an unlocked vault does not replace. Old copies of `identity.age` are not affected.

With --recovery, the service instead generates a new offline recovery key and shows it once, as `init` does; save it, type yes, then authorize with the vault passphrase. Check it with `recovery check`, then remove the old recovery key with `recipient remove`.

With --host-unlock, RECIPIENT is a host unlock identity's key, such as a new one provisioned after a lost TPM. It is enrolled with the `host-unlock` role and authorized the same way. Once a restart reaches Ready with no `unlock`, remove the old `host-unlock` recipient with `recipient remove`.

- `<RECIPIENT>`: The `age1...` public key to enroll.
- `--recovery`: Generate a new recovery key and enroll it, instead of enrolling a key you supply.
- `--host-unlock`: Enroll RECIPIENT as the host unlock identity's recipient, role `host-unlock`, rather than `added`.
- `--label <LABEL>`: Which device or copy the key is, 1 to 64 bytes: `alice laptop 2026`.
  - required

## `iron-vault recipient remove`

```text
iron-vault recipient remove [OPTIONS] <RECIPIENT>
```

Remove an enrolled recipient by its `age1...` key. The service shows what will change, then asks for the approval passphrase. It refuses the operational recipient, the last recovery recipient and, in the Protected and Container profiles, the `host-unlock` recipient whose identity the unlock handoff holds. It says that copies of `identity.age` made before still open with the removed key.

- `<RECIPIENT>`: The recipient's `age1...` key, as `recipient list` prints it.
  - required

## `iron-vault approver`

```text
iron-vault approver [OPTIONS] <COMMAND>
```

Manage the approvers that sign configuration approvals.

## `iron-vault approver list`

```text
iron-vault approver list [OPTIONS]
```

List every approver, one line each: its approver ID, signer kind, enrolment time, `active` when it signed the active approval, and label. The first line is the approver a prompt asks first. It works while the service is Ready.

## `iron-vault approver add`

```text
iron-vault approver add [OPTIONS] --label <LABEL>
```

Enroll another approval signer. The service shows what changes, asks for the approval passphrase of an approver already pinned, then for the new signer's own approval passphrase, twice; choose one different from the vault passphrase. The new signer alone can approve a config, so keep its passphrase apart from the first. Prints the new approver's ID.

- `--label <LABEL>`: What the approver is, 1 to 64 bytes: `backup passphrase`.
  - required
- `--kind <KIND>`: The signer kind. `tpm` is offered only on a protected install with the TPM signing helper, and asks for a PIN of at least 6 characters; the service refuses the kinds it does not offer.
  - default: `software`
  - possible values:
    - `software`: A key sealed to its own approval passphrase.
    - `tpm`: A TPM approval key with a PIN.
    - `hardware`: A hardware key with PIN and touch.

## `iron-vault approver remove`

```text
iron-vault approver remove [OPTIONS] <APPROVER>
```

Remove an approval signer, named by the approver ID `approver list` prints. The service shows what changes, then asks for the approval passphrase of any pinned approver, the one being removed included. It refuses the last approver and the approver that signed the active approval: approve the config with another approver first. Copies of the state directory made before still pin the removed approver. Prints nothing on success.

- `<APPROVER>`: The approver ID, a UUID.
  - required

## `iron-vault forget-machine`

```text
iron-vault forget-machine [OPTIONS] <RECIPIENT>
```

Check that a retired machine's recipient key is gone from the vault, then print how to decommission the machine. Run it on the vault that stays, with the key `recipient list` showed for the machine. It exits 1 with `machine-not-forgotten`, telling you to run `recipient remove`, while the key is still enrolled. It warns when the vault no longer meets the independence rule or no recovery check has run lately. It changes nothing and runs no TPM tool: you run every step it prints.

- `<RECIPIENT>`: The retired machine's `age1...` recipient key.
  - required

## `iron-vault completions`

```text
iron-vault completions [OPTIONS] <SHELL>
```

Print a shell completion script to stdout. It never contacts the service, so it also runs at build time.

- `<SHELL>`: The shell to generate the script for.
  - required
  - possible values:
    - `bash`: Bash, through the bash-completion framework.
