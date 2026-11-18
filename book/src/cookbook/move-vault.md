# Move a vault to a new machine

Move your vault, with the same credentials, vault ID and approval counters, to a new machine with `export` and
`import`. The old machine keeps serving until you retire it. See the
[migration bundle design](../../../design/migration-bundle.md) for what the bundle holds.

Run every `iron-vault` command through `sudo` (see [`sudo` in a protected
installation](../reference/cli.md#sudo-in-a-protected-installation)).

## Prerequisites

- **The source**, running and Ready, and its **vault passphrase**. A `tpm` approver's PIN can stand in for it (Ctrl-Y at
  the prompt).
- **The new machine**, with Iron Vault installed and its service running, and no vault: `iron-vault status` shows
  `vault: not initialized`.
- **A software approver** on the source, and its approval passphrase. `export` refuses a vault with no software approver
  (`approver-set-invalid`, error 42); enroll one first with [`approver add`](approval-signers.md).
- **A way to carry one file** between the machines, such as a USB stick or `scp`. **Carry the export passphrase
  separately.**

## Steps

### 1. Export on the source

```sh
iron-vault export vault.bundle
```

It asks for the vault passphrase, then for a new export passphrase, twice. **Make it long and new:** the bundle can be
guessed at offline.

```text
exported vault 3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b to vault.bundle: 3 credentials, 6144 bytes
the source vault keeps serving until you retire it
the bundle opens only with the export passphrase
```

If export was killed, remove `.vault.bundle.partial` before you run it again.

### 2. Carry the bundle to the new machine

Copy `vault.bundle` across. **Delete other copies once the import has worked.**

### 3. Import on the new machine

```sh
iron-vault import vault.bundle
```

It asks for the export passphrase, then shows a summary:

```text
import a migration bundle
  vault: 3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b
  credentials: 3
  approvers: approval passphrase
  committed approval: version 4; highest reserved version: 4
  config: the source's committed config, to be approved on this machine
  then: a new vault passphrase and a new recovery key for this machine
  routing starts after iron-vault config approve, at version 5 or later
```

A TPM approver shows as `bound to the source machine`; it cannot sign here.

Then it asks for a new vault passphrase, twice, and shows a new recovery key once, as `init` does. Store it as in
[check and store your recovery key](recovery-key.md), then type `yes`. It writes the source's config to
`vault.bundle.config.toml`:

```text
imported vault 3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b: 3 credentials, approval version 4 committed, highest reserved version 4
recipients: operational, recovery
the source's committed config has the digest blake2b:…
next:
  1. iron-vault unlock                    (the service then answers 503 until a config is approved)
  2. iron-vault config approve vault.bundle.config.toml
  …
```

### 4. Unlock, and approve the config

```sh
iron-vault unlock
iron-vault config approve vault.bundle.config.toml
```

`unlock` is expected to end with `unlocked-unavailable` (error 16), "the vault unlocked, but the config check failed",
and a non-zero exit status (a `set -e` script must allow it); requests get `503` until the approval.

Edit the config copy first if the new machine needs a different listener address or path. `config approve` lists the
whole config as added; answer with a software approver's passphrase. Then send a request through a route you use, as
[getting started](getting-started.md) does.

### 5. Replace the TPM approvers

Skip this step if the summary listed no approver `bound to the source machine`. Otherwise remove each one:

```sh
iron-vault approver list
iron-vault approver remove <approver ID>
```

To have a TPM approver here, enrol a new one as in [approve configs with a TPM PIN](tpm-approval.md).

### 6. Check the recovery key

```sh
iron-vault recovery check
```

Type the recovery key that import showed. See [check and store your recovery key](recovery-key.md).

### 7. Compare the versions with the source

On the source, run `iron-vault status` and compare its `approval committed` and `approval highest reserved` lines with
the versions import printed. If the source shows higher versions, a config was approved there after the export: export again, run [`iron-vault reset`](../reference/cli.md#iron-vault-reset) on the new machine to discard the vault
you imported, and import the new bundle.

### 8. Retire the source

Stop its service, and keep or destroy its state directory as you would any copy of the vault: its passphrase and
recovery key still open it. If it had TPM unlock, follow
[retire a machine](forget-machine.md) for its TPM.

## What can go wrong

- **`import-denied`.** The export passphrase was wrong. Nothing was written; run `import` again.
- **`already-initialized`.** The new machine has a vault, or files in its state directory that are not a vault.
- **`bundle-invalid`.** The file is not a bundle this version reads, or was damaged on the way. The message names the
  rule it failed. Nothing was written; export again from the source.
- **`import-failed`.** A write failed. `status` shows `import unfinished (run iron-vault import again)`, and `unlock`
  refuses. Run `import` again: it discards the unfinished import and starts over, with a new recovery key.
- **`migration-denied`** or **`migration-rate-limited`** from `export`. The vault passphrase was wrong, or wrong too
  many times; see the [errors reference](../reference/errors.md).

## Reference

- [CLI](../reference/cli.md#iron-vault-export): `export` and `import`.
- [Files and locations](../reference/files.md): the bundle, its partial file and the config copy.
- [Migration bundle design](../../../design/migration-bundle.md): what the bundle holds and how import checks it.
- Requirements: [§16](../../../design/iron-vault-specification.md#16-administration-recovery-and-migration).
