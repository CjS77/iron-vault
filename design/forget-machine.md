# Forget machine

How `iron-vault forget-machine <age1…>` checks that a retired machine's recipient key is gone from the vault and prints
what the administrator does next to decommission the machine
([§16](iron-vault-specification.md#16-administration-recovery-and-migration), "Removing a recipient protects future
envelopes, not old backups"). It checks and advises. It never removes a recipient, deletes a file or runs a TPM tool: the
administrator runs every step it prints. Terms follow the [glossary](glossary.md); the recipient model is
[recipients.md](recipients.md), and the TPM on Linux is [tpm-unlock.md](tpm-unlock.md).

Three rules drive the design:

- **Read-only.** The command changes nothing the owner can see. Its one write is the one every read of the recipient
  inventory may make: the [inventory check](recipients.md#the-inventory-check) finishes or discards a recipient change
  that a crash left staged, as `recipient list` does, because the answer is wrong until it has ([decision
  6](#decisions)).
- **It never runs a tool.** The service and the CLI spawn no process. The TPM belongs to the host, and the CLI never
  calls it (§4); clearing a TPM destroys keys that other software on the machine may hold, which only the administrator
  can judge ([§16](iron-vault-specification.md#16-administration-recovery-and-migration): "Do not silently clear a
  shared TPM").
- **The vault that stays does the checking.** The retired machine's key is checked against the inventory of the vault
  that remains; the guidance is printed for the machine that goes.

## Where it runs

`forget-machine` runs against the **vault that stays**: a service that is Ready, with the retired machine's recipient
key as the argument.

- **Ready only.** The recipient inventory is a MAC'd file keyed from the vault identity, which only Ready holds. The
  command maps onto `AdminOperation::VaultChange`, as `recipient list` does, and in any other state ends with
  `wrong-state` before it reads anything.
- **Not on the retiring machine.** A vault copy that stays on the retiring machine still lists that machine's own
  `host-unlock` key, and `recipient remove` refuses that key while the machine's unlock handoff holds it
  ([recipients.md](recipients.md#recipient-remove-age1)). After `export` and `reset`, or after `import` elsewhere,
  there is no vault to ask. So the command is not run there; the retiring machine follows the printed steps by hand, and
  the [manual's recipe](../book/src/cookbook/forget-machine.md) says so. A command run there anyway answers
  `machine-not-forgotten` for the key it still lists, with a line that names this case.
- **After a migration** the new vault never held the old machine's key: the bundle carries none of the source's
  recipients ([tpm-unlock.md](tpm-unlock.md#enrolment-and-retirement)). The command then answers that the key is not a
  recipient, which is the true and wanted answer, and prints the guidance for the old machine.

## What it checks

In this order, under the service-wide lock the inventory check takes (tried, so `busy` at once if it is taken):

1. **State and key.** The service is Ready, else `wrong-state`; the argument parses as an `age1…` recipient key, else
   `recipient-invalid`.
2. **The key is not a recipient.** The inventory check runs (`recipient-inventory-damaged` or `vault-write-failed` when
   it cannot); a key that is still enrolled ends the command with `machine-not-forgotten`. The message gives the key's
   role and label and the command to run, `iron-vault recipient remove <key>`. Nothing is changed. Every role counts,
   `operational` and `recovery` included: the command never says a key in use is gone.
3. **The independence rule holds** on the inventory as it is
   ([recipients.md](recipients.md#independence-rule), parts 2 to 4; part 1 needs the host unlock configuration, which
   a removal already checked). A removal enforces the rule, so this fails only for an inventory restored from an old
   copy or edited around the service. The result carries which part failed.
4. **The recovery path is recent.** The [recovery check record](recovery.md#the-recovery-check-record) says the last
   successful `recovery check` is no older than the config's `reminder_days` (90 by default): the same fact `status`
   shows as `overdue`, taken from the same code. A recipient of role `recovery` is what part 3 of the rule already
   demands; this part says whether the owner has lately proved the key opens the vault. A record that is `never
   checked`, `unknown` or past the interval is a warning.

Steps 3 and 4 never stop the command. A failed one is a **warning** on stderr and in the result, and the guidance still
prints with the warning above it: the question the command answers, whether the key is gone, has its answer, and
withholding the steps would leave an administrator holding a lost machine with nothing. The warning says what to fix
before clearing any TPM. The command exits 0 when the key is not a recipient, and 1 with `machine-not-forgotten` when
it is.

The check proves the key is absent, not that it was ever there. A mistyped key reads as forgotten. The output repeats
the key as given, and the guidance tells the administrator to compare it with the retiring machine's provisioning
output or `recipient list` ([decision 3](#decisions)).

## The guidance

Printed to stdout after the checks, the same for every call so that it is testable byte for byte. The retired machine
held one of two things, and the text covers both rather than asking which:

> Iron Vault runs none of these steps. Run them on the retired machine, as root.
>
> If this machine held TPM unlock, its recipient had the role `host-unlock`:
>
> 1. Find out what else uses the TPM. Clearing it destroys every key it holds.
>    - disk encryption: `systemd-cryptenroll DEVICE` for each LUKS device lists its TPM keyslots;
>    - other sealed credentials: `grep -rl LoadCredentialEncrypted /etc/systemd /usr/lib/systemd` and
>      `ls /etc/credstore.encrypted`;
>    - persistent handles: `tpm2_getcap handles-persistent`. The handle `0x81000001` is systemd's storage root key,
>      shared by every `systemd-creds` user on the machine;
>    - other software that keeps keys in the TPM, such as Clevis or `tpm2-pkcs11`, and every other user of the machine.
> 2. Delete the sealed credential: `systemctl stop iron-vault-host-unlock.service`, then
>    `rm /etc/iron-vault-host/host-unlock.cred`. A copy of that file in a backup still opens on this TPM.
> 3. Clear the TPM only when step 1 found nothing else that needs it and the recovery check above is recent. Use the
>    firmware's clear-TPM setting, or `tpm2_clear`. If anything else uses the TPM, leave it: step 2 has retired the
>    machine from this vault, and only the old backup copies stay reachable through this TPM.
>
> If the machine was lost or stolen, removing its recipient could not revoke what was already copied. Reissue every
> provider credential, then `iron-vault replace NAME` each one; `iron-vault list` names them.
>
> If the machine held only an `added` or `recovery` key, there is no TPM step: delete that key where it was kept.

The commands are fixed text. The service sends nothing the CLI interpolates except the key the administrator typed and
the warnings, so no vault content reaches the terminal.

## Decisions

The specification and the ticket leave these open; each is decided here, with its reason.

1. **Run on the vault that stays, in Ready.** The inventory needs the vault identity (above). The ticket's own
   description (`forget-machine <age1…>`, "the key must not be in `identity.age`'s recipient set") is this. *Reason:*
   it is the only place the question has an answer.
2. **Not supported on the retiring machine.** Before `reset` or after `export`, the vault copy there still lists the
   key; after `reset` there is none. *Reason:* the answer would be wrong or absent. The guidance does not need the
   vault, so the manual carries it for that machine.
3. **The role is not an argument.** The vault does not keep removed recipients, so the role of the retired key is not
   known; an argument could be wrong without anything noticing. One guidance covers both what a TPM machine held and
   what a machine without a TPM held. *Reason:* the cost of the extra lines is nothing, and a wrong `--role` would hide
   the TPM steps. In v0 the only recipient role that holds TPM state is `host-unlock`: `tpm`, role code 4, stays
   reserved ([tpm-unlock.md](tpm-unlock.md#the-recipient-role)), and when it is enrolled its guidance is these steps.
4. **A warning does not stop the guidance, and does not change the exit status.** *Reason:* see [What it
   checks](#what-it-checks). A script that must know reads the warnings on stderr, or the audit event.
5. **Overdue means the reminder is due.** One definition of "recent" for `status`, the reminder and this command.
   *Reason:* a second interval would let `status` say overdue while this command says fine.
6. **The inventory check may settle a staged change.** *Reason:* a staged change means `recipients.age` and
   `identity.age` disagree about the set; reading either alone could say a key is gone that is still in the envelope.
   The check is the same function `recipient list` runs and logs `recipient.change-recovered` when it settles one.
   Reading the inventory without it is not offered.
7. **The sealed credential's path and the unit names are the package's.** They come from
   [tpm-unlock.md](tpm-unlock.md#provisioning) and are fixed text here; the packaging ticket that renames either also
   changes this text and its test.

## Admin protocol

The CLI sends command 22, `forget-machine`, with one argument, tag 2: the key's text, as `recipient remove` sends it.
The result is [described in admin-protocol.md](admin-protocol.md#forget-machine): whether the independence rule holds
and which part failed, and the recovery check state as `status` carries it (tags 13 to 17). The one new error code is
52, `machine-not-forgotten`. The command also answers `wrong-state`, `busy`, `recipient-invalid`,
`recipient-inventory-damaged` and `vault-write-failed`, with their usual meanings.

## Audit event

`recipient.forget-checked`, written once the key parsed and the inventory check ran:

| Field | Value |
|---|---|
| `recipient` | the key checked |
| `forget_outcome` | `forgotten` or `still_enrolled` |
| `recipient_role` | the enrolled role's name, `still_enrolled` only |
| `independence` | `holds`, or `broken`; `forgotten` only |
| `recovery_due` | whether the recovery reminder is due; `forgotten` only |

INFO when the key is forgotten, the rule holds and no reminder is due; WARN otherwise. It holds no label and no secret.

## Interactions

- **Recipients** ([recipients.md](recipients.md)). `recipient remove` stays the only way to remove a key. This
  command is the check that follows it, and the first line of its failure says what to run.
- **Reset** ([reset.md](reset.md#what-reset-is-not)). Reset touches only the state and config directories and leaves
  `/etc/iron-vault-host` and the TPM alone; the printed steps are what retire them.
- **TPM unlock** ([tpm-unlock.md](tpm-unlock.md)). The TPM design makes no persistent TPM object of its own, so
  the printed steps have one file to delete and nothing to remove from the TPM short of clearing it.

## Release checks

On a real service, with a vault holding an `operational`, a `recovery` and a `host-unlock` recipient:

1. `forget-machine` for the `host-unlock` key answers `machine-not-forgotten` and names `recipient remove`; the
   inventory is as it was.
2. After `recipient remove` of that key and a `recovery check`, `forget-machine` for it exits 0 and prints the guidance
   and no warning.
3. The same call 100 days later with no check prints the overdue warning and the guidance.
4. In Locked, it ends with `wrong-state`.
5. `strace -f -e trace=execve,fork,clone` on the service across a run shows no `execve`.
