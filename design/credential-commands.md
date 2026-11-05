# Replacing and removing credentials

How `iron-vault replace` and `iron-vault rm` change a credential record that already exists (specification
[§3.3](iron-vault-specification.md#33-credential-records-and-configuration),
[§3.13](iron-vault-specification.md#313-administration-recovery-and-migration)). It covers how the owner proves
presence, what happens to the routes that use the name, and how the change reaches the requests the service serves.
Terms follow the [glossary](glossary.md). The frames, prompts and error codes are in
[admin-protocol.md](admin-protocol.md#replace), and the store's writes are `Vault::replace` and `Vault::remove`.

Three rules drive the design:

- **A name never stands in for the record behind it** ([§1.3](iron-vault-specification.md#13-terms)). A replacement is
  a new record ID, so an account swapped under the same name shows as a new record (R-5).
- **Every name the active config references is in the vault manifest.** Approval already enforces this: activation
  refuses an unknown credential, which invalidates the whole config
  ([§3.9](iron-vault-specification.md#39-configuration-approval-and-reload)). Nothing here may break it.
- **Owner presence authorizes only the change the service just described.** The service writes its own summary
  ([§3.2](iron-vault-specification.md#32-service-and-cli-boundary)), and the owner proves presence after reading it.

## Owner presence

[§3.3](iron-vault-specification.md#33-credential-records-and-configuration) requires owner presence "through the
approval mechanism" for `replace` and `rm`. In v0 the service proves it like this, inside one exchange:

1. It sends a secret prompt, `Approval passphrase`, the same label `config approve` uses.
2. It reads `approver.age` and opens it with the passphrase (`open_signer_key`). The key inside must be the pinned
   approver in the approval state the service holds.
3. It drops the opened signer at once.

Presence reserves no approval version, signs nothing and writes nothing to `approval.age`. It proves only that the
person typing knows the approval passphrase now. A wrong passphrase, or a key that is not the pinned approver, ends
the exchange with `approval-denied` (code 9), before anything is written. That code's meaning widens from "the
approval passphrase was wrong" to "owner presence failed", which covers both uses. There is no second try in the same
exchange.

There is no separate `Type yes` confirmation. Typing the approval passphrase after the summary is the confirmation,
and cancelling the prompt declines. `config approve` asks for `yes` first so that declining never needs the
passphrase. A vault change has no version to protect, so a second prompt would add nothing.

**Alternative not taken: a signed vault-change payload.** The service could reserve a version and sign a payload
naming the vault change, as it signs a config. That needs a new payload purpose, a storage format and a verifier. It
would also consume approval versions on changes that are not approvals. Nothing ever verifies the signature later,
because the vault manifest's MAC already says which records are real. The passphrase check gives the same proof of
presence and none of that cost.

## Vault change check

Before writing, the service checks what the change would do to the active config. This is the **vault change check**:

1. Take the credential catalog as it is now, and apply the change to it:
   - **`rm`:** the name becomes *unknown*;
   - **`replace`:** the name becomes *usable*, with the new kind and permitted origins. This holds even when the record
     it replaces is damaged.
2. Run `activate` on the active config (the one the serving snapshot was built from) against that catalog, with the
   service's capabilities and account directory. Nothing is written, and the serving snapshot is not touched.
3. Refuse the change with `credential-in-use` (code 24) when activation fails on a route that uses the name. The
   message names each such route, in route-name order, and why it would fail.

An activation error on a route that does not use the name, or on a peer account, was not caused by the change, so it
does not refuse it. The config check after the write finds it, just as the next reload would.

The service runs the check before any prompt, so the owner is never asked for a passphrase or a secret that cannot
be used. It holds the service-wide lock from then until the write, so the active config and the catalog cannot change
in between (see [Order of steps](#order-of-steps)).

### `rm`: refused while any route uses the name

The dry run turns every route that uses the name into an unknown credential, so `rm` is refused whenever any route
uses the name. This includes a route that is unavailable because the record is damaged: it still names the
credential. The refusal names the routes. The owner first approves a config without them, then runs `rm`. Retiring a
service is therefore two steps: approve a config without its routes, then remove its credential.

This keeps the rule that every name the active config references is in the manifest:

- **No rebinding under live routes.** Once a name is removed, no active route names it. A later `add` of the name
  creates a record with a new record ID that no route uses. A route can use it only after an approval, whose summary
  shows the route and its credential to the owner. `add` needs no owner presence, so this is what stops malware with
  an admin connection from removing a name and adding its own account in its place (R-5).
- **No whole-config failure.** If a route still used a removed name, the next config check would fail with an
  unknown credential for the whole config, and the service would become Unavailable with every route down.
- **No storage format change.** The manifest stays a list of the records that exist.

**Alternative not taken: a manifest tombstone.** `rm` could leave a marker for the name in the manifest. The catalog
would report the name as *unusable*, so its routes become unavailable and the others keep serving; `add` would
refuse the name, and the next approval that no longer references it would clear the marker. That needs a manifest
format change that survives restarts, a new catalog entry and an approval step that writes the manifest. The owner
chose the simpler rule.

### `replace`: refused when a route would no longer activate

The dry run checks every route that uses the name against the new kind and origins. `replace` is refused when one of
them would fail:

- its upstream's host and port are not among the new permitted origins (`OriginNotPermitted`);
- its slot does not suit the new kind (`SlotMismatch`), such as a header slot for a Basic credential.

The refusal names each route and which rule it breaks. Replacing a secret with the same kind and origins never needs
a config change. To move a credential to origins its routes do not reach, the owner first approves a config without
those routes, then replaces the credential, then approves the routes for the new origins.

Replacing a damaged record is how it is repaired. Its routes are unavailable before the replace, and the dry run
checks them against the new record. A repair can therefore never bring back a route that the new record does not
permit.

## Vault change summary

Before the presence prompt, the service sends a **vault change summary** in one or more notices
([§3.2](iron-vault-specification.md#32-service-and-cli-boundary)). The CLI's display of it is never evidence of what
the owner authorized. The summary goes to the audit log too.

For `replace`:

```text
replace credential fx
  record: 0b7c2f9e-6a51-4d1e-9d43-1f2a3b4c5d6e -> a new record ID, assigned when the change is written
  kind: static -> static
  origins: api.fx.example:443 -> api.fx.example:443, api.fx.example:8443
  routes using fx: fx (callers: fx-mcp), fx-history (callers: fx-mcp, reports)
```

For `rm`:

```text
remove credential old_key
  record: 6f1e0d2c-3b4a-4958-8776-655443322110
  kind: basic
  origins: legacy.example:443
  routes using old_key: none
```

- The old kind and origins come from the record. A damaged record has neither, so the summary says
  `unknown (record damaged: <damage>)` and adds `routes available again: <routes>` for the routes the repair would
  bring back.
- The new record ID is drawn inside the write, so the summary cannot name it yet. The result carries it.
- Routes and callers are in name order. Each caller is listed with the routes the active config grants it. Every
  configured name is printed with the configured-name escaping of the approval summary
  ([§3.15](iron-vault-specification.md#315-logging-and-v0-acceptance)).
- `rm` only gets this far when no route uses the name, so its list is always `none`. The line stays, so the owner
  sees that the service checked.

## Order of steps

| Step | `replace` | `rm` | Refusal |
|---|---|---|---|
| 1 | The service is Ready; the name, kind and origins follow their rules | The service is Ready; the name follows its rule | `wrong-state`, `credential-invalid` |
| 2 | Try the service-wide lock, and record the check generation and the state | as `replace` | `busy` |
| 3 | The manifest lists the name, healthy or damaged | as `replace` | `unknown-credential` |
| 4 | Vault change check | as `replace` | `credential-in-use` |
| 5 | Vault change summary | as `replace` | |
| 6 | Owner presence | as `replace` | `approval-denied`, `approval-unavailable` |
| 7 | The secret prompts for the kind, as for `add` | | `credential-invalid` |
| 8 | The service is still Ready, with the check generation recorded in step 2; then `Vault::replace` | as `replace`, then `Vault::remove` | `wrong-state`, `vault-write-failed` |
| 9 | Config check with `ServiceEvent::VaultChanged`, then release the lock | as `replace` | `committed-not-active` |

A prompt that gets no owner input cancels the command before step 8, and nothing is written.

**The service-wide lock is held from step 2 to the response, prompts included,** as `config approve` holds it. The
check in step 4 and the summary in step 5 then stay true until the write, so presence authorizes exactly the change
it was shown. Meanwhile approvals and other vault writes get `busy`, and a reload waits. A `lock` does not wait for
the lock: like an approval, a vault change still at a prompt is cancelled by a `lock`. Step 8 therefore checks the
state and the check generation again, and a `lock` and `unlock` while the owner was typing ends the change with
`wrong-state`. Three prompts of up to 5 minutes each (presence, then a Basic username and password) can hold the
lock for up to 15 minutes.

**Alternative not taken: take the lock after the prompts,** as `add` does so that a slow owner never blocks an
approval. The change would then need the check and the summary again under the lock, and a refusal for a summary
that had gone stale, after the owner had typed both the passphrase and the secret.

Presence comes before the secret, so a caller without the approval passphrase never gets the owner to type a new
secret into the exchange.

## Reaching serving

`add` leaves the serving snapshot alone, because no active route can use a new name. `replace` and `rm` cannot: a
replaced record's routes must use the new secret, and a removed or replaced secret must leave memory
([§3.11](iron-vault-specification.md#311-recipients-startup-and-memory): "clear cached values on lock or
replacement").

So after the write commits, and before it releases the service-wide lock, the service runs the config check from
Ready, through the event `ServiceEvent::VaultChanged` on the Ready → Checking edge of
[§3.12](iron-vault-specification.md#312-service-states-and-errors) ([open question 1](#open-questions)). It runs
after a write that may have committed too, because the check reads whatever the disk holds. A write that failed
cleanly changed nothing and runs no check.

- **During the check** requests get `503` `checking`, as during a reload. The check opens a new vault from disk with
  the kept vault identity and builds a new serving snapshot.
- **When the check passes**, the service is Ready on the new snapshot. The config is unchanged, so the listener
  rebuild keeps every listener and its connections. Requests admitted earlier finish on the old snapshot. The replaced
  or removed secret is cleared when the last of them releases it, as the old snapshot's vault drops.
- **When the check fails**, the service is Unavailable with the check's failure reason, and the old snapshot is
  withdrawn. The vault change check makes this rare, because it only fails for a cause the change did not make.
  The command answers `committed-not-active` (code 12): the change is durable, but the service no longer serves.
  That code's meaning widens to cover a vault change.

**Alternative not taken: answer success, or `vault-write-failed`, when the check fails.** Success would hide that
the service stopped serving. `vault-write-failed` says the write failed, and it did not.

**Alternative not taken: swap only the vault inside the serving snapshot.** A serving snapshot is built only by the
config check, so there is one path that decides what is served.

## Audit events

These are audit events in the audit log; [audit-logging.md](audit-logging.md#audit-events) gives each one's exact
field names and types, and the record shape they share. None carries credential material or the approval passphrase.

| Event | Level | When | Fields |
|---|---|---|---|
| `credential.replaced` | INFO | the replace committed | name, old and new record IDs, old and new kind and origins (the old ones only for a healthy record) |
| `credential.removed` | INFO | the remove committed | name, record ID |

A superseded record file the write could not remove is recorded as `vault.superseded-left` at WARN, from the write
report; the next vault write removes it.

## Open questions

The specification leaves each point below open, or this design departs from its wording. The design takes the
default stated for each, until the owner decides.

1. **The event a vault change uses.** The [§3.12](iron-vault-specification.md#312-service-states-and-errors) diagram
   labels its one edge from Ready to Checking "explicit reload". *Default:* a new event, `ServiceEvent::VaultChanged`,
   on that edge, as an approval adds `ApprovalCommitting` there
   ([config-approval open question 3](config-approval.md#open-questions)). *Reload* stays the SIGHUP operation alone.
   The alternative reuses `Reload`, so a failed check after a vault change would be logged as a failed reload.
2. **"Update affected references explicitly".** [§3.13](iron-vault-specification.md#313-administration-recovery-and-migration)'s
   `replace` row asks `replace` to update affected references explicitly. *Default:* `replace` changes no reference
   itself. A route that would not activate refuses the replace, and the owner updates references by approving a
   config, which shows each change in its summary. The alternative edits the config as part of `replace`, which would
   make `replace` a second way to approve a config.
