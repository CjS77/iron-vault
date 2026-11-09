# Owner notifications

How the service tells the owner about approvals, vault changes and failures without the owner reading the audit log
(specification [§5](iron-vault-specification.md#5-service-and-cli-separation-of-concerns) and
[§18](iron-vault-specification.md#18-logging)). Terms follow the [glossary](glossary.md).

**Phase.** Owner notifications ship in v1, the OAuth phase, in EP-40
([future spec §1](future-specifications.md#1-v1-oauth-login-and-refresh)). v0 has none: the service's own summary of an operation goes only to
the command's result and the audit log. This document is the design for v1; nothing in it applies to v0.

Delivery is the hard part. The service runs as the service account, `iron-vault`. The owner's desktop belongs to the
owner's login account, which in a protected install has no authority and is never an admin principal
([§5](iron-vault-specification.md#5-service-and-cli-separation-of-concerns)). Malware running as that account controls what the
desktop shows ([§2](iron-vault-specification.md#2-security-promise-and-limits)). This design decides which events
notify, how a notification reaches the desktop without giving the login account any new authority, and what happens
where there is no desktop.

The design is written as the default answers to the [open questions](#open-questions), which the owner has not yet
decided.

## Model

An **owner notification** is a short, secret-free message the service makes from exactly one audit event. It says what
happened and what to do about it. It is informational only:

- it never asks for input;
- it carries no actions, buttons or links;
- it is never evidence that something did or did not happen.

The audit log and `sudo iron-vault status` stay the authority, because
[§2](iron-vault-specification.md#2-security-promise-and-limits) says no display on a compromised desktop can be
trusted.

Every owner notification is written to the audit log as the audit event
[`owner.notified`](#the-ownernotified-audit-event), in every deployment. That record is the log-only fallback. It is
also the record of what the owner was told, and the one event name a collector can alert on.

Where the owner has a desktop, the service also streams each owner notification over the
[notification socket](#notification-socket) to the [notification agent](#notification-agent), which shows it on the
desktop. The service never detects desktops: "a desktop is available" means only that an agent is connected.

## Which events notify

Each notification topic is a fixed snake_case label (`NotificationTopic`). The source events are the typed audit
events of the [audit log catalogue](audit-logging.md#catalogue). Each row is one source event. Its body is built from
that source event struct's domain-typed fields, and its remediation is a fixed phrase for that source (for
`config.check-failed`, one per unavailable reason).

| Topic | Source event | Urgency | Body | Remediation |
|---|---|---|---|---|
| `approval_completed` | `config.approval-completed` | normal | `version <version>: <headline>`, the headline of the struct's approval summary | If this is not the change you approved, read the audit log and run `sudo iron-vault status` |
| `approval_refused` | `config.approval-refused` | normal | `<refusal>` (`wrong_passphrase` or `key_mismatch`) | If this was not you, someone can act as an admin principal: review who can use `sudo` |
| `unlock_refused` | `vault.unlock-refused` | normal | `<refusal>` | If this was not you, someone can act as an admin principal: review who can use `sudo` |
| `vault_changed` | `credential.added` | normal | `<credential>: added, <kind>; origins <host:port,...>` | If you did not make this change, run `sudo iron-vault list` and read the audit log |
| `vault_changed` | `credential.replaced` | normal | `<credential>: replaced, <old_kind> → <kind>; origins <old origins> → <origins>`; for a damaged old record, `<credential>: replaced, <kind>; origins <origins>` | If you did not make this change, run `sudo iron-vault list` and read the audit log |
| `vault_changed` | `credential.removed` | normal | `<credential>: removed` | If you did not make this change, run `sudo iron-vault list` and read the audit log |
| `service_unavailable` | `config.check-failed` | critical | `<unavailable_reason>: <failure>` | For `policy_invalid`: Run `sudo iron-vault status`; approving a valid config makes the service ready again. For `recovery_needed`: Run `sudo iron-vault status` and read the audit log; the service needs an authorized repair or a restart |
| `service_unavailable` | `config.activation-failed`, only for an uncertain commit that could not be settled | critical | `version <version>: <detail>`, where the detail is the cause's fixed phrase | Run `sudo iron-vault status` and read the audit log; the service needs an authorized repair or a restart |
| `vault_damaged` | `vault.record-damaged` | critical | `<credential>: record <damage>; its routes are unavailable` | The fixed phrase the source records in its own `remediation`, one per damage kind |
| `vault_damaged` | `vault.shared-state-damaged` | critical | `<file>: <damage>; the whole vault is unavailable` | The fixed phrase the source records in its own `remediation` |
| `vault_damaged` | `vault.commit-uncertain` | critical | `<file>: replaced, but may not survive power loss (<error_kind>)` | Check the storage that holds the state directory, then run `sudo iron-vault status` |
| `vault_damaged` | `config.commit-uncertain` | critical | `version <version>: committed, but may not survive power loss (<error_kind>)` | The service settles the commit itself; if a `service_unavailable` notification follows, run `sudo iron-vault status` |
| `vault_damaged` | `config.conflicting-approval-discarded` | critical | `version <version>: a second approval for another config was discarded` | Find out who can write to the config directory, and read the audit log |
| `hardening_incomplete` | `service.hardening-incomplete` | critical | `core dumps <core_dumps>; memory <memory_protection>` | The fixed phrases the source records in its own `remediation`, one per missing protection |
| `recovery_reminder` | `recovery.reminder` | normal | by `recovery_record`: `last checked <last_checked>`, `never checked (counting since <reminders_since>)`, or `check record unusable (<error_kind>)` | The fixed phrase the source records in its own `remediation`: run the recovery check, and keep copies of the approved config and of `iron-vault list` with the recovery key ([recovery.md](recovery.md#reminders)) |
| `recovery_check_failed` | `recovery.checked`, only when `recovery_outcome` is `failed` | critical | `the recovery key did not open the vault` | Check that you used the current recovery key; if it no longer opens the vault, replace it before you need it |

`config.activation-failed` notifies only for an uncertain commit that could not be settled. Its other cause, a failed
config check after a committed approval, already records `config.check-failed`, which notifies on its own.

In [§15](iron-vault-specification.md#15-service-states-and-errors) only Checking leads to Unavailable, and every
way out of Checking into Unavailable records `config.check-failed` but one: a commit that could not be settled ends
Checking at once, without running the config check, and records `config.activation-failed`
([config-approval.md](config-approval.md#when-a-step-fails)). So `config.check-failed`, plus the unsettled commit,
raises exactly one `service_unavailable` each time the service becomes Unavailable.

The recovery topics are EP-40 work in v1. Their source events come with the recovery epic in v0
([§16](iron-vault-specification.md#16-administration-recovery-and-migration)), which sends reminders through the
log alone; EP-40 makes those events notify once both exist.

### Reserved topics

These topics are designed here and built by the epics that bring their source events. Each gains its row in the
table above when it is built:

- `needs_touch` ([§15](iron-vault-specification.md#15-service-states-and-errors),
  [future spec §2.1](future-specifications.md#21-hardware-key-recipients-signers-and-touch-confirmation); the hardware-key
  phase);
- `needs_login` ([future spec §1.3](future-specifications.md#13-refresh-token-rotation-and-crash-recovery); v1);
- `migration_refused`, from `migration.authorization-refused`
  ([§16](iron-vault-specification.md#16-administration-recovery-and-migration),
  [migration-authorization.md](migration-authorization.md#audit-events); v1, once the migration authorization epic
  emits its source event in v0). A refused migration authorization can mean someone is guessing the vault passphrase.

### Deliberately not notifying

- Request events and scrub events: there are too many of them, and they are the caller's business.
- `admin.command`.
- A lock or unlock the owner made.
- `config.approval-failed`, which the owner already sees in the command's result.

[Open questions](#open-questions) 4 to 6 revisit these choices.

## The `owner.notified` audit event

| Event | Level | Fields |
|---|---|---|
| `owner.notified` | INFO | `topic`, `source_event` (the source event's event name), `urgency` (`normal` or `critical`), `title`, `body`, `remediation` |

How it is emitted:

- Each source event's struct implements `audit::NotifiesOwner`, whose `notification(&self) -> Option<OwnerNotification>`
  is built only from that struct's own domain-typed fields.
- The struct's `emit()` writes its own record first, then `owner.notified`.
- No call site changes, so a notifying event cannot forget to notify.
- `title` is a fixed phrase per topic. `body` is at most 1024 bytes, cut at a character boundary and ended with `…`.
- Configured names go through the same escaping of configured names as the
  [approval summary](config-approval.md#approval-summary).
- Origins are written as `host:port`, never as `https://…`, so no notification contains anything that looks like a URL.

**Alternative not taken:** a `tracing` layer that builds notifications from the field values of any record. It would
match on field-name strings, and the approval summary's headline is not in the `config.approval-completed` record. The
typed method keeps the mapping from event to notification checked by the compiler.

## Delivery options considered

| Option | How | Trust trade-offs | Verdict |
|---|---|---|---|
| D-Bus `org.freedesktop.Notifications` from the service | The service connects to the owner's session bus at `/run/user/<uid>/bus` | That directory is `0700` and owned by the login account, and the session bus admits only its own uid. The service would need root, `CAP_SETUID` or `CAP_DAC_OVERRIDE` to reach it, which breaks the dedicated-account boundary ([§4](iron-vault-specification.md#4-installation-and-ownership)). It would also put a D-Bus client into the process that holds the secrets, talking to a bus that malware running as the owner controls: malware can own the `org.freedesktop.Notifications` name and answer with crafted messages. | Rejected |
| `notify-send` through `systemd-run --user --machine=<user>@` | The service spawns a helper into the user's service manager | Needs root, or a polkit rule for the service account. It forks child processes from the process that holds the secrets, whose environment must then be controlled. The text is in argv, which other accounts can read in `/proc/<pid>/cmdline`. | Rejected |
| A per-user agent on the admin socket | The agent connects to `admin.sock` | The login account would have to become an admin principal, against [§5](iron-vault-specification.md#5-service-and-cli-separation-of-concerns)'s rule that it never is in a protected install. That hands the admin interface to malware running as the owner. Even a read-only command would widen the `0600` socket and the admin principal check. | Rejected |
| The agent tails the audit log | The login account joins the log's reader group | The login account can then read the whole log, including every request event of every caller, other accounts' routes and failure details: far more than a notification needs. | Rejected |
| A system-bus signal | The service emits a signal on the system bus and the agent subscribes | Needs a D-Bus client in the service and a system-bus policy file. A broadcast signal reaches every subscriber the policy allows, and that policy is easy to get wrong. A peer-checked Unix socket does the same with code the service already has. | Rejected |
| Email, webhook or push service from the service | Outbound network from the service | Another egress path out of the process that holds the secrets. A collector can turn `owner.notified` records into alerts outside the service. | Not in the service; documented as collector alerting |
| **The notification socket and a per-user agent** | [Below](#the-notification-socket-and-the-notification-agent) | [Below](#why-a-caller-can-neither-read-nor-forge-a-notification) | **Chosen** |
| Log only | `owner.notified` in the audit log | No new channel; the owner needs a collector, or must read the log | Always present; the only delivery on servers, in Docker and on macOS and Windows |

## The notification socket and the notification agent

### Notification account

- The approved config may name one OS account to receive owner notifications: `[notifications] account = "alice"`.
  This is normally the owner's login account. The owner is a person, never an account.
- The config check resolves the name to a uid through the account directory, as it resolves a peer caller's account.
  A name that does not resolve refuses the config.
- The approval summary shows the notification account in a "Notifications" section, old → new, so redirecting
  notifications to another account is never hidden. The implementing ticket adds that section to the approval
  summary's fixed sections.
- With no `[notifications]` section there is no desktop delivery, only the log.
- This follows audit-logging decision
  [D1](audit-logging.md#d1-the-log-directory-is-set-in-configtoml): the approved config is the one reviewed record of
  how the service behaves. [Open question 1](#open-questions) gives the cost.

Naming an account as the notification account gives it no other authority. It never becomes an admin principal, and it
gains nothing on the request interface.

### Notification socket

- `notify.sock` in the runtime directory (`/run/iron-vault/notify.sock` in a protected install), bound at startup like
  the admin socket, with the same socket-file checks.
- Mode `0666`, as for request sockets: the mode grants nothing, and the kernel-reported peer uid decides.
- The service accepts a connection only when the peer's uid is the notification account's uid in the active policy.
  Every other peer, and every peer while no notification account is set, is closed at once and recorded as a WARN
  diagnostic record with the peer uid.
- At most 4 connections at a time.
- The socket is **one-way**: the service never reads from it.
- The service writes one JSON object per line:
  `{"schema_version":1,"timestamp":"…","topic":"…","urgency":"…","title":"…","body":"…","remediation":"…"}`. The
  values are those of the `owner.notified` record.
- Each write has a 5-second timeout. An agent whose connection queue (at most 64 lines) fills is disconnected, so
  delivery never blocks the code that emits audit events.
- When a newly activated config changes the notification account, the old account's connections are closed.
- The socket file is removed on shutdown, as the admin socket's is.
- The socket keeps working through Locked and Unavailable, with the notification account from the last activated
  config.
- Before any config naming a notification account has activated, for example at boot, nothing reaches the desktop
  ([open question 1](#open-questions)).

### Delivery to agents

- A `tracing` layer installed by `serve` passes each `owner.notified` record to the notification socket's sender. It
  copies the record's fields and builds nothing. What an agent can read is therefore a subset of the audit log, never
  more.
- A new owner notification goes to every connected agent of the notification account.
- While no agent is connected, it waits in the **notification backlog**:
  - in memory only, never on disk;
  - at most 32 owner notifications, the oldest dropped first;
  - cleared on restart.
- The first agent to connect receives the backlog, and those entries then leave it. No later connection replays
  them, so restarting the agent does not repeat old notifications.

### Notification agent

The notification agent, `iron-vault-notify`, is a separate crate and binary.

- It runs as the notification account in the owner's graphical session, from a shipped `systemd --user` unit bound to
  `graphical-session.target`.
- It connects to the notification socket and reads lines of at most 8 KiB. It drops a malformed or oversized line and
  carries on.
- It shows each line through `org.freedesktop.Notifications.Notify` on its own session bus:
  - app name `Iron Vault`;
  - summary: the title;
  - body: the body, then the remediation;
  - no actions;
  - urgency hint 2 for `critical`, 1 otherwise;
  - a critical notification does not expire.
- It escapes `&`, `<` and `>` when the notification server advertises `body-markup`, so a configured name can never
  become markup or a link.
- It reconnects with a backoff from 1 to 60 seconds.
- It is trusted no more than the login account it runs as, and it holds nothing secret.

The D-Bus client lives in this separate crate so that the service process never links one. `zbus` 5 with
`default-features = false, features = ["tokio"]` is expected to bring no new copy of `rand`, `rand_core` or
`getrandom`; the implementing ticket checks `Cargo.lock` again.

## Why a caller can neither read nor forge a notification

**Read.**

- Owner notifications describe policy (credential names, origins, approval headlines) and failures.
- A caller of another account must not learn them, just as
  [§15](iron-vault-specification.md#15-service-states-and-errors) hides other callers' grants behind `404`.
- So they never travel on the request interface, and the notification socket admits only the notification account.
- **Accepted limit:** on a single-user desktop, callers often run as the owner's login account, and malware running as
  that account can connect in place of the agent and read owner notifications. That is new information to it, since
  the config is `0600` and the log `0640`. The owner opts in by naming the account
  ([open question 2](#open-questions)).

**Forge.**

- The stream is one-way and comes only from the service, so no caller can inject a notification into it, such as a
  fake "approved version 8" to hide a real change.
- A process running as the login account can still post a lookalike desktop notification straight to its own session
  bus. No design prevents this ([§2](iron-vault-specification.md#2-security-promise-and-limits)).
- That is why owner notifications never ask for input, never carry actions or links, never tell the owner to type a
  secret, and are never the authority.

**Block.** Malware running as the owner can kill the agent, or drain the socket first. A missing notification proves
nothing, and `owner.notified` in the log still records that one was raised.

## Where there is no desktop

On servers, in Docker and on macOS and Windows, leave `[notifications]` out. Every owner notification is then only its
`owner.notified` record. In v1 the [log operations guide](../book/src/reference/log-operations.md) gains a collector alert rule on
`event="owner.notified"`, keyed by `urgency`.

In Docker:

- the runtime directory is never mounted into application containers, so neither the admin socket nor the
  notification socket reaches a caller ([§17](iron-vault-specification.md#17-docker-remote-servers-and-appliances));
- `[notifications]` is pointless there, because no agent can connect.

## No secrets

An owner notification is made only from the source event struct's domain-typed fields. These are mostly the fields of
the source's own record. The one exception is the approval summary's headline, which comes from the `summary` field of
`audit::ApprovalCompleted` and is not in the `config.approval-completed` record, which holds the whole rendered summary
instead. So a notification holds only:

- configured names, kinds, `host:port` origins, versions, fixed labels and fixed phrases;
- never a secret, token, passphrase, header value, URL, path, query, body, config bytes or library error text (the
  [never-logged list](audit-logging.md#never-logged)).

Delivery through the `tracing` layer adds a second guarantee: the socket carries only fields of an `owner.notified`
record, which already passed those rules.

## Specification changes

Proposed for the owner's approval ([open question 7](#open-questions)); they apply from v1:

- [§5](iron-vault-specification.md#5-service-and-cli-separation-of-concerns) gains the one-way notification socket, a third
  interface: it sends owner notifications only to the notification account the approved config names, reads nothing
  and grants nothing, and the notification account never becomes an admin principal. Notifications are informational
  and never request input or serve as evidence of an operation.
- [§17](iron-vault-specification.md#17-docker-remote-servers-and-appliances) adds the notification socket to what
  application containers never receive.
- [implementation spec §1](implementation-specification.md#1-implementation-structure) adds the crate `iron-vault-notify`, the desktop
  notification agent.

## Open questions

Questions for the owner. Each has a default, which the design above follows and the implementing tickets build.

1. **Where the notification account is set.** *Default:* the approved config (`[notifications] account`), shown in
   the approval summary.
   - The cost: before a config naming an account has activated (at boot, or when the config never verifies), nothing
     reaches the desktop. Startup failures and "locked after reboot" are then only in the log.
   - The alternative is a `serve --notify-account <name>` flag in the root-owned unit. It reaches the desktop from boot,
     but no approval summary ever shows it, which is why audit-logging
     [D1](audit-logging.md#d1-the-log-directory-is-set-in-configtoml) rejected a flag for the log directory.
2. **Content exposure.** On a desktop, the notification account, and any caller or malware running as it, learns
   credential names, origins, approval headlines and unavailable reasons it cannot read today. *Default:* accepted,
   because the owner opts in by naming the account. The alternative is content-free notifications ("Iron Vault needs
   attention: run `sudo iron-vault status`"), which disclose nothing.
3. **Approval body.** *Default:* the version plus the approval summary's headline. The alternative is the full approval
   summary, which is long, names hosts and base paths, and is truncated by most notification servers.
   [§5](iron-vault-specification.md#5-service-and-cli-separation-of-concerns) says owner notifications carry the approval summary
   and [§18](iron-vault-specification.md#18-logging) that they contain the operation summary; the
   default reads that as the headline, with the full summary in the audit log's `config.approval-completed`.
4. **Refusals.** *Default:* notify on `config.approval-refused` and `vault.unlock-refused`, but not on `admin.refused`
   (`not_admin_principal`), to avoid noise. Should a refused admin-socket peer, which is malware probing, notify too?
5. **Ready again.** *Default:* no notification when the service returns to Ready after Unavailable. Should one pair
   each `service_unavailable`?
6. **Locked at start.** *Default:* none. It needs a new audit event, and under question 1's default the notification
   account is not yet known at boot.
7. **Specification additions.** Approve the [specification changes](#specification-changes): the
   [§5](iron-vault-specification.md#5-service-and-cli-separation-of-concerns) notification socket (a third interface), the
   [§17](iron-vault-specification.md#17-docker-remote-servers-and-appliances) line, and the new crate
   `iron-vault-notify` in [implementation spec §1](implementation-specification.md#1-implementation-structure), which already assigns
   notifications to `iron-vault`. The service side stays in `iron-vault`; only the desktop agent is separate, so the
   service never links a D-Bus client.
8. **Platforms.** *Default:* Linux only. macOS and Windows are log-only until a later phase gives them an agent
   transport of their own.
9. **Commit-uncertain alerts.** *Default:* `vault.commit-uncertain` and `config.commit-uncertain` each raise a
   critical `vault_damaged`. A commit that settles a moment later still raises one. The alternative notifies only when
   settling fails, which already raises `service_unavailable`.
10. **The field name `body`.** *Default:* `owner.notified` records its text in `body`. The name reads close to the
    never-logged rule for request and response bodies. The alternative is `message`, though every record already has
    a `message` field, its fixed phrase, so it would need another name, such as `notification_text`.

## Spec check

Checked against [§2](iron-vault-specification.md#2-security-promise-and-limits) (no trusted display on a compromised
desktop: notifications are never input or authority), [§4](iron-vault-specification.md#4-installation-and-ownership)
(the service keeps its dedicated account and gains no privilege over the owner's session),
[§5](iron-vault-specification.md#5-service-and-cli-separation-of-concerns) (the login account never becomes an admin principal;
see open question 3 for the summary), [§15](iron-vault-specification.md#15-service-states-and-errors),
[§17](iron-vault-specification.md#17-docker-remote-servers-and-appliances) (no socket reaches a container),
[§18](iron-vault-specification.md#18-logging) (notifications carry remediation and never secrets)
and [implementation spec §1](implementation-specification.md#1-implementation-structure). v0 is unchanged: it has no notification socket, no
agent and no `owner.notified` event.
