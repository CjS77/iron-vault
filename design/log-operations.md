# Log operations guide

How to run, rotate, collect and query the Iron Vault log. [Audit logging](audit-logging.md) defines what the log holds;
this guide covers the host and the tools around it (specification
[§3.15](iron-vault-specification.md#315-logging-and-v0-acceptance)). Terms follow the [glossary](glossary.md). Field,
event and reason names below are those of [audit-logging.md](audit-logging.md); when the two disagree, that document wins.

The log is JSON Lines: one JSON object per line, UTF-8, in one file, `iron-vault.log`. A line is a request event
(`request.completed`), an audit event (`config.approval-completed`, `service.lock-transition` and so on) or a diagnostic
record with no `event` field. Every line has `timestamp`, `level`, `target`, `service`, `service_version`,
`schema_version`, `deployment_profile` and `message` ([Record shape](audit-logging.md#record-shape)).

**Implementation status.** The service writes the bootstrap destination, follows a rename by `logrotate` and stops when a
write fails. The packaged unit (`LogsDirectory=iron-vault`, `LogsDirectoryMode=0750`), the shipped
`/etc/logrotate.d/iron-vault`, the Docker image and the Compose file are not in the repository yet, and the service does
not yet switch destination from the approved config's `[logging] destination`. Where this guide describes them, it
describes what [audit-logging.md](audit-logging.md#log-destination) requires them to be.

## Location and permissions

| Deployment | Log destination |
|---|---|
| Protected install (systemd) | `/var/log/iron-vault/iron-vault.log` |
| Development build | `$XDG_STATE_HOME/iron-vault-dev-log/iron-vault.log` (default `~/.local/state/iron-vault-dev-log`) |
| Docker or Compose | stdout ([Docker](#docker)) |

An approved config can move the log: `[logging] destination` is an absolute directory path or `"stdout"`. It is a setting
of the approved config, so it appears in the approval summary and takes effect when the config check activates it, never
from the unverified `config.toml`. Moving the directory also needs a new rotation rule ([Rotation](#rotation)).

**The log directory in a protected install:**

- It is owned by the service account, mode `0750`; the log file is `0640`. Callers have no access, so they cannot read or
  edit the audit log.
- The packaged unit's `LogsDirectory=iron-vault` and `LogsDirectoryMode=0750` make systemd create the directory for the
  service account before the service starts. The service never creates a protected log directory.
- A directory set by the approved config is yours to create, with the same owner and mode. A missing directory, or one
  that fails the [trusted-path rule](audit-logging.md#trust), stops `serve` at startup with one line on stderr, and fails
  the config check when a config names it.
- The service creates `iron-vault.log` itself, at `0640`. It refuses a file or directory that any group or other account
  can write, so never loosen the modes to give a tool access.

**Giving a collector read access.** Create a group for the collector and have it read; it must never write.

- The collector's account, and no caller account, is a member of the group that owns the log directory and file. The
  group is the service account's own unless you choose another for the collector ([Permissions](audit-logging.md#permissions)).
- Keep the modes at `0750` and `0640`. A group that can write the directory could plant `iron-vault.log` after a rotation,
  and the service would refuse to start.
- Never add a caller account to the group, and never make the log world-readable. Anyone who can read it sees every route,
  caller and refusal.
- After any change, restart the unit and check `systemctl status iron-vault`: the service reports an unusable directory
  there, not in the log.

How the group is assigned (the unit's `Group=`, or a group on the directory) is not fixed by the design yet.

## Rotation

The service writes one fixed file. `logrotate` renames it; the service sees that the name now points to a different
inode, opens a fresh `iron-vault.log` and carries on. No signal is involved.

The package ships `/etc/logrotate.d/iron-vault`, owned by root, mode `0644`:

```
/var/log/iron-vault/iron-vault.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    nocreate
    su iron-vault iron-vault
}
```

- **`nocreate`** is required. It overrides the global `create` in `/etc/logrotate.conf`, so `logrotate` only renames the
  file and the service creates the new one with the right owner and mode. With `create`, `logrotate` and the service race
  to create the file, and `logrotate` moves the service's new file aside as a `.backup` it never compresses or prunes.
- **`delaycompress`** leaves the renamed file uncompressed until the next rotation. A record written between the rename and
  the service's reopen lands in it, so no record is lost.
- **`su iron-vault iron-vault`** runs `logrotate` as the service account, in a directory root does not own.
- **A size limit** is a `maxsize` line added to the same rule, for example `maxsize 100M`. `logrotate` evaluates it when it
  runs (normally once a day from its timer), so run it more often if you need a hard cap.
- **A moved log directory** needs its own rule: copy the one above with the new path. The shipped rule then matches
  nothing, and `missingok` keeps it quiet. The service never writes to `/etc/logrotate.d`.

**Do not use these:**

- **`copytruncate`.** It loses every record written between its copy and its truncate. An audit log must not have that
  window, and the rename-based rule above needs no copy.
- **A `postrotate` signal.** `SIGHUP` means "reload the config" ([§3.9](iron-vault-specification.md#39-configuration-approval-and-reload)),
  so a rotation script would trigger a reload. The service needs no signal to follow a rename.
- **Rotating by hand** with `mv` is fine for the same reason; deleting the file under the service is too, and it creates
  a new one. Never `touch` or create `iron-vault.log` yourself: the service refuses a file it did not create with the
  right owner.

In development nothing rotates the log; remove the file, or run a user `logrotate` with its own state file.

## Docker

In Docker the service writes to stdout (`iron-vault serve --log-to-stdout`, the image's default command) and the container
runtime keeps the log. Rotation is the runtime's: set the log driver and its options in the Compose file.

```yaml
services:
  iron-vault:
    image: iron-vault
    logging:
      driver: json-file
      options:
        max-size: "50m"
        max-file: "30"
```

- **Do not use the `journald` log driver**, in Docker or in Podman. The journal's readers are not bound by the log
  directory's mode, and it breaks the decision that the service writes no journald output. Podman's default driver on
  Fedora and RHEL is `journald`, so select another explicitly: `--log-driver k8s-file --log-opt max-size=50m`, or
  `log_driver` and `log_size_max` in `containers.conf`.
- The `json-file` driver wraps each line in its own JSON object (`{"log":"...","stream":"stdout","time":"..."}`). A
  collector must unwrap `log` before it reads the record.
- Whoever controls the Docker daemon can read these logs, replace the service and run commands in its container
  ([§3.14](iron-vault-specification.md#314-docker-remote-servers-and-appliances)). A collector that reads container logs
  through the daemon's socket holds that control; prefer a host agent that reads the driver's files, owned by root.
- The service refuses `stdout` when stdout is the systemd journal, so `--log-to-stdout` is for containers and pipes, not
  for a unit.

## Collectors

Each example follows the file at its default path, keeps up with `logrotate` renaming it, and reads the lines as JSON. The
collector's account needs read access ([Location and permissions](#location-and-permissions)). Examples are checked by
reading against the field names, not run against a live service.

**Loki labels** are `service`, `event` and `level`, and `route` if you want it. Never label `request_id` or `caller`: each
distinct value would become its own stream. Keep them in the line and filter with `| json`. A diagnostic record has no
`event`, so its `event` label is empty or absent.

### Grafana Alloy to Loki

```alloy
local.file_match "iron_vault" {
  path_targets = [{ "__path__" = "/var/log/iron-vault/iron-vault.log" }]
}

loki.source.file "iron_vault" {
  targets    = local.file_match.iron_vault.targets
  forward_to = [loki.process.iron_vault.receiver]
}

loki.process "iron_vault" {
  stage.json {
    expressions = { service = "service", event = "event", level = "level", route = "route", ts = "timestamp" }
  }
  stage.timestamp {
    source = "ts"
    format = "RFC3339Nano"
  }
  stage.labels {
    values = { service = "", event = "", level = "", route = "" }
  }
  forward_to = [loki.write.default.receiver]
}

loki.write "default" {
  endpoint {
    url = "http://loki:3100/loki/api/v1/push"
  }
}
```

Promtail takes the same stages under `pipeline_stages` (`json`, `timestamp`, `labels`) and a `static_configs` entry with
`__path__`.

### Vector

```toml
[sources.iron_vault]
type = "file"
include = ["/var/log/iron-vault/iron-vault.log"]

[transforms.iron_vault_json]
type = "remap"
inputs = ["iron_vault"]
source = '''
. = parse_json!(.message)
.timestamp = parse_timestamp!(.timestamp, "%+")
.event = .event ?? "diagnostic"
'''

[sinks.loki]
type = "loki"
inputs = ["iron_vault_json"]
endpoint = "http://loki:3100"
encoding.codec = "json"
labels.service = "{{ service }}"
labels.event = "{{ event }}"
labels.level = "{{ level }}"
```

Vector's file source identifies a file by content, so it follows a rename. The `.event` line gives diagnostic records a
label value; Vector's template would otherwise fail on the missing field.

### Fluent Bit

`fluent-bit.conf`:

```ini
[SERVICE]
    Parsers_File parsers.conf

[INPUT]
    Name   tail
    Path   /var/log/iron-vault/iron-vault.log
    Parser iron_vault
    DB     /var/lib/fluent-bit/iron-vault.db

[OUTPUT]
    Name       loki
    Match      *
    Host       loki
    Port       3100
    Label_Keys $service,$event,$level
```

`parsers.conf`:

```ini
[PARSER]
    Name        iron_vault
    Format      json
    Time_Key    timestamp
    Time_Format %Y-%m-%dT%H:%M:%S.%LZ
```

The `tail` input follows a renamed file and keeps its place in the `DB` file.

### Filebeat to Elastic

```yaml
filebeat.inputs:
  - type: filestream
    id: iron-vault
    paths:
      - /var/log/iron-vault/iron-vault.log
    parsers:
      - ndjson:
          target: "iron_vault"

processors:
  - timestamp:
      field: iron_vault.timestamp
      layouts:
        - "2006-01-02T15:04:05.999999999Z07:00"
  - drop_fields:
      fields: ["iron_vault.timestamp"]

output.elasticsearch:
  hosts: ["https://elastic:9200"]
```

The `timestamp` processor writes the record's `timestamp` to `@timestamp`, so the service keeps its own field name. The
`target` keeps the record under `iron_vault`: Filebeat's index template (ECS) maps `event` and `service` as objects, and
Iron Vault's `event` and `service` are strings, which Elasticsearch would reject. Field types are stable across events by
rule ([Field rules](audit-logging.md#field-rules)), so a mapping built from the first record holds.

### OpenTelemetry Collector

Iron Vault does not send OTLP; a collector can convert the file.

```yaml
receivers:
  filelog:
    include: [/var/log/iron-vault/iron-vault.log]
    operators:
      - type: json_parser
        timestamp:
          parse_from: attributes.timestamp
          layout_type: strptime
          layout: "%Y-%m-%dT%H:%M:%S.%LZ"
        severity:
          parse_from: attributes.level

processors:
  resource:
    attributes:
      - key: service.name
        value: iron-vault
        action: upsert
  batch: {}

exporters:
  otlp:
    endpoint: otel-backend:4317

service:
  pipelines:
    logs:
      receivers: [filelog]
      processors: [resource, batch]
      exporters: [otlp]
```

## Querying

For local use with `jq`; reading the log needs the same group as a collector. Rotated files are the same format;
`zcat iron-vault.log.*.gz | jq ...` reads the compressed ones.

All refusals for a route (`brave` is a route name):

```sh
jq -c 'select(.event == "request.completed" and .route == "brave" and .outcome == "failure")
       | {timestamp, request_id, caller, status, reason}' /var/log/iron-vault/iron-vault.log
```

Everything about one request, which includes `response.scrubbed` and `request.defect` when they fired:

```sh
jq -c 'select(.request_id == "0f8fad5b-d9cb-469f-a165-70867728950e")' /var/log/iron-vault/iron-vault.log
```

Approvals in a time range (`timestamp` is UTC RFC 3339, so strings compare in time order):

```sh
jq -c 'select(.event == "config.approval-completed"
              and .timestamp >= "2026-11-01T00:00:00Z" and .timestamp < "2026-12-01T00:00:00Z")
       | {timestamp, version, config_digest}' /var/log/iron-vault/iron-vault.log
```

## Not supported

- **journald output.** The owner chose files. JSON inside journald's `MESSAGE` field loses journald's own field queries,
  and the journal's readers are not bound by the log directory's mode ([Owner decisions](audit-logging.md#owner-decisions)).
- **OTLP export from the service.** It brings heavy dependencies, possibly another copy of `rand`, and a further network
  path out of the process that holds the secrets. Use the [OpenTelemetry Collector](#opentelemetry-collector) outside it.
