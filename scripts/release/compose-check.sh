#!/usr/bin/env bash
# Release check for the Docker Compose profile: caller isolation and container hardening
# (design/docker-compose.md "Release checks"; spec §7, §14, §17, §19, implementation spec §2).
#
# !! RUN THE FULL CHECK ONLY ON A DISPOSABLE VM. !!  It runs as root and, on the host, creates the `iron-vault` account (uid 460),
# /run/iron-vault, /run/iron-vault-unlock, /etc/iron-vault-host and /usr/local/bin/iron-vault, builds two Docker images, and starts
# a Compose project named ivcheck from packaging/compose/compose.yaml. All of it is removed on every exit path.
#
# Set up:
#   1. A fresh Ubuntu LTS VM with Docker Engine and the Compose plugin, sudo, util-linux (runuser, script), openssl, curl and jq.
#      Nothing of Iron Vault's may be installed: the script refuses to start if any of the paths above, or an `iron-vault`
#      account, already exists.
#   2. An ordinary account to play another host user:  sudo useradd -m testuser
#   3. This repository checked out on the VM. The service image is built from packaging/compose/Dockerfile (a few minutes of
#      cargo build), unless --image names one already built.
#
# Run:  sudo scripts/release/compose-check.sh --i-know-this-is-a-disposable-vm [--image REF] [--override FILE]... TEST_ACCOUNT
#   TEST_ACCOUNT  an existing account that is not root and not iron-vault.
#   --image       a service image already built from packaging/compose/Dockerfile (default: build one).
#   --override    a Compose file merged over compose.yaml, to try a broken variant. Repeatable. The script's own image override
#                 (the compose file's all-zero image digests cannot be pulled) is merged last.
#
# Static checks only, which need no root, no VM and no image (docker, the Compose plugin and jq are enough):
#   scripts/release/compose-check.sh --static-only [--compose FILE] [--override FILE]...
#
# Prints one PASS or FAIL line per check, with the reason under a FAIL, and exits 1 if any check failed. Exit 2 means the
# script could not start (bad arguments, a missing tool, not root, no opt-in, host paths already taken, an image that will not
# build). Setup failures after the host is touched also exit 2; cleanup still runs.
#
# Which unlock path: the stack is unlocked with the vault passphrase over the admin socket, as `iron-vault unlock` does. The
# host unlock handoff (K-252) is not used, so /run/iron-vault-unlock is an empty directory and this check does not depend on it.
# The jq programs are single-quoted on purpose: $name in them is jq's, not the shell's.
# shellcheck disable=SC2016
set -euo pipefail

SERVICE_UID=460
SERVICE_ACCOUNT=iron-vault
PROJECT=ivcheck
SERVICE_IMAGE=ivcheck-iron-vault:check
CALLER_IMAGE=ivcheck-caller:check
HOST_CLI=/usr/local/bin/iron-vault
HOST_DIR=/etc/iron-vault-host
HOST_TLS=$HOST_DIR/tls
RUN_DIR=/run/iron-vault
UNLOCK_DIR=/run/iron-vault-unlock
SPOOFER=ivcheck-spoofer
# Fixed by packaging/compose/compose.yaml and config.example.toml; the static checks read the file, the live ones use these.
LISTENER_A=172.30.1.2
LISTENER_B=172.30.2.2
SPOOFED_B=172.30.2.3
SPOOF_IP=172.30.1.4
VAULT_PASS="ivcheck vault passphrase"
APPROVAL_PASS="ivcheck approval passphrase"

REPO=""
COMPOSE=""
COMPOSE_ARGS=()
ACCOUNT=""
IMAGE=""
STATIC_ONLY=0
WORK=""
CONFIG_JSON=""
PASSED=0
FAILED=0
# Cleanup flags: each is set just before the thing it undoes is made.
STACK_UP=0
BUILT_SERVICE=0
BUILT_CALLER=0
CREATED_CLI=0
CREATED_HOST=0
CREATED_ACCOUNT=0

die() { echo "error: $*" >&2; exit 2; }

# --- Check framework (the same as linux-install-check.sh) ---------------------------------------------------------------

# Runs one check in this shell (not a subshell, so the cleanup flags survive). Prints PASS, or FAIL and what it said.
check() {
    local name=$1 out="$WORK/check.out"
    shift
    if "$@" >"$out" 2>&1; then
        echo "PASS $name"
        PASSED=$((PASSED + 1))
    else
        echo "FAIL $name"
        sed 's/^/     /' "$out"
        FAILED=$((FAILED + 1))
    fi
}

# grep -q exits at the first match, which under pipefail would fail the pipeline it ends, so output goes via a variable.
has_line() { grep -q "$1" <<<"$2"; }

compose() { docker compose -p "$PROJECT" "${COMPOSE_ARGS[@]}" "$@"; }

# --- Static checks: read `docker compose config --format json` ----------------------------------------------------------

# Shared jq definitions. A caller is any service but iron-vault. A caller network is one that iron-vault and a caller share; a
# caller may have other networks of its own, but never a non-internal one. `covers` is true for a host path that is, or contains,
# one of the Docker socket and vault paths, so mounting /var/run or /var/lib/docker is caught as well as the socket itself. Compose renders `core: 0` as `{}`, so a missing soft or hard
# limit in an object counts as 0.
JQ_DEFS='
def callers: .services | to_entries | map(select(.key != "iron-vault"));
def caps(l): (l // []) | map(ltrimstr("CAP_") | ascii_upcase);
def nets(s): (s.networks // {}) | keys;
def members($n): .services | to_entries | map(select(nets(.value) | index($n))) | map(.key) | sort;
def callernets: . as $root | [callers[] | nets(.value)[]] | unique | map(. as $n | select($root | members($n) | index("iron-vault") != null));
def iv: .services["iron-vault"];
def protected: ["/run/docker.sock", "/var/run/docker.sock", "/run/iron-vault", "/run/iron-vault-unlock", "/etc/iron-vault-host", "/var/lib/docker"];
def covers($src): ($src | sub("/+$"; "")) as $s | protected | any(. == $s or $s == "" or startswith($s + "/"));
. as $r |
'

# Succeeds when the jq program prints nothing; otherwise prints its lines, one violation each, and fails.
no_violations() {
    local out
    out=$(jq -r "$JQ_DEFS $1" "$CONFIG_JSON") || { echo "jq failed on the program"; return 1; }
    [ -z "$out" ] || { echo "$out"; return 1; }
}

# Proves the programs below are looking at a real stack: an empty services list would make every one of them pass.
config_has_the_stack() {
    jq -e '(.services["iron-vault"] != null) and ((.services | length) >= 2)' "$CONFIG_JSON" >/dev/null \
        || { echo "the resolved config has no iron-vault service, or no caller"; return 1; }
}

callers_drop_net_raw() {
    no_violations 'callers[] | select((caps(.value.cap_add) | any(. == "NET_RAW" or . == "ALL"))
                                      or (caps(.value.cap_drop) | any(. == "NET_RAW" or . == "ALL") | not))
                   | "\(.key) keeps NET_RAW: cap_drop \(.value.cap_drop // []), cap_add \(.value.cap_add // [])"'
}

no_service_is_privileged() {
    no_violations '.services | to_entries[] | .key as $k | .value as $v
        | (if $v.privileged == true then "\($k) is privileged" else empty end,
           if $v.pid != null then "\($k) sets pid: \($v.pid)" else empty end,
           if $v.ipc != null then "\($k) sets ipc: \($v.ipc)" else empty end,
           if $v.network_mode != null then "\($k) sets network_mode: \($v.network_mode)" else empty end,
           if ($v.devices // [] | length) > 0 then "\($k) maps devices" else empty end,
           if ($v.volumes_from // [] | length) > 0 then "\($k) takes volumes_from" else empty end,
           if ($v.security_opt // [] | any(test("unconfined"))) then "\($k) turns off seccomp or apparmor" else empty end,
           if (caps($v.cap_add) | any(. == "NET_ADMIN")) then "\($k) adds NET_ADMIN" else empty end)'
}

# A caller shares no mount with iron-vault (the state, config, runtime, unlock and TLS mounts), and mounts neither the Docker
# socket, /var/lib/docker, a vault path, nor any directory that contains one.
callers_mount_nothing_of_the_vault() {
    no_violations '(iv.volumes // [] | map(.source)) as $ivsrc
        | callers[] | .key as $k | (.value.volumes // [])[]
        | select((.source // "" | test("docker\\.sock|iron-vault")) or (.target | test("docker\\.sock|iron-vault"))
                 or (.type == "bind" and covers(.source)) or (.source as $s | $ivsrc | index($s)))
        | "\($k) mounts \(.source // "an anonymous volume") at \(.target)"'
}

caller_networks_are_internal() {
    no_violations 'callernets[] as $n | select($r.networks[$n].internal != true) | "network \($n) is not internal"'
}

# Each caller network holds iron-vault and exactly one caller, and every caller has one.
caller_networks_hold_one_caller() {
    no_violations '(callers[] | select((nets(.value) | map(. as $n | $r | members($n) | index("iron-vault") != null) | any) | not)
         | "\(.key) shares no network with iron-vault"),
        (callernets[] as $n | members($n) as $m | select(($m | index("iron-vault") | not) or (($m - ["iron-vault"]) | length) != 1)
         | "network \($n) holds \($m | join(", ")); want iron-vault and exactly one caller")'
}

no_caller_on_egress() {
    no_violations 'callers[] | .key as $k | nets(.value)[] as $n | select($n == "egress" or $r.networks[$n].internal != true)
                   | "\($k) is on the non-internal network \($n)"'
}

# The bridge has no host address, so a host process cannot reach a listener and be taken for a caller; IPv6 is off.
caller_networks_are_isolated() {
    no_violations 'callernets[] as $n | $r.networks[$n] as $d
        | (if ($d.driver_opts // {})["com.docker.network.bridge.gateway_mode_ipv4"] != "isolated"
           then "network \($n) does not use gateway_mode_ipv4 isolated" else empty end,
           if $d.enable_ipv6 != false then "network \($n) does not turn IPv6 off" else empty end)'
}

# Every container on a caller network has an address of its own, so none can be handed the service's while it is stopped.
caller_network_members_have_static_addresses() {
    no_violations 'callernets as $cn | .services | to_entries[] | .key as $k | (.value.networks // {}) | to_entries[]
        | select(.key as $n | $cn | index($n)) | select((.value // {}).ipv4_address == null)
        | "\($k) has no ipv4_address on \(.key)"'
}

iron_vault_memlock_is_unlimited() {
    no_violations 'iv.ulimits.memlock as $m | select(($m == -1 or ($m | type == "object" and .soft == -1 and .hard == -1)) | not)
                   | "memlock is \($m | tojson), want -1"'
}

iron_vault_core_is_zero() {
    no_violations 'iv.ulimits.core as $c | select(($c == 0 or ($c | type == "object" and (.soft // 0) == 0 and (.hard // 0) == 0)) | not)
                   | "core is \($c | tojson), want 0"'
}

iron_vault_is_read_only() { no_violations 'select(iv.read_only != true) | "read_only is \(iv.read_only | tojson)"'; }

iron_vault_drops_all_capabilities() {
    no_violations '(if (caps(iv.cap_drop) | index("ALL")) == null then "cap_drop lacks ALL" else empty end),
                   (if (caps(iv.cap_add) | length) > 0 then "cap_add is set: \(iv.cap_add)" else empty end)'
}

iron_vault_runs_as_the_fixed_uid() {
    no_violations "select(iv.user != \"$SERVICE_UID:$SERVICE_UID\") | \"user is \(iv.user | tojson)\""
}

run_static_checks() {
    check "the resolved config has iron-vault and a caller" config_has_the_stack
    check "static: every caller drops NET_RAW" callers_drop_net_raw
    check "static: no service is privileged or shares a host or foreign namespace" no_service_is_privileged
    check "static: no caller mounts the Docker socket or anything of the vault" callers_mount_nothing_of_the_vault
    check "static: every caller network is internal" caller_networks_are_internal
    check "static: every caller network holds iron-vault and exactly one caller" caller_networks_hold_one_caller
    check "static: no caller is on egress" no_caller_on_egress
    check "static: caller networks have no host address and no IPv6" caller_networks_are_isolated
    check "static: every container on a caller network has a static address" caller_network_members_have_static_addresses
    check "static: iron-vault has memlock -1" iron_vault_memlock_is_unlimited
    check "static: iron-vault has core 0" iron_vault_core_is_zero
    check "static: iron-vault is read_only" iron_vault_is_read_only
    check "static: iron-vault drops ALL capabilities" iron_vault_drops_all_capabilities
    check "static: iron-vault runs as $SERVICE_UID:$SERVICE_UID" iron_vault_runs_as_the_fixed_uid
}

# --- Live setup: runs before the stack exists; a failure here is exit 2 ---------------------------------------------------

as_account() { runuser -u "$ACCOUNT" -- "$@"; }

# Names the host, kernel and Docker versions at the top of the output, because the release record needs them (design open
# question 6: the minimum Docker Engine version is recorded by this check).
banner() {
    # shellcheck source=/dev/null
    echo "compose-check on $(. /etc/os-release && echo "$PRETTY_NAME"), kernel $(uname -r), $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "docker $(docker version --format '{{.Server.Version}}'), compose $(docker compose version --short)"
}

# Cleanup removes by name and by project label, so anything of that name already here would be deleted with the check's own.
refuse_leftovers() {
    local label="label=com.docker.compose.project=$PROJECT" kind image
    for kind in "container ls -a" "volume ls" "network ls"; do
        # shellcheck disable=SC2086
        [ -z "$(docker $kind -q --filter "$label")" ] || die "a Docker ${kind%% *} labelled com.docker.compose.project=$PROJECT already exists"
    done
    ! docker container inspect "$SPOOFER" >/dev/null 2>&1 || die "a container named $SPOOFER already exists"
    for image in "$SERVICE_IMAGE" "$CALLER_IMAGE"; do
        ! docker image inspect "$image" >/dev/null 2>&1 || die "the image $image already exists"
    done
}

preflight() {
    local tool path
    for tool in openssl script runuser sudo curl getent useradd groupadd userdel groupdel ip; do
        command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
    done
    docker info >/dev/null 2>&1 || die "the Docker daemon is not reachable"
    for path in "$HOST_CLI" "$HOST_DIR" "$RUN_DIR" "$UNLOCK_DIR"; do
        [ ! -e "$path" ] || die "$path already exists; this check needs a host with nothing of Iron Vault's on it"
    done
    # getent with two keys fails when either is missing, so each key is asked on its own.
    for path in "$SERVICE_ACCOUNT" "$SERVICE_UID"; do
        ! getent passwd "$path" >/dev/null || die "an account named or numbered $path exists"
        ! getent group "$path" >/dev/null || die "a group named or numbered $path exists"
    done
    refuse_leftovers
    id "$ACCOUNT" >/dev/null 2>&1 || die "no account $ACCOUNT"
    [ "$(id -u "$ACCOUNT")" -ne 0 ] || die "TEST_ACCOUNT must not be root"
    # Positive control: if runuser silently fails, "the account is refused" would pass for the wrong reason.
    [ "$(as_account id -u 2>/dev/null)" = "$(id -u "$ACCOUNT")" ] || die "runuser did not run a command as $ACCOUNT"
}

build_images() {
    if [ -n "$IMAGE" ]; then
        SERVICE_IMAGE=$IMAGE
    else
        BUILT_SERVICE=1
        docker build -q -f "$REPO/packaging/compose/Dockerfile" -t "$SERVICE_IMAGE" "$REPO" >/dev/null || die "the service image did not build"
    fi
    BUILT_CALLER=1
    # curl and python3 are the caller's tools for the checks; the Compose file's placeholder callers only sleep.
    docker build -q -t "$CALLER_IMAGE" - >/dev/null <<'DOCKERFILE' || die "the caller image did not build"
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl python3 && rm -rf /var/lib/apt/lists/*
DOCKERFILE
}

# The Compose file's image digests are all-zero placeholders, so the images built here replace them in a merged file.
add_image_override() {
    cat >"$WORK/images.yaml" <<YAML
services:
  iron-vault: { image: $SERVICE_IMAGE, pull_policy: never }
  caller-a: { image: $CALLER_IMAGE, pull_policy: never }
  caller-b: { image: $CALLER_IMAGE, pull_policy: never }
YAML
    COMPOSE_ARGS+=(-f "$WORK/images.yaml")
}

# The layout design/docker-compose.md "Host layout" gives, less the files only the host unlock needs.
create_host_layout() {
    CREATED_ACCOUNT=1
    groupadd --system --gid "$SERVICE_UID" "$SERVICE_ACCOUNT"
    useradd --system --uid "$SERVICE_UID" --gid "$SERVICE_UID" --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin "$SERVICE_ACCOUNT"
    CREATED_HOST=1
    install -d -m 0711 -o "$SERVICE_ACCOUNT" -g "$SERVICE_ACCOUNT" "$RUN_DIR"
    install -d -m 0755 "$UNLOCK_DIR"
    install -d -m 0700 "$HOST_DIR"
    install -d -m 0755 "$HOST_TLS"
}

# One CA and one server certificate naming both listener addresses; only iron-vault holds the key.
create_certificates() {
    local ext="$WORK/san.ext" curve="-newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes" name
    # shellcheck disable=SC2086
    {
        openssl req -x509 $curve -keyout "$WORK/ca.key" -out "$WORK/ca.crt" -subj /CN=ivcheck-ca -days 2 \
            -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign
        openssl req -new $curve -keyout "$WORK/server.key" -out "$WORK/server.csr" -subj /CN=iron-vault
    } 2>/dev/null
    printf 'subjectAltName=IP:%s,IP:%s\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' "$LISTENER_A" "$LISTENER_B" >"$ext"
    openssl x509 -req -in "$WORK/server.csr" -CA "$WORK/ca.crt" -CAkey "$WORK/ca.key" -CAcreateserial -days 2 \
        -extfile "$ext" -out "$WORK/server.crt" 2>/dev/null
    for name in caller-a caller-b; do
        install -m 0644 "$WORK/server.crt" "$HOST_TLS/$name.crt"
        install -m 0600 -o "$SERVICE_ACCOUNT" -g "$SERVICE_ACCOUNT" "$WORK/server.key" "$HOST_TLS/$name.key"
    done
}

# The host CLI is the image's own binary, copied out as the design's host setup does.
install_host_cli() {
    local ctr
    ctr=$(docker create "$SERVICE_IMAGE") || die "cannot create a container from $SERVICE_IMAGE"
    docker cp "$ctr:/usr/bin/iron-vault" "$WORK/iron-vault" >/dev/null || { docker rm "$ctr" >/dev/null; die "cannot copy the binary out"; }
    docker rm "$ctr" >/dev/null
    CREATED_CLI=1
    install -m 0755 -o root -g root "$WORK/iron-vault" "$HOST_CLI"
}

run_live_setup() {
    preflight
    banner
    build_images
    add_image_override
    create_host_layout
    create_certificates
    install_host_cli
}

# --- Bringing the stack up and making it Ready ---------------------------------------------------------------------------

cid() { compose ps -q "$1"; }

wait_for_admin_socket() {
    local _
    for _ in $(seq 60); do
        "$HOST_CLI" ping >/dev/null 2>&1 && return 0
        sleep 0.5
    done
    return 1
}

stack_comes_up() {
    STACK_UP=1
    compose up -d --no-build 2>&1 || return 1
    wait_for_admin_socket || { echo "no answer on the admin socket"; compose logs --tail 20 iron-vault; return 1; }
}

# `init` shows the recovery key on the controlling terminal only, so it runs under script(1), which gives it a pty while its
# stdin stays the answers file. The key is redacted from any output this prints.
run_init() {
    printf '%s\n' "$VAULT_PASS" "$VAULT_PASS" "$APPROVAL_PASS" "$APPROVAL_PASS" yes >"$WORK/init.in"
    HOST_CLI=$HOST_CLI INIT_IN=$WORK/init.in script -qec '"$HOST_CLI" init <"$INIT_IN"' /dev/null </dev/null >"$WORK/init.out" 2>&1 \
        || { sed 's/AGE-SECRET-KEY-[A-Z0-9]*/[recovery key]/' "$WORK/init.out" | tail -n 5; return 1; }
}

# The callers trust the CA by a file copied into them, not a mount: a caller has no host mounts at all.
trust_ca() { local c; for c in caller-a caller-b; do docker cp "$WORK/ca.crt" "$(cid "$c"):/ca.crt" || return 1; done; }

# Unlock is by passphrase over the admin socket, so the check does not depend on the host unlock handoff.
provision() {
    run_init || return 1
    printf '%s\n' "$VAULT_PASS" | "$HOST_CLI" unlock || return 1
    printf '%s\n' ivcheck-not-a-real-key | "$HOST_CLI" add venice_chat --origin api.venice.ai || return 1
    printf '%s\n' ivcheck-not-a-real-key | "$HOST_CLI" add brave --origin api.search.brave.com || return 1
    printf '%s\n' yes "$APPROVAL_PASS" | "$HOST_CLI" config approve "$REPO/packaging/compose/config.example.toml" || return 1
    trust_ca
}

# --- Live checks: the service process ------------------------------------------------------------------------------------

# Empty when docker cannot say, and 0 for a container that is not running; require_pid turns both into a FAIL.
service_pid() { docker inspect -f '{{.State.Pid}}' "$(cid iron-vault)" 2>/dev/null || true; }

require_pid() { [[ ${1:-} =~ ^[1-9][0-9]*$ ]] || { echo "no running service process (pid '${1:-}')"; return 1; }; }

runs_as_fixed_uid() {
    local got
    require_pid "$1" || return 1
    got=$(awk '/^Uid:/ { print $2, $3, $4, $5 }' "/proc/$1/status")
    [ "$got" = "$SERVICE_UID $SERVICE_UID $SERVICE_UID $SERVICE_UID" ] || { echo "uids are '$got', want $SERVICE_UID four times"; return 1; }
}

memory_is_locked() {
    local kb
    require_pid "$1" || return 1
    kb=$(awk '/^VmLck:/ { print $2 }' "/proc/$1/status")
    echo "VmLck: ${kb:-missing} kB"
    [ "${kb:-0}" -gt 0 ]
}

# The kernel makes the files under /proc/PID of a non-dumpable process belong to root, whatever account runs the
# process. The /proc/PID directory itself keeps the process's own uid, so stat a file inside it.
process_not_dumpable() {
    local owner
    require_pid "$1" || return 1
    owner=$(stat -c %u "/proc/$1/status") || return 1
    [ "$owner" = 0 ] || { echo "/proc/$1/status belongs to uid $owner, so the process is dumpable"; return 1; }
}

# --- Live checks: callers ------------------------------------------------------------------------------------------------

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# The request.completed records the service has logged since $1, one JSON object per line.
requests_since() { docker logs --since "$1" "$(cid iron-vault)" 2>&1 | jq -R -c 'fromjson? | select(.event == "request.completed")'; }

# Waits for a request record naming this caller, route and reason. The status alone cannot tell "reached its route" from "not
# granted": both are 403. The reason in the audit record can.
expect_record() {
    local since=$1 caller=$2 route=$3 reason=$4 recs="" _
    for _ in $(seq 20); do
        recs=$(requests_since "$since")
        jq -e -s --arg c "$caller" --arg r "$route" --arg why "$reason" \
            'any(.[]; .caller == $c and .route == $r and .reason == $why)' <<<"$recs" >/dev/null && return 0
        sleep 0.5
    done
    echo "no request.completed record with caller $caller, route $route, reason $reason; the last ones:"
    jq -c '{caller, route, status, reason}' <<<"$recs" | tail -n 5
    return 1
}

# curl inside a caller, trusting only the check's CA; prints the HTTP status.
caller_status() { docker exec "$(cid "$1")" curl -sS --max-time 10 --cacert /ca.crt -X "$3" -o /dev/null -w '%{http_code}' "https://$2$4"; }

# The positive control for a caller: a request its route refuses for its method. Only a caller identified from its own listener
# and granted the route gets that far, and the status cannot tell that from "not granted" (both are 403), so the audit record's
# reason decides. Without it, "the other listener is unreachable" would also pass if this listener never came up.
caller_reaches_its_route() {
    local caller=$1 listener=$2 route=$3 method=$4 path=$5 since status
    since=$(now)
    status=$(caller_status "$caller" "$listener:8443" "$method" "$path") || { echo "the TLS request failed: $status"; return 1; }
    [ "$status" = 403 ] || { echo "status $status, want 403"; return 1; }
    expect_record "$since" "$caller" "$route" method_not_allowed
}

# Runs a curl -v command and succeeds only when it found no way to the address: a timeout (28), or exit 7 with a missing route in
# its text. Exit 7 alone is not enough: it is also "Connection refused", which means something answered at the address. curl -sS
# words every exit 7 as "Couldn't connect to server", so the reason is read from the -v line ("Network unreachable", "Network is
# unreachable" or "No route to host", by version).
unreachable() {
    local rc=0 out
    out=$("$@" 2>&1) || rc=$?
    echo "$out"
    case $rc in
        28) ;;
        7) has_line 'unreachable\|No route to host' "$out" || { echo "exit 7 without a missing-route reason (a refusal means the address answered)"; return 1; } ;;
        *) echo "curl exited $rc, want 28, or 7 for a missing route"; return 1 ;;
    esac
}

caller_b_listener_unreachable_from_caller_a() {
    unreachable docker exec "$(cid caller-a)" curl -sSv --max-time 5 --cacert /ca.crt -o /dev/null "https://$LISTENER_B:8443/"
}

# The bridge has no host address (gateway mode isolated), so the host reaches no listener.
host_reaches_no_listener() {
    local found
    found=$(ip -4 -o addr show | awk '$4 ~ /^172\.30\.[12]\./')
    [ -z "$found" ] || { echo "the host has an address on a caller network: $found"; return 1; }
    unreachable curl -sSv --max-time 5 -k -o /dev/null "https://$LISTENER_A:8443/"
}

raw_socket_is_refused() {
    docker exec -i "$(cid "$1")" python3 - <<'PY'
import errno, socket, sys
for family, proto in ((socket.AF_INET, socket.IPPROTO_RAW), (socket.AF_PACKET, 0)):
    try:
        socket.socket(family, socket.SOCK_RAW, proto)
    except OSError as e:
        if e.errno != errno.EPERM:
            print(f"{family.name}: errno {e.errno}, want EPERM"); sys.exit(1)
        continue
    print(f"{family.name}: a raw socket opened"); sys.exit(1)
PY
}

# Sends hand-built TCP SYNs as raw Ethernet frames straight to iron-vault's MAC on caller-a's network. First from its own
# address to caller-a's listener (the control: the sender and the sniffer work, so silence later means something), then from
# caller-b's address to caller-b's listener. The SYN-ACK to a forged source is routed to the real owner of that address, on
# another network, so the forger sees nothing and has no connection to send a request on.
write_spoof_script() {
    cat >"$WORK/spoof.py" <<'PY'
import select, socket, struct, sys, time
iface, target_mac, own_ip, own_listener, other_listener, spoofed = sys.argv[1:7]
PORT = 8443
target = bytes.fromhex(target_mac.replace(":", ""))
own_mac = bytes.fromhex(open(f"/sys/class/net/{iface}/address").read().strip().replace(":", ""))

def checksum(data):
    data += b"\0" * (len(data) % 2)
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF

def syn_frame(src, dst, sport):
    tcp = struct.pack("!HHIIBBHHH", sport, PORT, 1000, 0, 5 << 4, 0x02, 65535, 0, 0)
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0x1234, 0, 64, 6, 0, socket.inet_aton(src), socket.inet_aton(dst))
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return target + own_mac + b"\x08\x00" + ip + tcp

def tcp_flags_to(frame, sport):
    if frame[6:12] != target or frame[12:14] != b"\x08\x00" or frame[23] != 6:
        return None
    ihl = (frame[14] & 15) * 4
    dport = struct.unpack("!H", frame[14 + ihl + 2:14 + ihl + 4])[0]
    return frame[14 + ihl + 13] if dport == sport else None

def probe(src, dst, sport):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    sock.bind((iface, 0))
    sock.send(syn_frame(src, dst, sport))
    end = time.time() + 3
    while time.time() < end:
        if select.select([sock], [], [], 0.2)[0]:
            flags = tcp_flags_to(sock.recv(2048), sport)
            if flags is not None:
                return flags
    return None

control = probe(own_ip, own_listener, 40001)
spoof = probe(spoofed, other_listener, 40002)
print(f"control: SYN from {own_ip} to {own_listener}: reply flags {control}")
print(f"spoof: SYN from {spoofed} to {other_listener}: reply flags {spoof}")
sys.exit(0 if control == 0x12 and spoof is None else 1)
PY
}

# A throwaway container with NET_RAW added back, on caller-a's network at an unused address.
spoofing_caller_b_gets_no_connection() {
    local mac
    mac=$(docker inspect -f "{{(index .NetworkSettings.Networks \"${PROJECT}_caller-a\").MacAddress}}" "$(cid iron-vault)")
    write_spoof_script
    docker run --rm -i --name "$SPOOFER" --network "${PROJECT}_caller-a" --ip "$SPOOF_IP" --pull never \
        --cap-drop ALL --cap-add NET_RAW --security-opt no-new-privileges:true "$CALLER_IMAGE" \
        python3 - eth0 "$mac" "$SPOOF_IP" "$LISTENER_A" "$LISTENER_B" "$SPOOFED_B" <"$WORK/spoof.py"
}

# Only exit 1 from `test -e` means absent; a docker exec that fails (exit 125, 126, 127, a stopped container) must not read as
# absent, so `test -e /` has to answer 0 first.
caller_has_none_of_the_vault() {
    local path rc bad=0 caller
    caller=$(cid caller-a)
    docker exec "$caller" test -e / || { echo "docker exec test -e / failed in caller-a"; return 1; }
    for path in /var/lib/iron-vault /run/iron-vault /run/iron-vault-unlock /etc/iron-vault /etc/iron-vault-tls /var/run/docker.sock; do
        rc=0
        docker exec "$caller" test -e "$path" || rc=$?
        case $rc in
            0) echo "$path exists in caller-a"; bad=1 ;;
            1) ;;
            *) echo "docker exec test -e $path exited $rc"; bad=1 ;;
        esac
    done
    return $bad
}

# --- Live checks: the stack as docker sees it ----------------------------------------------------------------------------

inspect_holds_no_recovery_key() {
    local ids out
    mapfile -t ids < <(compose ps -aq)
    [ "${#ids[@]}" -ge 3 ] || { echo "expected 3 containers, found ${#ids[@]}"; return 1; }
    out=$(docker inspect "${ids[@]}") || { echo "docker inspect failed"; return 1; }
    [ -n "$out" ] || { echo "docker inspect printed nothing"; return 1; }
    ! has_line 'AGE-SECRET-KEY' "$out" || { echo "docker inspect shows AGE-SECRET-KEY"; return 1; }
}

no_container_shares_a_network_namespace() {
    local id mode bad=0
    for id in $(compose ps -aq); do
        mode=$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$id")
        case "$mode" in host | container:* | service:*) echo "$id has NetworkMode $mode"; bad=1 ;; esac
    done
    return $bad
}

addresses_match_the_compose_file() {
    local svc net want got rows=0 bad=0
    while read -r svc net want; do
        rows=$((rows + 1))
        got=$(docker inspect -f "{{(index .NetworkSettings.Networks \"${PROJECT}_$net\").IPAddress}}" "$(cid "$svc")")
        [ "$got" = "$want" ] || { echo "$svc on $net has $got, want $want"; bad=1; }
    done < <(jq -r '.services | to_entries[] | .key as $s | (.value.networks // {}) | to_entries[]
                    | select(.value.ipv4_address) | "\($s) \(.key) \(.value.ipv4_address)"' "$CONFIG_JSON")
    [ "$rows" -ge 5 ] || { echo "only $rows addresses in the config"; return 1; }
    return $bad
}

# Docker copies the image directory's owner and mode into an empty named volume (design open question 5).
volumes_have_the_images_modes() {
    local out
    out=$(docker exec "$(cid iron-vault)" stat -c '%n %u:%g %a' /etc/iron-vault /var/lib/iron-vault)
    echo "$out"
    [ "$(grep -c " $SERVICE_UID:$SERVICE_UID 700$" <<<"$out")" -eq 2 ]
}

# --- Live checks: the admin socket ---------------------------------------------------------------------------------------

# The refusal must be one of the two real ones from cli/client.rs, so a stopped service or a broken runuser cannot pass.
other_account_ping_is_refused() {
    local out
    if out=$(as_account "$HOST_CLI" ping 2>&1); then echo "ping succeeded: $out"; return 1; fi
    echo "$out"
    case "$out" in
        *"permission denied connecting to the admin socket"*) echo "refused by the filesystem" ;;
        *"(not-admin-principal)"*) echo "refused by the service's peer-account check" ;;
        *) echo "not refused by the socket's permissions or the peer-account check"; return 1 ;;
    esac
}

sudo_ping_is_accepted() {
    local out
    out=$(sudo -n "$HOST_CLI" ping 2>&1) || { echo "$out"; return 1; }
    echo "$out"
    has_line 'container profile' "$out"
}

run_live_checks() {
    local pid
    check "the stack comes up and answers on the admin socket" stack_comes_up
    # Nothing else can run without the stack; the FAIL above says why.
    [ "$STACK_UP" = 1 ] && [ -n "$(cid iron-vault)" ] || return 0
    check "the vault is initialised, unlocked and holds the example config" provision
    pid=$(service_pid)
    check "the service runs as uid $SERVICE_UID" runs_as_fixed_uid "$pid"
    check "VmLck is above zero" memory_is_locked "$pid"
    check "the service process is not dumpable" process_not_dumpable "$pid"
    check "caller-a reaches its own route over TLS on its own listener" \
        caller_reaches_its_route caller-a "$LISTENER_A" venice-chat GET /venice-chat/models
    check "caller-b reaches its own route over TLS on its own listener" \
        caller_reaches_its_route caller-b "$LISTENER_B" brave-search POST /brave-search/res/v1/web/search
    check "caller-b's listener is unreachable from caller-a" caller_b_listener_unreachable_from_caller_a
    check "the host reaches no listener and has no caller-network address" host_reaches_no_listener
    check "caller-a cannot open a raw socket (EPERM)" raw_socket_is_refused caller-a
    check "caller-b cannot open a raw socket (EPERM)" raw_socket_is_refused caller-b
    check "NET_RAW added back, spoofing caller-b's address still gets no connection to caller-b's listener" spoofing_caller_b_gets_no_connection
    check "caller-a has no vault, runtime, unlock, TLS or Docker socket path" caller_has_none_of_the_vault
    check "docker inspect shows no AGE-SECRET-KEY" inspect_holds_no_recovery_key
    check "no container shares another's network namespace" no_container_shares_a_network_namespace
    check "every container has the address the Compose file gives it" addresses_match_the_compose_file
    check "the named volumes have the image's owner and mode" volumes_have_the_images_modes
    check "$ACCOUNT: iron-vault ping is refused" other_account_ping_is_refused
    check "sudo iron-vault ping is accepted" sudo_ping_is_accepted
}

# --- Driver -------------------------------------------------------------------------------------------------------------

usage() {
    echo "usage: $0 --i-know-this-is-a-disposable-vm [--image REF] [--override FILE]... TEST_ACCOUNT" >&2
    echo "       $0 --static-only [--compose FILE] [--override FILE]..." >&2
}

parse_args() {
    local opted_in=0 overrides=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --i-know-this-is-a-disposable-vm) opted_in=1 ;;
            --static-only) STATIC_ONLY=1 ;;
            --image) IMAGE=${2:?--image needs a value}; shift ;;
            --compose) COMPOSE=${2:?--compose needs a value}; shift ;;
            --override) overrides+=("${2:?--override needs a value}"); shift ;;
            -*) usage; die "unknown option $1" ;;
            *) [ -z "$ACCOUNT" ] || die "one test account only"; ACCOUNT=$1 ;;
        esac
        shift
    done
    REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
    : "${COMPOSE:=$REPO/packaging/compose/compose.yaml}"
    [ -f "$COMPOSE" ] || die "no Compose file at $COMPOSE"
    COMPOSE_ARGS=(-f "$COMPOSE")
    local file
    for file in "${overrides[@]}"; do
        [ -f "$file" ] || die "no override file $file"
        COMPOSE_ARGS+=(-f "$(realpath "$file")")
    done
    [ "$STATIC_ONLY" = 1 ] && return 0
    [ "$(id -u)" -eq 0 ] || { usage; die "run as root, on a disposable VM"; }
    [ "$opted_in" = 1 ] || { usage; die "this changes the host; on a disposable VM, pass --i-know-this-is-a-disposable-vm"; }
    [ -n "$ACCOUNT" ] || { usage; die "name an existing ordinary account to play another host user"; }
}

resolve_config() {
    CONFIG_JSON="$WORK/config.json"
    compose config --format json >"$CONFIG_JSON" || die "docker compose config failed on ${COMPOSE_ARGS[*]}"
}

cleanup() {
    set +e
    [ "$STACK_UP" = 0 ] || { docker rm -f "$SPOOFER"; compose down --volumes --remove-orphans; } >/dev/null 2>&1
    [ "$BUILT_SERVICE" = 0 ] || docker rmi "$SERVICE_IMAGE" >/dev/null 2>&1
    [ "$BUILT_CALLER" = 0 ] || docker rmi "$CALLER_IMAGE" >/dev/null 2>&1
    [ "$CREATED_CLI" = 0 ] || rm -f "$HOST_CLI"
    [ "$CREATED_HOST" = 0 ] || rm -rf "$HOST_DIR" "$RUN_DIR" "$UNLOCK_DIR"
    [ "$CREATED_ACCOUNT" = 0 ] || { userdel "$SERVICE_ACCOUNT" >/dev/null 2>&1; groupdel "$SERVICE_ACCOUNT" >/dev/null 2>&1; }
    [ -z "$WORK" ] || rm -rf "$WORK"
}

main() {
    parse_args "$@"
    WORK=$(mktemp -d)
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM HUP
    for tool in docker jq; do command -v "$tool" >/dev/null 2>&1 || die "$tool is required"; done
    docker compose version >/dev/null 2>&1 || die "the Docker Compose plugin is required"
    [ "$STATIC_ONLY" = 1 ] || run_live_setup
    resolve_config
    run_static_checks
    [ "$STATIC_ONLY" = 1 ] || run_live_checks
    echo "$PASSED passed, $FAILED failed"
    [ "$FAILED" -eq 0 ]
}

# Sourcing the file (to test the helpers) defines the functions and runs nothing.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then main "$@"; fi
