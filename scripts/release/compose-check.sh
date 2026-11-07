#!/usr/bin/env bash
# Release check for the Docker Compose profile: caller isolation and container hardening
# (design/docker-compose.md "Release checks"; spec 3.4 R-27, 3.11, 3.14 R-25 R-28, 3.15, 8).
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
# The stack is left Ready only for the checks that need to send requests through it.
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

# Shared jq definitions. A caller is any service but iron-vault. Compose renders `core: 0` as `{}`, so a missing soft or hard
# limit in an object counts as 0.
JQ_DEFS='
def callers: .services | to_entries | map(select(.key != "iron-vault"));
def caps(l): (l // []) | map(ltrimstr("CAP_") | ascii_upcase);
def nets(s): (s.networks // {}) | keys;
def members($n): .services | to_entries | map(select(nets(.value) | index($n))) | map(.key) | sort;
def callernets: [callers[] | nets(.value)[]] | unique;
def iv: .services["iron-vault"];
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

# A caller shares no mount with iron-vault (the state, config, runtime, unlock and TLS mounts) and never mounts the Docker socket.
callers_mount_nothing_of_the_vault() {
    no_violations '(iv.volumes // [] | map(.source)) as $ivsrc
        | callers[] | .key as $k | (.value.volumes // [])[]
        | select((.source // "" | test("docker\\.sock|iron-vault")) or (.target | test("docker\\.sock|iron-vault"))
                 or (.source as $s | $ivsrc | index($s)))
        | "\($k) mounts \(.source // "an anonymous volume") at \(.target)"'
}

caller_networks_are_internal() {
    no_violations 'callernets[] as $n | select($r.networks[$n].internal != true) | "network \($n) is not internal"'
}

# Each caller network holds iron-vault and exactly one caller.
caller_networks_hold_one_caller() {
    no_violations '(callers[] | select(nets(.value) | length == 0) | "\(.key) is on no network of its own"),
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

config_holds_no_recovery_key() { no_violations 'tojson | select(test("AGE-SECRET-KEY")) | "the resolved config contains AGE-SECRET-KEY"'; }

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
    check "static: the resolved config holds no AGE-SECRET-KEY" config_holds_no_recovery_key
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
    docker rm -f "$SPOOFER" >/dev/null 2>&1
    [ "$STACK_UP" = 0 ] || compose down --volumes --remove-orphans >/dev/null 2>&1
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
