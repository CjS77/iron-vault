#!/usr/bin/env bash
# Release check for a real install of the Linux package (design/linux-package.md; spec 3.1, 3.2, 3.4, 3.11, 3.15).
#
# !! RUN THIS ONLY ON A DISPOSABLE VM. !!  It runs as root, restarts the service, makes /etc/iron-vault group-writable
# for a few seconds, and adds one listener socket unit. The service is left Locked, because it was restarted.
#
# Set up:
#   1. A fresh Ubuntu LTS (or Debian) VM with systemd, journald, and util-linux (runuser).
#   2. Build the package on another machine (scripts/build-deb.sh) and install it: sudo apt install ./iron-vault_*.deb
#   3. Create an ordinary account to play the desktop user:  sudo useradd -m testuser
#   4. Check out this repository on the VM; the script reads the ownership table from design/linux-package.md.
#
# Run:  sudo scripts/release/linux-install-check.sh --i-know-this-is-a-disposable-vm [--port PORT] [--table FILE] TEST_ACCOUNT
#   TEST_ACCOUNT  an existing account that is not root and not iron-vault.
#   --port        loopback port for the listener socket check (default 7899); it must be free.
#   --table       the markdown file holding the ownership table (default: design/linux-package.md next to this script).
#
# Prints one PASS or FAIL line per check, with the reason under a FAIL, and exits 1 if any check failed. Exit 2 means
# the script could not start (bad arguments, not root, no opt-in, a missing tool, the package not installed, the service not
# active, runuser not working, the port busy or the drop-in present). That happens before the script changes anything.
# The script never edits a vault file. Its only changes are the /etc/iron-vault mode, restored to the table's mode on every
# exit path, and one listener drop-in, removed on every exit path. Both cleanups are idempotent, and each restarts the
# service, so it ends Locked and no longer holds the listener socket's file descriptor.
set -euo pipefail

BINARY=/usr/bin/iron-vault
SERVICE=iron-vault.service
SERVICE_ACCOUNT=iron-vault
CONFIG_DIR=/etc/iron-vault
LISTENER_NAME=irvcheck
LISTENER_UNIT="iron-vault-listener@$LISTENER_NAME.socket"
DROPIN_DIR="/etc/systemd/system/$LISTENER_UNIT.d"

PORT=7899
TABLE=""
ACCOUNT=""
WORK=""
CONFIG_MODE=""
CONFIG_CHANGED=0
SAMPLER=""
DROPIN_MADE=0
PASSED=0
FAILED=0

die() { echo "error: $*" >&2; exit 2; }

# --- Pure helpers: no side effects, so they can be run against fake input -----------------------------------------------

# Prints "path<TAB>owner:group<TAB>mode" for each row of the Ownership table on stdin. The table is parsed rather than
# copied so the script cannot drift from the design. Only rows whose first cell is a backticked absolute path count.
parse_table() {
    awk -F'|' '
        /^## Ownership/ { on = 1; next }
        /^## / { on = 0 }
        on && $2 ~ /^ *`\// {
            for (i = 2; i <= 4; i++) gsub(/[ `]/, "", $i)
            printf "%s\t%s\t%s\n", $2, $3, $4
        }'
}

# Octal modes compare as numbers, so 0700 (the table) equals 700 (stat).
normalise_mode() { printf '%o' "$((8#$1))"; }

# Succeeds when the actual owner:group and mode equal the wanted ones; otherwise says what differs.
attrs_match() {
    local want_og=$1 want_mode got_og=$3 got_mode
    want_mode=$(normalise_mode "$2") || return 1
    got_mode=$(normalise_mode "$4") || return 1
    [ "$want_og" = "$got_og" ] || { echo "owner:group is $got_og, want $want_og"; return 1; }
    [ "$want_mode" = "$got_mode" ] || { echo "mode is $got_mode, want $want_mode"; return 1; }
}

# Prints the mode the table gives the path, or nothing when the path has no row.
table_mode_of() { parse_table | awk -F'\t' -v want="$1" '$1 == want { print $3 }'; }

# Succeeds when the argument is a decimal TCP port, 1 to 65535, with no sign or leading zero.
valid_port() { [[ $1 =~ ^[1-9][0-9]{0,4}$ ]] && [ "$1" -le 65535 ]; }

# Succeeds when neither the group nor others have the write bit in the given octal mode.
not_group_or_other_writable() { [ $(((8#$1) & 8#022)) -eq 0 ]; }

# Succeeds when /proc/PID/limits-style text on stdin shows both core limits at 0.
core_limit_is_zero() { awk '/^Max core file size/ { found = 1; ok = ($5 == 0 && $6 == 0) } END { exit !(found && ok) }'; }

# --- Check framework ----------------------------------------------------------------------------------------------------

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

# --- Cleanup ------------------------------------------------------------------------------------------------------------

restore_config_mode() {
    [ "$CONFIG_CHANGED" = 1 ] || return 0
    chmod "$CONFIG_MODE" "$CONFIG_DIR" || true
    CONFIG_CHANGED=0
    # The refused restarts exhausted the start limit; bring the service back.
    systemctl reset-failed "$SERVICE" || true
    systemctl restart "$SERVICE" || true
}

remove_listener() {
    [ "$DROPIN_MADE" = 1 ] || return 0
    systemctl stop "$LISTENER_UNIT" || true
    rm -f "$DROPIN_DIR/override.conf"
    rmdir "$DROPIN_DIR" || true
    systemctl daemon-reload || true
    DROPIN_MADE=0
    # The service still holds the file descriptor systemd passed it; a restart drops it.
    systemctl restart "$SERVICE" || true
}

cleanup() {
    set +e
    [ -z "$SAMPLER" ] || kill "$SAMPLER" 2>/dev/null
    restore_config_mode
    remove_listener
    [ -z "$WORK" ] || rm -rf "$WORK"
}

# --- Checks on the installed files and process --------------------------------------------------------------------------

path_matches() {
    local path=$1 got
    got=$(stat -c '%U:%G %a' -- "$path" 2>/dev/null) || { echo "$path is missing"; return 1; }
    attrs_match "$2" "$3" "${got% *}" "${got#* }"
}

check_table() {
    local rows=0 path owner mode
    while IFS=$'\t' read -r path owner mode; do
        rows=$((rows + 1))
        check "$path is $owner mode $mode" path_matches "$path" "$owner" "$mode"
    done < <(parse_table <"$TABLE")
    [ "$rows" -ge 8 ] || check "ownership table in $TABLE has its rows" false
}

binary_is_roots() {
    [ "$(stat -c %U "$BINARY")" = root ] || { echo "$BINARY is not owned by root"; return 1; }
    not_group_or_other_writable "$(stat -c %a "$BINARY")" || { echo "$BINARY is writable by group or others"; return 1; }
}

version_lists_no_features() {
    local out
    out=$("$BINARY" --version) || return 1
    echo "$out"
    case "$out" in *"(features: none)"*) ;; *) return 1 ;; esac
}

main_pid() { systemctl show -p MainPID --value "$SERVICE"; }

runs_as_service_account() {
    local pid=$1 want got
    want=$(id -u "$SERVICE_ACCOUNT")
    # Real, effective, saved and filesystem uid must all be the service account's.
    got=$(awk '/^Uid:/ { print $2, $3, $4, $5 }' "/proc/$pid/status")
    [ "$got" = "$want $want $want $want" ] || { echo "uids are '$got', want '$want' four times"; return 1; }
}

memory_is_locked() {
    local kb
    kb=$(awk '/^VmLck:/ { print $2 }' "/proc/$1/status")
    echo "VmLck: ${kb:-missing} kB"
    [ "${kb:-0}" -gt 0 ]
}

core_dumps_are_off() {
    [ "$(systemctl show -p LimitCORE --value "$SERVICE")" = 0 ] || { echo "the unit's LimitCORE is not 0"; return 1; }
    core_limit_is_zero <"/proc/$1/limits" || { echo "the process's core limit is not 0"; return 1; }
}

# The kernel makes /proc/PID/* of a non-dumpable process belong to root, whatever account runs the process.
process_not_dumpable() {
    local owner
    owner=$(stat -c %u "/proc/$1")
    [ "$owner" = 0 ] || { echo "/proc/$1 belongs to uid $owner, so the process is dumpable"; return 1; }
}

# --- Checks as the ordinary test account --------------------------------------------------------------------------------

as_account() { runuser -u "$ACCOUNT" -- "$@"; }

# Succeeds when the test account's attempt to open the path for reading fails with "Permission denied". Any other failure
# (a missing path, a wrong pid) does not count, so the check cannot pass by looking at the wrong thing. A directory opens
# for reading the same way a file does.
open_is_denied() {
    local out
    if out=$(as_account sh -c 'exec 3<"$1"' _ "$1" 2>&1); then echo "$ACCOUNT opened $1"; return 1; fi
    echo "$out"
    case "$out" in *"Permission denied"*) ;; *) echo "not refused with 'Permission denied'"; return 1 ;; esac
}

# The refusal must be one of the two real ones from cli/client.rs, so a stopped service or a broken runuser cannot pass.
ping_is_refused() {
    local out
    if out=$(as_account "$BINARY" ping 2>&1); then echo "ping succeeded: $out"; return 1; fi
    echo "$out"
    case "$out" in
        *"permission denied connecting to the admin socket"*)
            echo "refused by the filesystem: admin.sock is not open to $ACCOUNT, so the peer-account check was not reached" ;;
        *"(not-admin-principal)"*) echo "refused by the service's peer-account check" ;;
        *) echo "not refused by either the socket's permissions or the peer-account check"; return 1 ;;
    esac
}

# --- Checks that restart the service ------------------------------------------------------------------------------------

journal_since() { journalctl -u "$SERVICE" --since "$1" --no-pager -o cat; }

# grep -q exits at the first match, which under pipefail would fail the pipeline it ends, so output goes via a variable.
has_line() { grep -q "$1" <<<"$2"; }

# Type=exec reports a successful start, so the service is briefly active before it exits; the failed run is what counts.
service_has_failed() {
    [ "$(systemctl show -p Result --value "$SERVICE")" != success ] || [ "$(systemctl show -p ActiveState --value "$SERVICE")" = failed ]
}

# A writable config directory is refused at startup. Type=exec reports a successful start, so the refusal is read from
# the journal, where the service's one-line startup error goes.
group_writable_config_is_refused() {
    local since text refusal="refusing to start: $CONFIG_DIR is not trusted"
    since=$(date '+%Y-%m-%d %H:%M:%S')
    CONFIG_CHANGED=1
    chmod g+w "$CONFIG_DIR"
    systemctl restart "$SERVICE" || true
    for _ in $(seq 20); do
        text=$(journal_since "$since")
        has_line "$refusal" "$text" && service_has_failed && break
        sleep 0.5
    done
    has_line "$refusal" "$text" || {
        echo "the journal has no line '$refusal':"
        tail -n 5 <<<"$text"
        return 1
    }
    service_has_failed || { echo "$SERVICE did not fail with $CONFIG_DIR group-writable"; return 1; }
}

second_instance_fails_on_lock() {
    local out status=0
    # --log-to-stdout keeps the intruder from opening the real log file; timeout bounds a run that wrongly succeeds.
    out=$(timeout 20 runuser -u "$SERVICE_ACCOUNT" -- "$BINARY" serve --log-to-stdout 2>&1) || status=$?
    echo "exit $status: $(tail -n 3 <<<"$out")"
    [ "$status" -ne 0 ] && [ "$status" -ne 124 ] || return 1
    has_line 'state-directory lock' "$out"
}

port_owner_is_systemd() { has_line 'pid=1,' "$(ss -H -ltnp "sport = :$PORT")"; }

add_listener() {
    mkdir "$DROPIN_DIR"
    DROPIN_MADE=1
    printf '[Socket]\nListenStream=127.0.0.1:%s\n' "$PORT" >"$DROPIN_DIR/override.conf"
    systemctl daemon-reload
    systemctl start "$LISTENER_UNIT"
}

# Samples the port every 50 ms across a restart, because a gap shorter than the restart would not show in a before/after look.
port_stays_bound_across_restart() {
    local stop="$WORK/stop" gaps="$WORK/gaps" before after
    port_owner_is_systemd || { echo "port $PORT is not bound by systemd (pid 1) before the restart"; return 1; }
    before=$(main_pid)
    rm -f "$stop" "$gaps"
    ( while [ -d "$WORK" ] && [ ! -e "$stop" ]; do port_owner_is_systemd || echo gap >>"$gaps"; sleep 0.05; done ) &
    SAMPLER=$!
    systemctl restart "$SERVICE" || true
    touch "$stop"
    wait "$SAMPLER"
    SAMPLER=""
    after=$(main_pid)
    [ "$before" != "$after" ] || { echo "the service did not restart (pid $before)"; return 1; }
    [ ! -s "$gaps" ] || { echo "port $PORT was unbound in $(wc -l <"$gaps") samples during the restart"; return 1; }
    port_owner_is_systemd || { echo "port $PORT is no longer bound by systemd after the restart"; return 1; }
}

# --- Driver -------------------------------------------------------------------------------------------------------------

parse_args() {
    local opted_in=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --i-know-this-is-a-disposable-vm) opted_in=1 ;;
            --port) PORT=${2:?--port needs a value}; shift ;;
            --table) TABLE=${2:?--table needs a value}; shift ;;
            -*) die "unknown option $1" ;;
            *) [ -z "$ACCOUNT" ] || die "one test account only"; ACCOUNT=$1 ;;
        esac
        shift
    done
    valid_port "$PORT" || die "--port must be an integer from 1 to 65535, not '$PORT'"
    [ "$(id -u)" -eq 0 ] || die "run as root, on a disposable VM"
    [ "$opted_in" = 1 ] || die "this changes a live install; on a disposable VM, pass --i-know-this-is-a-disposable-vm"
    [ -n "$ACCOUNT" ] || die "usage: $0 --i-know-this-is-a-disposable-vm [--port PORT] [--table FILE] TEST_ACCOUNT"
    : "${TABLE:=$(dirname "${BASH_SOURCE[0]}")/../../design/linux-package.md}"
}

preflight() {
    local tool
    for tool in runuser ss journalctl systemctl stat awk timeout dpkg-query; do
        command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
    done
    [ -f "$TABLE" ] || die "no ownership table at $TABLE"
    dpkg-query -W iron-vault >/dev/null 2>&1 || die "the iron-vault package is not installed"
    id "$ACCOUNT" >/dev/null 2>&1 || die "no account $ACCOUNT"
    [ "$(id -u "$ACCOUNT")" -ne 0 ] && [ "$ACCOUNT" != "$SERVICE_ACCOUNT" ] || die "TEST_ACCOUNT must be an ordinary login account"
    systemctl is-active --quiet "$SERVICE" || die "$SERVICE is not active"
    CONFIG_MODE=$(table_mode_of "$CONFIG_DIR" <"$TABLE")
    [ -n "$CONFIG_MODE" ] || die "$TABLE has no row for $CONFIG_DIR"
    # Positive control: if runuser silently fails, every "the account cannot" check below would pass for the wrong reason.
    [ "$(as_account id -u 2>/dev/null)" = "$(id -u "$ACCOUNT")" ] || die "runuser did not run a command as $ACCOUNT"
    [ -z "$(ss -H -ltn "sport = :$PORT")" ] || die "port $PORT is already in use; pass --port"
    [ ! -e "$DROPIN_DIR" ] || die "$DROPIN_DIR already exists"
}

run_checks() {
    local pid
    pid=$(main_pid)
    check_table
    check "$BINARY is root's and not writable by group or others" binary_is_roots
    check "iron-vault --version lists no features" version_lists_no_features
    check "the service runs as $SERVICE_ACCOUNT" runs_as_service_account "$pid"
    check "VmLck is above zero" memory_is_locked "$pid"
    check "LimitCORE is 0" core_dumps_are_off "$pid"
    check "the service process is not dumpable" process_not_dumpable "$pid"
    check "$ACCOUNT: iron-vault ping is refused" ping_is_refused
    check "$ACCOUNT cannot open /proc/$pid/mem" open_is_denied "/proc/$pid/mem"
    check "$ACCOUNT cannot open /proc/$pid/environ" open_is_denied "/proc/$pid/environ"
    check "$ACCOUNT cannot open /var/lib/iron-vault" open_is_denied /var/lib/iron-vault
    check "a second iron-vault serve fails on the state lock" second_instance_fails_on_lock
    check "a group-writable $CONFIG_DIR is refused at restart" group_writable_config_is_refused
    restore_config_mode
    add_listener
    check "port $PORT stays bound by systemd while the service restarts" port_stays_bound_across_restart
}

main() {
    parse_args "$@"
    WORK=$(mktemp -d)
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM HUP
    preflight
    run_checks
    echo "$PASSED passed, $FAILED failed"
    [ "$FAILED" -eq 0 ]
}

# Sourcing the file (to test the pure helpers) defines the functions and runs nothing.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then main "$@"; fi
