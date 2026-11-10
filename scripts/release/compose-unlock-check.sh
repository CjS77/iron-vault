#!/usr/bin/env bash
# Release check for the Compose profile's host unlock handoff, the evidence for spec section 9's "Host unlock handoff" gate
# (design/docker-compose.md "Against the section 9 gate"; spec 3.11, 3.12, 3.14, 3.15, 9).
#
# !! RUN THIS ONLY ON A DISPOSABLE VM WITH A TPM. !!  It runs as root and, on the host, creates the `iron-vault` account (uid 460),
# /run/iron-vault, /run/iron-vault-unlock, /etc/iron-vault-host, /usr/local/bin/iron-vault, the host unlock unit, tmpfiles.d and
# sysusers.d files, a TPM-sealed credential, and a Compose project named ivcheck. The checks are in two parts with a reboot between
# them, so the first part leaves all of that in place for the second. The second part (or --cleanup) removes it.
#
# Set up:
#   1. A fresh Ubuntu LTS VM with a TPM 2.0 (real, or swtpm under the hypervisor), systemd 250 or later, Docker Engine, the
#      Compose plugin and the buildx plugin (BuildKit; Ubuntu package docker-buildx, Docker's docker-buildx-plugin, not needed
#      with --image) with Docker enabled at boot, and: age (age-keygen), jq, openssl, util-linux (script, findmnt), iproute2 (ss),
#      binutils (strings). Nothing of Iron Vault's may be installed: the script refuses to start if any of the paths above, or
#      an `iron-vault` account, already exists.
#   2. This repository checked out on the VM, outside /etc and /var (the key scans read those). The service image is built
#      from packaging/compose/Dockerfile (a few minutes of cargo build), unless --image names one already built.
#
# Run, in order:
#   sudo scripts/release/compose-unlock-check.sh --i-know-this-is-a-disposable-vm [--image REF]    # part 1
#   sudo reboot
#   sudo scripts/release/compose-unlock-check.sh --i-know-this-is-a-disposable-vm --after-reboot   # part 2, removes everything
#   --cleanup     removes everything a part 1 left, to abandon a run.
#
# Prints one PASS or FAIL line per check, with the reason under a FAIL, and exits 1 if any check failed (part 2 counts part 1's).
# The swap item prints SKIP, not PASS, on a host with no swap: it neither fails the run nor counts as evidence, and the summary says
# how many were skipped. Rerun on a host with swap for that item.
# Exit 2 means the script could not start or set up (bad arguments, a missing tool, not root, no opt-in, no TPM, host paths already
# taken, an image that will not build, no earlier part 1, no reboot since it). Attach both parts' output to the ticket: it is the gate's
# evidence.
#
# Scope. `recovery check` needs the recovery key, which init shows once on a terminal. The script holds it only on a ramfs, but the
# host `iron-vault` process and the pty that read it are ordinary memory, so a key found in swap may be that one and not the
# service's. The swap check says so when it fails. Keys that appear in the repository (test fixtures, docs) are not counted, because
# the image's build cache holds a copy of the sources; any other full-length key is.
#
# The jq programs are single-quoted on purpose: $name in them is jq's, not the shell's.
# shellcheck disable=SC2016
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# The same host layout, image build, certificates, stack start and PASS/FAIL framework as the isolation check.
# shellcheck source=scripts/release/compose-check.sh
source "$SCRIPT_DIR/compose-check.sh"

REPO=$(cd "$SCRIPT_DIR/../.." && pwd)
COMPOSE=$REPO/packaging/compose/compose.yaml
COMPOSE_ARGS=(-f "$COMPOSE")
HOST_FILES=$REPO/packaging/compose/host
PROVISION=$HOST_FILES/provision-host-unlock.sh
UNIT=iron-vault-host-unlock.service
UNIT_FILE=/etc/systemd/system/$UNIT
TMPFILES_CONF=/usr/lib/tmpfiles.d/iron-vault-compose.conf
SYSUSERS_CONF=/usr/lib/sysusers.d/iron-vault.conf
CRED=$HOST_DIR/host-unlock.cred
HANDOFF=$UNLOCK_DIR/host-unlock
# Part 1 leaves its state here between the reboot: the images override, certificates and counts. Under /var on purpose: nothing in
# it is an age key, so the key scans read it like any other host file.
STATE_DIR=/var/lib/ivcheck-unlock-check
# The recovery key and the init transcript live on a ramfs, which is never swapped, and are gone before the reboot.
SECRETS=/run/ivcheck-unlock-secrets
# Built so this file does not contain the marker it searches for.
KEY_MARKER="AGE-SECRET-""KEY-1"
KEY_RE="$KEY_MARKER[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}"
CONTROL_KEY="$KEY_MARKER$(printf 'Q%.0s' $(seq 58))"
ALLOWED_KEYS=""

MODE=before
KEEP=0
# Set once the run owns the state directory, so a refused start never tears down an earlier run's.
ARMED=0
SKIPPED=0
BOOT_ID=""
SCRIPT_START=$(date +%s)

# --- State between the two parts ----------------------------------------------------------------------------------------------

save_state() {
    {
        printf 'PASSED=%q\nFAILED=%q\nSERVICE_IMAGE=%q\nBUILT_SERVICE=%q\nBUILT_CALLER=%q\n' \
            "$PASSED" "$FAILED" "$SERVICE_IMAGE" "$BUILT_SERVICE" "$BUILT_CALLER"
        printf 'BOOT_ID=%q\n' "$(cat /proc/sys/kernel/random/boot_id)"
    } >"$STATE_DIR/state.env"
}

load_state() {
    [ -f "$STATE_DIR/state.env" ] || die "no $STATE_DIR/state.env: run part 1 first"
    # shellcheck source=/dev/null
    source "$STATE_DIR/state.env"
}

# --- Log and state helpers ----------------------------------------------------------------------------------------------------

# The service's audit records, one JSON object per line; arguments go to `docker logs` (for example --since T).
audit() { docker logs "$@" "$(cid iron-vault)" 2>&1 | jq -R -c 'fromjson? | select(type == "object")'; }

# Prints the outcome, and the refusal when there is one, of the newest vault.host-unlock record since $1.
host_unlock_record() {
    audit --since "$1" | jq -r 'select(.event == "vault.host-unlock")
                                | .host_unlock_outcome + (if .refusal then " " + .refusal else "" end)' | tail -n 1
}

service_state() { { "$HOST_CLI" status 2>/dev/null || true; } | sed -n 's/^service: //p'; }

wait_for_state() {
    local _
    for _ in $(seq 60); do
        [ "$(service_state)" = "$1" ] && return 0
        sleep 1
    done
    echo "the service is '$(service_state)', want $1"
    return 1
}

# Waits up to $1 seconds for the container to exist and the admin socket to answer; needed after a reboot.
wait_up() {
    local _
    for _ in $(seq "$1"); do
        [ -n "$(cid iron-vault 2>/dev/null)" ] && "$HOST_CLI" ping >/dev/null 2>&1 && return 0
        sleep 1
    done
    echo "the service did not answer on the admin socket within $1 s"
    return 1
}

# Waits for the vault.host-unlock record since $1 and succeeds when it reads $2. The record comes before the state settles, so the
# state is only read after it: a Locked seen before the record could be Starting.
expect_host_unlock() {
    local got="" _
    for _ in $(seq 40); do
        got=$(host_unlock_record "$1")
        [ -z "$got" ] || break
        sleep 1
    done
    [ "$got" = "$2" ] || { echo "the vault.host-unlock record is '${got:-missing}', want '$2'"; audit --since "$1" | tail -n 5; return 1; }
}

# Restarts the service container and expects the given host unlock record and the given settled state.
restart_expecting() {
    local since
    since=$(now)
    sleep 2
    compose restart iron-vault || return 1
    expect_host_unlock "$since" "$1" && wait_for_state "$2"
}

# --- Part 1: setup ------------------------------------------------------------------------------------------------------------

preflight_unlock() {
    local tool path
    for tool in openssl script getent useradd groupadd userdel groupdel age-keygen systemd-creds systemctl mount \
        findmnt nsenter ss strings swapon jq; do
        command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
    done
    docker info >/dev/null 2>&1 || die "the Docker daemon is not reachable"
    require_buildkit
    systemctl is-enabled docker.service >/dev/null 2>&1 || die "docker.service must be enabled: the reboot check needs Docker at boot"
    systemd-creds has-tpm2 >/dev/null 2>&1 || die "systemd-creds finds no usable TPM2 (real hardware, or swtpm under the hypervisor)"
    case "$REPO" in /etc/* | /var/*) die "check this repository out outside /etc and /var: the key scans read both" ;; esac
    for path in "$HOST_CLI" "$HOST_DIR" "$RUN_DIR" "$UNLOCK_DIR" "$UNIT_FILE" "$TMPFILES_CONF" "$SYSUSERS_CONF" "$STATE_DIR" "$SECRETS"; do
        [ ! -e "$path" ] || die "$path already exists; this check needs a host with nothing of Iron Vault's on it (--cleanup removes it)"
    done
    for path in "$SERVICE_ACCOUNT" "$SERVICE_UID"; do
        ! getent passwd "$path" >/dev/null || die "an account named or numbered $path exists"
        ! getent group "$path" >/dev/null || die "a group named or numbered $path exists"
    done
    refuse_leftovers
    ! docker container inspect ivcheck-export >/dev/null 2>&1 || die "a container named ivcheck-export already exists"
}

banner() {
    # shellcheck source=/dev/null
    echo "compose-unlock-check ($1) on $(. /etc/os-release && echo "$PRETTY_NAME"), kernel $(uname -r), $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "docker $(docker version --format '{{.Server.Version}}'), compose $(docker compose version --short)," \
        "$(systemctl --version | head -n 1)"
    echo "tpm: $(systemd-creds has-tpm2 2>&1 | tr '\n' ' '), swap: $(swapon --noheadings --raw --show=NAME | tr '\n' ' ')"
}

# The host's files from packaging/compose/host, installed as design/docker-compose.md "Host layout" says: the account and the two
# directories come from sysusers.d and tmpfiles.d at every boot, and the handoff unit starts before Docker.
install_host_files() {
    install -m 0644 "$HOST_FILES/sysusers.d/iron-vault.conf" "$SYSUSERS_CONF"
    install -m 0644 "$HOST_FILES/tmpfiles.d/iron-vault-compose.conf" "$TMPFILES_CONF"
    install -m 0644 "$HOST_FILES/$UNIT" "$UNIT_FILE"
    systemctl daemon-reload
    systemctl enable "$UNIT" >/dev/null 2>&1
}

# Seals a new host unlock identity to the TPM and starts the handoff unit; prints the script's own output (recipient key only).
provision_and_hand_off() {
    "$PROVISION" || return 1
    systemctl restart "$UNIT" || return 1
    [ -f "$HANDOFF" ] || { echo "the handoff unit left no $HANDOFF"; return 1; }
}

setup_part_one() {
    preflight_unlock
    install -d -m 0700 "$STATE_DIR"
    ARMED=1
    banner "part 1"
    build_images
    add_image_override
    create_host_layout
    create_certificates
    install_host_cli
    install_host_files
    install -d -m 0700 "$SECRETS"
    mount -t ramfs -o mode=0700 ramfs "$SECRETS"
    provision_and_hand_off >"$WORK/provision.out" 2>&1 \
        || { cat "$WORK/provision.out"; die "the host unlock identity could not be sealed and handed off"; }
    grep -E '^age1' "$WORK/provision.out" || true
}

# --- Part 1: checks -----------------------------------------------------------------------------------------------------------

# Replaces every age secret key, and anything after the marker that looks like one, with a placeholder, and drops the rows of block
# characters that draw the key as a QR code. sed -E: in basic mode {58} would be literal and nothing would be redacted.
redact_keys() { sed -E "s/$KEY_MARKER[A-Za-z0-9]*/[recovery key]/g" | { grep -avE '█|▀|▄' || true; }; }

# `init --host-unlock` shows the recovery key on the controlling terminal only; script(1) gives it a pty. The transcript is on the
# ramfs, and the key goes to a file there for the recovery check.
run_init_host_unlock() {
    printf '%s\n' "$VAULT_PASS" "$VAULT_PASS" "$APPROVAL_PASS" "$APPROVAL_PASS" yes >"$SECRETS/init.in"
    HOST_CLI=$HOST_CLI INIT_IN=$SECRETS/init.in script -qec '"$HOST_CLI" init --host-unlock <"$INIT_IN"' /dev/null </dev/null \
        >"$SECRETS/init.out" 2>&1 || { redact_keys <"$SECRETS/init.out" | tail -n 5; return 1; }
    grep -aoE "$KEY_RE" "$SECRETS/init.out" >"$SECRETS/recovery.key"
    [ "$(wc -l <"$SECRETS/recovery.key")" -eq 1 ] || { echo "init did not show exactly one recovery key"; return 1; }
}

# Everything before the restart that must not depend on a passphrase unlock after it: the vault, two credentials, an approved config.
prepare_vault() {
    run_init_host_unlock || return 1
    printf '%s\n' "$VAULT_PASS" | "$HOST_CLI" unlock || return 1
    printf '%s\n' ivcheck-not-a-real-key | "$HOST_CLI" add venice_chat --origin api.venice.ai || return 1
    printf '%s\n' ivcheck-not-a-real-key | "$HOST_CLI" add brave --origin api.search.brave.com || return 1
    printf '%s\n' yes "$APPROVAL_PASS" | "$HOST_CLI" config approve "$REPO/packaging/compose/config.example.toml"
}

# The restart clears the service's memory, so Ready afterwards can only come from the handoff.
restart_is_ready_by_handoff() { prepare_vault && restart_expecting unlocked ready; }

# The vault ID in the newest recovery.checked "opened" record, polled for as expect_host_unlock does: the record may lag the reply.
recovery_checked_id() {
    local id="" _
    for _ in $(seq 20); do
        id=$(audit | jq -r 'select(.event == "recovery.checked" and .recovery_outcome == "opened") | .vault_id' | tail -n 1)
        [ -z "$id" ] || break
        sleep 1
    done
    echo "$id"
}

recovery_key_opens_the_same_vault() {
    local init_id status_id check_id out
    init_id=$(audit | jq -r 'select(.event == "vault.initialized") | .vault_id' | tail -n 1)
    status_id=$("$HOST_CLI" status | sed -n 's/^vault id: //p')
    out=$("$HOST_CLI" recovery check <"$SECRETS/recovery.key") || { echo "$out"; return 1; }
    echo "$out"
    check_id=$(recovery_checked_id)
    echo "vault id: init $init_id, status $status_id, recovery check $check_id"
    [ -n "$init_id" ] && [ "${init_id,,}" = "${status_id,,}" ] && [ "${init_id,,}" = "${check_id,,}" ]
}

# age adds one random "-grease" stanza to every file, so it is allowed; any other kind is not.
identity_has_three_x25519_stanzas() {
    local kinds x25519 scrypt other file=$WORK/identity.age
    docker cp "$(cid iron-vault):/var/lib/iron-vault/identity.age" "$file" || { echo "cannot copy identity.age out"; return 1; }
    kinds=$(LC_ALL=C awk '/^--- / { exit } /^-> / { print $2 }' "$file")
    rm -f "$file"
    x25519=$(grep -cx X25519 <<<"$kinds" || true)
    scrypt=$(grep -cx scrypt <<<"$kinds" || true)
    other=$(grep -vxE 'X25519|scrypt|.*-grease' <<<"$kinds" || true)
    echo "stanzas: $(tr '\n' ' ' <<<"$kinds")"
    [ "$x25519" -eq 3 ] && [ "$scrypt" -eq 0 ] && [ -z "$other" ]
}

handoff_is_on_a_host_ramfs() {
    local fstype attrs
    fstype=$(findmnt -n -o FSTYPE -M "$UNLOCK_DIR") || { echo "$UNLOCK_DIR is not a mount point"; return 1; }
    attrs=$(stat -c '%U:%G %a' "$HANDOFF") || return 1
    echo "$UNLOCK_DIR is $fstype; $HANDOFF is $attrs"
    [ "$fstype" = ramfs ] && [ "$attrs" = "$SERVICE_ACCOUNT:$SERVICE_ACCOUNT 400" ]
}

run_part_one() {
    setup_part_one
    check "the stack starts with the handoff in place" stack_comes_up
    [ "$STACK_UP" = 1 ] && [ -n "$(cid iron-vault)" ] || return 0
    check "init --host-unlock then compose restart: Ready with no unlock, vault.host-unlock unlocked" restart_is_ready_by_handoff
    check "recovery check with the recovery key opens the same vault ID" recovery_key_opens_the_same_vault
    check "identity.age has exactly three X25519 stanzas and no scrypt stanza" identity_has_three_x25519_stanzas
    check "the handoff is a 0400 service-owned file on a host ramfs" handoff_is_on_a_host_ramfs
}

# --- Part 2: checks -----------------------------------------------------------------------------------------------------------

# The containers were started by Docker's restart policy at boot, before this script ran, and the script has run no `up` or `unlock`.
reboot_leaves_it_ready() {
    local since started
    wait_up 180 || return 1
    since=$(date -u -d "$(uptime -s)" +%Y-%m-%dT%H:%M:%SZ)
    started=$(date -d "$(docker inspect -f '{{.State.StartedAt}}' "$(cid iron-vault)")" +%s)
    [ "$started" -lt "$SCRIPT_START" ] || { echo "the container started after this script did, so the boot did not start it"; return 1; }
    systemctl is-active --quiet "$UNIT" || { echo "$UNIT is not active after the boot"; return 1; }
    expect_host_unlock "$since" unlocked && wait_for_state ready
}

unit_stopped_leaves_it_locked() {
    systemctl stop "$UNIT" || return 1
    [ ! -e "$HANDOFF" ] || { echo "$HANDOFF is still there after the unit stopped"; return 1; }
    restart_expecting absent locked || return 1
    printf '%s\n' "$VAULT_PASS" | "$HOST_CLI" unlock || return 1
    wait_for_state ready
}

# A second credential, sealed to a key that is not a recipient of this vault.
another_key_leaves_it_locked() {
    systemctl stop "$UNIT" || return 1
    mv "$CRED" "$CRED.first" || return 1
    provision_and_hand_off || return 1
    restart_expecting "refused not_a_recipient" locked
}

first_credential_restores_ready() {
    [ -f "$CRED.first" ] || { echo "no first credential to put back"; return 1; }
    systemctl stop "$UNIT" || return 1
    mv -f "$CRED.first" "$CRED" || return 1
    systemctl start "$UNIT" || return 1
    restart_expecting unlocked ready
}

# --- Part 2: the key scans ----------------------------------------------------------------------------------------------------

# Reads `grep -o` output, KEY or PATH:KEY per line, and prints a count per source for each key that is not one the repository
# itself contains. It never prints a key.
stray_sources() {
    awk -v allow="$ALLOWED_KEYS" '
        BEGIN { while ((getline k < allow) > 0) ok[k] = 1 }
        { n = split($0, f, ":"); if (!(f[n] in ok)) print (n > 1 ? substr($0, 1, length($0) - length(f[n]) - 1) : "(stream)") }' \
        | sort | uniq -c
}

stream_strays() { { grep -aoE "$KEY_RE" || true; } | stray_sources; }

tree_strays() { { find "$@" -type f -exec grep -aHoE "$KEY_RE" {} + 2>/dev/null || true; } | stray_sources; }

# Every scan below can only say "none" if the scanner can find one: plant a key in a stream and in a file and expect both.
scanner_finds_a_planted_key() {
    local stream tree
    stream=$(printf 'x %s y\n' "$CONTROL_KEY" | stream_strays)
    mkdir "$WORK/control"
    printf '%s\n' "$CONTROL_KEY" >"$WORK/control/key"
    tree=$(tree_strays "$WORK/control")
    rm -rf "$WORK/control"
    echo "stream: $stream; tree: $tree"
    [ "$(wc -l <<<"$stream")" -eq 1 ] && [ -n "$stream" ] && [ -n "$tree" ]
}

# Prints stdin with "$1: " in front of every line.
prefix_lines() { local line; while IFS= read -r line; do printf '%s: %s\n' "$1" "$line"; done; }

# Runs the command $2... and scans its output for stray keys. A command that fails scanned nothing, which is a failure, not a pass.
scan_command() {
    local label=$1 rc out
    shift
    rm -f "$WORK/scan.rc"
    out=$({ "$@"; echo $? >"$WORK/scan.rc"; } | stream_strays)
    rc=$(cat "$WORK/scan.rc" 2>/dev/null)
    [ "$rc" = 0 ] || { echo "$label: the command exited $rc, so nothing was scanned"; return 1; }
    # Not sed: a label such as a swap device path holds a slash.
    [ -z "$out" ] || { prefix_lines "$label" <<<"$out"; return 1; }
}

service_environment() { tr '\0' '\n' <"/proc/$1/environ"; }

# `docker save` layers are compressed under the containerd image store, which the scanner cannot read through; `docker export` of a
# container made from the image is a plain tar of its filesystem.
image_filesystem() {
    local rc ctr="ivcheck-export"
    docker create --name "$ctr" "$SERVICE_IMAGE" >/dev/null || return 1
    docker export "$ctr"
    rc=$?
    docker rm -f "$ctr" >/dev/null 2>&1
    return $rc
}

no_key_in_image_or_environment() {
    local pid ids bad=0
    pid=$(service_pid)
    require_pid "$pid" || return 1
    mapfile -t ids < <(compose ps -aq)
    [ "${#ids[@]}" -ge 3 ] || { echo "expected 3 containers, found ${#ids[@]}"; return 1; }
    scan_command "docker save" docker save "$SERVICE_IMAGE" || bad=1
    scan_command "image filesystem" image_filesystem || bad=1
    scan_command "docker inspect" docker inspect "${ids[@]}" || bad=1
    scan_command "service environment" service_environment "$pid" || bad=1
    return $bad
}

no_key_on_disk() {
    local roots=(/etc /var) vol out found=0
    while read -r vol; do
        found=$((found + 1))
        case $vol in /etc/* | /var/*) ;; *) roots+=("$vol") ;; esac
    done < <(docker volume ls -q --filter "label=com.docker.compose.project=$PROJECT" | xargs -r docker volume inspect -f '{{.Mountpoint}}')
    [ "$found" -ge 2 ] || { echo "found $found named volumes, want the config and state volumes"; return 1; }
    out=$(tree_strays "${roots[@]}")
    [ -z "$out" ] || { echo "$out"; return 1; }
}

has_swap() { [ -n "$(swapon --noheadings --raw --show=NAME)" ]; }

swap_text() { strings -a -n 70 "$1"; }

no_key_in_swap() {
    local dev bad=0 devs
    mapfile -t devs < <(swapon --noheadings --raw --show=NAME)
    for dev in "${devs[@]}"; do
        scan_command "$dev" swap_text "$dev" || bad=1
    done
    [ "$bad" = 0 ] || echo "a hit may be the recovery key this check typed (see the Scope note), or the service's"
    return $bad
}

# --- Part 2: listeners --------------------------------------------------------------------------------------------------------

# Local addresses of the listeners in the service container's network namespace, read with the host's ss. Docker's embedded DNS
# listens on 127.0.0.11 at a random port, TCP and UDP, in the namespace of every container on a user-defined network; it is
# dockerd's, not the service's, so it is left out. A UDP listener counts like a TCP one: a datagram service could be an oracle too.
container_listeners() {
    nsenter -t "$1" -n ss "$2" -lnH | awk -v col="$3" '$col !~ /^127\.0\.0\.11:/ { print $col }' | sort -u
}

only_the_expected_listeners() {
    local pid tcp udp unix host_tcp host_udp host_unix bad=0
    pid=$(service_pid)
    require_pid "$pid" || return 1
    tcp=$(container_listeners "$pid" -t 4)
    udp=$(container_listeners "$pid" -u 4)
    unix=$(container_listeners "$pid" -x 5)
    [ "$tcp" = "$(printf '%s\n' "$LISTENER_A:8443" "$LISTENER_B:8443" | sort)" ] || { echo "container TCP listeners: $tcp"; bad=1; }
    [ -z "$udp" ] || { echo "container UDP listeners: $udp"; bad=1; }
    [ "$unix" = "$RUN_DIR/admin.sock" ] || { echo "container unix listeners: $unix"; bad=1; }
    # The positive control: a working ss lists at least systemd's own unix sockets.
    [ -n "$(ss -lxH)" ] || { echo "ss -lx on the host listed nothing: it is not working"; bad=1; }
    host_unix=$(ss -lxpH | awk -v ok="$RUN_DIR/admin.sock" \
        '$5 != ok && ($5 ~ /iron-vault|ivcheck/ || $0 ~ /"(iron-vault|systemd-creds|age-keygen)"/)') || { echo "ss -lxp failed"; bad=1; }
    host_tcp=$(ss -ltnpH | awk '$4 ~ /^172\.30\./ || $0 ~ /"(iron-vault|systemd-creds|age-keygen|docker-proxy)"/') \
        || { echo "ss -ltnp failed"; bad=1; }
    host_udp=$(ss -lunpH | awk '$4 ~ /^172\.30\./ || $0 ~ /"(iron-vault|systemd-creds|age-keygen|docker-proxy)"/') \
        || { echo "ss -lunp failed"; bad=1; }
    [ -z "$host_udp" ] || { echo "host UDP listeners of ours: $host_udp"; bad=1; }
    [ -z "$host_unix" ] || { echo "host unix listeners of ours: $host_unix"; bad=1; }
    [ -z "$host_tcp" ] || { echo "host TCP listeners of ours: $host_tcp"; bad=1; }
    return $bad
}

# A check that cannot run because the service container is gone is a FAIL, so the evidence has one line for every item.
fail_unrun() {
    echo "FAIL $1"
    echo "     not run: the service container did not survive the reboot"
    FAILED=$((FAILED + 1))
}

# A check that has nothing to test on this host. It is neither a PASS nor a FAIL, and the summary counts it.
skip() {
    echo "SKIP $1"
    echo "     $2"
    SKIPPED=$((SKIPPED + 1))
}

run_part_two() {
    load_state
    [ "$BOOT_ID" != "$(cat /proc/sys/kernel/random/boot_id)" ] || die "the host has not rebooted since part 1"
    ARMED=1
    COMPOSE_ARGS+=(-f "$WORK/images.yaml")
    banner "part 2"
    ALLOWED_KEYS=$WORK/allowed-keys
    grep -rhoE "$KEY_RE" "$REPO" --exclude-dir=.git --exclude-dir=target >"$ALLOWED_KEYS" || true
    check "after a host reboot the stack is Ready unattended" reboot_leaves_it_ready
    if [ -n "$(cid iron-vault)" ]; then
        check "unit stopped, restart: Locked with absent; passphrase unlock reaches Ready" unit_stopped_leaves_it_locked
        check "credential sealed for another key: Locked with refused not_a_recipient" another_key_leaves_it_locked
        check "the first credential back, restart: Ready again" first_credential_restores_ready
    else
        fail_unrun "unit stopped, restart: Locked with absent; passphrase unlock reaches Ready"
        fail_unrun "credential sealed for another key: Locked with refused not_a_recipient"
        fail_unrun "the first credential back, restart: Ready again"
    fi
    check "the key scanner finds a planted key in a stream and in a file" scanner_finds_a_planted_key
    if [ -n "$(cid iron-vault)" ]; then
        check "no age secret key in the image, docker inspect or the service environment" no_key_in_image_or_environment
    else
        fail_unrun "no age secret key in the image, docker inspect or the service environment"
    fi
    check "no age secret key under /etc, /var or the named volumes" no_key_on_disk
    if has_swap; then
        check "no age secret key in swap" no_key_in_swap
    else
        skip "no age secret key in swap" "this host has no swap device, so the swap evidence is missing; rerun on a host with swap"
    fi
    if [ -n "$(cid iron-vault)" ]; then
        check "only the admin socket and the request listeners listen: no signing oracle" only_the_expected_listeners
    else
        fail_unrun "only the admin socket and the request listeners listen: no signing oracle"
    fi
}

# --- Driver -------------------------------------------------------------------------------------------------------------------

usage() {
    echo "usage: $0 --i-know-this-is-a-disposable-vm [--image REF]      (part 1; then reboot)" >&2
    echo "       $0 --i-know-this-is-a-disposable-vm --after-reboot     (part 2; removes everything)" >&2
    echo "       $0 --i-know-this-is-a-disposable-vm --cleanup          (abandon a run)" >&2
}

parse_args() {
    local opted_in=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --i-know-this-is-a-disposable-vm) opted_in=1 ;;
            --after-reboot) MODE=after ;;
            --cleanup) MODE=cleanup ;;
            --image) IMAGE=${2:?--image needs a value}; shift ;;
            *) usage; die "unknown argument $1" ;;
        esac
        shift
    done
    [ -f "$COMPOSE" ] || die "no Compose file at $COMPOSE"
    [ "$(id -u)" -eq 0 ] || { usage; die "run as root, on a disposable VM"; }
    [ "$opted_in" = 1 ] || { usage; die "this changes the host; on a disposable VM, pass --i-know-this-is-a-disposable-vm"; }
}

# Removes whatever a run made. Part 1 sets KEEP when it ends normally, because part 2 needs it all; the ramfs is dropped either way.
# It acts only once the run owns the state directory, which setup creates after preflight_unlock found that none of it existed.
cleanup() {
    set +e
    [ "$ARMED" = 1 ] || return 0
    mountpoint -q "$SECRETS" && umount "$SECRETS"
    rm -rf "$SECRETS"
    [ "$KEEP" = 0 ] || return 0
    docker rm -f ivcheck-export >/dev/null 2>&1
    docker compose -p "$PROJECT" -f "$COMPOSE" down --volumes --remove-orphans >/dev/null 2>&1
    systemctl disable --now "$UNIT" >/dev/null 2>&1
    mountpoint -q "$UNLOCK_DIR" && umount "$UNLOCK_DIR"
    rm -f "$UNIT_FILE" "$TMPFILES_CONF" "$SYSUSERS_CONF" "$HOST_CLI"
    systemctl daemon-reload
    rm -rf "$HOST_DIR" "$RUN_DIR" "$UNLOCK_DIR"
    userdel "$SERVICE_ACCOUNT" >/dev/null 2>&1
    groupdel "$SERVICE_ACCOUNT" >/dev/null 2>&1
    [ "$BUILT_SERVICE" = 0 ] || docker rmi "$SERVICE_IMAGE" >/dev/null 2>&1
    [ "$BUILT_CALLER" = 0 ] || docker rmi "$CALLER_IMAGE" >/dev/null 2>&1
    rm -rf "$STATE_DIR"
}

main() {
    local tool
    parse_args "$@"
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM HUP
    for tool in docker jq; do command -v "$tool" >/dev/null 2>&1 || die "$tool is required"; done
    docker compose version >/dev/null 2>&1 || die "the Docker Compose plugin is required"
    WORK=$STATE_DIR
    case $MODE in
        cleanup)
            [ -d "$STATE_DIR" ] || die "nothing to clean up: no $STATE_DIR"
            [ ! -f "$STATE_DIR/state.env" ] || load_state
            ARMED=1
            echo "removing what a run left"
            return 0
            ;;
        after) [ -d "$STATE_DIR" ] || die "no $STATE_DIR: run part 1 first"; run_part_two ;;
        before)
            run_part_one
            KEEP=1
            save_state
            echo "$PASSED passed, $FAILED failed so far. Reboot now (sudo reboot), then run the second part:"
            echo "  sudo $0 --i-know-this-is-a-disposable-vm --after-reboot"
            [ "$FAILED" -eq 0 ]
            return
            ;;
    esac
    echo "$PASSED passed, $FAILED failed, $SKIPPED skipped (a skipped item has no evidence from this host)"
    [ "$FAILED" -eq 0 ]
}

# Sourcing the file (to test the helpers) defines the functions and runs nothing.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then main "$@"; fi
