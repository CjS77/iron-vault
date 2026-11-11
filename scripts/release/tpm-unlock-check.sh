#!/usr/bin/env bash
# Release check for TPM unlock on a protected Linux install: the evidence for implementation spec §3's "TPM unlock binding" and "TPM
# authorization and power failure" gates (design/tpm-unlock.md "Release checks"; product spec §14 Recipients, startup, and memory;
# §15 Service states and errors; §19 V0 user acceptance). Items 1 to 14 below are that section's numbers.
#
# !! RUN THIS ONLY ON A DISPOSABLE VM WITH A TPM. !!  It runs as root on a real install of the package, and changes it:
#   - it creates the vault, enrols a host unlock identity sealed to the TPM, locks, unlocks, crashes and restarts the service,
#     reinstalls the package when --deb is given, and leaves the vault in place (destroy the VM; --cleanup does not delete it);
#   - it extends PCR 7 with tpm2_pcrextend (item 9), which lasts until the next reboot and is what a Secure Boot update does to a seal;
#   - item 13 makes loop devices, a LUKS volume and an LVM volume from a file under /var/lib, bind-mounts them over
#     /etc/iron-vault-host while the provisioning helper runs, and edits /etc/crypttab, restoring all of it on every exit path.
# It never clears the TPM, sets an authorization, or changes dictionary-attack parameters.
#
# OS matrix (design/tpm-unlock.md "Supported releases"): Ubuntu 24.04 LTS (systemd 255) only. Evidence for the gates comes from two
# runs: an Ubuntu 24.04 VM under a hypervisor with an `swtpm` TPM and OVMF Secure Boot, and an Ubuntu 24.04 machine with a firmware
# TPM, for the non-destructive items and the power-loss item. On any other release the script runs item 14 alone.
#
# Set up:
#   1. A fresh Ubuntu 24.04 VM with a TPM 2.0 and the package installed (scripts/build-deb.sh, then sudo apt install ./iron-vault_*.deb)
#      with the service running and no vault. Also: age (age-keygen), jq, tpm2-tools, cryptsetup-bin, e2fsprogs, util-linux (script,
#      findmnt, runuser), iproute2 (ss), binutils (strings), initramfs-tools-core and, for item 13's LVM case, lvm2.
#   2. This repository checked out on the VM, outside /etc and /var (the key scans read those).
#   3. For item 3's reinstall, the same .deb file that is installed: --deb FILE.
#
# Run, in order, with the same command each time; the script keeps its place in /var/lib/ivcheck-tpm-unlock-check:
#   sudo scripts/release/tpm-unlock-check.sh --i-know-this-is-a-disposable-vm [--deb FILE]    # part 1
#   sudo reboot
#   sudo scripts/release/tpm-unlock-check.sh --i-know-this-is-a-disposable-vm [--deb FILE]    # part 2
#   sudo reboot
#   sudo scripts/release/tpm-unlock-check.sh --i-know-this-is-a-disposable-vm [--deb FILE]    # part 3, prints the summary
#   --cleanup     stops the handoff unit and removes what the run kept, to abandon it.
#
# Prints one PASS, FAIL or SKIP line per item (a letter marks the halves of an item that a reboot separates), with the reason under a
# FAIL, and exits 1 if any item failed (later parts count earlier ones). A SKIP is neither a PASS nor a FAIL and is no evidence;
# the summary counts them. Exit 2 means the script could not start (bad arguments, not root, no opt-in, the package missing, a
# missing tool, no TPM, an earlier run's leftovers, no reboot since the last part). That happens before it changes anything.
# Attach all three parts' output to the ticket: it is the gate's evidence.
#
# Items 1 to 14 and how this script covers them:
#   1 no TPM in the service's device policy or /dev ........ part 1, run
#   2 helper, handoff unit, init --host-unlock, reboot ...... part 1 and 2, run
#   3 kill -9 and reinstall keep it Ready ................... part 2, run (the reinstall needs --deb, else SKIP)
#   4 recovery check, three X25519 stanzas ................. part 1, run
#   5 ramfs, modes, ordinary accounts ....................... part 1, run
#   6 no age secret key on disk, in the environment, in swap  part 2, run (swap SKIPs on a host with none)
#   7 handoff started after the service ..................... part 3, run
#   8 owner-lock file across kill -9 and a reboot ........... part 2 and 3, run
#   9 failed unseal after tpm2_pcrextend, re-provisioning ... part 3, run
#  10 retiring TPM unlock ................................... part 3, run
#  11 TPM2_PT_LOCKOUT_COUNTER before and after item 9 ....... part 3, run
#  12 only the admin socket listens ......................... part 2, run
#  13 --portable cases, `yes |`, acceptance record .......... part 3, run on loop devices rather than a rebuilt root
#  14 the helper stops on another release ................... SKIP on Ubuntu 24.04; on any other release this is all that runs
# Two items need the hypervisor, not this script; part 3 prints their instructions: power loss, and lockout on an emulated TPM.
#
# Scope. `recovery check` needs the recovery key, which init shows once on a terminal. The script holds it only on a ramfs, but the
# host `iron-vault` process and the pty that read it are ordinary memory, so a key found in swap may be that one and not the
# service's. The swap check says so when it fails.
# The helper is sourced in a subshell for one case, which assigns its own HOST_DIR there; the parent keeps its own.
# shellcheck disable=SC2031
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$SCRIPT_DIR/../.." && pwd)
BINARY=/usr/bin/iron-vault
SERVICE=iron-vault.service
HANDOFF_UNIT=iron-vault-host-unlock.service
PROVISION=/usr/sbin/iron-vault-provision-host-unlock
OS_RELEASE=/etc/os-release
HOST_DIR=/etc/iron-vault-host
CRED=$HOST_DIR/host-unlock.cred
UNLOCK_DIR=/run/iron-vault-unlock
HANDOFF=$UNLOCK_DIR/host-unlock
UNSEAL_FAILED=$UNLOCK_DIR/unseal-failed
OWNER_LOCK=/var/lib/iron-vault/locked-by-owner
AUDIT_LOG=/var/log/iron-vault/iron-vault.log
CRYPTTAB=/etc/crypttab
# Under /var on purpose: nothing in it is an age key, so the key scans read it like any other host file.
STATE_DIR=/var/lib/ivcheck-tpm-unlock-check
# The recovery key and the init transcript live on a ramfs, which is never swapped, and are gone before the first reboot.
SECRETS=/run/ivcheck-tpm-unlock-secrets
VAULT_PASS="ivcheck vault passphrase"
APPROVAL_PASS="ivcheck approval passphrase"
# Built so this file does not contain the marker it searches for.
KEY_MARKER="AGE-SECRET-""KEY-1"
KEY_RE="${KEY_MARKER}[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}"
CONTROL_KEY="$KEY_MARKER$(printf 'Q%.0s' $(seq 58))"
# Item 13's scratch volume.
PORT_IMG=$STATE_DIR/portable.img
PORT_KEY=$STATE_DIR/portable.key
PORT_MNT=$STATE_DIR/portable-mnt
PORT_MAP=ivcheck-crypt
PORT_VG=ivcheckvg
PORT_LOOP=""

MODE=run
DEB=""
WORK=""
ARMED=0
PASSED=0
FAILED=0
SKIPPED=0
NEXT=1
BOOT_ID=""
HOST_KEY=""
NEW_KEY=""
LOCKOUT_BEFORE=""

die() { echo "error: $*" >&2; exit 2; }

# --- Check framework (the same as compose-unlock-check.sh) ---------------------------------------------------------------------

# Runs one check in this shell (not a subshell, so the variables it sets survive). Prints PASS, or FAIL and what it said.
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

# A check that has nothing to test on this host. It is neither a PASS nor a FAIL, and the summary counts it.
skip() {
    echo "SKIP $1"
    echo "     $2"
    SKIPPED=$((SKIPPED + 1))
}

save_state() {
    printf 'PASSED=%q\nFAILED=%q\nSKIPPED=%q\nNEXT=%q\nHOST_KEY=%q\nBOOT_ID=%q\n' \
        "$PASSED" "$FAILED" "$SKIPPED" "$1" "$HOST_KEY" "$(cat /proc/sys/kernel/random/boot_id)" >"$STATE_DIR/state.env"
}

load_state() {
    [ -f "$STATE_DIR/state.env" ] || die "$STATE_DIR has no state.env: an earlier run stopped in its setup; run with --cleanup"
    # shellcheck source=/dev/null
    source "$STATE_DIR/state.env"
}

# --- Service and log helpers ---------------------------------------------------------------------------------------------------

now() { date -u +%Y-%m-%dT%H:%M:%S; }
# `uptime -s` prints local time, so convert it to epoch seconds before formatting as UTC.
boot_since() { date -u -d "@$(date -d "$(uptime -s)" +%s)" +%Y-%m-%dT%H:%M:%S; }
main_pid() { systemctl show -p MainPID --value "$SERVICE"; }
status_line() { { "$BINARY" status 2>/dev/null || true; } | sed -n "s/^$1: //p"; }
service_state() { status_line service; }
unlock_service() { printf '%s\n' "$VAULT_PASS" | "$BINARY" unlock; }
add_host_unlock() { printf '%s\n' "$VAULT_PASS" | "$BINARY" recipient add --host-unlock "$1" --label "ivcheck host unlock"; }
remove_recipient() { printf '%s\n' "$APPROVAL_PASS" | "$BINARY" recipient remove "$1"; }

# The outcome, and the refusal when there is one, of the newest vault.host-unlock record at or after the timestamp $1.
host_unlock_record() {
    { jq -R -r --arg s "$1" 'fromjson? | select(type == "object" and .event == "vault.host-unlock" and .timestamp >= $s)
                             | .host_unlock_outcome + (if .refusal then " " + .refusal else "" end)' "$AUDIT_LOG" 2>/dev/null || true; } | tail -n 1
}

wait_for_state() {
    local _
    for _ in $(seq 60); do
        [ "$(service_state)" = "$1" ] && return 0
        sleep 1
    done
    echo "the service is '$(service_state)', want $1"
    return 1
}

# Waits up to $1 seconds for the admin socket to answer; needed after a reboot.
wait_up() {
    local _
    for _ in $(seq "$1"); do
        "$BINARY" ping >/dev/null 2>&1 && return 0
        sleep 1
    done
    echo "the service did not answer on the admin socket within $1 s"
    return 1
}

# Waits for the vault.host-unlock record since $1 and succeeds when it reads $2. The record comes before the state settles, so the
# state is only read after it.
expect_host_unlock() {
    local got="" _
    for _ in $(seq 40); do
        got=$(host_unlock_record "$1")
        [ -z "$got" ] || break
        sleep 1
    done
    [ "$got" = "$2" ] || { echo "the vault.host-unlock record is '${got:-missing}', want '$2'"; return 1; }
}

# Runs the command $2... and expects the given host unlock record and the given settled state.
expecting() {
    local outcome=$1 state=$2 since
    shift 2
    since=$(now)
    sleep 1
    "$@" || return 1
    expect_host_unlock "$since" "$outcome" && wait_for_state "$state"
}

restart_service() { systemctl restart "$SERVICE"; }

# SIGKILL, which systemd's Restart=on-failure treats as a crash; waits until a new process answers.
crash_service() {
    local old _
    old=$(main_pid)
    kill -9 "$old" || return 1
    for _ in $(seq 30); do
        [ "$(main_pid)" != "$old" ] && [ "$(main_pid)" != 0 ] && "$BINARY" ping >/dev/null 2>&1 && return 0
        sleep 1
    done
    echo "the service did not come back within 30 s of the kill"
    return 1
}

# Changes only when the handoff unit runs again.
handoff_invocation() { systemctl show -p InvocationID -p ActiveEnterTimestampMonotonic "$HANDOFF_UNIT" | tr '\n' ' '; }

# Seals a new identity with the helper as an unattended run, starts the handoff unit and sets NEW_KEY to the recipient key.
provision_and_hand_off() {
    local out
    out=$("$PROVISION" --server --accept-physical-access </dev/null 2>&1) || { echo "$out"; return 1; }
    NEW_KEY=$(sed -n 's/^\(age1[0-9a-z]*\)$/\1/p' <<<"$out" | tail -n 1)
    [[ $NEW_KEY == age1* ]] || { echo "the helper printed no recipient key: $out"; return 1; }
    systemctl start "$HANDOFF_UNIT" || return 1
    [ -f "$HANDOFF" ] || { echo "the handoff unit left no $HANDOFF"; return 1; }
}

# The install guide's retirement steps.
retire_tpm_unlock() {
    systemctl stop "$HANDOFF_UNIT" || return 1
    rm -f "$CRED"
    remove_recipient "$1"
}

# The value of a TPM property from `tpm2_getcap properties-variable`. tpm2-tools 5.x prints `TPM2_PT_LOCKOUT_COUNTER: 0x0` on one
# line; a property with named fields prints `NAME:` and then an indented `raw: 0x...` line, which is the fallback.
tpm_property() {
    local v
    v=$(tpm2_getcap properties-variable 2>/dev/null | awk -v p="$1" '
        $1 == p ":" && NF > 1 { print $2; exit }
        $1 == p ":" { f = 1; next }
        f && $1 == "raw:" { print $2; exit }
        f && /^[^ ]/ { exit }')
    [ -n "$v" ] || { echo "cannot read $1" >&2; return 1; }
    echo "$v"
}

lockout_counter() { tpm_property TPM2_PT_LOCKOUT_COUNTER; }

# --- Starting ------------------------------------------------------------------------------------------------------------------

usage() {
    echo "usage: $0 --i-know-this-is-a-disposable-vm [--deb FILE]      (run at the start, then after each reboot it asks for)" >&2
    echo "       $0 --i-know-this-is-a-disposable-vm --cleanup         (abandon a run)" >&2
}

# The opt-in comes first: without it the script reads nothing of the host.
parse_args() {
    local opted_in=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --i-know-this-is-a-disposable-vm) opted_in=1 ;;
            --cleanup) MODE=cleanup ;;
            --deb) DEB=${2:?--deb needs a value}; shift ;;
            *) usage; die "unknown argument $1" ;;
        esac
        shift
    done
    [ "$opted_in" = 1 ] || { usage; die "this changes the host; on a disposable VM, pass --i-know-this-is-a-disposable-vm"; }
    [ -z "$DEB" ] || [ -f "$DEB" ] || die "no package file at $DEB"
}

os_field() { sed -n "s/^$1=//p" "$OS_RELEASE" 2>/dev/null | head -n 1 | tr -d "\"'"; }
on_supported_release() { [ "$(os_field ID)" = ubuntu ] && [ "$(os_field VERSION_ID)" = 24.04 ]; }

require_root_and_package() {
    [ "$(id -u)" -eq 0 ] || die "run as root, on a disposable VM"
    command -v dpkg-query >/dev/null 2>&1 || die "dpkg-query is required"
    [ "$(dpkg-query -W -f='${Status}' iron-vault 2>/dev/null)" = "install ok installed" ] \
        || die "the iron-vault package is not installed (scripts/build-deb.sh, then sudo apt install ./iron-vault_*.deb)"
}

preflight() {
    local tool
    on_supported_release || die "TPM unlock is supported on Ubuntu 24.04 LTS only; this machine runs $(os_field PRETTY_NAME)"
    for tool in jq script findmnt runuser ss strings swapon systemctl journalctl logger age-keygen systemd-creds systemd-cryptenroll \
        tpm2_getcap tpm2_pcrextend lsinitramfs cryptsetup losetup mkfs.ext4 mountpoint truncate sha256sum; do
        command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
    done
    systemd-creds has-tpm2 >/dev/null 2>&1 || die "systemd-creds finds no usable TPM2 (real hardware, or swtpm under the hypervisor)"
    case "$REPO" in /etc/* | /var/*) die "check this repository out outside /etc and /var: the key scans read both" ;; esac
    systemctl is-active --quiet "$SERVICE" || die "$SERVICE is not active"
}

preflight_part_one() {
    local path
    preflight
    for path in "$HOST_DIR" "$STATE_DIR" "$SECRETS"; do
        [ ! -e "$path" ] || die "$path already exists; this check needs a host with no TPM unlock set up (--cleanup removes a run's leftovers)"
    done
    ! findmnt -n -M "$UNLOCK_DIR" >/dev/null 2>&1 || die "$UNLOCK_DIR is a mount point: a handoff unit is already running"
    [[ $(status_line vault) == "not initialized"* ]] || die "the vault already exists; this check needs a package with no vault"
}

banner() {
    echo "tpm-unlock-check ($1) on $(os_field PRETTY_NAME), kernel $(uname -r), $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "$(systemctl --version | head -n 1), virtualisation: $(systemd-detect-virt 2>/dev/null || true)," \
        "$(if command -v mokutil >/dev/null; then mokutil --sb-state 2>&1 | head -n 1; else echo 'Secure Boot state unknown'; fi)"
    echo "tpm: $(systemd-creds has-tpm2 2>&1 | tr '\n' ' '), swap: $(swapon --noheadings --raw --show=NAME | tr '\n' ' ')"
}

# --- Part 1 --------------------------------------------------------------------------------------------------------------------

# Replaces every age secret key, and anything after the marker that looks like one, with a placeholder, and drops the rows of block
# characters that draw the key as a QR code. sed -E: in basic mode {58} would be literal and nothing would be redacted.
redact_keys() { sed -E "s/${KEY_MARKER}[A-Za-z0-9]*/[recovery key]/g" | { grep -avE '█|▀|▄' || true; }; }

# `init --host-unlock` shows the recovery key on the controlling terminal only; script(1) gives it a pty. The transcript is on the
# ramfs, and the key goes to a file there for the recovery check.
# The command is single-quoted so that the shell script(1) starts expands the two variables.
# shellcheck disable=SC2016
run_init_host_unlock() {
    printf '%s\n' "$VAULT_PASS" "$VAULT_PASS" "$APPROVAL_PASS" "$APPROVAL_PASS" yes >"$SECRETS/init.in"
    BINARY=$BINARY INIT_IN=$SECRETS/init.in script -qec '"$BINARY" init --host-unlock <"$INIT_IN"' /dev/null </dev/null \
        >"$SECRETS/init.out" 2>&1 || { redact_keys <"$SECRETS/init.out" | tail -n 5; return 1; }
    grep -aoE "$KEY_RE" "$SECRETS/init.out" >"$SECRETS/recovery.key"
    [ "$(wc -l <"$SECRETS/recovery.key")" -eq 1 ] || { echo "init did not show exactly one recovery key"; return 1; }
}

service_has_no_tpm() {
    local pid nodes
    [ "$(systemctl show -p PrivateDevices --value "$SERVICE")" = yes ] || { echo "PrivateDevices is not yes"; return 1; }
    ! grep -qi tpm <<<"$(systemctl show -p DeviceAllow --value "$SERVICE")" || { echo "DeviceAllow= names a TPM"; return 1; }
    pid=$(main_pid)
    # The positive control: /dev/null shows the service's own /dev is the one being read.
    if [ "$pid" -le 0 ] || [ ! -e "/proc/$pid/root/dev/null" ]; then echo "cannot read the service's /dev (pid '$pid')"; return 1; fi
    nodes=$(ls "/proc/$pid/root/dev")
    ! grep -q '^tpm' <<<"$nodes" || { echo "the service's /dev has a tpm node: $(grep '^tpm' <<<"$nodes" | tr '\n' ' ')"; return 1; }
}

# Item 2's setup half: the service is running when the helper, the handoff unit and init --host-unlock enrol the identity.
enrol_with_init() {
    provision_and_hand_off || return 1
    HOST_KEY=$NEW_KEY
    run_init_host_unlock || return 1
    unlock_service || return 1
    wait_for_state ready
}

recovery_key_opens_the_vault() {
    local kinds x25519 other
    "$BINARY" recovery check <"$SECRETS/recovery.key" || return 1
    # age adds one random "-grease" stanza to every file, so it is allowed; any other kind is not.
    kinds=$(LC_ALL=C awk '/^--- / { exit } /^-> / { print $2 }' /var/lib/iron-vault/identity.age)
    x25519=$(grep -cx X25519 <<<"$kinds" || true)
    other=$(grep -vxE 'X25519|.*-grease' <<<"$kinds" || true)
    echo "stanzas: $(tr '\n' ' ' <<<"$kinds")"
    [ "$x25519" -eq 3 ] && [ -z "$other" ]
}

handoff_is_private() {
    local attrs
    attrs=$(stat -c '%U:%G %a' "$HANDOFF") || return 1
    echo "$UNLOCK_DIR is $(findmnt -n -o FSTYPE -M "$UNLOCK_DIR"), $(stat -c '%U %a' "$UNLOCK_DIR"); $HANDOFF is $attrs"
    [ "$(findmnt -n -o FSTYPE -M "$UNLOCK_DIR")" = ramfs ] && [ "$attrs" = "iron-vault:iron-vault 400" ] \
        && [ "$(stat -c '%U %a' "$UNLOCK_DIR")" = "root 711" ] || return 1
    # The positive control: the service account does read the handoff; an ordinary account reads neither file nor listing.
    runuser -u iron-vault -- test -r "$HANDOFF" || { echo "the service account cannot read the handoff"; return 1; }
    ! runuser -u nobody -- test -r "$HANDOFF" || { echo "an ordinary account reads the handoff"; return 1; }
    ! runuser -u nobody -- test -r "$CRED" || { echo "an ordinary account reads the blob"; return 1; }
    ! runuser -u nobody -- ls "$UNLOCK_DIR" >/dev/null 2>&1 || { echo "an ordinary account lists $UNLOCK_DIR"; return 1; }
}

run_part_one() {
    preflight_part_one
    install -d -m 0700 "$STATE_DIR"
    # Armed only now: a refused start must not tear down an earlier run's ramfs or state.
    ARMED=1
    banner "part 1"
    install -d -m 0700 "$SECRETS"
    mount -t ramfs -o mode=0700 ramfs "$SECRETS"
    check "item 1: PrivateDevices=yes, no TPM in DeviceAllow=, no tpm node in the service's /dev" service_has_no_tpm
    check "item 2a: with the service running, the helper, the handoff unit and init --host-unlock enrol; the vault is Ready" enrol_with_init
    [ -n "$HOST_KEY" ] || return 0
    check "item 4: recovery check opens the vault; identity.age has three X25519 stanzas" recovery_key_opens_the_vault
    check "item 5: the handoff is a 0400 service-owned file on a ramfs in a root 0711 mount; ordinary accounts read nothing" handoff_is_private
}

# --- Part 2 --------------------------------------------------------------------------------------------------------------------

reboot_leaves_it_ready() {
    wait_up 180 || return 1
    systemctl is-active --quiet "$HANDOFF_UNIT" || { echo "$HANDOFF_UNIT is not active after the boot"; return 1; }
    expect_host_unlock "$(boot_since)" unlocked && wait_for_state ready
}

# After a crash or a reinstall the service is Ready by the handoff it already holds, and the handoff unit did not run again.
same_handoff_still_ready() {
    local before after
    before=$(handoff_invocation)
    expecting unlocked ready "$@" || return 1
    after=$(handoff_invocation)
    [ "$before" = "$after" ] || { echo "the handoff unit ran again: $before / $after"; return 1; }
}

reinstall_keeps_it_ready() { same_handoff_still_ready env DEBIAN_FRONTEND=noninteractive dpkg -i "$DEB"; }

# Every full-length age secret key found under the roots, counted per file. It never prints a key.
tree_strays() { { find "$@" -xdev -type f -exec grep -aHoE "$KEY_RE" {} + 2>/dev/null || true; } | cut -d: -f1 | sort | uniq -c; }

# The scan can only say "none" if it can find one, so a planted key is found first.
no_key_on_disk_or_in_environment() {
    local out pid
    printf '%s\n' "$CONTROL_KEY" >"$STATE_DIR/control-key"
    out=$(tree_strays /var)
    rm -f "$STATE_DIR/control-key"
    grep -q "$STATE_DIR/control-key" <<<"$out" || { echo "the scanner did not find a planted key, so it is not working"; return 1; }
    out=$(tree_strays /etc /var)
    [ -z "$out" ] || { echo "files holding an age secret key:"; echo "$out"; return 1; }
    pid=$(main_pid)
    [ -s "/proc/$pid/environ" ] || { echo "cannot read the service's environment"; return 1; }
    out=$(tr '\0' '\n' <"/proc/$pid/environ")
    ! grep -aqE "$KEY_RE" <<<"$out" || { echo "the service's environment holds an age secret key"; return 1; }
}

no_key_in_swap() {
    local dev hits bad=0
    while read -r dev; do
        hits=$(strings -a -n 70 "$dev" | { grep -acE "$KEY_RE" || true; })
        [ "${hits:-0}" -eq 0 ] || { echo "$dev: $hits lines hold an age secret key"; bad=1; }
    done < <(swapon --noheadings --raw --show=NAME)
    [ "$bad" = 0 ] || echo "a hit may be the recovery key this check typed (see the Scope note), or the service's"
    return $bad
}

only_the_expected_listeners() {
    local unix tcp udp
    [ -n "$(ss -lxH)" ] || { echo "ss -lx listed nothing: it is not working"; return 1; }
    unix=$(ss -lxpH | awk '/"iron-vault"/ { print $5 }' | sort -u)
    tcp=$(ss -ltnpH | awk '/"iron-vault"/ { print $4 }')
    udp=$(ss -lunpH | awk '/"iron-vault"/ { print $4 }')
    [ -z "$tcp$udp" ] || { echo "TCP listeners: $tcp; UDP listeners: $udp"; return 1; }
    [ "$unix" = /run/iron-vault/admin.sock ] || { echo "unix listeners: $unix"; return 1; }
}

# Item 8, first half: lock leaves the owner-lock file, and a crash restarts the service Locked.
lock_survives_a_crash() {
    "$BINARY" lock || return 1
    [ -e "$OWNER_LOCK" ] || { echo "lock left no $OWNER_LOCK"; return 1; }
    wait_for_state locked || return 1
    expecting owner_locked locked crash_service || return 1
    [ -e "$OWNER_LOCK" ] || { echo "the crash removed $OWNER_LOCK"; return 1; }
}

run_part_two() {
    banner "part 2"
    check "item 2b: after a reboot the service is Ready with no unlock, and vault.host-unlock says unlocked" reboot_leaves_it_ready
    check "item 3a: kill -9 reaches Ready again with no unlock, and the handoff unit did not run again" \
        same_handoff_still_ready crash_service
    if [ -n "$DEB" ]; then
        check "item 3b: reinstalling the same .deb reaches Ready again with no unlock, and the handoff unit did not run again" \
            reinstall_keeps_it_ready
    else
        skip "item 3b: reinstalling the same .deb reaches Ready again" "pass --deb FILE, the installed package file, to run this"
    fi
    check "item 6: no age secret key under /etc or /var or in the service's environment" no_key_on_disk_or_in_environment
    if [ -n "$(swapon --noheadings --raw --show=NAME)" ]; then
        check "item 6: no age secret key in swap" no_key_in_swap
    else
        skip "item 6: no age secret key in swap" "this host has no swap device, so the swap evidence is missing; rerun on a host with swap"
    fi
    check "item 12: nothing but the admin socket listens" only_the_expected_listeners
    check "item 8a: lock leaves locked-by-owner; kill -9 restarts the service Locked with owner_locked" lock_survives_a_crash
}

# --- Part 3 --------------------------------------------------------------------------------------------------------------------

# Item 8, second half: the owner lock holds across the reboot; a passphrase unlock removes it, and a crash then reaches Ready.
lock_survives_a_reboot() {
    wait_up 180 || return 1
    expect_host_unlock "$(boot_since)" owner_locked && wait_for_state locked || return 1
    [ -e "$OWNER_LOCK" ] || { echo "$OWNER_LOCK is gone after the reboot"; return 1; }
    unlock_service && wait_for_state ready || return 1
    [ ! -e "$OWNER_LOCK" ] || { echo "$OWNER_LOCK is still there after unlock"; return 1; }
    expecting unlocked ready crash_service
}

tpm_unlock_retired() {
    retire_tpm_unlock "$HOST_KEY" || return 1
    expecting absent locked restart_service || return 1
    [ "$(systemctl show -p ConditionResult --value "$HANDOFF_UNIT")" = no ] || { echo "the handoff unit was not skipped"; return 1; }
    [ "$(systemctl show -p ActiveState --value "$HANDOFF_UNIT")" = inactive ] || { echo "the handoff unit is not inactive"; return 1; }
    [ ! -e "$UNSEAL_FAILED" ] || { echo "$UNSEAL_FAILED exists after a retirement"; return 1; }
    unlock_service && wait_for_state ready
}

# With the service running and no host-unlock recipient, the handoff unit starts after it. The running service must see the handoff
# through mount propagation, so it refuses to remove the recipient whose identity the handoff holds (error 38).
handoff_after_the_service() {
    local out
    provision_and_hand_off || return 1
    add_host_unlock "$NEW_KEY" || return 1
    if out=$(remove_recipient "$NEW_KEY" 2>&1); then echo "recipient remove accepted the enrolled host unlock recipient"; return 1; fi
    echo "$out"
    grep -q 'recipient-set-invalid' <<<"$out" && grep -q 'host unlock identity' <<<"$out" || return 1
    HOST_KEY=$NEW_KEY
    expecting unlocked ready restart_service
}

# Item 9: PCR 7 changes as a Secure Boot update would change it. Then the install guide's six steps after an update.
failed_unseal_then_reprovision() {
    local since old=$HOST_KEY attrs out
    LOCKOUT_BEFORE=$(lockout_counter) || LOCKOUT_BEFORE=""   # item 11 fails on an empty value; the failed unseal still has to run
    tpm2_pcrextend "7:sha256=$(printf ivcheck | sha256sum | cut -d' ' -f1)" || return 1
    since=$(now)
    sleep 1
    systemctl restart "$HANDOFF_UNIT" || true
    restart_service || return 1
    expect_host_unlock "$since" unseal_failed && wait_for_state locked || return 1
    [ "$(status_line 'host unlock')" = unseal_failed ] || { echo "status says '$(status_line 'host unlock')', want unseal_failed"; return 1; }
    attrs=$(stat -c '%U %a %F' "$UNSEAL_FAILED") || { echo "no $UNSEAL_FAILED"; return 1; }
    [ "$attrs" = "root 644 regular empty file" ] || { echo "$UNSEAL_FAILED is '$attrs'"; return 1; }
    unlock_service && wait_for_state ready || return 1
    mv "$CRED" "$CRED.old" || return 1
    provision_and_hand_off || return 1
    add_host_unlock "$NEW_KEY" || return 1
    HOST_KEY=$NEW_KEY
    expecting unlocked ready restart_service || return 1
    [ ! -e "$UNSEAL_FAILED" ] || { echo "$UNSEAL_FAILED is still there after the new identity unsealed"; return 1; }
    remove_recipient "$old" || return 1
    rm -f "$CRED.old"
    out=$("$BINARY" recipient list)
    ! grep -q "$old" <<<"$out" || { echo "the old recipient is still enrolled"; return 1; }
}

lockout_counter_unchanged() {
    local after
    [ -n "$LOCKOUT_BEFORE" ] || { echo "item 9 did not read the counter"; return 1; }
    after=$(lockout_counter) || return 1
    echo "TPM2_PT_LOCKOUT_COUNTER: $LOCKOUT_BEFORE before item 9, $after after"
    [ "$LOCKOUT_BEFORE" = "$after" ]
}

# --- Item 13: --portable ---------------------------------------------------------------------------------------------------------
# The helper's HOST_DIR is fixed, and the cases need roots of different kinds. So each case builds a volume on a loop device and
# bind-mounts a directory of it over /etc/iron-vault-host, and the unmodified helper runs against that: it resolves the device
# stack from the mount, as it does on a rebuilt root. The real directory is back after every case.

# portable_up KIND: plain, luks or lvm. LOOP holds the volume's header, as the helper reads it.
portable_up() {
    local kind=$1 dev
    install -d -m 0700 "$HOST_DIR" "$PORT_MNT"
    truncate -s 128M "$PORT_IMG"
    PORT_LOOP=$(losetup --find --show "$PORT_IMG")
    dev=$PORT_LOOP
    if [ "$kind" != plain ]; then
        printf 'ivcheck luks passphrase' >"$PORT_KEY"
        cryptsetup luksFormat -q --type luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --key-file "$PORT_KEY" "$PORT_LOOP"
        cryptsetup open --key-file "$PORT_KEY" "$PORT_LOOP" "$PORT_MAP"
        dev=/dev/mapper/$PORT_MAP
    fi
    if [ "$kind" = lvm ]; then
        pvcreate -qy "$dev" && vgcreate -q "$PORT_VG" "$dev" && lvcreate -q -n lv -l 100%FREE "$PORT_VG"
        dev=/dev/$PORT_VG/lv
    fi
    mkfs.ext4 -q "$dev"
    mount "$dev" "$PORT_MNT"
    install -d -m 0700 "$PORT_MNT/host"
    mount --bind "$PORT_MNT/host" "$HOST_DIR"
}

# Idempotent, and driven by what exists rather than by flags, so --cleanup can undo a run that was killed.
portable_down() {
    if mountpoint -q "$HOST_DIR"; then umount "$HOST_DIR" || true; fi
    if mountpoint -q "$PORT_MNT"; then umount "$PORT_MNT" || true; fi
    if command -v vgs >/dev/null 2>&1 && vgs "$PORT_VG" >/dev/null 2>&1; then
        vgchange -an "$PORT_VG" >/dev/null || true
        vgremove -ff -y "$PORT_VG" >/dev/null || true
        pvremove -ff -y "/dev/mapper/$PORT_MAP" >/dev/null || true
    fi
    if [ -e "/dev/mapper/$PORT_MAP" ]; then cryptsetup close "$PORT_MAP" || true; fi
    if [ -f "$PORT_IMG" ]; then losetup -j "$PORT_IMG" -O NAME -n | xargs -r -n 1 losetup -d || true; fi
    rm -rf "$PORT_IMG" "$PORT_KEY" "$PORT_MNT"
    restore_crypttab
}

# write_crypttab KEYFIELD: the real /etc/crypttab plus an entry for the scratch volume, which a LUKS case needs and which never
# opens at boot. The original is kept in the state directory and put back by portable_down.
write_crypttab() {
    if [ ! -e "$STATE_DIR/crypttab.orig" ] && [ ! -e "$STATE_DIR/crypttab.none" ]; then
        if [ -e "$CRYPTTAB" ]; then cp -p "$CRYPTTAB" "$STATE_DIR/crypttab.orig"; else : >"$STATE_DIR/crypttab.none"; fi
    fi
    { cat "$STATE_DIR/crypttab.orig" 2>/dev/null || true
      printf '%s UUID=%s %s luks,noauto,nofail\n' "$PORT_MAP" "$(cryptsetup luksUUID "$PORT_LOOP")" "$1"; } >"$CRYPTTAB"
}

restore_crypttab() {
    if [ -e "$STATE_DIR/crypttab.orig" ]; then
        cat "$STATE_DIR/crypttab.orig" >"$CRYPTTAB" && rm -f "$STATE_DIR/crypttab.orig"
    elif [ -e "$STATE_DIR/crypttab.none" ]; then
        rm -f "$CRYPTTAB" "$STATE_DIR/crypttab.none"
    fi
}

# portable_helper WANT: runs the helper as an unattended owner would, then clears what it sealed. WANT is a regex that a warning must
# match in the record and the journal, or - when the helper must find no warning.
portable_helper() {
    local want=$1 since out rec=$HOST_DIR/provisioning.txt journal warned
    since=$(date '+%F %T')
    sleep 1
    out=$("$PROVISION" --portable --accept-no-second-secret </dev/null 2>&1) || { echo "$out"; return 1; }
    journal=$(journalctl -q -t iron-vault-host-unlock --since "$since" -o cat)
    warned=$(journalctl -q -t iron-vault-host-unlock -p warning --since "$since" -o cat)
    if ! grep -q 'mode: portable' "$rec" || ! grep -q 'mode: portable' <<<"$journal"; then
        echo "the record lacks the mode: $(cat "$rec")"
        return 1
    fi
    if [ "$want" = - ]; then
        if grep -q ' warning: ' "$rec" || ! grep -q 'accepted: not needed' "$rec" || [ -n "$warned" ]; then
            echo "unexpected warnings: $out"
            return 1
        fi
    elif ! grep -q " warning: .*$want" "$rec" || ! grep -q 'accepted: flag' "$rec" || ! grep -q "$want" <<<"$warned"; then
        echo "want a warning matching '$want' in the record and as auth.warning in the journal: $out"
        return 1
    fi
    [ -f "$CRED" ] || { echo "nothing was sealed"; return 1; }
    rm -f "$CRED" "$rec"
}

# portable_terminal ANSWER: the helper at a pty, answering the prompt. Prints what it said.
portable_terminal() { printf '%s\n' "$1" | script -qec "$PROVISION --portable" /dev/null 2>&1 || true; }

# An unencrypted root: the warning, and who may accept it. `yes |` and a terminal "no" seal nothing; a terminal "yes" seals.
portable_plain_root() {
    local out
    out=$(yes 2>/dev/null | "$PROVISION" --portable 2>&1 || true)
    grep -q 'stdin is not a terminal' <<<"$out" || { echo "yes | helper did not refuse for want of a terminal: $out"; return 1; }
    out=$(portable_terminal no)
    grep -q 'not accepted' <<<"$out" || { echo "a terminal 'no' did not refuse: $out"; return 1; }
    if [ -e "$CRED" ] || [ -e "$HOST_DIR/provisioning.txt" ]; then echo "a refused run left a blob or a record"; return 1; fi
    portable_terminal yes >/dev/null
    if [ ! -f "$CRED" ] || ! grep -q 'accepted: terminal' "$HOST_DIR/provisioning.txt"; then
        echo "a terminal 'yes' did not seal and record"
        return 1
    fi
    rm -f "$CRED" "$HOST_DIR/provisioning.txt"
    portable_helper 'has no dm-crypt layer above it'
}

# cryptsetup_hidden: the helper with no cryptsetup on its path warns that it could not check, and does not pass.
portable_without_cryptsetup() {
    local warnings
    warnings=$(
        # Without -x shellcheck cannot follow $PROVISION (SC1091), so it sees neither the helper's check_portable calling this
        # have_tool override (SC2317) nor its WARNINGS array (SC2153).
        # shellcheck source=packaging/linux/iron-vault-provision-host-unlock
        # shellcheck disable=SC1091
        source "$PROVISION"
        # shellcheck disable=SC2317
        have_tool() { if [ "$1" = cryptsetup ]; then return 1; fi; command -v "$1" >/dev/null; }
        check_portable
        # shellcheck disable=SC2153
        printf '%s\n' "${WARNINGS[@]}"
    )
    grep -q 'cryptsetup is not installed' <<<"$warnings" || { echo "warnings: $warnings"; return 1; }
}

portable_crypttab_key_file() {
    local rc
    write_crypttab "$STATE_DIR/ivcheck.key"
    portable_helper 'key file' || rc=$?
    write_crypttab none
    return "${rc:-0}"
}

portable_clevis_token() {
    local rc
    cryptsetup token import --token-id 5 "$PORT_LOOP" <<<'{"type":"clevis","keyslots":["0"]}' || return 1
    portable_helper 'clevis token' || rc=$?
    cryptsetup token remove --token-id 5 "$PORT_LOOP"
    return "${rc:-0}"
}

# portable_tpm_slot pin|nopin WANT: a systemd-tpm2 slot on the scratch volume, with or without a PIN.
portable_tpm_slot() {
    local rc
    if [ "$1" = pin ]; then
        NEWPIN=ivcheck-pin systemd-cryptenroll --tpm2-device=auto --tpm2-with-pin=yes --unlock-key-file="$PORT_KEY" "$PORT_LOOP" || return 1
    else
        systemd-cryptenroll --tpm2-device=auto --unlock-key-file="$PORT_KEY" "$PORT_LOOP" || return 1
    fi
    portable_helper "$2" || rc=$?
    systemd-cryptenroll --wipe-slot=tpm2 --unlock-key-file="$PORT_KEY" "$PORT_LOOP"
    return "${rc:-0}"
}

run_portable_cases() {
    portable_up plain
    check "item 13: an unencrypted root warns; yes | and a terminal no seal nothing; a terminal yes seals and records" portable_plain_root
    portable_down
    portable_up luks
    write_crypttab none
    check "item 13: a LUKS root opened by passphrase only gives no warning, and the record says so" portable_helper -
    check "item 13: with cryptsetup missing the helper warns that it could not check" portable_without_cryptsetup
    check "item 13: a crypttab key file warns" portable_crypttab_key_file
    check "item 13: a clevis token warns" portable_clevis_token
    check "item 13: a PIN-less systemd-tpm2 slot warns" portable_tpm_slot nopin 'does not need a PIN'
    check "item 13: a systemd-tpm2 slot that needs a PIN gives no warning" portable_tpm_slot pin -
    portable_down
    if command -v lvcreate >/dev/null 2>&1; then
        portable_up lvm
        write_crypttab none
        check "item 13: LVM on a passphrase-only LUKS root gives no warning" portable_helper -
        portable_down
    else
        skip "item 13: LVM on a passphrase-only LUKS root gives no warning" "lvm2 is not installed"
    fi
}

# Item 14 is the one item that needs another release. The helper stops before it touches anything.
helper_stops_on_this_release() {
    local out
    out=$("$PROVISION" --server --accept-physical-access </dev/null 2>&1) && { echo "the helper ran to the end: $out"; return 1; }
    echo "$out"
    grep -q 'supported on Ubuntu 24.04 LTS only' <<<"$out" && [ ! -e "$CRED" ]
}

hypervisor_instructions() {
    local max_fail
    max_fail=$(tpm_property TPM2_PT_MAX_AUTH_FAIL 2>/dev/null || true)
    cat <<TEXT

Two items need the hypervisor, not this script. Record their output with the others.
  Power loss. This TPM's TPM2_PT_MAX_AUTH_FAIL is ${max_fail:-unreadable},
    and TPM2_PT_LOCKOUT_COUNTER is $(lockout_counter 2>/dev/null || echo unreadable).
    Item 9 extended PCR 7 on this boot, so first reboot and provision again (the install guide's TPM unlock section). Then, with the
    service Ready by host unlock (status shows host unlock: unlocked), hard power the machine off: a VM from the hypervisor, not a
    guest shutdown. Do that more times than TPM2_PT_MAX_AUTH_FAIL, each after a boot's unseal. It passes when
    TPM2_PT_LOCKOUT_COUNTER (tpm2_getcap properties-variable) is unchanged and the last boot still reaches Ready with no unlock.
  Lockout, on an emulated TPM only, never on a real machine's. On the swtpm VM, make a throwaway object protected by
    dictionary-attack lockout and give it wrong authorizations until TPM2_PT_LOCKOUT_COUNTER reaches TPM2_PT_MAX_AUTH_FAIL:
    tpm2_createprimary -C o -c prim.ctx; echo throwaway | tpm2_create -C prim.ctx -i - -p goodauth -a 'fixedtpm|fixedparent|userwithauth'
    -u o.pub -r o.priv (no noda, so wrong guesses count); tpm2_load -C prim.ctx -u o.pub -r o.priv -c o.ctx; then tpm2_unseal -c o.ctx
    -p wrongauth that many times; tpm2_getcap properties-variable shows TPM2_PT_LOCKOUT_COUNTER at TPM2_PT_MAX_AUTH_FAIL.
    Reboot without clearing it, and check that the service still reaches Ready with no unlock. Only then reset it with
    tpm2_dictionarylockout --clear-lockout.
TEXT
}

run_part_three() {
    banner "part 3"
    check "item 8b: the owner lock holds across a reboot; unlock removes it; kill -9 then reaches Ready" lock_survives_a_reboot
    check "item 10: retiring TPM unlock leaves the service Locked with absent, the handoff unit skipped, no unseal-failure file" \
        tpm_unlock_retired
    check "item 7: the handoff unit started after the service: recipient remove of that recipient is refused" handoff_after_the_service
    check "item 9: PCR 7 extended: unseal_failed in the record and status, the root-owned file, unlock works, re-provisioning restores" \
        failed_unseal_then_reprovision
    check "item 11: TPM2_PT_LOCKOUT_COUNTER is unchanged by item 9" lockout_counter_unchanged
    run_portable_cases
    skip "item 14: the helper stops on a release other than Ubuntu 24.04" "this is Ubuntu 24.04; run this script on Debian 12 or another release"
    retire_tpm_unlock "$HOST_KEY" >/dev/null 2>&1 || echo "note: could not retire TPM unlock at the end; destroy the VM"
    if ! mountpoint -q "$HOST_DIR"; then rm -rf "$HOST_DIR"; fi
}

# --- Driver --------------------------------------------------------------------------------------------------------------------

# Part 1 and 2 end by asking for a reboot; part 3 and an unsupported release end with the summary.
run_next_part() {
    local part=1
    WORK=$STATE_DIR
    if [ -d "$STATE_DIR" ]; then
        load_state
        part=$NEXT
        [ "$BOOT_ID" != "$(cat /proc/sys/kernel/random/boot_id)" ] || die "the host has not rebooted since part $((part - 1))"
    fi
    case $part in
        1) run_part_one ;;
        2) ARMED=1; run_part_two ;;
        3) ARMED=1; run_part_three; finish; return ;;
    esac
    save_state $((part + 1))
    echo "$PASSED passed, $FAILED failed, $SKIPPED skipped so far. Reboot now (sudo reboot), then run this command again."
    [ "$FAILED" -eq 0 ]
}

# The summary, then what the hypervisor must do; the exit status is the summary's.
finish() {
    local rc=0
    summary || rc=1
    hypervisor_instructions
    rm -rf "$STATE_DIR"
    return $rc
}

summary() {
    echo "$PASSED passed, $FAILED failed, $SKIPPED skipped (a skipped item has no evidence from this host)"
    [ "$FAILED" -eq 0 ]
}

# On any release but Ubuntu 24.04 only item 14 runs, and it changes nothing.
run_unsupported_release() {
    WORK=$(mktemp -d)
    banner "item 14 only"
    check "item 14: the helper stops on $(os_field PRETTY_NAME)" helper_stops_on_this_release
    rm -rf "$WORK"
    summary
}

# Removes what a run kept, never the vault. It acts on what exists, so it also undoes a run that was killed.
abandon() {
    set +e
    # Without a run's state directory, /etc/iron-vault-host may hold a real sealed blob; leave it alone.
    [ -d "$STATE_DIR" ] || { echo "no run to abandon: $STATE_DIR does not exist, so nothing was removed"; return 0; }
    systemctl stop "$HANDOFF_UNIT" >/dev/null 2>&1
    portable_down
    mountpoint -q "$SECRETS" && umount "$SECRETS"
    rm -rf "$SECRETS" "$HOST_DIR" "$STATE_DIR"
    echo "removed the handoff, $HOST_DIR and $STATE_DIR; the vault in /var/lib/iron-vault is still there (destroy the VM)"
}

# On every exit path: the scratch volume and the ramfs holding the recovery key go; the state between parts stays.
cleanup() {
    set +e
    [ "$ARMED" = 1 ] || return 0
    portable_down
    mountpoint -q "$SECRETS" && umount "$SECRETS"
    rm -rf "$SECRETS"
}

main() {
    parse_args "$@"
    require_root_and_package
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM HUP
    if [ "$MODE" = cleanup ]; then abandon; return 0; fi
    on_supported_release || { run_unsupported_release; return; }
    run_next_part
}

# Sourcing the file (to test the helpers) defines the functions and runs nothing.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then main "$@"; fi
