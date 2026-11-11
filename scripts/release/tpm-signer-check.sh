#!/usr/bin/env bash
# Release check for the TPM approval signer on a real install of the package: the evidence for implementation spec §3's "TPM
# authorization and power failure" gate and for product spec §14 to list the TPM approval signer as offered
# (design/tpm-approval-signer.md, "Release checks"; the item numbers below are that section's). It covers the parts an emulator
# cannot: the installed units under systemd, a firmware TPM's dictionary-attack settings, the helper's TCTI trace on the real bus,
# and the dictionary-attack counter and the approval key across unclean power loss. The emulator-only items (7, 10) run against
# swtpm in crates/iron-vault/tests/tpm_approver_linux.rs and are SKIPped here.
#
# !! RUN THIS ONLY ON A DISPOSABLE MACHINE WITH A TPM 2.0 AT /dev/tpmrm0. !!  It runs as root on a real install of the package. It:
#   - creates a vault (init), enrolls a TPM approver, approves configs, adds and removes one credential and one recipient;
#   - spends two wrong tries of the TPM's dictionary-attack counter (item 6) and one per power cut it asks for;
#   - adds a systemd drop-in that turns on the TSS library's TCTI trace for the helper (item 9), removed on every exit path.
# It never clears the TPM, sets an authorization or changes dictionary-attack parameters.
#
# Set up: Ubuntu 24.04 LTS with the package installed (scripts/build-deb.sh, then sudo apt install ./iron-vault_*.deb), the
# service running with no vault, and tpm2-tools, age (age-keygen), python3, util-linux (runuser) and binutils (ldd comes with libc).
# An ordinary account that is not root, iron-vault or iron-vault-tpm: TEST_ACCOUNT.
#
# Run, in order, with the same command each time; the script keeps its place in /var/lib/ivcheck-tpm-signer-check:
#   sudo scripts/release/tpm-signer-check.sh --i-know-this-is-a-disposable-vm TEST_ACCOUNT   # part 1: items 1 to 10
#   <cut the power without a clean shutdown: the hypervisor's power off or reset, not `reboot`>
#   (same command)                                                                            # part 2: counter, approval, cut 2
#   <cut the power>
#   (same command)                                                                            # part 3: counter, approval, cut 3
#   <cut the power>
#   (same command)                                                                            # part 4: counter, approval, item 11, summary
#   --cleanup     removes the drop-in and the script's state, to abandon a run.
#
# Prints one PASS, FAIL or SKIP line per item, with the reason under a FAIL, and exits 1 if any failed. A SKIP is no evidence.
# Exit 2 means the script could not start (bad arguments, not root, no opt-in, a missing tool, no TPM, no reboot since the last
# part). Attach all four parts' output to the ticket: it is the gate's evidence. Part 1 also records the TPM's dictionary-attack
# settings, so the manual can say what the reserve allows on this hardware, and the counter after each boot.
set -euo pipefail

BINARY=/usr/bin/iron-vault
HELPER=/usr/libexec/iron-vault/iron-vault-tpm-signer
SERVICE=iron-vault.service
SOCKET_UNIT=iron-vault-tpm-signer.socket
SOCKET=/run/iron-vault-tpm/signer.sock
STATE_DIR=/var/lib/ivcheck-tpm-signer-check
VAULT_DIR=/var/lib/iron-vault
CONFIG_SIG=/etc/iron-vault/config.toml.sig
AUDIT_LOG=/var/log/iron-vault/iron-vault.log
DROPIN_DIR=/etc/systemd/system/iron-vault-tpm-signer@.service.d
VAULT_PASS="ivcheck vault passphrase"
APPROVAL_PASS="ivcheck approval passphrase"
PIN="ivcheck pin 7731"
WRONG_PIN="ivcheck wrong 0000"
CYCLES=3

PASSED=0
FAILED=0
SKIPPED=0
WORK=""
ACCOUNT=""

die() { echo "error: $*" >&2; exit 2; }

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

skip() {
    echo "SKIP $1"
    echo "     $2"
    SKIPPED=$((SKIPPED + 1))
}

# --- Driving the CLI's terminal prompts ------------------------------------------------------------------------------------------

# Runs `drive ANSWER... -- COMMAND...` under a pty, answering each prompt in turn once the output has been quiet for a moment.
# CTRL-Y is the switch key; every other answer is typed with a newline. Exits with the command's status.
write_driver() {
    cat >"$WORK/drive.py" <<'PY'
import os, pty, select, sys, time
split = sys.argv.index("--")
answers, command = sys.argv[1:split], sys.argv[split + 1:]
pid, fd = pty.fork()
if pid == 0:
    os.execvp(command[0], command)
sent, last = 0, time.time()
while True:
    ready, _, _ = select.select([fd], [], [], 0.3)
    if ready:
        try:
            data = os.read(fd, 4096)
        except OSError:
            break
        if not data:
            break
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
        last = time.time()
    elif sent < len(answers) and time.time() - last > 0.8:
        answer = answers[sent]
        os.write(fd, b"\x19" if answer == "CTRL-Y" else answer.encode() + b"\n")
        sent += 1
        last = time.time()
_, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status))
PY
}

drive() { python3 "$WORK/drive.py" "$@"; }

# --- Helpers ---------------------------------------------------------------------------------------------------------------------

lockout_counter() { tpm2_getcap properties-variable | sed -n 's/^TPM2_PT_LOCKOUT_COUNTER: *0x\([0-9a-f]*\).*/\1/p' | { read -r hex; echo $((16#${hex:-0})); }; }
tpm_approver_id() { "$BINARY" approver list | awk '$2 == "tpm" { print $1 }'; }
unlock_service() { printf '%s\n' "$VAULT_PASS" | "$BINARY" unlock; }
now() { date -u +%Y-%m-%dT%H:%M:%S; }

# Approves a config that differs from the last one, asking the TPM approver for $1. The active signer is asked first, so when it is
# not the TPM approver the owner switches.
approve_with_tpm() {
    local pin=$1 order=$2
    printf 'schema_version = 1\n# ivcheck %s\n' "$(date +%s%N)" >"$STATE_DIR/config.toml"
    if [ "$order" = switch ]; then
        drive yes CTRL-Y "$pin" -- "$BINARY" config approve "$STATE_DIR/config.toml"
    else
        drive yes "$pin" -- "$BINARY" config approve "$STATE_DIR/config.toml"
    fi
}

# --- Items -----------------------------------------------------------------------------------------------------------------------

item_1() {
    [ "$(systemctl show -p PrivateDevices --value "$SERVICE")" = yes ] || { echo "iron-vault.service lost PrivateDevices=yes"; return 1; }
    ! systemctl cat "$SERVICE" | grep -q '^DeviceAllow=' || { echo "iron-vault.service has a DeviceAllow= line"; return 1; }
    local pid
    pid=$(systemctl show -p MainPID --value "$SERVICE")
    compgen -G "/proc/$pid/root/dev/tpm*" >/dev/null && { echo "the service's /dev has a tpm node"; return 1; }
    ! ldd "$BINARY" | grep -q libtss2 || { echo "$BINARY links libtss2"; return 1; }
    ldd "$HELPER" | grep -q libtss2
}

# A held connection starts one instance. The socket is iron-vault:root 0600; MaxConnections=1 closes a second connection at once; the
# instance runs as iron-vault-tpm with the tss group; an ordinary account cannot connect.
item_2() {
    [ "$(stat -c '%U:%G %a' "$SOCKET")" = "iron-vault:root 600" ] || { echo "socket is $(stat -c '%U:%G %a' "$SOCKET")"; return 1; }
    [ "$(systemctl show -p MaxConnections --value "$SOCKET_UNIT")" = 1 ] || { echo "MaxConnections is not 1"; return 1; }
    python3 - "$SOCKET" "$(id -u iron-vault)" <<'PY'
import os, socket, subprocess, sys, time
path, uid = sys.argv[1], int(sys.argv[2])
os.seteuid(uid)
first = socket.socket(socket.AF_UNIX); first.connect(path)
time.sleep(1)
pids = subprocess.run(["pgrep", "-f", "^/usr/libexec/iron-vault/iron-vault-tpm-signer"], capture_output=True, text=True).stdout.split()
status = open(f"/proc/{pids[0]}/status").read() if pids else ""
if "Uid:\t" not in status:
    sys.exit("no helper instance started for the held connection")
account = subprocess.run(["id", "-u", "iron-vault-tpm"], capture_output=True, text=True).stdout.strip()
tss = subprocess.run(["getent", "group", "tss"], capture_output=True, text=True).stdout.split(":")[2]
if status.split("Uid:\t")[1].split()[0] != account or tss not in status.split("Groups:")[1].split("\n")[0].split():
    sys.exit(f"instance is not iron-vault-tpm with the tss group:\n{status}")
second = socket.socket(socket.AF_UNIX); second.settimeout(2)
second.connect(path)
if second.recv(1) != b"":
    sys.exit("a second connection was answered, not closed")
PY
    ! runuser -u "$ACCOUNT" -- python3 -c "import socket; s = socket.socket(socket.AF_UNIX); s.connect('$SOCKET')" 2>/dev/null \
        || { echo "$ACCOUNT can connect to the helper's socket"; return 1; }
}

item_3() {
    drive "$APPROVAL_PASS" "$PIN" "$PIN" -- "$BINARY" approver add --kind tpm --label "ivcheck TPM" >"$WORK/enroll.out"
    local id
    id=$(tpm_approver_id)
    [ -n "$id" ] || { echo "approver list shows no tpm approver"; return 1; }
    [ "$(stat -c %a "$VAULT_DIR/approver-$id.tpm")" = 600 ] || { echo "blob mode is not 0600"; return 1; }
}

item_4() {
    approve_with_tpm "$PIN" switch >"$WORK/approve.out"
    [ "$(stat -c %s "$CONFIG_SIG")" = 191 ] || { echo "config.toml.sig is $(stat -c %s "$CONFIG_SIG") bytes, not 191"; return 1; }
    systemctl restart "$SERVICE"
    unlock_service
    "$BINARY" status | grep -q 'service: ready'
}

# Owner presence by PIN for rm; the TPM approver signed the active approval, so it is asked first.
item_5() {
    drive "ivcheck-secret" -- "$BINARY" add ivcheck_key --origin example.invalid >/dev/null
    drive "$PIN" -- "$BINARY" rm ivcheck_key >/dev/null
}

# A wrong PIN is approval-denied, and the dictionary-attack counter rises by exactly one.
item_6() {
    local before after
    before=$(lockout_counter)
    if approve_with_tpm "$WRONG_PIN" order >"$WORK/wrong.out"; then echo "a wrong PIN approved"; return 1; fi
    after=$(lockout_counter)
    [ "$after" = $((before + 1)) ] || { echo "counter went from $before to $after"; return 1; }
    grep -qi 'approval-denied\|counts against' "$WORK/wrong.out"
}

# recipient add accepts the PIN by switching from the vault passphrase; the audit log names tpm_pin and the approver.
item_8() {
    local key since
    key=$(age-keygen 2>/dev/null | sed -n 's/^# public key: //p')
    since=$(now)
    drive "CTRL-Y" "$PIN" -- "$BINARY" recipient add "$key" --label "ivcheck recipient" >/dev/null
    jq -e -R --arg s "$since" 'fromjson? | select(.event == "migration.authorized" and .timestamp >= $s and .method == "tpm_pin")' "$AUDIT_LOG" >/dev/null
    ! grep -qF "$PIN" "$AUDIT_LOG" || { echo "the PIN is in the audit log"; return 1; }
}

# The TSS library's trace of the helper, on the real bus: the PIN never appears, and the session encrypts the authorization value.
item_9() {
    mkdir -p "$DROPIN_DIR"
    printf '[Service]\nEnvironment=TSS2_LOG=tcti+trace\n' >"$DROPIN_DIR/ivcheck-trace.conf"
    systemctl daemon-reload
    local since
    since=$(now)
    approve_with_tpm "$PIN" order >/dev/null
    journalctl -u 'iron-vault-tpm-signer@*' --since "$since" -o cat --no-pager >"$WORK/trace.txt"
    python3 - "$WORK/trace.txt" "$PIN" <<'PY'
import re, sys
dump = "".join(m.group(1) for m in re.finditer(r"^[0-9a-f]{4}: ([0-9a-f]+)", open(sys.argv[1]).read(), re.M))
if len(dump) < 200:
    sys.exit("the trace holds no TPM traffic, so it proves nothing")
if sys.argv[2].encode().hex() in dump:
    sys.exit("the PIN is in the trace")
PY
}

# The TPM approver signed the active approval, so a software approver approves again before the TPM one can go; then its blob is gone.
item_11() {
    local id
    id=$(tpm_approver_id)
    drive yes CTRL-Y "$APPROVAL_PASS" -- "$BINARY" config approve "$STATE_DIR/config.toml" >/dev/null
    drive "$APPROVAL_PASS" -- "$BINARY" approver remove "$id" >/dev/null
    [ ! -e "$VAULT_DIR/approver-$id.tpm" ] || { echo "the blob is still there"; return 1; }
}

record_da_settings() {
    echo "== dictionary-attack settings of this TPM (record them for the manual)"
    tpm2_getcap properties-variable | grep -E 'LOCKOUT|MAX_AUTH_FAIL|PERMANENT' || true
    tpm2_getcap properties-fixed | grep -E 'MANUFACTURER|VENDOR_STRING_1|FIRMWARE_VERSION_1' || true
}

# --- Power loss ------------------------------------------------------------------------------------------------------------------

save_state() { printf 'CYCLE=%q\nCOUNTER=%q\nBOOT_ID=%q\n' "$1" "$2" "$(cat /proc/sys/kernel/random/boot_id)" >"$STATE_DIR/state.env"; }

# Item 12, the power-loss item: after each unclean power cut the counter rose by at most one and an approval still works.
power_loss_part() {
    # shellcheck source=/dev/null
    source "$STATE_DIR/state.env"
    [ "$BOOT_ID" != "$(cat /proc/sys/kernel/random/boot_id)" ] || die "the machine has not rebooted since the last part"
    local now_counter
    now_counter=$(lockout_counter)
    # shellcheck disable=SC2153 # CYCLE comes from the state file sourced above
    echo "cycle ${CYCLE}: dictionary-attack counter before the cut $COUNTER, after the boot $now_counter"
    check "power cut $CYCLE: the counter rose by at most one" test "$now_counter" -le $((COUNTER + 1))
    unlock_service >/dev/null
    check "power cut $CYCLE: the TPM approver still approves" approve_with_tpm "$PIN" order
    if [ "$CYCLE" -lt "$CYCLES" ]; then
        save_state $((CYCLE + 1)) "$(lockout_counter)"
        echo "Cut the power now without a clean shutdown, then run this script again."
        return
    fi
    check "item 11: removing the TPM approver deletes its blob" item_11
    finish
}

finish() {
    echo "passed $PASSED, failed $FAILED, skipped $SKIPPED"
    rm -rf "$DROPIN_DIR" "$STATE_DIR"
    systemctl daemon-reload
    [ "$FAILED" = 0 ]
}

# --- Entry -----------------------------------------------------------------------------------------------------------------------

cleanup_dropin() { rm -rf "$DROPIN_DIR"; systemctl daemon-reload || true; }

first_part() {
    mkdir -p "$STATE_DIR"
    check "item 1: the service has no TPM device and links no libtss2" item_1
    drive "$VAULT_PASS" "$VAULT_PASS" "$APPROVAL_PASS" "$APPROVAL_PASS" yes -- "$BINARY" init >/dev/null
    unlock_service >/dev/null
    check "item 2: the helper's account, group and socket" item_2
    check "item 3: approver add --kind tpm enrolls, with a 0600 blob" item_3
    check "item 4: config approve with the PIN is a 191-byte envelope that survives a restart" item_4
    check "item 5: rm accepts the PIN as owner presence" item_5
    check "item 6: a wrong PIN is denied and spends exactly one try" item_6
    skip "item 7: the lockout reserve" "emulated TPM only: it needs lowered dictionary-attack settings; run in tests/tpm_approver_linux.rs"
    check "item 8: recipient add accepts the PIN and the audit log names tpm_pin" item_8
    check "item 9: the TCTI trace holds no PIN" item_9
    cleanup_dropin
    skip "item 10: a cleared TPM is not this TPM" "emulated TPM only: this script never clears the TPM"
    record_da_settings
    save_state 1 "$(lockout_counter)"
    echo "Part 1 done. Cut the power now without a clean shutdown, then run this script again."
    [ "$FAILED" = 0 ]
}

main() {
    local opt_in=0 cleanup=0 arg
    for arg in "$@"; do
        case "$arg" in
            --i-know-this-is-a-disposable-vm) opt_in=1 ;;
            --cleanup) cleanup=1 ;;
            -*) die "unknown option $arg" ;;
            *) ACCOUNT=$arg ;;
        esac
    done
    [ "$(id -u)" = 0 ] || die "run as root"
    if [ "$cleanup" = 1 ]; then cleanup_dropin; rm -rf "$STATE_DIR"; echo "cleaned up"; exit 0; fi
    [ "$opt_in" = 1 ] || die "this changes the machine; pass --i-know-this-is-a-disposable-vm"
    [ -n "$ACCOUNT" ] || die "name an ordinary test account"
    id "$ACCOUNT" >/dev/null 2>&1 || die "no account $ACCOUNT"
    local tool
    for tool in tpm2_getcap python3 runuser age-keygen jq journalctl systemctl; do
        command -v "$tool" >/dev/null 2>&1 || die "$tool is not installed"
    done
    [ -c /dev/tpmrm0 ] || die "no /dev/tpmrm0: this machine has no TPM 2.0"
    [ -x "$HELPER" ] || die "$HELPER is not installed: install the package"
    WORK=$(mktemp -d)
    trap 'rm -rf "$WORK" "$DROPIN_DIR"' EXIT
    write_driver
    if [ -f "$STATE_DIR/state.env" ]; then
        power_loss_part
    else
        [ ! -e "$VAULT_DIR/identity.age" ] || die "a vault exists already; run this on a fresh install"
        first_part
    fi
}

# Defines the functions only when sourced, so a test can call them.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    main "$@"
fi
