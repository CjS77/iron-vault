#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# Release check for the TPM approval signer on a real install of the package: the evidence for implementation spec §3's "TPM
# authorization and power failure" gate and for product spec §14 to list the TPM approval signer as offered
# (design/tpm-approval-signer.md, "Release checks"; the item numbers below are that section's). Two runs make the gate:
#   - on hardware with a firmware TPM, the default: the installed units under systemd, the dictionary-attack settings, the helper's
#     TCTI trace on the real bus, and the dictionary-attack counter and the approval key across unclean power loss. Items 7 and 10
#     change or clear the TPM, so they are SKIPped, and a SKIP is no evidence;
#   - in a VM whose TPM is `swtpm`, with --emulated-tpm: the same items except the power cuts, plus items 7 (the lockout reserve,
#     including many wrong-PIN connections at once, which only the socket unit's MaxConnections=1 keeps from overspending) and 10
#     (a cleared TPM is not this TPM). The script refuses the flag unless the TPM reports the emulator's manufacturer.
#
# !! RUN THIS ONLY ON A DISPOSABLE MACHINE WITH A TPM 2.0 AT /dev/tpmrm0. !!  It runs as root on a real install of the package. It:
#   - creates a vault (init), enrolls a TPM approver, approves configs, adds, replaces and removes one credential, adds and removes
#     two recipients and writes one export bundle;
#   - creates the account ivcheck-member (in the iron-vault group) for item 2 and deletes it again;
#   - spends two wrong tries of the TPM's dictionary-attack counter (item 6) and one per power cut it asks for;
#   - adds a systemd drop-in that turns on the TSS library's TCTI trace for the helper (item 9), removed on every exit path.
# On hardware it never clears the TPM, sets an authorization or changes dictionary-attack parameters. With --emulated-tpm it does all
# three (items 7 and 10) and leaves the emulator's dictionary-attack parameters at a maximum of 32 tries and a 600 s interval.
#
# Set up: Ubuntu 24.04 LTS with the package installed (scripts/build-deb.sh, then sudo apt install ./target/debian/iron-vault_*.deb),
# the service running with no vault, and tpm2-tools, age (age-keygen), jq, python3 and util-linux (runuser).
# An ordinary account that is not root, iron-vault or iron-vault-tpm: TEST_ACCOUNT.
#
# On hardware, run in order, with the same command each time; the script keeps its place in /var/lib/ivcheck-tpm-signer-check:
#   sudo scripts/release/tpm-signer-check.sh --i-know-this-is-a-disposable-vm TEST_ACCOUNT   # part 1: items 1 to 6, 8, 9
#   <cut the power without a clean shutdown: the hypervisor's power off or reset, not `reboot`>
#   (same command)                                                                            # part 2: counter, approval, cut 2
#   <cut the power>
#   (same command)                                                                            # part 3: counter, approval, cut 3
#   <cut the power>
#   (same command)                                                                            # part 4: counter, approval, item 11, summary
# In a swtpm VM, one run does everything:
#   sudo scripts/release/tpm-signer-check.sh --i-know-this-is-a-disposable-vm --emulated-tpm TEST_ACCOUNT
#   --cleanup     removes the drop-in, the ivcheck-member account and the script's state, to abandon a run.
#
# Prints one PASS, FAIL or SKIP line per item, with the reason under a FAIL. Every part exits 1 if any item so far failed, and the
# last part's summary counts all parts. Exit 2 means the script could not start (bad arguments, not root, no opt-in, a missing tool,
# no TPM, --emulated-tpm on a TPM that is not the emulator, no reboot since the last part). Attach every part's output to the
# ticket: it is the gate's evidence. Part 1 also records the TPM's dictionary-attack settings, so the manual can say what the
# reserve allows on this hardware, and the counter after each boot.
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
MEMBER=ivcheck-member
VAULT_PASS="ivcheck vault passphrase"
APPROVAL_PASS="ivcheck approval passphrase"
EXPORT_PASS="ivcheck export passphrase"
PIN="ivcheck pin 7731"
WRONG_PIN="ivcheck wrong 0000"
CYCLES=3
# Item 7's settings: a maximum of 2 tries gives the helper a share of one; the interval is the design's floor.
RESERVE_MAX_TRIES=2
DA_INTERVAL=600
SHARE=1

PASSED=0
FAILED=0
SKIPPED=0
WORK=""
ACCOUNT=""
EMULATED=0

die() { echo "error: $*" >&2; exit 2; }

# Runs the item in a subshell with `set -e` on. A bare `if "$@"` would suspend `set -e` for the whole item, so an assertion whose
# status nothing tested could never fail it.
check() {
    local name=$1 out="$WORK/check.out" status
    shift
    set +e
    ( set -e; "$@" ) >"$out" 2>&1
    status=$?
    set -e
    if [ "$status" = 0 ]; then
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

# The kind of the approver a prompt asks first (`approver list` prints it first): the one that signed the active approval.
first_kind() { "$BINARY" approver list | awk 'NR == 1 { print $2 }'; }

# CTRL-Y when the prompt must be switched to reach an approver of kind $1, nothing when it already starts there.
switch_to() { [ "$(first_kind)" = "$1" ] || echo CTRL-Y; }

# A config that differs from every earlier one, so each approval is a change.
new_config() {
    local file
    file="$STATE_DIR/config-$(date +%s%N).toml"
    printf 'schema_version = 1\n# ivcheck %s\n' "$(date +%s%N)" >"$file"
    echo "$file"
}

# Approves a new config with the TPM approver, switching to it if another approver is asked first.
approve_with_tpm() {
    local pin=$1 file=${2:-} sw
    sw=$(switch_to tpm)
    [ -n "$file" ] || file=$(new_config)
    # shellcheck disable=SC2086 # $sw is CTRL-Y or empty
    drive yes $sw "$pin" -- "$BINARY" config approve "$file"
}

approve_with_software() {
    local sw
    sw=$(switch_to software)
    # shellcheck disable=SC2086 # $sw is CTRL-Y or empty
    drive yes $sw "$APPROVAL_PASS" -- "$BINARY" config approve "$(new_config)"
}

# The authorization value the service derives from the PIN (iron-vault-tpm-protocol/src/pin.rs: BLAKE2b-256 personalized
# "iv-tpm-pin-v1" over the approver's 16 ID bytes and the PIN), as lowercase hex. The helper receives this, never the PIN.
auth_value_hex() {
    python3 -c 'import hashlib, sys, uuid
print(hashlib.blake2b(uuid.UUID(sys.argv[1]).bytes + sys.argv[2].encode(), digest_size=32, person=b"iv-tpm-pin-v1").hexdigest())' "$1" "$2"
}

# Lowers or raises the TPM's dictionary-attack parameters and clears its counter. Emulated TPM only.
set_dictionary_attack() {
    tpm2_dictionarylockout --clear-lockout
    tpm2_dictionarylockout --setup-parameters "--max-tries=$1" "--recovery-time=$2" --lockout-recovery-time=1
}

# Whether $1 gets "permission denied" when it connects to the helper's socket: any other outcome, including a connection, is a failure.
cannot_connect() {
    runuser -u "$1" -- python3 - "$SOCKET" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX)
try:
    s.connect(sys.argv[1])
except PermissionError:
    sys.exit(0)
sys.exit("connected, or failed other than by permission")
PY
}

drop_member() {
    if id "$MEMBER" >/dev/null 2>&1; then userdel "$MEMBER" >/dev/null 2>&1 || true; fi
}

# --- Items -----------------------------------------------------------------------------------------------------------------------

item_1() {
    [ "$(systemctl show -p PrivateDevices --value "$SERVICE")" = yes ] || { echo "iron-vault.service lost PrivateDevices=yes"; return 1; }
    ! systemctl cat "$SERVICE" | grep -q '^DeviceAllow=' || { echo "iron-vault.service has a DeviceAllow= line"; return 1; }
    local pid
    pid=$(systemctl show -p MainPID --value "$SERVICE")
    ! compgen -G "/proc/$pid/root/dev/tpm*" >/dev/null || { echo "the service's /dev has a tpm node"; return 1; }
    ! ldd "$BINARY" | grep -q libtss2 || { echo "$BINARY links libtss2"; return 1; }
    ldd "$HELPER" | grep -q libtss2 || { echo "$HELPER does not link libtss2"; return 1; }
}

# A held connection starts one instance. The socket is iron-vault:root 0600; MaxConnections=1 closes a second connection at once; the
# instance runs as iron-vault-tpm with tss only as a supplementary group; an ordinary account and an account in the iron-vault group
# cannot connect.
item_2() {
    [ "$(stat -c '%U:%G %a' "$SOCKET")" = "iron-vault:root 600" ] || { echo "socket is $(stat -c '%U:%G %a' "$SOCKET")"; return 1; }
    [ "$(systemctl show -p MaxConnections --value "$SOCKET_UNIT")" = 1 ] || { echo "MaxConnections is not 1"; return 1; }
    python3 - "$SOCKET" "$(id -u iron-vault)" "$(id -u iron-vault-tpm)" "$(id -g iron-vault-tpm)" "$(getent group tss | cut -d: -f3)" <<'PY' || return 1
import os, socket, subprocess, sys, time
path, service_uid, account_uid, account_gid, tss_gid = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
os.seteuid(service_uid)
first = socket.socket(socket.AF_UNIX)
first.connect(path)
time.sleep(1)
pids = subprocess.run(["pgrep", "-f", "^/usr/libexec/iron-vault/iron-vault-tpm-signer"], capture_output=True, text=True).stdout.split()
if not pids:
    sys.exit("no helper instance started for the held connection")
fields = dict(line.split(":\t", 1) for line in open(f"/proc/{pids[0]}/status").read().splitlines() if ":\t" in line)
if fields["Uid"].split()[0] != account_uid or fields["Gid"].split()[0] != account_gid:
    sys.exit(f"instance is not iron-vault-tpm:iron-vault-tpm: Uid {fields['Uid']} Gid {fields['Gid']}")
if tss_gid not in fields["Groups"].split():
    sys.exit(f"instance lacks the tss group as a supplementary group: Groups {fields['Groups']}")
second = socket.socket(socket.AF_UNIX)
second.settimeout(2)
second.connect(path)
if second.recv(1) != b"":
    sys.exit("a second connection was answered, not closed")
PY
    cannot_connect "$ACCOUNT" || { echo "$ACCOUNT can connect to the helper's socket"; return 1; }
    drop_member
    useradd --system --no-create-home --no-user-group --groups iron-vault --shell /usr/sbin/nologin "$MEMBER"
    cannot_connect "$MEMBER" || { drop_member; echo "$MEMBER, in the iron-vault group, can connect to the helper's socket"; return 1; }
    drop_member
}

item_3() {
    drive "$APPROVAL_PASS" "$PIN" "$PIN" -- "$BINARY" approver add --kind tpm --label "ivcheck TPM" >"$WORK/enroll.out"
    local id
    id=$(tpm_approver_id)
    [ -n "$id" ] || { echo "approver list shows no tpm approver"; return 1; }
    [ "$(stat -c %a "$VAULT_DIR/approver-$id.tpm")" = 600 ] || { echo "blob mode is not 0600"; return 1; }
}

item_4() {
    approve_with_tpm "$PIN" >"$WORK/approve.out"
    [ "$(stat -c %s "$CONFIG_SIG")" = 191 ] || { echo "config.toml.sig is $(stat -c %s "$CONFIG_SIG") bytes, not 191"; return 1; }
    systemctl restart "$SERVICE"
    unlock_service
    "$BINARY" status | grep -q 'service: ready' || { echo "the service is not ready after a restart"; return 1; }
}

# Owner presence by PIN for replace, rm and recipient remove. The recipient is added with the vault passphrase, which is what
# recipient add asks first.
item_5() {
    local key sw
    key=$(age-keygen 2>/dev/null | sed -n 's/^# public key: //p')
    drive "ivcheck-secret" -- "$BINARY" add ivcheck_key --origin example.invalid >/dev/null
    sw=$(switch_to tpm)
    # shellcheck disable=SC2086 # $sw is CTRL-Y or empty
    drive $sw "$PIN" "ivcheck-secret-2" -- "$BINARY" replace ivcheck_key --origin example.invalid >/dev/null
    # shellcheck disable=SC2086
    drive $sw "$PIN" -- "$BINARY" rm ivcheck_key >/dev/null
    drive "$VAULT_PASS" -- "$BINARY" recipient add "$key" --label "ivcheck removable" >/dev/null
    "$BINARY" recipient list | grep -qF "$key" || { echo "recipient add did not enroll the key"; return 1; }
    # shellcheck disable=SC2086
    drive $sw "$PIN" -- "$BINARY" recipient remove "$key" >/dev/null
    ! "$BINARY" recipient list | grep -qF "$key" || { echo "recipient remove left the key"; return 1; }
}

# A wrong PIN is approval-denied, and the dictionary-attack counter rises by exactly one.
item_6() {
    local before after
    before=$(lockout_counter)
    if approve_with_tpm "$WRONG_PIN" >"$WORK/wrong.out"; then echo "a wrong PIN approved"; return 1; fi
    after=$(lockout_counter)
    [ "$after" = $((before + 1)) ] || { echo "counter went from $before to $after"; return 1; }
    grep -qi 'approval-denied\|counts against' "$WORK/wrong.out" || { echo "the refusal is not approval-denied"; cat "$WORK/wrong.out"; return 1; }
}

# Emulated TPM only. With a maximum of 2 tries the helper's share is one: after one wrong PIN it answers tpm-locked-out and the
# counter stops. A key outside Iron Vault still authorizes, the software approver still approves, wrong PINs sent at once spend no
# more than the share, and settings that would not limit guessing make the approver unavailable without spending a try.
item_7() {
    set_dictionary_attack "$RESERVE_MAX_TRIES" "$DA_INTERVAL"
    if approve_with_tpm "$WRONG_PIN" >"$WORK/wrong.out"; then echo "a wrong PIN approved"; return 1; fi
    grep -q 'approval-denied' "$WORK/wrong.out" || { echo "the first wrong PIN is not approval-denied"; cat "$WORK/wrong.out"; return 1; }
    if approve_with_tpm "$PIN" >"$WORK/locked.out"; then echo "the right PIN approved past the share"; return 1; fi
    grep -q 'tpm-locked-out' "$WORK/locked.out" || { echo "the helper did not answer tpm-locked-out"; cat "$WORK/locked.out"; return 1; }
    [ "$(lockout_counter)" = "$SHARE" ] || { echo "counter is $(lockout_counter), not the share $SHARE"; return 1; }
    throwaway_key_signs || return 1
    approve_with_software >/dev/null || { echo "the software approver could not approve while the TPM approver was locked out"; return 1; }
    wrong_pins_at_once || return 1
    weak_settings_make_the_approver_unavailable || return 1
    set_dictionary_attack 32 "$DA_INTERVAL"
}

# A key with its own authorization value, made and used with tpm2-tools, signs while Iron Vault's approver is held back.
throwaway_key_signs() {
    local dir="$WORK/throwaway"
    mkdir -p "$dir"
    # Flushing after each step is for a TPM without a resource manager, which holds only three transient objects.
    tpm2_flushcontext --transient-object
    tpm2_createprimary -C o -c "$dir/primary.ctx" >/dev/null
    tpm2_flushcontext --transient-object
    tpm2_create -C "$dir/primary.ctx" -G ecc256:ecdsa-sha256 -p throwaway -u "$dir/k.pub" -r "$dir/k.priv" >/dev/null
    tpm2_flushcontext --transient-object
    tpm2_load -C "$dir/primary.ctx" -u "$dir/k.pub" -r "$dir/k.priv" -c "$dir/k.ctx" >/dev/null
    tpm2_flushcontext --transient-object
    printf unrelated >"$dir/message"
    tpm2_sign -c "$dir/k.ctx" -p throwaway -g sha256 -o "$dir/signature" "$dir/message" >/dev/null \
        || { echo "a PIN-protected key outside Iron Vault could not sign"; return 1; }
    tpm2_flushcontext --transient-object
    [ -s "$dir/signature" ]
}

# Four approvals and four exports, each with a wrong PIN, start together. The service may queue some and the socket unit's
# MaxConnections=1 closes any connection that reaches the helper while another is open; either way no more than the share is spent.
wrong_pins_at_once() {
    local i sw pids=()
    set_dictionary_attack "$RESERVE_MAX_TRIES" "$DA_INTERVAL"
    sw=$(switch_to tpm)
    for i in 1 2 3 4; do
        # shellcheck disable=SC2086 # $sw is CTRL-Y or empty
        drive yes $sw "$WRONG_PIN" -- "$BINARY" config approve "$(new_config)" >"$WORK/at-once-approve-$i.out" 2>&1 &
        pids+=($!)
        drive CTRL-Y "$WRONG_PIN" -- "$BINARY" export "$WORK/at-once-$i.bundle" >"$WORK/at-once-export-$i.out" 2>&1 &
        pids+=($!)
    done
    wait "${pids[@]}" || true
    local counter
    counter=$(lockout_counter)
    [ "$counter" = "$SHARE" ] || { echo "after eight wrong-PIN commands at once the counter is $counter, not the share $SHARE"; return 1; }
}

weak_settings_make_the_approver_unavailable() {
    local settings
    for settings in "32 $((DA_INTERVAL - 1))" "1 $DA_INTERVAL"; do
        # shellcheck disable=SC2086 # two words
        set_dictionary_attack $settings
        if approve_with_tpm "$PIN" >"$WORK/weak.out"; then echo "an approval ran with settings '$settings'"; return 1; fi
        grep -q 'approval-unavailable' "$WORK/weak.out" || { echo "settings '$settings' did not answer approval-unavailable"; cat "$WORK/weak.out"; return 1; }
        [ "$(lockout_counter)" = 0 ] || { echo "settings '$settings' spent a try"; return 1; }
    done
}

# recipient add and export accept the PIN by switching from the vault passphrase; the audit log names tpm_pin and the approver, and
# holds neither the PIN nor the authorization value.
item_8() {
    local key since id value operations
    key=$(age-keygen 2>/dev/null | sed -n 's/^# public key: //p')
    id=$(tpm_approver_id)
    since=$(now)
    drive CTRL-Y "$PIN" -- "$BINARY" recipient add "$key" --label "ivcheck recipient" >/dev/null
    drive CTRL-Y "$PIN" "$EXPORT_PASS" "$EXPORT_PASS" -- "$BINARY" export "$WORK/item-8.bundle" >/dev/null
    operations=$(jq -R -r --arg s "$since" --arg id "$id" \
        'fromjson? | select(.event == "migration.authorized" and .timestamp >= $s and .method == "tpm_pin" and .approver_id == $id) | .operation' \
        "$AUDIT_LOG")
    grep -qx add_recipient <<<"$operations" || { echo "no migration.authorized with method tpm_pin for the TPM approver ($id) on add_recipient"; return 1; }
    grep -qx export <<<"$operations" || { echo "no migration.authorized with method tpm_pin for the TPM approver ($id) on export"; return 1; }
    ! grep -qF "$PIN" "$AUDIT_LOG" || { echo "the PIN is in the audit log"; return 1; }
    value=$(auth_value_hex "$id" "$PIN")
    ! grep -qi "$value" "$AUDIT_LOG" || { echo "the authorization value is in the audit log"; return 1; }
}

# Turned on before the first enrollment, so the trace holds an enrollment as well as approvals. journald's rate limit is off for the
# helper's units: a trace is long, and a dropped line would let a leak go unseen.
trace_on() {
    mkdir -p "$DROPIN_DIR"
    printf '[Service]\nEnvironment=TSS2_LOG=tcti+trace\nLogRateLimitIntervalSec=0\n' >"$DROPIN_DIR/ivcheck-trace.conf"
    systemctl daemon-reload
    now >"$WORK/trace-since"
}

# The TSS library's trace of the helper, on the real bus, from before the enrollment: neither the PIN nor the authorization value
# derived from it appears, whichever PIN was typed, and the trace holds TPM traffic at all.
item_9() {
    local id
    id=$(tpm_approver_id)
    journalctl -u 'iron-vault-tpm-signer@*' --since "$(cat "$WORK/trace-since")" -o cat --no-pager >"$WORK/trace.txt"
    python3 - "$WORK/trace.txt" "$id" "$PIN" "$WRONG_PIN" <<'PY' || return 1
import hashlib, re, sys, uuid
path, approver, *pins = sys.argv[1:]
text = open(path).read()
dump = "".join(m.group(1) for m in re.finditer(r"^[0-9a-f]{4}: ([0-9a-f]+)", text, re.M | re.I)).lower()
if len(dump) < 200:
    sys.exit("the trace holds no TPM traffic, so it proves nothing")
for pin in pins:
    value = hashlib.blake2b(uuid.UUID(approver).bytes + pin.encode(), digest_size=32, person=b"iv-tpm-pin-v1").hexdigest()
    for what, needle in (("PIN", pin.encode().hex()), ("authorization value", value)):
        if needle in dump:
            sys.exit(f"the {what} derived from {pin!r} is in the trace")
PY
}

# Emulated TPM only. The TPM approver signed the active approval, so it is asked first. A clear makes the blob foreign to the TPM
# (the stand-in for a copy on a second machine): the helper answers `not this TPM` and spends no try. The software approver then
# approves, and the approver order starts at it.
item_10() {
    approve_with_tpm "$PIN" >/dev/null || { echo "the TPM approver could not approve before the clear"; return 1; }
    tpm2_clear -c l
    set_dictionary_attack 32 "$DA_INTERVAL"
    if approve_with_tpm "$PIN" >"$WORK/cleared.out"; then echo "an approval ran on a cleared TPM"; return 1; fi
    grep -q 'approval-unavailable' "$WORK/cleared.out" || { echo "a cleared TPM did not answer approval-unavailable"; cat "$WORK/cleared.out"; return 1; }
    grep -qi 'not this TPM' "$WORK/cleared.out" || { echo "the message does not say 'not this TPM'"; cat "$WORK/cleared.out"; return 1; }
    [ "$(lockout_counter)" = 0 ] || { echo "a cleared TPM cost a try"; return 1; }
    approve_with_software >/dev/null || { echo "the software approver could not approve after the clear"; return 1; }
    [ "$(first_kind)" = software ] || { echo "the approver order starts at $(first_kind), not the software approver"; return 1; }
}

# The TPM approver may have signed the active approval, so a software approver approves again before the TPM one can go; then its
# blob is gone.
item_11() {
    local id
    id=$(tpm_approver_id)
    approve_with_software >/dev/null
    drive "$APPROVAL_PASS" -- "$BINARY" approver remove "$id" >/dev/null
    [ ! -e "$VAULT_DIR/approver-$id.tpm" ] || { echo "the blob is still there"; return 1; }
}

record_da_settings() {
    echo "== dictionary-attack settings of this TPM (record them for the manual)"
    tpm2_getcap properties-variable | grep -E 'LOCKOUT|MAX_AUTH_FAIL|PERMANENT' || true
    tpm2_getcap properties-fixed | grep -E 'MANUFACTURER|VENDOR_STRING_1|FIRMWARE_VERSION_1' || true
}

# --- Power loss ------------------------------------------------------------------------------------------------------------------

save_state() {
    printf 'CYCLE=%q\nCOUNTER=%q\nBOOT_ID=%q\nPASSED=%q\nFAILED=%q\nSKIPPED=%q\n' \
        "$1" "$2" "$(cat /proc/sys/kernel/random/boot_id)" "$PASSED" "$FAILED" "$SKIPPED" >"$STATE_DIR/state.env"
}

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
    check "power cut $CYCLE: the TPM approver still approves" approve_with_tpm "$PIN"
    if [ "$CYCLE" -lt "$CYCLES" ]; then
        save_state $((CYCLE + 1)) "$(lockout_counter)"
        echo "Cut the power now without a clean shutdown, then run this script again."
        [ "$FAILED" = 0 ]
        return
    fi
    check "item 11: removing the TPM approver deletes its blob" item_11
    finish
}

finish() {
    echo "passed $PASSED, failed $FAILED, skipped $SKIPPED"
    rm -rf "$DROPIN_DIR" "$STATE_DIR"
    drop_member
    systemctl daemon-reload
    [ "$FAILED" = 0 ]
}

# --- Entry -----------------------------------------------------------------------------------------------------------------------

cleanup_dropin() { rm -rf "$DROPIN_DIR"; systemctl daemon-reload || true; }

# Items 7 and 10 on the emulator; on hardware they are SKIPped, because they change dictionary-attack parameters and clear the TPM.
emulator_only_item() {
    local number=$1 title=$2 item=$3
    if [ "$EMULATED" = 1 ]; then
        check "item $number: $title" "$item"
    else
        skip "item $number: $title" "emulated TPM only: it changes dictionary-attack parameters or clears the TPM; run with --emulated-tpm in a swtpm VM"
    fi
}

first_part() {
    mkdir -p "$STATE_DIR"
    check "item 1: the service has no TPM device and links no libtss2" item_1
    drive "$VAULT_PASS" "$VAULT_PASS" "$APPROVAL_PASS" "$APPROVAL_PASS" yes -- "$BINARY" init >/dev/null
    unlock_service >/dev/null
    check "item 2: the helper's account, group and socket" item_2
    trace_on
    check "item 3: approver add --kind tpm enrolls, with a 0600 blob" item_3
    check "item 4: config approve with the PIN is a 191-byte envelope that survives a restart" item_4
    check "item 5: replace, rm and recipient remove accept the PIN as owner presence" item_5
    check "item 6: a wrong PIN is denied and spends exactly one try" item_6
    emulator_only_item 7 "the lockout reserve holds, also against wrong PINs sent at once" item_7
    check "item 8: recipient add and export accept the PIN and the audit log names tpm_pin" item_8
    check "item 9: the TCTI trace of an enrollment and approvals holds no PIN or authorization value" item_9
    cleanup_dropin
    emulator_only_item 10 "a cleared TPM is not this TPM" item_10
    if [ "$EMULATED" = 1 ]; then
        check "item 11: removing the TPM approver deletes its blob" item_11
        skip "item 12: power loss" "hardware only: an emulator's state is not a firmware TPM's; run without --emulated-tpm on the release hardware"
        finish
        return
    fi
    record_da_settings
    save_state 1 "$(lockout_counter)"
    echo "Part 1 done. Cut the power now without a clean shutdown, then run this script again."
    [ "$FAILED" = 0 ]
}

# Refuses --emulated-tpm on any TPM whose manufacturer is not the emulator's, because item 7 and item 10 would damage a real one.
require_emulator() {
    tpm2_getcap properties-fixed | grep -A2 'TPM2_PT_MANUFACTURER' | grep -q 'IBM' \
        || die "--emulated-tpm: the TPM's manufacturer is not the emulator's (IBM); items 7 and 10 would change or clear a real TPM"
}

main() {
    local opt_in=0 cleanup=0 arg
    for arg in "$@"; do
        case "$arg" in
            --i-know-this-is-a-disposable-vm) opt_in=1 ;;
            --emulated-tpm) EMULATED=1 ;;
            --cleanup) cleanup=1 ;;
            -*) die "unknown option $arg" ;;
            *) ACCOUNT=$arg ;;
        esac
    done
    [ "$(id -u)" = 0 ] || die "run as root"
    if [ "$cleanup" = 1 ]; then cleanup_dropin; drop_member; rm -rf "$STATE_DIR"; echo "cleaned up"; exit 0; fi
    [ "$opt_in" = 1 ] || die "this changes the machine; pass --i-know-this-is-a-disposable-vm"
    [ -n "$ACCOUNT" ] || die "name an ordinary test account"
    id "$ACCOUNT" >/dev/null 2>&1 || die "no account $ACCOUNT"
    local tool
    for tool in tpm2_getcap tpm2_dictionarylockout tpm2_clear tpm2_createprimary tpm2_create tpm2_load tpm2_sign \
        python3 runuser age-keygen jq journalctl systemctl useradd userdel; do
        command -v "$tool" >/dev/null 2>&1 || die "$tool is not installed"
    done
    [ -c /dev/tpmrm0 ] || die "no /dev/tpmrm0: this machine has no TPM 2.0"
    [ -x "$HELPER" ] || die "$HELPER is not installed: install the package"
    [ "$EMULATED" = 0 ] || require_emulator
    WORK=$(mktemp -d)
    trap 'rm -rf "$WORK" "$DROPIN_DIR"; drop_member' EXIT
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
