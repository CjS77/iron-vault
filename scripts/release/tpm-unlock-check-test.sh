#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# Tests that tpm-unlock-check.sh refuses to start before it changes anything: with no opt-in, as an ordinary user, with the package
# missing, and off Ubuntu 24.04, where it runs item 14 alone. Every tool is a stub in a mktemp dir ahead of PATH, and each stub that
# could change a host leaves a marker, so it needs no root, TPM or VM. The script only defines functions when sourced, so each case
# sources it and calls main.
# The stub scripts are single-quoted on purpose; the overrides are called by the sourced script.
# shellcheck disable=SC2016,SC2317,SC2034
set -uo pipefail

dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
stubs=$(mktemp -d)
trap 'rm -rf "$stubs"' EXIT
status=0
marker=$stubs/host-changed

# Tools that would change the host leave a marker. systemctl does so for anything but a read.
for tool in mount umount install losetup cryptsetup tpm2_pcrextend kill dpkg; do
    printf '#!/bin/sh\ntouch "%s"\nexit 1\n' "$marker" >"$stubs/$tool"
done
printf '#!/bin/sh\ncase $1 in --version|show|is-active) echo "systemd 255";; *) touch "%s";; esac\nexit 0\n' "$marker" >"$stubs/systemctl"
printf '#!/bin/sh\nexit 0\n' >"$stubs/systemd-creds"
# The helper, as it behaves on a release it does not support.
printf '#!/bin/sh\necho "error: TPM unlock is supported on Ubuntu 24.04 LTS only; this machine runs Debian." >&2\nexit 1\n' \
    >"$stubs/helper"
chmod +x "$stubs"/*
printf 'ID=debian\nVERSION_ID="12"\nPRETTY_NAME="Debian GNU/Linux 12"\n' >"$stubs/os-release-debian"

# run UID PACKAGE_STATUS ARGS...: runs main with the host paths pointed at the stubs; prints its output.
run() {
    local uid=$1 installed=$2
    shift 2
    rm -f "$marker"
    (
        PATH="$stubs:$PATH"
        # shellcheck source=/dev/null
        source "$dir/tpm-unlock-check.sh"
        id() { echo "$uid"; }
        dpkg-query() { echo -n "$installed"; }
        OS_RELEASE=$stubs/os-release-debian PROVISION=$stubs/helper CRED=$stubs/none/cred STATE_DIR=$stubs/none/state
        main "$@"
    ) 2>&1
}

# expect NAME WANT-EXIT GOT-EXIT OUTPUT FRAGMENT: the exit status, a fragment of the message, and no host change.
expect() {
    local seen=no
    [ ! -e "$marker" ] || seen=yes
    if [ "$2" = "$3" ] && [ "$seen" = no ] && grep -q "$5" <<<"$4"; then
        echo "ok   $1"
    else
        echo "FAIL $1 (exit $3, host changed: $seen): $4"
        status=1
    fi
}

out=$(run 0 "install ok installed"); expect "no opt-in refuses with exit 2" 2 $? "$out" "disposable-vm"
out=$(run 1000 "install ok installed" --i-know-this-is-a-disposable-vm); expect "an ordinary user is refused" 2 $? "$out" "run as root"
out=$(run 0 "" --i-know-this-is-a-disposable-vm); expect "a missing package is refused" 2 $? "$out" "package is not installed"
out=$(run 0 "install ok installed" --i-know-this-is-a-disposable-vm); expect "Debian runs item 14 alone and it passes" 0 $? "$out" "PASS item 14"
! grep -q 'item 1:' <<<"$out" || { echo "FAIL Debian ran an item other than 14"; status=1; }
out=$(run 0 "install ok installed" --i-know-this-is-a-disposable-vm --bogus); expect "an unknown argument is refused" 2 $? "$out" "unknown argument"
exit $status
