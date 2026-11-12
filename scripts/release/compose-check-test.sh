#!/usr/bin/env bash
# Tests that compose-check.sh's preflight and compose-unlock-check.sh's preflight_unlock refuse a host without BuildKit before they
# touch any host path, and that compose-check.sh accepts only an image whose `--version` lists exactly `container`. Every tool is a
# stub in a mktemp dir ahead of PATH, so it needs no Docker, root or VM and writes nowhere else.
# The scripts only define functions when sourced, so each case sources one and calls its preflight function.
set -uo pipefail

dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
stubs=$(mktemp -d)
trap 'rm -rf "$stubs"' EXIT
status=0
marker=$stubs/host-checked

# Every tool the two preflights look for. getent and systemctl are the first host-touching calls after the BuildKit check; they leave a
# marker, so a marker after a refusal means the check ran too late.
for tool in openssl script runuser sudo curl useradd groupadd userdel groupdel ip age-keygen systemd-creds mount findmnt nsenter ss \
    strings swapon jq; do
    printf '#!/bin/sh\nexit 0\n' >"$stubs/$tool"
done
for tool in getent systemctl; do
    printf '#!/bin/sh\ntouch "%s"\nexit 1\n' "$marker" >"$stubs/$tool"
done
# `docker info` succeeds; `docker buildx version` exits $BUILDX_EXIT; anything else fails (nothing exists yet).
printf '#!/bin/sh\n[ "$1" = info ] && exit 0\n[ "$1 $2" = "buildx version" ] && exit "$BUILDX_EXIT"\nexit 1\n' >"$stubs/docker"
chmod +x "$stubs"/*

# run SCRIPT FUNCTION BUILDX_EXIT [IMAGE]: runs the preflight function in a subshell; prints its output.
run() {
    rm -f "$marker"
    (
        export BUILDX_EXIT=$3
        PATH="$stubs:$PATH"
        # shellcheck source=/dev/null
        source "$dir/$1"
        IMAGE=${4:-}
        # Point every host path at a place that does not exist, so the result does not depend on the machine running the test.
        HOST_CLI=$stubs/none/cli HOST_DIR=$stubs/none/host RUN_DIR=$stubs/none/run UNLOCK_DIR=$stubs/none/unlock
        UNIT_FILE=$stubs/none/unit TMPFILES_CONF=$stubs/none/tmpfiles SYSUSERS_CONF=$stubs/none/sysusers
        STATE_DIR=$stubs/none/state SECRETS=$stubs/none/secrets
        ACCOUNT=nobody
        "$2"
    ) 2>&1
}

check() { # name want-exit got-exit output want-marker(yes|no) [message-fragment]
    local seen=no
    [ ! -e "$marker" ] || seen=yes
    if [ "$2" = "$3" ] && [ "$5" = "$seen" ] && { [ -z "${6:-}" ] || grep -q "$6" <<<"$4"; }; then
        echo "ok   $1"
    else
        echo "FAIL $1 (exit $3, host checks reached: $seen): $4"
        status=1
    fi
}

for case in "compose-check.sh preflight" "compose-unlock-check.sh preflight_unlock"; do
    read -r script fn <<<"$case"
    out=$(run "$script" "$fn" 1); check "$fn: no buildx refuses with exit 2 before any host check" 2 $? "$out" no docker-buildx
    # After the BuildKit check the stubs make later steps fail in ways that do not matter here; only the marker and message count.
    out=$(run "$script" "$fn" 1 some:image); rc=$?
    check "$fn: a prebuilt --image skips the check" "$rc" "$rc" "$out" yes
    out=$(run "$script" "$fn" 0); rc=$?
    check "$fn: buildx present reaches the host checks" "$rc" "$rc" "$out" yes
    ! grep -q docker-buildx <<<"$out" || { echo "FAIL $fn: buildx present still complains of BuildKit: $out"; status=1; }
done

# The live check's reading of the image's `--version`: only a feature list of exactly `container` passes.
# shellcheck source=/dev/null
source "$dir/compose-check.sh"
for features in container none dev-mode 'dev-mode, container' 'container, dev-mode' 'container, test-support'; do
    want=fail; [ "$features" = container ] && want=pass
    version_lists_only_container "iron-vault 0.3.0-alpha (features: $features)" && got=pass || got=fail
    [ "$got" = "$want" ] && echo "ok   version_lists_only_container: $want for $features" \
        || { echo "FAIL version_lists_only_container: expected $want for $features"; status=1; }
done
exit $status
