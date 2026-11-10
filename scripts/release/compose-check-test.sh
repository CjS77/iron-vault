#!/usr/bin/env bash
# Tests compose-check.sh's BuildKit preflight against a stub `docker`; it needs no Docker, root or VM.
set -uo pipefail

dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
stubs=$(mktemp -d)
trap 'rm -rf "$stubs"' EXIT
status=0

# Runs require_buildkit in a subshell with a docker whose `buildx version` exits $1. Args after it set IMAGE.
run() {
    local buildx_exit=$1 image=${2:-}
    printf '#!/bin/sh\n[ "$1 $2" = "buildx version" ] && exit %s\nexit 0\n' "$buildx_exit" >"$stubs/docker"
    chmod +x "$stubs/docker"
    (
        PATH="$stubs:$PATH"
        # shellcheck source=scripts/release/compose-check.sh
        source "$dir/compose-check.sh"
        IMAGE=$image
        require_buildkit
    ) 2>&1
}

expect() { # name want-exit got-exit output [message-fragment]
    if [ "$2" = "$3" ] && { [ -z "${5:-}" ] || grep -q "$5" <<<"$4"; }; then echo "ok   $1"; else echo "FAIL $1 (exit $3): $4"; status=1; fi
}

out=$(run 1); expect "no buildx refuses with exit 2 naming the package" 2 $? "$out" docker-buildx
out=$(run 0); expect "buildx present passes" 0 $? "$out"
out=$(run 1 some:image); expect "a prebuilt --image skips the check" 0 $? "$out"
exit $status
