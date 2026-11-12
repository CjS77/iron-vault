#!/usr/bin/env bash
# Runs build-deb.sh's feature check against `--version` outputs (design/linux-package.md, "Building and checking the package"):
# only a binary built with no feature may be packaged.
set -uo pipefail

# shellcheck source=build-deb.sh
source "$(dirname "${BASH_SOURCE[0]}")/build-deb.sh"
status=0

expect() { # expected-result version-output
    local want=$1 got
    (require_no_features "$2") >/dev/null 2>&1 && got=pass || got=fail
    [ "$got" = "$want" ] && echo "ok   $want '$2'" || { echo "FAIL expected $want for '$2'"; status=1; }
}

expect pass 'iron-vault 0.3.0-alpha (features: none)'
for features in dev-mode container 'dev-mode, container' test-support 'none, dev-mode'; do
    expect fail "iron-vault 0.3.0-alpha (features: $features)"
done
expect fail 'iron-vault 0.3.0-alpha'
expect fail ''
exit $status
