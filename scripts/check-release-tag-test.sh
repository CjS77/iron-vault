#!/usr/bin/env bash
# Runs scripts/check-release-tag.sh against the accepted and refused tag names of the release-tag rule
# (design/linux-package.md, "Building and checking the package").
set -uo pipefail

check="$(dirname "${BASH_SOURCE[0]}")/check-release-tag.sh"
status=0

expect() { # expected-result tag [crate-version]
    local want=$1 tag=$2 crate=${3:-${2#v}} got
    "$check" "$tag" "$crate" >/dev/null 2>&1 && got=pass || got=fail
    [ "$got" = "$want" ] && echo "ok   $want $tag" || { echo "FAIL expected $want for $tag"; status=1; }
}

for tag in v0.1.2 v0.3.0-alpha v1.12.342-alpha.ubuntu v10.0.0-rc.1; do expect pass "$tag"; done
for tag in v1.0 v1.2.3.4 v1.1.1_rc1 v1.0.0- v01.2.3 v1.2.3-alpha_1 'v1.12.342-alpha~ubuntu' x1.2.3 ''; do expect fail "$tag"; done
# A well-formed tag whose version is not the crate's is refused.
expect fail v0.3.1 0.3.0-alpha
expect fail v0.3.0 0.3.0-alpha
expect pass v0.3.0-alpha 0.3.0-alpha
exit $status
