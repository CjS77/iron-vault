#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# Checks a release tag name, for .github/workflows/release.yml.
#
# Usage: scripts/check-release-tag.sh <tag> [crate-version]
#
# Fails unless the tag is `v` plus a SemVer version with no leading zeros and an optional non-empty pre-release of
# [0-9A-Za-z.-], and the version equals the iron-vault crate version (found as scripts/build-deb.sh finds it). The
# optional second argument replaces the crate version, so the tag format can be tested without a matching crate.
# GitHub's tag filters are globs and cannot say all of this; this script is the exact rule.
set -euo pipefail

tag=${1:?usage: check-release-tag.sh <tag> [crate-version]}
pattern='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$'

[[ $tag =~ $pattern ]] || {
    echo "error: tag '$tag' is not a release tag: expected v<major>.<minor>.<patch>[-<pre-release>], e.g. v0.3.0-alpha" >&2
    exit 1
}

if [ $# -ge 2 ]; then
    crate_version=$2
else
    cd "$(dirname "${BASH_SOURCE[0]}")/.."
    crate_version=$(cargo metadata --no-deps --locked --format-version 1 \
        | python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "iron-vault"))')
fi

[ "${tag#v}" = "$crate_version" ] || {
    echo "error: tag '$tag' names version ${tag#v}, but the iron-vault crate is version $crate_version" >&2
    exit 1
}
echo "tag $tag matches crate version $crate_version"
