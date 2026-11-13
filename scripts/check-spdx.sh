#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# Checks that every tracked source file starts with the one-line SPDX licence header, or adds it.
#
# MPL-2.0's copyleft applies file by file, so each file names its licence itself and still does when copied out of the
# repository alone. A source file is a tracked .rs, .sh, .py or .js file, or any other tracked file whose first line is
# a shebang (the Debian maintainer scripts, the provisioning helper). The header is the first line, or the second when
# the first is a shebang:
#
#     // SPDX-License-Identifier: MPL-2.0      (.rs, .js)
#     # SPDX-License-Identifier: MPL-2.0       (everything else)
#
# Usage: scripts/check-spdx.sh [--check | --fix]
#   --check  (default) list the source files without the header; exit 1 if there are any.
#   --fix    add the header to each source file without it.
set -euo pipefail

readonly LICENSE_ID="MPL-2.0"
readonly TAG="SPDX-License-Identifier: $LICENSE_ID"

usage() {
    echo "usage: scripts/check-spdx.sh [--check | --fix]" >&2
    exit 2
}

mode=check
case "${1:-}" in
    "" | --check) mode=check ;;
    --fix) mode=fix ;;
    -h | --help) usage ;;
    *) echo "error: unknown argument: $1" >&2; usage ;;
esac
[ "$#" -le 1 ] || usage

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

# Prints the comment leader for a source file, or nothing when the file is not source.
comment_leader() {
    case "$1" in
        *.rs | *.js) echo "//" ;;
        *.sh | *.py) echo "#" ;;
        *) has_shebang "$1" && echo "#" || true ;;
    esac
}

# A Rust inner attribute (`#![forbid(...)]`) also starts with `#!`, so `#![` is not a shebang.
has_shebang() {
    local start
    start=$(head -c 3 "$1")
    [ "${start:0:2}" = "#!" ] && [ "${start:2:1}" != "[" ]
}

# The line the header belongs on: 2 after a shebang, else 1.
header_line_number() {
    has_shebang "$1" && echo 2 || echo 1
}

has_header() {
    local file=$1 leader=$2
    [ "$(sed -n "$(header_line_number "$file")p" "$file")" = "$leader $TAG" ]
}

add_header() {
    local file=$1 leader=$2
    local header="$leader $TAG"
    if [ ! -s "$file" ]; then
        printf '%s\n' "$header" >"$file"
    elif has_shebang "$file"; then
        sed -i "1a\\$header" "$file"
    else
        sed -i "1i\\$header" "$file"
    fi
}

missing=()
while IFS= read -r -d '' file; do
    [ -f "$file" ] && [ ! -L "$file" ] || continue
    leader=$(comment_leader "$file")
    [ -n "$leader" ] || continue
    has_header "$file" "$leader" && continue
    missing+=("$file")
    [ "$mode" = fix ] && add_header "$file" "$leader"
done < <(git ls-files -z -- . ':(exclude).kanban')

if [ "${#missing[@]}" -eq 0 ]; then
    echo "every source file has the SPDX header ($TAG)"
    exit 0
fi

if [ "$mode" = fix ]; then
    printf 'added the SPDX header to %d file(s)\n' "${#missing[@]}"
    exit 0
fi

printf '%s\n' "${missing[@]}" >&2
printf 'error: %d source file(s) lack the SPDX header "%s"; run scripts/check-spdx.sh --fix\n' "${#missing[@]}" "$TAG" >&2
exit 1
