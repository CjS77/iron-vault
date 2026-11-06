#!/usr/bin/env bash
# Builds the Linux package (.deb) and checks it against design/linux-package.md.
#
# Build tools (not workspace dependencies):
#   cargo install cargo-deb --locked
#   sudo apt install dpkg lintian        # dpkg-deb is required; lintian is run when present
#
# Usage: scripts/build-deb.sh [extra cargo-deb arguments]
# The build uses the release profile and default features. Extra arguments exist so the check can be seen to fail:
# `scripts/build-deb.sh --features dev-mode` must be refused, because the packaged binary reports the feature.
#
# The checks, each of which fails the script:
#  - the packaged binary's `--version` lists no feature;
#  - every file's owner and mode match the design's ownership table, and nothing is owned by a non-root account;
#  - nothing is shipped under the service's own directories, and the only conffile is the logrotate rule;
#  - the maintainer scripts are present and executable;
#  - lintian reports no error (skipped, loudly, when lintian is not installed).
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

fail() { echo "error: $*" >&2; exit 1; }

command -v dpkg-deb >/dev/null 2>&1 || { echo "error: dpkg-deb is not installed; install dpkg" >&2; exit 2; }
cargo deb --version >/dev/null 2>&1 || { echo "error: cargo-deb is not installed; run: cargo install cargo-deb --locked" >&2; exit 2; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

echo "== cargo deb -p iron-vault $*"
cargo deb -p iron-vault --locked -o "$work/pkg.deb" "$@"
deb="$work/pkg.deb"

echo "== packaged binary reports no features"
dpkg-deb --fsys-tarfile "$deb" | tar -xO ./usr/bin/iron-vault >"$work/iron-vault"
chmod +x "$work/iron-vault"
version=$("$work/iron-vault" --version)
echo "$version"
case "$version" in
    *"(features: none)"*) ;;
    *) fail "the packaged binary lists features; a package must be built with default features only" ;;
esac

echo "== file owners and modes"
contents=$(dpkg-deb -c "$deb")
expected=$(cat <<'TABLE'
./usr/bin/iron-vault -rwxr-xr-x
./usr/lib/systemd/system/iron-vault.service -rw-r--r--
./usr/lib/systemd/system/iron-vault-listener@.socket -rw-r--r--
./usr/lib/sysusers.d/iron-vault.conf -rw-r--r--
./usr/lib/tmpfiles.d/iron-vault.conf -rw-r--r--
./etc/logrotate.d/iron-vault -rw-r--r--
TABLE
)
# Fields of `dpkg-deb -c`: mode, owner/group, size, date, time, path (symlinks add ` -> target`).
echo "$contents" | awk '{ print $1, $2, $6 }' | while read -r mode owner path; do
    # cargo-deb writes numeric ids, which dpkg reads as root.
    [ "$owner" = "root/root" ] || [ "$owner" = "0/0" ] || fail "$path is owned by $owner, not root/root"
    case "$path" in
        ./etc/iron-vault* | ./var/lib/iron-vault* | ./var/log/iron-vault* | ./run/iron-vault*)
            fail "$path: the service's directories are created by tmpfiles.d, not shipped" ;;
    esac
    # Characters 6 and 9 of the mode string are the group and others write bits.
    [ "${mode:5:1}" = "-" ] && [ "${mode:8:1}" = "-" ] || fail "$path has mode $mode, which the group or others can write"
done
echo "$expected" | while read -r path mode; do
    got=$(echo "$contents" | awk -v p="$path" '$6 == p { print $1 }')
    [ "$got" = "$mode" ] || fail "$path: expected mode $mode, found '${got:-missing}'"
    echo "ok $mode $path"
done

echo "== conffiles and maintainer scripts"
dpkg-deb -e "$deb" "$work/control"
conffiles=$(cat "$work/control/conffiles" 2>/dev/null || true)
[ "$conffiles" = "/etc/logrotate.d/iron-vault" ] || fail "conffiles must be only /etc/logrotate.d/iron-vault, found: ${conffiles:-none}"
for script in postinst prerm postrm templates; do
    [ -f "$work/control/$script" ] || fail "the package has no $script"
done
for script in postinst prerm postrm; do
    [ -x "$work/control/$script" ] || fail "$script is not executable"
    grep -q '#DEBHELPER#' "$work/control/$script" && fail "$script still has its #DEBHELPER# token"
done
echo ok

echo "== lintian"
if command -v lintian >/dev/null 2>&1; then
    lintian --fail-on error "$deb"
else
    echo "SKIPPED: lintian is not installed (sudo apt install lintian); the package was not linted" >&2
fi
echo "package checks passed"
