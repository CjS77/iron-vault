#!/usr/bin/env bash
# Verifies the Linux package's and the Compose host's systemd units and prints the service's exposure score.
#
# `systemd-analyze verify` is the gate: any complaint fails the script. `systemd-analyze security` only reports a
# score to read, and never fails the script.
#
# The checked copy differs from packaging/linux in two ways that `verify` needs and the files deliberately lack:
#  - the listener socket template gets a drop-in with a ListenStream=, because the template names no address;
#  - ExecStart= points at an existing executable when /usr/bin/iron-vault is not installed on this machine.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
units="$root/packaging/linux"
host_unit="$root/packaging/compose/host/iron-vault-host-unlock.service"

if ! command -v systemd-analyze >/dev/null 2>&1; then
    echo "error: systemd-analyze is not installed; install systemd to check the units" >&2
    exit 2
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

service="$work/iron-vault.service"
socket="$work/iron-vault-listener@probe.socket"

binary=/usr/bin/iron-vault
[ -x "$binary" ] || binary=$(command -v true)
sed "s#^ExecStart=/usr/bin/iron-vault #ExecStart=$binary #" "$units/iron-vault.service" >"$service"
cp "$units/iron-vault-listener@.socket" "$socket"
mkdir "$socket.d"
printf '[Socket]\nListenStream=/run/iron-vault/probe.sock\n' >"$socket.d/listen.conf"

echo "== systemd-analyze verify"
# The package's and the Compose host's handoff units share a name, so each is verified in a run of its own.
systemd-analyze verify "$service" "$socket" "$units/iron-vault-host-unlock.service"
systemd-analyze verify "$host_unit"
echo "ok"

echo
echo "== systemd-analyze security (a score to read, not a gate)"
systemd-analyze security --offline=yes --no-pager "$service" || echo "security report unavailable on this systemd version"
