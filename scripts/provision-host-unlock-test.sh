#!/usr/bin/env bash
# Tests the Linux package's provisioning helper, packaging/linux/iron-vault-provision-host-unlock, without root or a TPM
# (design/tpm-unlock.md, "Provisioning"). id, age-keygen, systemd-creds and install are stubs in a mktemp dir ahead of
# PATH, and the helper's /etc paths are pointed into that dir, so it writes nowhere else. The helper only defines
# functions when sourced, so each case sources it and calls main.
set -uo pipefail

helper=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/packaging/linux/iron-vault-provision-host-unlock
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
stubs=$work/bin
sealed=$work/sealed
status=0
mkdir "$stubs"

# id -u says root. age-keygen prints an identity as the real one does, comment lines included, and with -y a recipient.
# systemd-creds leaves a marker holding its arguments and copies the secret text to the blob path. install drops its
# owner and group options, which only root may pass.
cat >"$stubs/id" <<'STUB'
#!/bin/sh
echo 0
STUB
cat >"$stubs/age-keygen" <<'STUB'
#!/bin/sh
if [ "${1:-}" = -y ]; then cat >/dev/null; echo age1stubrecipient; exit 0; fi
echo "# created: 2026-11-11T00:00:00Z"
echo "# public key: age1stubrecipient"
echo AGE-SECRET-KEY-1STUBSECRET
STUB
cat >"$stubs/systemd-creds" <<STUB
#!/bin/sh
echo "\$@" >"$sealed"
for last; do :; done
cat >"\$last"
STUB
cat >"$stubs/install" <<'STUB'
#!/bin/sh
args=
while [ $# -gt 0 ]; do
    case $1 in -o | -g) shift 2 ;; *) args="$args $1"; shift ;; esac
done
# shellcheck disable=SC2086
exec /usr/bin/install $args
STUB
chmod +x "$stubs"/*

printf 'PRETTY_NAME="Ubuntu 24.04.1 LTS"\nNAME="Ubuntu"\nVERSION_ID="24.04"\nID=ubuntu\n' >"$work/ubuntu-24.04"
printf 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nVERSION_ID="12"\nID=debian\n' >"$work/debian-12"
printf 'PRETTY_NAME="Ubuntu 22.04.4 LTS"\nVERSION_ID="22.04"\nID=ubuntu\n' >"$work/ubuntu-22.04"

# run OS_RELEASE ARGS...: runs the helper's main in a subshell with stdin from /dev/null, so stdin is never a terminal.
# Prints its output; the exit status is main's. With BLOB=1 a host unlock blob already exists.
run() {
    local release=$1
    shift
    rm -rf "$work/host" "$sealed"
    [ -z "${BLOB:-}" ] || { mkdir "$work/host" && : >"$work/host/host-unlock.cred"; }
    (
        PATH="$stubs:$PATH"
        # shellcheck source=/dev/null
        source "$helper"
        # shellcheck disable=SC2034 # read by the sourced helper's main
        HOST_DIR=$work/host
        # shellcheck disable=SC2034
        OS_RELEASE=$work/$release
        main "$@"
    ) </dev/null 2>&1
}

# run_tty ANSWER OS_RELEASE ARGS...: as run, but with stdin a terminal: util-linux script(1) gives the helper a pty and
# types ANSWER into it.
run_tty() {
    local answer=$1 release=$2
    shift 2
    rm -rf "$work/host" "$sealed"
    printf '%s\n' "$answer" | HELPER=$helper STUBS=$stubs WORK=$work RELEASE=$release \
        script -qec "bash -c 'PATH=\$STUBS:\$PATH; source \$HELPER; HOST_DIR=\$WORK/host; OS_RELEASE=\$WORK/\$RELEASE; main $*'" \
        /dev/null 2>&1
}

check() { # name want-exit got-exit output want-sealed(yes|no) [message-fragment]
    local seen=no
    [ ! -e "$sealed" ] || seen=yes
    if [ "$2" = "$3" ] && [ "$5" = "$seen" ] && { [ -z "${6:-}" ] || grep -q -- "$6" <<<"$4"; }; then
        echo "ok   $1"
    else
        echo "FAIL $1 (exit $3, sealed: $seen): $4"
        status=1
    fi
}

for release in debian-12 ubuntu-22.04; do
    out=$(run "$release" --server --accept-physical-access); rc=$?
    check "$release stops, naming the supported release" 1 $rc "$out" no "Ubuntu 24.04 LTS only"
    [ ! -e "$work/host" ] || { echo "FAIL $release: the helper created its directory"; status=1; }
done

for args in "" "--server --portable" "--portable --server" "--server --server" "--bogus" "--server --bogus" \
    "--accept-physical-access" "--portable --accept-physical-access"; do
    # shellcheck disable=SC2086
    out=$(run ubuntu-24.04 $args); rc=$?
    check "'$args' is a usage error" 2 $rc "$out" no "usage:"
done

out=$(run ubuntu-24.04 --portable); rc=$?
check "--portable stops: its check is not built yet" 1 $rc "$out" no "not built yet"

out=$(run ubuntu-24.04 --server); rc=$?
check "--server with no terminal stops without --accept-physical-access" 1 $rc "$out" no "not a terminal"
grep -q "physical access" <<<"$out" || { echo "FAIL --server does not state the physical-access condition: $out"; status=1; }

# A piped answer is never read: stdin is a pipe, not a terminal.
out=$(yes | run ubuntu-24.04 --server); rc=$?
check "'yes |' cannot accept for anyone" 1 $rc "$out" no "not a terminal"

# At a terminal the administrator always answers: the flag does not skip the prompt.
out=$(run_tty no ubuntu-24.04 --server --accept-physical-access); rc=$?
check "at a terminal, --accept-physical-access still prompts" 1 $rc "$out" no "Type yes to accept"
out=$(run_tty yes ubuntu-24.04 --server); rc=$?
check "at a terminal, typing yes seals" 0 $rc "$out" yes "age1stubrecipient"

out=$(run ubuntu-24.04 --server --accept-physical-access); rc=$?
check "--server --accept-physical-access with no terminal seals" 0 $rc "$out" yes "age1stubrecipient"
grep -qx -- "encrypt --with-key=tpm2 --tpm2-pcrs=7 --name=host-unlock - $work/host/host-unlock.cred" "$sealed" \
    || { echo "FAIL systemd-creds was called with: $(cat "$sealed")"; status=1; }
[ "$(stat -c %a "$work/host" "$work/host/host-unlock.cred" | tr '\n' ' ')" = "700 600 " ] \
    || { echo "FAIL modes are $(stat -c '%n %a' "$work/host" "$work/host/host-unlock.cred")"; status=1; }
! grep -q AGE-SECRET-KEY <<<"$out" || { echo "FAIL the secret text was printed: $out"; status=1; }

out=$(BLOB=1 run ubuntu-24.04 --server --accept-physical-access); rc=$?
check "an existing blob is refused" 1 $rc "$out" no "exists"
[ ! -s "$work/host/host-unlock.cred" ] || { echo "FAIL the existing blob was changed"; status=1; }

exit $status
