#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# Generates the host unlock identity and seals it to this host's TPM. Run once, as root.
#
# The secret text exists only in pipes: it is never a file, an argument or an environment variable. Only the
# recipient key, `age1...`, is printed, to enrol with `init --host-unlock` or `recipient add --host-unlock`.
#
# usage: provision-host-unlock.sh [--with-key host+tpm2]
#   --with-key  `tpm2` (default) seals to the TPM alone; `host+tpm2` also ties the seal to the host key file
#               /var/lib/systemd/credential.secret. No other value is accepted.
set -euo pipefail

dir=/etc/iron-vault-host
cred=$dir/host-unlock.cred
key=tpm2

case $# in
    0) ;;
    2) [ "$1" = --with-key ] && [ "$2" = host+tpm2 ] && key=$2 || { echo "error: --with-key may only be host+tpm2" >&2; exit 2; } ;;
    *) echo "usage: $0 [--with-key host+tpm2]" >&2; exit 2 ;;
esac

[ "$(id -u)" -eq 0 ] || { echo "error: run as root" >&2; exit 1; }
for tool in age-keygen systemd-creds; do
    command -v "$tool" >/dev/null || { echo "error: $tool is not installed" >&2; exit 1; }
done
[ ! -e "$cred" ] || { echo "error: $cred exists; enrol a new identity under another name first" >&2; exit 1; }

umask 077
install -d -m 0700 -o root -g root "$dir"

# A failed seal must not leave a partial credential that the check above would then mistake for a real one.
trap 'rm -f "$cred"' ERR

# grep drops age-keygen's comment lines; the process substitution derives the recipient key from the same pipe.
age-keygen 2>/dev/null \
    | grep '^AGE-SECRET-KEY-1' \
    | tee >(age-keygen -y >&2) \
    | systemd-creds encrypt --with-key="$key" --tpm2-pcrs=7 --name=host-unlock - "$cred"

chmod 0600 "$cred"
echo "sealed $cred (--with-key=$key, PCR 7); enrol the recipient key printed above" >&2
