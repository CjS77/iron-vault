#!/usr/bin/env bash
# Tests the Linux package's provisioning helper, packaging/linux/iron-vault-provision-host-unlock, without root or a TPM
# (design/tpm-unlock.md, "Provisioning"). id, age-keygen, systemd-creds, install, logger, findmnt, cryptsetup, luksmeta and
# lsinitramfs are stubs in a mktemp dir ahead of PATH, and the helper's /etc, /sys and /boot paths are pointed into that
# dir, so it writes nowhere else. The helper only defines functions when sourced, so each case sources it and calls main.
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
# findmnt prints the file named after the field asked for with -o: $work/rootdev for SOURCE, fstype for FSTYPE (ext4 when
# there is none) and fsuuid for UUID. cryptsetup luksDump, luksmeta show -d and lsinitramfs print the file named after their
# device or image, and fail when there is none; logger appends what it was given, priority included, to the fake journal,
# and fails when the file $work/loggerfail exists.
cat >"$stubs/findmnt" <<STUB
#!/bin/sh
case "\$*" in
    *FSTYPE*) cat "$work/fstype" 2>/dev/null || echo ext4 ;;
    *UUID*) cat "$work/fsuuid" ;;
    *) cat "$work/rootdev" ;;
esac
STUB
cat >"$stubs/cryptsetup" <<STUB
#!/bin/sh
[ "\$1" = luksDump ] && cat "$work/luksdump/\$(basename "\$2")"
STUB
cat >"$stubs/luksmeta" <<STUB
#!/bin/sh
[ "\$1 \$2" = "show -d" ] && cat "$work/luksmeta/\$(basename "\$3")"
STUB
cat >"$stubs/lsinitramfs" <<STUB
#!/bin/sh
cat "$work/initramfs/\$(basename "\$1")"
STUB
cat >"$stubs/logger" <<STUB
#!/bin/sh
[ ! -e "$work/loggerfail" ] || exit 1
printf '%s\n' "\$*" >>"$work/journal"
STUB
chmod +x "$stubs"/*

# The helper's fixed paths, reassigned after sourcing it. NOTOOL=name makes the helper see that tool as not installed.
cat >"$work/overrides.sh" <<OVR
HOST_DIR=$work/host
OS_RELEASE=$work/\$RELEASE
SYS_ROOT=$work/sys
CRYPTTAB=$work/crypttab
BOOT_DIR=$work/boot
if [ -n "\${NOTOOL:-}" ]; then have_tool() { [ "\$1" != "\$NOTOOL" ] && command -v "\$1" >/dev/null; }; fi
OVR

printf 'PRETTY_NAME="Ubuntu 24.04.1 LTS"\nNAME="Ubuntu"\nVERSION_ID="24.04"\nID=ubuntu\n' >"$work/ubuntu-24.04"
printf 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nVERSION_ID="12"\nID=debian\n' >"$work/debian-12"
printf 'PRETTY_NAME="Ubuntu 22.04.4 LTS"\nVERSION_ID="22.04"\nID=ubuntu\n' >"$work/ubuntu-22.04"

# run OS_RELEASE ARGS...: runs the helper's main in a subshell with stdin from /dev/null, so stdin is never a terminal.
# Prints its output; the exit status is main's. With BLOB=1 a host unlock blob already exists.
run() {
    local release=$1
    shift
    rm -rf "$work/host" "$sealed" "$work/journal"
    [ -z "${BLOB:-}" ] || { mkdir "$work/host" && : >"$work/host/host-unlock.cred"; }
    [ -z "${DIRREC:-}" ] || mkdir -p "$work/host/provisioning.txt"
    [ -z "${OLDREC:-}" ] || { mkdir -p "$work/host" && echo stale >"$work/host/provisioning.txt"; }
    (
        PATH="$stubs:$PATH"
        # shellcheck disable=SC2034 # read by overrides.sh
        RELEASE=$release
        # shellcheck source=/dev/null
        source "$helper"
        # shellcheck source=/dev/null
        source "$work/overrides.sh"
        main "$@"
    ) </dev/null 2>&1
}

# run_tty ANSWER OS_RELEASE ARGS...: as run, but with stdin a terminal: util-linux script(1) gives the helper a pty and
# types ANSWER into it.
run_tty() {
    local answer=$1 release=$2
    shift 2
    rm -rf "$work/host" "$sealed" "$work/journal"
    printf '%s\n' "$answer" | HELPER=$helper STUBS=$stubs WORK=$work RELEASE=$release \
        script -qec "bash -c 'PATH=\$STUBS:\$PATH; source \$HELPER; source \$WORK/overrides.sh; main $*'" \
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

# A fake sysfs, crypttab, /boot and luksDump output. sys_reset starts an empty one; leaf and dm add block devices, with
# dm's trailing arguments the device's slaves.
sys_reset() {
    rm -rf "${work:?}/fstype" "${work:?}/fsuuid" "${work:?}/sys" "${work:?}/luksdump" "${work:?}/luksmeta" "${work:?}/initramfs" "${work:?}/boot"
    mkdir -p "$work/sys/class/block" "$work/luksdump" "$work/luksmeta" "$work/initramfs" "$work/boot"
    : >"$work/crypttab"
}
leaf() { mkdir -p "$work/sys/class/block/$1"; }
dm() { # name uuid mapname slave...
    local d=$work/sys/class/block/$1 s
    mkdir -p "$d/dm" "$d/slaves"
    echo "$2" >"$d/dm/uuid"
    echo "$3" >"$d/dm/name"
    shift 3
    for s; do : >"$d/slaves/$s"; done
}
luks_dump() { # device tokens-text
    printf 'LUKS header information\nVersion:       2\n\nKeyslots:\n  0: luks2\n\tKey: 512 bits\n\nTokens:\n%s\nDigests:\n  0: pbkdf2\n' \
        "$2" >"$work/luksdump/$1"
}
luks1_dump() { # device
    printf 'LUKS header information for %s\n\nVersion:       1\nCipher name:    aes\n\nKey Slot 0: ENABLED\n' "$1" >"$work/luksdump/$1"
}
boot_image() { # name listing
    : >"$work/boot/$1"
    printf '%s\n' "$2" >"$work/initramfs/$1"
}
tpm_token() { printf '  0: systemd-tpm2\n\ttpm2-hash-pcrs:   7\n\ttpm2-pin:         %s\n\tKeyslot:    1\n' "$1"; }

# LVM-on-LUKS holding the host directory, opened by a passphrase: no warning.
lvm_on_luks() {
    sys_reset
    leaf nvme0n1p3
    dm dm-0 CRYPT-LUKS2-abc luks-abc nvme0n1p3
    dm dm-1 LVM-xyz vg-root dm-0
    echo /dev/dm-1 >"$work/rootdev"
    echo "luks-abc UUID=abc none luks" >"$work/crypttab"
    luks_dump nvme0n1p3 ""
    boot_image initrd.img-6.8.0-1 "scripts/local-top/cryptroot"
}
unencrypted() {
    sys_reset
    leaf sda2
    dm dm-0 LVM-xyz vg-root sda2
    echo /dev/dm-0 >"$work/rootdev"
    boot_image initrd.img-6.8.0-1 "scripts/local-top/lvm2"
}

# A volume with LVM over one LUKS PV (dm-0 on nvme0n1p3) and a second PV, sdb1, that is not encrypted.
lvm_over_two() {
    lvm_on_luks
    leaf sdb1
    dm dm-1 LVM-xyz vg-root dm-0 sdb1
}

# A multi-device filesystem: findmnt names only the encrypted one (dm-1, over dm-0) and the fake sysfs lists the members. btrfs lists them in
# /sys/fs/btrfs/UUID/devices; bcachefs has a dev-N/block symlink for each, named as the kernel does.
fs_uuid=11111111-2222-3333-4444-555555555555
multi_fs() { # fstype
    lvm_on_luks
    echo "$1" >"$work/fstype"
    echo "$fs_uuid" >"$work/fsuuid"
}
btrfs_member() { mkdir -p "$work/sys/fs/btrfs/$fs_uuid/devices" && ln -s "../../../../devices/block/$1" "$work/sys/fs/btrfs/$fs_uuid/devices/$1"; }
bcachefs_member() { # N device
    mkdir -p "$work/sys/fs/bcachefs/$fs_uuid/dev-$1" && ln -s "../../../../devices/block/$2" "$work/sys/fs/bcachefs/$fs_uuid/dev-$1/block"
}
# Two members: dm-0 over LUKS on nvme0n1p3 (from lvm_on_luks), and dm-2 over LUKS on nvme0n1p4, or the plain sdb1.
second_luks() { leaf nvme0n1p4; dm dm-2 CRYPT-LUKS2-def luks-def nvme0n1p4; luks_dump nvme0n1p4 ""; echo "luks-def UUID=def none luks" >>"$work/crypttab"; }

# md0 over the LUKS devices dm-0 and dm-2 (see second_luks), partitioned: md0p1 holds the host directory. As in the kernel's sysfs,
# class/block/md0p1 links to .../md0/md0p1 and the partition has a `partition` file and no slaves of its own.
md_partition_on_luks() {
    lvm_on_luks; second_luks
    mkdir -p "$work/sys/devices/block/md0/md0p1" "$work/sys/devices/block/md0/slaves"
    : >"$work/sys/devices/block/md0/slaves/dm-0"; : >"$work/sys/devices/block/md0/slaves/dm-2"
    : >"$work/sys/devices/block/md0/md0p1/partition"
    ln -s ../../devices/block/md0 "$work/sys/class/block/md0"
    ln -s ../../devices/block/md0/md0p1 "$work/sys/class/block/md0p1"
    echo /dev/md0p1 >"$work/rootdev"
}

# portable NAME COUNT FRAGMENT...: --portable on the current fixture prints COUNT warnings, each fragment in one of them.
# With a warning it stops until accepted, and continues with --accept-no-second-secret.
portable() {
    local name=$1 count=$2 out rc got frag
    shift 2
    out=$(run ubuntu-24.04 --portable --accept-no-second-secret); rc=$?
    check "$name: --accept-no-second-secret continues" 0 $rc "$out" yes
    got=$(grep -c '^warning: ' <<<"$out")
    [ "$got" = "$count" ] || { echo "FAIL $name: $got warnings, wanted $count: $out"; status=1; }
    for frag; do grep -q -- "$frag" <<<"$out" || { echo "FAIL $name: no warning mentions '$frag': $out"; status=1; }; done
    out=$(run ubuntu-24.04 --portable); rc=$?
    if [ "$count" = 0 ]; then check "$name: no warning, nothing to accept" 0 $rc "$out" yes
    else check "$name: stops with no terminal and no flag" 1 $rc "$out" no "not a terminal"; fi
}

for release in debian-12 ubuntu-22.04; do
    out=$(run "$release" --server --accept-physical-access); rc=$?
    check "$release stops, naming the supported release" 1 $rc "$out" no "Ubuntu 24.04 LTS only"
    [ ! -e "$work/host" ] || { echo "FAIL $release: the helper created its directory"; status=1; }
done

for args in "" "--server --portable" "--portable --server" "--server --server" "--bogus" "--server --bogus" \
    "--accept-physical-access" "--portable --accept-physical-access" "--server --accept-no-second-secret" \
    "--accept-no-second-secret"; do
    # shellcheck disable=SC2086
    out=$(run ubuntu-24.04 $args); rc=$?
    check "'$args' is a usage error" 2 $rc "$out" no "usage:"
done

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

# --portable's checks, one fixture each.
unencrypted; portable "an unencrypted stack" 1 "not encrypted" "anyone who steals this machine can boot it and start the vault" "encrypt the disk"
lvm_on_luks; portable "LVM-on-LUKS, passphrase slot only" 0
lvm_over_two; portable "an LV over a LUKS PV and a plain PV" 1 "sdb1" "no dm-crypt layer above it" "every device"
sys_reset; leaf sda2; dm dm-0 LVM-xyz vg sda2; dm dm-1 CRYPT-LUKS2-abc luks-abc dm-0; echo /dev/dm-1 >"$work/rootdev"
echo "luks-abc UUID=abc none luks" >"$work/crypttab"; luks_dump dm-0 ""; boot_image initrd.img-6.8.0-1 x
portable "LUKS-on-LVM, passphrase slot only" 0
lvm_on_luks; luks_dump nvme0n1p3 "$(tpm_token false)"
portable "a PIN-less systemd-tpm2 token" 1 "does not need a PIN" "tpm2-with-pin=yes"
lvm_on_luks; luks_dump nvme0n1p3 "$(tpm_token true)"; echo "luks-abc UUID=abc none tpm2-device=auto" >"$work/crypttab"
portable "a TPM+PIN token" 0
lvm_on_luks; luks_dump nvme0n1p3 "$(printf '  0: clevis\n\tKeyslot:    1\n')"
portable "a clevis token" 1 "clevis token"
lvm_on_luks; luks_dump nvme0n1p3 "$(printf '  0: systemd-fido2\n\tKeyslot:    1\n  1: systemd-pkcs11\n\tKeyslot:    2\n')"
portable "FIDO2 and PKCS#11 tokens" 0
lvm_on_luks; luks_dump nvme0n1p3 "$(printf '  0: ssh-agent-key\n\tKeyslot:    1\n')"
portable "an unrecognised token type" 1 "ssh-agent-key token" "does not recognise"
lvm_on_luks; luks1_dump nvme0n1p3; printf '0   active empty\n1   active cb6e8904-81ff-40da-a84a-07ab9ab5715e\n' >"$work/luksmeta/nvme0n1p3"
portable "a LUKS1 clevis binding" 1 "LUKS1 with a clevis binding" "clevis luks unbind"
lvm_on_luks; luks1_dump nvme0n1p3; printf '0   active empty\n' >"$work/luksmeta/nvme0n1p3"
portable "LUKS1, passphrase slot only" 0
lvm_on_luks; luks1_dump nvme0n1p3; : >"$work/luksmeta/nvme0n1p3"
portable "LUKS1 with an empty luksmeta" 1 "listed no key slots" "run luksmeta show -d .* as root"
lvm_on_luks; luks1_dump nvme0n1p3; printf 'unexpected text\n' >"$work/luksmeta/nvme0n1p3"
portable "LUKS1 with a luksmeta listing that has no slot line" 1 "listed no key slots"
lvm_on_luks; luks1_dump nvme0n1p3; printf '0   inactive empty\n' >"$work/luksmeta/nvme0n1p3"
portable "LUKS1 with only an inactive slot listed" 0
lvm_on_luks; luks1_dump nvme0n1p3; NOTOOL=luksmeta portable "LUKS1 with no luksmeta" 1 "luksmeta is not installed" "install luksmeta"
lvm_on_luks; luks1_dump nvme0n1p3; portable "LUKS1 with a failing luksmeta" 1 "luksmeta show -d .* failed"
out=$(run ubuntu-24.04 --portable --accept-no-second-secret)
! grep -q "luksmeta init" <<<"$out" || { echo "FAIL a LUKS1 luksmeta warning points at luksmeta init: $out"; status=1; }
grep -q "no clevis binding exists" <<<"$out" || { echo "FAIL the luksmeta warning does not say no binding exists: $out"; status=1; }
lvm_on_luks; echo "luks-abc UUID=abc /etc/keys/root.key luks" >"$work/crypttab"
portable "a crypttab key file" 1 "key file /etc/keys/root.key"
lvm_on_luks; luks_dump nvme0n1p3 "$(tpm_token false)"; echo "luks-abc UUID=abc none luks,tpm2-device=auto" >"$work/crypttab"
portable "tpm2-device= with a PIN-less token" 2 "does not need a PIN" "tpm2-device="
lvm_on_luks; boot_image initrd.img-6.8.0-2 "$(printf 'cryptroot/keyfiles\ncryptroot/keyfiles/cryptroot.key')"
portable "a key file in one of two initramfs images" 1 "initrd.img-6.8.0-2 holds a key file"
lvm_on_luks; NOTOOL=cryptsetup portable "a missing cryptsetup" 1 "cryptsetup is not installed" "install cryptsetup and run this again"
lvm_on_luks; NOTOOL=lsinitramfs portable "a missing lsinitramfs" 1 "lsinitramfs is not installed" "install initramfs-tools-core"
md_partition_on_luks; portable "a partitioned md array over two LUKS devices" 0
md_partition_on_luks; echo "luks-abc UUID=abc none luks" >"$work/crypttab"
portable "a partitioned md array whose second LUKS device has no crypttab entry" 1 "no entry named luks-def"
md_partition_on_luks; leaf sdc1; : >"$work/sys/devices/block/md0/slaves/sdc1"
portable "a partitioned md array with a plain member" 1 "sdc1, under"
lvm_on_luks; echo /dev/dm-9 >"$work/rootdev"; portable "a stack that does not resolve" 1 "could not resolve"
lvm_on_luks; echo tmpfs >"$work/rootdev"; portable "a root that is not a block device" 1 "could not resolve"
lvm_on_luks; rm "$work/luksdump/nvme0n1p3"; portable "a failed luksDump" 1 "luksDump .* failed"
lvm_on_luks; echo garbage >"$work/luksdump/nvme0n1p3"; portable "luksDump output not recognised" 1 "printed nothing the helper recognises"
lvm_on_luks; luks_dump nvme0n1p3 "$(printf '  0: systemd-tpm2\n\tKeyslot:    1\n')"
portable "a systemd-tpm2 token that shows no tpm2-pin" 1 "not shown"
lvm_on_luks; : >"$work/crypttab"; portable "no crypttab entry for the LUKS device" 1 "no entry named luks-abc"
lvm_on_luks; rm "$work/crypttab"; portable "an unreadable crypttab" 1 "could not be read"
lvm_on_luks; rm "$work/boot/initrd.img-6.8.0-1"; portable "no initramfs image" 1 "no .*initrd.img-.* was found"
lvm_on_luks; rm "$work/initramfs/initrd.img-6.8.0-1"; portable "an initramfs lsinitramfs cannot list" 1 "could not list"
lvm_on_luks; : >"$work/initramfs/initrd.img-6.8.0-1"; portable "an empty initramfs listing" 1 "listed nothing"
lvm_on_luks; dm dm-0 CRYPT-PLAIN-abc luks-abc nvme0n1p3; portable "plain dm-crypt" 1 "plain dm-crypt"

# A btrfs or bcachefs filesystem is walked member by member, whatever findmnt names.
multi_fs btrfs; second_luks; btrfs_member dm-0; btrfs_member dm-2
portable "btrfs over two LUKS members" 0
multi_fs btrfs; leaf sdb1; btrfs_member dm-0; btrfs_member sdb1
portable "btrfs over a LUKS member and a plain one" 1 "sdb1, under .* not encrypted" "every device"
multi_fs btrfs; leaf sdb1; btrfs_member sdb1; btrfs_member dm-0
portable "btrfs whose plain member is first" 1 "sdb1, under .* not encrypted"
multi_fs btrfs; portable "btrfs with no devices directory" 1 "could not list the devices of the btrfs filesystem" "mount /sys"
multi_fs btrfs; mkdir -p "$work/sys/fs/btrfs/$fs_uuid/devices"; portable "btrfs with an empty devices directory" 1 "could not list"
multi_fs btrfs; : >"$work/fsuuid"; btrfs_member dm-0; portable "btrfs with no filesystem UUID" 1 "could not list"
multi_fs btrfs; echo "../../x" >"$work/fsuuid"; btrfs_member dm-0; portable "btrfs with a UUID that is not hex" 1 "could not list"
# A UUID the hex guard must refuse: unguarded, it climbs out of its own directory and back into it, and lists the members.
multi_fs btrfs; echo "$fs_uuid/../$fs_uuid" >"$work/fsuuid"; btrfs_member dm-0; portable "btrfs with a UUID that climbs out and back" 1 "could not list"
# Two members over one LUKS device (dm-1 is the LV on dm-0) reach the same LUKS layer; its warning is given once.
multi_fs btrfs; luks_dump nvme0n1p3 "$(tpm_token false)"; btrfs_member dm-0; btrfs_member dm-1
portable "btrfs members sharing one LUKS layer" 1 "does not need a PIN"
multi_fs btrfs; btrfs_member dm-9; portable "a btrfs member the device stack does not know" 1 "could not resolve"
multi_fs bcachefs; second_luks; bcachefs_member 0 dm-0; bcachefs_member 1 dm-2
portable "bcachefs over two LUKS members" 0
multi_fs bcachefs; leaf sdb1; bcachefs_member 0 dm-0; bcachefs_member 1 sdb1
portable "bcachefs over a LUKS member and a plain one" 1 "sdb1, under .* not encrypted"
multi_fs bcachefs; portable "bcachefs with no member list" 1 "could not list the devices of the bcachefs filesystem"
multi_fs bcachefs; mkdir -p "$work/sys/fs/bcachefs/$fs_uuid/dev-0"; portable "bcachefs with an unreadable member" 1 "could not list the devices of the bcachefs"
multi_fs bcachefs; second_luks; bcachefs_member 0 dm-0; mkdir -p "$work/sys/fs/bcachefs/$fs_uuid/dev-1"
portable "bcachefs with one unreadable member among readable ones" 1 "could not list"
multi_fs bcachefs; mkdir -p "$work/sys/fs/bcachefs/$fs_uuid"; portable "bcachefs with no dev-N entries" 1 "could not list"
multi_fs ext4; second_luks; leaf sdb1; btrfs_member sdb1
portable "other filesystems are walked from the findmnt device only" 0

# With a warning the answer comes from a terminal, never a pipe.
unencrypted
out=$(yes | run ubuntu-24.04 --portable); rc=$?
check "'yes |' cannot accept a --portable warning" 1 $rc "$out" no "not a terminal"
out=$(run_tty no ubuntu-24.04 --portable); rc=$?
check "at a terminal, any answer but yes stops --portable" 1 $rc "$out" no "not accepted"
out=$(run_tty no ubuntu-24.04 --portable --accept-no-second-secret); rc=$?
check "at a terminal, the flag does not skip the prompt" 1 $rc "$out" no "Type yes to accept"

# The acceptance record: the journal and provisioning.txt carry the same lines.
expect() { # description command...: the command must succeed
    local d=$1
    shift
    "$@" || { echo "FAIL $d"; status=1; }
}
expect_not() { # description command...: the command must fail
    local d=$1
    shift
    ! "$@" || { echo "FAIL $d"; status=1; }
}
record() { # name mode-line accepted-line priority-wanted priority-unwanted
    local rec=$work/host/provisioning.txt n=$1 stamp='[0-9T:Z-]*'
    expect "$n: provisioning.txt has '$2'" grep -qx -- "$stamp $2" "$rec"
    expect "$n: provisioning.txt has '$3'" grep -qx -- "$stamp $3" "$rec"
    expect "$n: provisioning.txt has SUDO_USER" grep -qx -- "$stamp sudo-user: alice" "$rec"
    expect "$n: provisioning.txt is 0600" test "$(stat -c %a "$rec")" = 600
    expect "$n: only the blob and provisioning.txt are left" test "$(find "$work/host" -type f | wc -l)" = 2
    expect "$n: the journal has '$2' at $4" grep -q -- "-t iron-vault-host-unlock -p $4 -- $2" "$work/journal"
    expect "$n: the journal has '$3' at $4" grep -q -- "-p $4 -- $3" "$work/journal"
    expect "$n: the journal has SUDO_USER" grep -q -- "-p $4 -- sudo-user: alice" "$work/journal"
    expect_not "$n: the journal has a line at $5" grep -q -- "-p $5 " "$work/journal"
}
export SUDO_USER=alice
unencrypted; out=$(OLDREC=1 run ubuntu-24.04 --portable --accept-no-second-secret)
record "a --portable warning accepted by flag" "mode: portable" "accepted: flag" auth.warning auth.notice
expect "provisioning.txt has the warning" grep -q '[0-9Z] warning: .*not encrypted' "$work/host/provisioning.txt"
expect "the journal has the warning" grep -q -- '-- warning: .*not encrypted' "$work/journal"
expect_not "provisioning.txt is replaced whole" grep -q stale "$work/host/provisioning.txt"

# A record that cannot be written stops before sealing.
: >"$work/loggerfail"
out=$(run ubuntu-24.04 --server --accept-physical-access); rc=$?
check "a failing logger stops before sealing" 1 $rc "$out" no "could not write the journal record"
rm -f "$work/loggerfail"
out=$(DIRREC=1 run ubuntu-24.04 --server --accept-physical-access); rc=$?
check "a provisioning.txt that is a directory stops before sealing" 1 $rc "$out" no "could not write"
out=$(run_tty yes ubuntu-24.04 --portable); rc=$?
record "a --portable warning accepted at a terminal" "mode: portable" "accepted: terminal" auth.warning auth.notice
lvm_on_luks; out=$(run ubuntu-24.04 --portable)
record "--portable with no warning" "mode: portable" "accepted: not needed (no warning)" auth.notice auth.warning
expect_not "no warning is recorded when none was found" grep -q 'warning: ' "$work/host/provisioning.txt"
out=$(run ubuntu-24.04 --server --accept-physical-access)
record "--server by flag" "mode: server" "accepted: flag" auth.notice auth.warning
out=$(run_tty yes ubuntu-24.04 --server)
record "--server at a terminal" "mode: server" "accepted: terminal" auth.notice auth.warning

exit $status
