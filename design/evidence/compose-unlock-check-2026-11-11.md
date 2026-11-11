# Compose host unlock check, 2026-11-11

Evidence for the [implementation spec §3](../implementation-specification.md#3-implementation-gates-and-unresolved-details)
"Host unlock handoff" gate, as [docker-compose.md](../docker-compose.md#against-the-implementation-spec-3-gate)
describes. [`compose-unlock-check.sh`](../../scripts/release/compose-unlock-check.sh) passed every item, with none
skipped: 5 of 5 in part 1 and 14 of 14 in part 2.

## Host

| | |
|---|---|
| Commit | `9591715` (fix(release): drop crate-source test keys from the Compose unlock disk scan) |
| Hypervisor | KVM/libvirt on a Geekom A9 (AMD Ryzen) running Ubuntu 24.04 |
| Guest | Fresh Ubuntu 24.04.5 LTS cloud image, kernel 6.8.0-149-generic, systemd 255.4-1ubuntu8.18, 8 vCPUs, 8 GiB |
| TPM | Emulated TPM 2.0 (`swtpm`, CRB); `systemd-creds has-tpm2`: yes, all five components |
| Firmware | UEFI (OVMF) with Secure Boot on and Microsoft keys enrolled |
| Swap | 2 GiB file, `/swap.img` |
| Docker | docker.io 29.1.3, Compose 2.40.3, buildx 0.30.1 |

The guest was rebooted once after first-boot setup and before part 1, so PCR 7 had settled. Part 1 and part 2 ran
either side of a guest reboot. The VM was destroyed after the run.

## Part 1

```
compose-unlock-check (part 1) on Ubuntu 24.04.5 LTS, kernel 6.8.0-149-generic, 2026-11-11T09:57:18Z
docker 29.1.3, compose 2.40.3+ds1-0ubuntu1~24.04.1, systemd 255 (255.4-1ubuntu8.18)
tpm: yes +firmware +driver +system +subsystem +libraries , swap: /swap.img
age1srfnweq35z9lumnwt6xxgjyq6zdwr7xcv68syrt9g8c86c8xx45sydagxq
PASS the stack starts with the handoff in place
PASS init --host-unlock then compose restart: Ready with no unlock, vault.host-unlock unlocked
PASS recovery check with the recovery key opens the same vault ID
PASS identity.age has exactly three X25519 stanzas and no scrypt stanza
PASS the handoff is a 0400 service-owned file on a host ramfs
5 passed, 0 failed so far. Reboot now (sudo reboot), then run the second part:
  sudo scripts/release/compose-unlock-check.sh --i-know-this-is-a-disposable-vm --after-reboot
```

The `age1...` line is the host unlock identity's public recipient, which the provisioning script prints.

## Part 2

```
compose-unlock-check (part 2) on Ubuntu 24.04.5 LTS, kernel 6.8.0-149-generic, 2026-11-11T09:59:57Z
docker 29.1.3, compose 2.40.3+ds1-0ubuntu1~24.04.1, systemd 255 (255.4-1ubuntu8.18)
tpm: yes +firmware +driver +system +subsystem +libraries , swap: /swap.img
PASS after a host reboot the stack is Ready unattended
PASS unit stopped, restart: Locked with absent; passphrase unlock reaches Ready
PASS credential sealed for another key: Locked with refused not_a_recipient
PASS the first credential back, restart: Ready again
PASS the key scanner finds a planted key in a stream and in a file
PASS no age secret key in the image, docker inspect or the service environment
PASS no age secret key under /etc, /var or the named volumes
     skipped 100 keys in published crate sources (*/usr/local/cargo/registry/src/*)
PASS no age secret key in swap
PASS only the admin socket and the request listeners listen: no signing oracle
14 passed, 0 failed, 0 skipped (a skipped item has no evidence from this host)
```

The 100 skipped keys are the `age` 0.12.1 crate's public test vectors, in the cargo registry the image's build stage
unpacks and the build cache keeps. They are in no vault.

## Not covered

This run used an emulated TPM, which meets the gate's "a host with a TPM". A run on TPM hardware (the A9's AMD fTPM)
is tracked separately and does not block the gate.
