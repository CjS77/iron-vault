# Installing Iron Vault with Docker Compose

This guide takes a server from nothing to a Ready Iron Vault stack: the service in one container, one isolated network
and TLS listener per caller container, and a host unlock so the service comes back Ready after a restart with no one
typing a passphrase. It is the server and appliance shape of [§17](../../../design/iron-vault-specification.md#17-docker-remote-servers-and-appliances).
[docker-compose.md](../../../design/docker-compose.md) says why each choice was made. On a desktop or a shared
workstation use [protected Linux](linux-install.md) instead, and to try Iron Vault use [development mode](development-mode.md).

The protection depends on the host, not only the stack. Whoever controls the Docker daemon can replace Iron Vault,
run commands in its container and read its memory after unlock, so the daemon's administrators are trusted. Do the
checks under [Before you start](#before-you-start) first.

Only this shape is supported: rootful Docker on a Linux host with systemd, run by a host administrator, with Iron
Vault and its callers in one Compose project. Rootless Docker, `userns-remap`, Podman and a TPM device passed into the
container are not supported.

Iron Vault's Compose profile has had no release check on a real machine yet, so don't rely on it to protect real
secrets. Every `sudo` line here is for you to run; none of it runs by itself.

## Before you start

### Who may control the Docker daemon

Daemon access is root on the host. No untrusted account may be in the `docker` group, hold a passwordless
`sudo docker`, or reach the Docker socket some other way, such as a socket ACL or a remote API. Group membership is not
the whole test; look at what can actually connect:

```sh
getent group docker
ls -l /var/run/docker.sock
sudo -l -U SOMEONE        # for each account that has sudo
```

Never use a user's rootless daemon for Iron Vault: that user controls it.

### Encrypt swap and hibernation storage

Iron Vault locks its memory, but locked memory does not stop hibernation from writing it to disk
([§14](../../../design/iron-vault-specification.md#14-recipients-startup-and-memory)). Use full-disk encryption, and check
swap and hibernation storage as in the Linux guide's
[Encrypt swap and hibernation storage](linux-install.md#encrypt-swap-and-hibernation-storage). The host CLI you type
passphrases into does not lock its memory either.

### Harden `sudo`

Every admin command runs through `sudo` on the host, so follow [Harden `sudo`](linux-install.md#harden-sudo).

### What else the host needs

- **systemd** with `systemd-creds`, and a **TPM 2.0**. The host unlock identity is sealed to the TPM and to the Secure
  Boot policy (PCR 7), so Secure Boot must be on.
- **Docker Engine** with the Compose and buildx plugins, new enough to support the network option
  `com.docker.network.bridge.gateway_mode_ipv4: isolated`, and enabled at boot. The service image is built with
  BuildKit, which the buildx plugin provides. On Ubuntu's own packages install `docker-buildx` with `docker.io` and
  `docker-compose-v2`: `docker.io` only suggests it, and without it the build fails with "the --chmod option requires
  BuildKit". Docker's apt repository calls it `docker-buildx-plugin`.
- `age-keygen` (Debian and Ubuntu package `age`), `openssl` and `curl`.
- This repository checked out, for the files under `packaging/compose/`.

## Set up

The paths below are the ones the service's trusted-path checks accept. Run everything from the repository root unless
a step says otherwise.

### 1. Install the host files

Three files make the `iron-vault` account at the fixed uid and gid 460, create the two runtime directories at each boot,
and define the unlock handoff unit:

```sh
sudo install -m 0644 packaging/compose/host/sysusers.d/iron-vault.conf /usr/lib/sysusers.d/iron-vault.conf
sudo install -m 0644 packaging/compose/host/tmpfiles.d/iron-vault-compose.conf /usr/lib/tmpfiles.d/iron-vault-compose.conf
sudo install -m 0644 packaging/compose/host/iron-vault-host-unlock.service /etc/systemd/system/iron-vault-host-unlock.service
sudo systemd-sysusers
sudo systemd-tmpfiles --create
sudo systemctl daemon-reload
id iron-vault             # uid=460(iron-vault) gid=460(iron-vault)
```

If `id` shows another uid, stop: something else already held 460, and the service refuses to run when the host's account
and the image's differ. The account has no shell, and nothing on the host may run as it. This stack must not share a host
with the [Linux package](linux-install.md): both use `/run/iron-vault` and the `iron-vault` account.

Then make the project directory, root's alone, and the TLS directory under it:

```sh
sudo install -d -m 0700 /etc/iron-vault-host
sudo install -d -m 0755 /etc/iron-vault-host/tls
```

### 2. Build or pull the image

Build the container image from this repository. The build refuses anything but the `container` feature set:

```sh
sudo docker build -f packaging/compose/Dockerfile -t iron-vault .
```

The uid and gid are build arguments, `IRON_VAULT_UID` and `IRON_VAULT_GID`, both 460 by default. Change them only
together with the host's `sysusers.d` file and the Compose file's `user:`. To use an image you pulled or were given,
skip the build. A digest pin needs a registry digest: push a local build to a registry you control and read
`docker image inspect --format '{{index .RepoDigests 0}}' IMAGE`.

Copy the host CLI out of the image. It is the same binary as the service, which is how the two stay in step:

```sh
ctr=$(sudo docker create IMAGE)
sudo docker cp "$ctr:/usr/bin/iron-vault" /usr/local/bin/iron-vault
sudo docker rm "$ctr"
sudo chown root:root /usr/local/bin/iron-vault && sudo chmod 0755 /usr/local/bin/iron-vault
iron-vault --version      # lists "container"
```

### 3. Write the Compose file

Copy the reference file and edit it:

```sh
sudo install -m 0600 packaging/compose/compose.yaml /etc/iron-vault-host/compose.yaml
sudo -e /etc/iron-vault-host/compose.yaml
```

Replace the image digests (they are placeholders), the two example callers with your own, and the subnets if they clash
with the host's. Pin `iron-vault`'s `image:` by digest, so a retagged image cannot change what a later recreation runs.
Keep every other line; the [hardening checklist](#hardening-checklist) says what each one is for. Put no
`compose.override.yaml` and no `.env` beside it: Compose reads both automatically.

### 4. Provision the host unlock identity

This generates the host unlock identity and seals it to the TPM, as root. The secret text exists only in a pipe:

```sh
sudo packaging/compose/host/provision-host-unlock.sh
```

It writes `/etc/iron-vault-host/host-unlock.cred` (root, `0600`) and prints one line to the terminal: the identity's
recipient key, `age1...`. Note it down to compare with what you enrol. The script refuses to run if the credential
already exists. `--with-key host+tpm2` also ties the seal to the host's `/var/lib/systemd/credential.secret`; no other
value is accepted.

### 5. Start the unlock unit

```sh
sudo systemctl enable --now iron-vault-host-unlock.service
findmnt /run/iron-vault-unlock        # a ramfs
```

The unit mounts a ramfs on `/run/iron-vault-unlock` and installs the identity there for the service account. It runs
before Docker at every boot. If it fails, Docker still starts and the service waits Locked.

### 6. Make the certificates

Each caller's listener is TLS, and the caller trusts only the CA that issued its certificate. The certificate names
Iron Vault's address on that caller's network as an IP subject alternative name. One certificate may name every
listener's address, because only Iron Vault holds its key. The addresses below are the reference file's; use yours.

```sh
cd "$(mktemp -d)"
curve="-newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes"
openssl req -x509 $curve -keyout ca.key -out ca.crt -subj /CN=iron-vault-ca -days 365 \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign
openssl req -new $curve -keyout server.key -out server.csr -subj /CN=iron-vault
printf 'subjectAltName=IP:172.30.1.2,IP:172.30.2.2\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' > san.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 -extfile san.ext -out server.crt
```

Install the certificate for each listener, and its key for the service account only:

```sh
for name in caller-a caller-b; do
    sudo install -m 0644 server.crt "/etc/iron-vault-host/tls/$name.crt"
    sudo install -m 0600 -o iron-vault -g iron-vault server.key "/etc/iron-vault-host/tls/$name.key"
done
```

Give each caller container `ca.crt` as its trust anchor, and nothing else from this directory. Then move `ca.key` out of
reach, to an offline store: it can sign certificates that callers would trust. Delete the directory's copy of
`server.key` too, once it is installed.

### 7. Start the stack

```sh
sudo docker compose -f /etc/iron-vault-host/compose.yaml up -d
sudo iron-vault ping                  # shows the container profile
sudo iron-vault status                # Locked: there is no vault yet
```

### 8. Create the vault and enrol the host unlock identity

```sh
sudo iron-vault init --host-unlock
```

`init` prompts for the vault and approval passphrases and shows the recovery key once. Store the recovery key offline.
`--host-unlock` makes `init` read the handoff first, and it refuses to start if the handoff is missing or unsafe. The
vault then has three recipients: the operational identity, the recovery key and the host unlock identity.
`sudo iron-vault recipient list` shows them once the service is Ready; the host unlock recipient's key is the one
step 4 printed.

`init` leaves the service Locked. Restart it, and it opens the vault from the handoff:

```sh
sudo docker compose -f /etc/iron-vault-host/compose.yaml restart iron-vault
sudo iron-vault status                # Ready
```

[vault-initialization.md](../../../design/vault-initialization.md) describes `init`.

### 9. Add the credentials and approve the config

Add each credential the config names, then write the config and approve it. `packaging/compose/config.example.toml` is
the matching example for the reference Compose file: one TLS listener per caller, each with `auth = "isolated-network"`.
The approval must come after the certificates are in place, because the config names them.

```sh
cp packaging/compose/config.example.toml config.toml
$EDITOR config.toml        # your callers, listener addresses, routes and credential names
sudo iron-vault add venice_chat --origin api.venice.ai
sudo iron-vault add brave --origin api.search.brave.com
sudo iron-vault config approve config.toml
```

An isolated-network caller needs no token. It must have its own TLS listener on a dedicated address, as that listener's
only caller; the approval refuses a config that breaks it. The approval cannot see Docker's networks, so keeping each
address on its own network is the Compose file's job.

### 10. Send a request

A caller reaches its own listener over TLS, trusting the CA from step 6 and sending no token: the network identifies it.
From a caller container that has `curl` and `ca.crt`:

```sh
curl --cacert /ca.crt -X POST https://172.30.1.2:8443/venice-chat/chat/completions
```

Use the body your application sends. A request outside the caller's routes is refused.

## Hardening checklist

Tick each line against your own Compose file and host. The reference file applies every line. The reasons, and the
threats each answers, are in the [design's checklist](../../../design/docker-compose.md#hardening-checklist).

### The Iron Vault container

- [ ] `user: "460:460"`, the same uid and gid as the image and the host's `iron-vault` account.
- [ ] `read_only: true`.
- [ ] `cap_drop: [ALL]`.
- [ ] `security_opt: [no-new-privileges:true]`.
- [ ] `ulimits` with `memlock: -1` and `core: 0`. Without an unlimited memlock the service cannot lock memory, and
  refuses to unlock.
- [ ] None of `privileged`, `pid: host`, `ipc: host`, `network_mode: host`, `devices`, or the Docker socket.
- [ ] No `seccomp=unconfined` or `apparmor=unconfined`.
- [ ] No `environment` or `env_file` holding a secret.
- [ ] `command: ["serve", "--log-to-stdout"]`, and `logging` with the `json-file` driver and `max-size` and `max-file`.
  Never `journald` ([log operations](../reference/log-operations.md#docker)).
- [ ] `restart: unless-stopped`.
- [ ] `image:` pinned by digest.
- [ ] Networks are `egress` and each caller's network, each with a static `ipv4_address`.
- [ ] No other container uses `network_mode: "service:iron-vault"` or `"container:..."` naming it.

### Mounts

- [ ] Named volumes `config` at `/etc/iron-vault` and `state` at `/var/lib/iron-vault`.
- [ ] Host `/run/iron-vault` at `/run/iron-vault`, read-write.
- [ ] Host `/run/iron-vault-unlock` at the same path, read-only, as a directory and not as a file.
- [ ] Host `/etc/iron-vault-host/tls` at `/etc/iron-vault-tls`, read-only.
- [ ] Nothing else: no home directory, no Docker socket.

### Each caller container

- [ ] `cap_drop: [ALL]`, and never `NET_ADMIN` or `NET_RAW`.
- [ ] `security_opt: [no-new-privileges:true]`.
- [ ] On its own caller network only: never `egress`, never another caller's.
- [ ] A static `ipv4_address` of its own on that network.
- [ ] No `network_mode` of `host`, or sharing Iron Vault's.
- [ ] No `config` or `state` volume, no `/run/iron-vault`, `/run/iron-vault-unlock` or TLS key mount, and no Docker
  socket.
- [ ] No `privileged`, `pid: host` or `ipc: host`.
- [ ] Trusts only the CA that issued its listener's certificate.

### The caller networks

- [ ] One network per caller, `internal: true`, with a small subnet such as a `/29`, and IPv6 off.
- [ ] `com.docker.network.bridge.gateway_mode_ipv4: isolated` on each, so the bridge has no host address.
- [ ] `egress` is not internal, and only Iron Vault joins it.

### The host

- [ ] `/etc/iron-vault-host` is root's, `0700`, and holds the Compose file, with no `compose.override.yaml` or `.env`.
- [ ] The image's build context, and any entrypoint or script mounted into a container, are root's too.
- [ ] `host-unlock.cred` is root's, `0600`; the unit and its scripts are root-owned.
- [ ] Only root reaches the Docker socket: no ordinary account in `docker`, no passwordless `sudo docker`.
- [ ] The host `iron-vault` account has no shell, and nothing on the host runs as it.
- [ ] Swap and hibernation storage are encrypted.
- [ ] `sudo` is hardened as in [protected Linux](linux-install.md#harden-sudo).

## Remote administration

Without user-namespace remapping the container shares the host's uids, so the service sees the host account that opens
the admin socket. Root is the only admin principal in this profile; the service account is not one. A plain
`docker exec` runs as the service uid and is refused for that reason, and `docker exec -u 0` is root without
`CAP_DAC_OVERRIDE`, so it cannot open the socket.

There are two ways to administer a server from elsewhere. Both are SSH, and neither exposes the admin protocol on a
network.

- **Run the command on the server (the default).**

  ```sh
  ssh -t admin@server sudo iron-vault status
  ```

  The command runs through `sudo` on the server, and what you type goes through the SSH terminal. `-t` is required for
  commands that prompt.

- **Forward the admin socket.** This needs a key-only root login (`PermitRootLogin prohibit-password`) on the server.

  ```sh
  ssh -N -L ~/.iv-admin.sock:/run/iron-vault/admin.sock root@server &
  iron-vault --admin-socket ~/.iv-admin.sock status
  ```

  Close the forward when you are done: any process of your local account can use the socket while it is open, as
  root on the server.

An `ssh -L` forward through a non-root login is refused. `sshd` connects to the socket as the login account, so the
kernel refuses the `connect()` first: the socket is `0600` and owned by the service account, in a `0711` directory, so
only root can open it. Even a login that got through would be refused, because the service accepts only uid 0. Use the first form, or log in as root with a key.

## Restarts and reboots

- **A restart of the service container**, by hand or after a crash (`restart: unless-stopped`), reads the handoff
  again, and the service comes back Ready with no one present.
- **A reboot of the host** runs the unlock unit before Docker starts, then Docker starts the stack, and the service
  reads the handoff. Check with `sudo iron-vault status` once it is up.
- **`lock`** holds only until the container restarts. In this profile whoever controls the runtime can restart it, and
  it will unlock itself.
- **If the handoff is missing or refused**, the service stays Locked, and `sudo iron-vault unlock` with the vault
  passphrase still works. The reason is in the `vault.host-unlock` record of the
  [audit log](../reference/audit-log.md#service-and-lock-state). A failed host unlock does not count toward the
  passphrase attempt limit.

## A lost TPM, or a cleared credential

The host unlock identity lives only sealed to this host's TPM. It is lost with the TPM, the motherboard, a TPM clear, or
a change to Secure Boot's policy (PCR 7). Then the stack starts Locked, and the vault is intact.

1. Open the vault with the vault passphrase, which `recipient add` needs. Optionally run `recovery check` to confirm the
   offline recovery key still opens it; it does not unlock the vault.

   ```sh
   sudo iron-vault unlock
   sudo iron-vault recovery check
   ```

2. Move the unusable credential aside, because the script will not overwrite it, and provision a new identity:

   ```sh
   sudo mv /etc/iron-vault-host/host-unlock.cred /etc/iron-vault-host/host-unlock.cred.old
   sudo packaging/compose/host/provision-host-unlock.sh
   sudo systemctl restart iron-vault-host-unlock.service
   ```

   Note the `age1...` recipient key it prints.

3. Enrol it, with the vault passphrase:

   ```sh
   sudo iron-vault recipient add age1... --label "host unlock, new TPM"
   ```

   [Recipients](../../../design/recipients.md) lists the key with the role `added`. `recipient add` has no
   `--host-unlock` form yet, so the role is not `host-unlock`.

4. Restart the container, and check it reaches Ready with no `unlock`:

   ```sh
   sudo docker compose -f /etc/iron-vault-host/compose.yaml restart iron-vault
   sudo iron-vault status
   ```

5. Remove the old entry, the one with the role `host-unlock` (not the `added` key from step 3), by its key as
   `recipient list` prints it, and delete the old credential:

   ```sh
   sudo iron-vault recipient list
   sudo iron-vault recipient remove age1...
   sudo rm /etc/iron-vault-host/host-unlock.cred.old
   ```

   Removal needs the approval passphrase, and it protects future copies of `identity.age` only.

## Upgrade

Build or pull the new image as in [step 2](#2-build-or-pull-the-image), put its digest in the Compose file's
`image:`, and recreate the service:

```sh
sudo docker compose -f /etc/iron-vault-host/compose.yaml up -d
```

The service restarts, reads the handoff and comes back Ready. The named volumes keep the vault and the config. Copy the
new host CLI out of the image as in step 2, so it matches the service. Without a working handoff, run
`sudo iron-vault unlock`.

## Remove

Stop the stack. The volumes, and with them the vault, stay:

```sh
sudo docker compose -f /etc/iron-vault-host/compose.yaml down
```

To retire the host unlock, stop and disable the handoff unit, remove the credential, then remove its recipient with
`recipient remove` while the stack still runs. The service keeps working through the passphrase.

To delete everything, **`down -v` deletes the vault and every stored credential, and nothing recovers them, not even the
recovery key.**

```sh
sudo docker compose -f /etc/iron-vault-host/compose.yaml down -v
sudo systemctl disable --now iron-vault-host-unlock.service
sudo rm -rf /etc/iron-vault-host
sudo rm /etc/systemd/system/iron-vault-host-unlock.service /usr/lib/tmpfiles.d/iron-vault-compose.conf \
    /usr/lib/sysusers.d/iron-vault.conf /usr/local/bin/iron-vault
sudo systemctl daemon-reload
sudo userdel iron-vault
```

Keep the account if you keep the volumes: a later account at the same uid could otherwise read a kept vault's files.
