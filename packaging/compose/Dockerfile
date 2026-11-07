# The Iron Vault container image: the `container` build, run by the fixed service account.
# Build from the repository root: docker build -f packaging/compose/Dockerfile -t iron-vault .
# See design/docker-compose.md. No secret, build-time environment or unlock material belongs in any layer.

FROM rust:1.98.0-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --locked --release -p iron-vault --features container \
    # A wrong feature set is a different deployment profile; refuse it here, not at run time.
    && target/release/iron-vault --version | tee /dev/stderr | grep -qE ' \(features: container\)$'

FROM debian:bookworm-slim

# The uid and gid must equal the Compose file's `user:` and the host's sysusers.d line.
ARG IRON_VAULT_UID=460
ARG IRON_VAULT_GID=460

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid "${IRON_VAULT_GID}" iron-vault \
    && useradd --system --uid "${IRON_VAULT_UID}" --gid "${IRON_VAULT_GID}" --no-create-home \
        --home-dir /nonexistent --shell /usr/sbin/nologin iron-vault \
    # Docker copies these owners and modes into new named volumes, so the trusted-path checks pass on first use.
    && install -d -o iron-vault -g iron-vault -m 0700 /etc/iron-vault /var/lib/iron-vault \
    && install -d -o iron-vault -g iron-vault -m 0711 /run/iron-vault

COPY --from=build --chown=root:root --chmod=0755 /src/target/release/iron-vault /usr/bin/iron-vault

USER iron-vault
ENTRYPOINT ["/usr/bin/iron-vault"]
CMD ["serve", "--log-to-stdout"]
