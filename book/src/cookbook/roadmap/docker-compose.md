# Run Iron Vault in Docker Compose

**Not yet available.** Planned for v0, and partly built ([roadmap](../../../../README.md#roadmap)).

Iron Vault runs in its own container, with one isolated network and TLS listener per caller container, and the host
hands it the vault identity at startup so it can unlock without a passphrase.

The container build, the image, a reference Compose file in `packaging/compose/` and the host unlock at startup are
in the repository, with an [install guide](../../installation/compose-install.md), but they have had no release check.
Don't rely on them to protect real secrets. Design: [docker-compose.md](../../../../design/docker-compose.md).
