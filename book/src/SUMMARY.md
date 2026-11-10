# Summary

[Introduction](introduction.md)

# Installation

- [Development mode](installation/development-mode.md)
- [Protected Linux](installation/linux-install.md)
    - [A shared Linux workstation](installation/multiuser-linux.md)
- [Docker Compose](installation/compose-install.md)

# Cookbook

- [Getting started in development mode](cookbook/getting-started.md)
- [Give an AI agent or MCP server an API key](cookbook/agent-api-key.md)
- [Two keys, two callers, different permissions](cookbook/two-callers.md)
- [Basic authentication upstreams](cookbook/basic-auth.md)
- [Point a real application at Iron Vault](cookbook/real-application.md)
- [Protected Linux install](cookbook/protected-linux.md)
- [Rotate a provider key](cookbook/rotate-key.md)
- [Remove a credential safely](cookbook/remove-credential.md)
- [Rotate or revoke a caller token](cookbook/caller-token.md)
- [Widen or narrow a route](cookbook/change-route.md)
- [Scrubbing and redirects](cookbook/scrubbing-redirects.md)
- [A route can't send a key to another host](cookbook/key-origins.md)
- [Investigate with the audit log](cookbook/investigate-audit-log.md)
- [Lock, unlock and restart](cookbook/lock-unlock-restart.md)
- [Check and store your recovery key](cookbook/recovery-key.md)
- [Rotate the recovery key, or add a machine's key](cookbook/recipients.md)
- [Tamper detection and recovery](cookbook/tamper-detection.md)
- [Start over in development mode](cookbook/start-over.md)
- [Run Iron Vault in Docker Compose](cookbook/compose.md)
- [Not yet available](cookbook/roadmap/index.md)
    - [Unlock at boot with a TPM](cookbook/roadmap/tpm-unlock.md)
    - [Approve configs with a TPM PIN](cookbook/roadmap/tpm-approval.md)
    - [Move a vault to a new machine](cookbook/roadmap/migration.md)
    - [Retire a machine, or reset the vault](cookbook/roadmap/reset.md)
    - [Log in to an OAuth provider](cookbook/roadmap/oauth.md)
    - [Get owner notifications on the desktop](cookbook/roadmap/notifications.md)
    - [Restrict what a request may contain](cookbook/roadmap/request-content.md)
    - [Use a YubiKey](cookbook/roadmap/yubikey.md)
    - [Other credential kinds](cookbook/roadmap/credential-kinds.md)
    - [Sync from a password manager](cookbook/roadmap/password-manager-sync.md)
    - [macOS and Windows](cookbook/roadmap/macos-windows.md)

# Reference

- [CLI](reference/cli.md)
- [Configuration](reference/configuration.md)
- [Errors](reference/errors.md)
- [Service states](reference/states.md)
- [Audit log](reference/audit-log.md)
    - [Log operations](reference/log-operations.md)
- [Files and locations](reference/files.md)

---

[Glossary](glossary.md)
[Security model](security-model.md)
