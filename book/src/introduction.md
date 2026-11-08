# Introduction

Iron Vault is a small local proxy that holds API credentials so the programs that use them never do.

Point an application's base URL at Iron Vault and give it a placeholder instead of a provider key. Iron Vault
authenticates the caller, checks its route, adds the credential, and forwards the request over verified TLS. The
application holds at most a local caller token that grants specific routes; it never needs the provider secret.

## Who it is for

- AI agents and MCP servers that call APIs such as Brave, Venice or an FX service, without real keys in their
  configuration or environment.
- Back-office applications that share an installation's credentials through isolated routes.
- Shared Linux workstations, where each OS account gets only its own routes.
- Server operators who want an unattended service with isolated callers and recoverable encrypted storage.

CLI tools such as `gh`, `npm` and `cargo` are supported only where a tested base-URL integration covers the whole
workflow. Setting `HTTPS_PROXY` alone does not inject credentials.

## What it promises, and what it doesn't

Iron Vault aims to stop a caller from reading a stored provider credential, sending it to another origin, or using a
route its identity is not granted. It refuses config changes that were not approved, and refuses an old config paired
with its old approval.

It does not stop misuse of a route a caller is granted. Malware that can read a caller's token, or that runs as an
account the service recognises, can use that caller's routes. Method and path restrictions and rate limits bound that
access. Response scrubbing reduces accidental disclosure when an upstream echoes a secret, but cannot recognise every
transformed form of it. Root and other host administrators are trusted. The [security model](security-model.md) says
more.

## Status

v0 is in progress, and Iron Vault runs on Linux only. The proxy works end to end in
[development mode](installation/development-mode.md). The Debian package for a
[protected Linux installation](installation/linux-install.md) is built from the repository, but it has not had a
release check on a real machine yet, so don't rely on it to protect real secrets.

## How this manual is organised

- **[Installation](installation/development-mode.md):** development mode, and the protected Linux install.
- **[Cookbook](cookbook/getting-started.md):** short recipes, each ending with something that works.
- **[Reference](reference/cli.md):** every command, config key, error, service state, audit event and file.
- **[Glossary](glossary.md):** the terms this manual and the code share, one name per concept.
