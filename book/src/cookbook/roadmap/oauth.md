# Log in to an OAuth provider

**Not yet available.** Planned for v1 ([roadmap](../../../../README.md#roadmap)).

`iron-vault login` runs the provider's consent flow inside the service, which then caches access tokens and
rotates refresh tokens itself, so an application never holds either.

Until then, Iron Vault holds static API keys and Basic credentials only; see
[give an AI agent or MCP server an API key](../agent-api-key.md).
