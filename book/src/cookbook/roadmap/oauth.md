# Log in to an OAuth provider

**Not yet available.** Planned for v1 ([roadmap](../../../../README.md#roadmap)).

`iron-vault login` will run the provider's consent flow inside the service. The service will then cache access tokens
and rotate refresh tokens itself, so an application never holds either.

Until then, Iron Vault holds static API keys and Basic credentials only; see
[give an AI agent or MCP server an API key](../agent-api-key.md).
