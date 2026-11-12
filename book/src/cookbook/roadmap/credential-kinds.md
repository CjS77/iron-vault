# Other credential kinds

**Not yet available.** Planned for a later phase ([roadmap](../../../../README.md#roadmap)).

Iron Vault will hold JWT, GitHub App, HMAC and AWS Signature Version 4 credentials. Each of these signs or builds every
request, where a static key adds the same value each time.

Until then, a credential is a static key or a Basic username and password; see
[Basic authentication upstreams](../basic-auth.md).
