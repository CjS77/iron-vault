# Move a vault to a new machine

**Not yet available.** Planned for v0 ([roadmap](../../../../README.md#roadmap)).

`iron-vault export` writes an encrypted bundle once you prove you own the source vault, and `import` opens it on
the new machine. No plaintext secret is written anywhere on the way, and old config approvals stay invalid.

Until then, there is no supported way to move a vault. Rebuild on the new machine from your copies of the approved
config and `iron-vault list`, with keys reissued by each provider. Requirements:
[§16](../../../../design/iron-vault-specification.md#16-administration-recovery-and-migration).
