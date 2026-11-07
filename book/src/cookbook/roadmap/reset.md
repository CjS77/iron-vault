# Retire a machine, or reset the vault

**Not yet available.** Planned for v0 ([roadmap](../../../../README.md#roadmap)).

`iron-vault forget-machine` checks that a retired machine's recipient is gone and guides you through clearing its
TPM. `iron-vault reset` discards a vault whose every way in is lost, so you can rebuild from reissued credentials.

Until then, a development vault can be deleted by hand; see [start over in development mode](../start-over.md).
Requirements: [§3.13](../../../../design/iron-vault-specification.md#313-administration-recovery-and-migration).
