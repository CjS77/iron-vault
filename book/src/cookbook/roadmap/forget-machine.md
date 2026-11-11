# Retire a machine

**Not yet available.** Planned for v0 ([roadmap](../../../../README.md#roadmap)).

`iron-vault forget-machine` checks that a retired machine's recipient is gone and guides you through clearing its
TPM.

Until then, remove the machine's recipient with [`recipient remove`](../recipients.md). To discard a whole vault, see
[reset the vault](../reset-vault.md). A development vault can also be deleted by hand; see
[start over in development mode](../start-over.md).
Requirements: [§16](../../../../design/iron-vault-specification.md#16-administration-recovery-and-migration).
