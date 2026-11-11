# Retire a machine, or reset the vault

**Not yet available.** Planned for v0 ([roadmap](../../../../README.md#roadmap)).

`iron-vault forget-machine` checks that a retired machine's recipient is gone and guides you through clearing its
TPM. (`iron-vault reset`, which discards a vault whose every way in is lost, is built; see the [CLI reference](../../reference/cli.md#iron-vault-reset).)

Until then, a development vault can be deleted by hand; see [start over in development mode](../start-over.md).
Requirements: [§16](../../../../design/iron-vault-specification.md#16-administration-recovery-and-migration).
