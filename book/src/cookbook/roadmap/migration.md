# Move a vault to a new machine

**Not yet available.** Planned for v0 ([roadmap](../../../../README.md#roadmap)).

`iron-vault export` writes an encrypted bundle once you prove you own the source vault, and `import` opens it on
the new machine. No plaintext secret is written anywhere on the way, and old config approvals stay invalid.

Until then, there is no supported way to move a vault. Rebuild on the new machine from your copies of the approved
config and `iron-vault list`, with keys reissued by each provider. Requirements:
[§16](../../../../design/iron-vault-specification.md#16-administration-recovery-and-migration).

## Vaults with a TPM approver

A TPM approver's key cannot leave its TPM, so a bundle carries no key for it. `export` needs at least one software
approver and refuses without one (`approver-set-invalid`, error 42): enroll one first with `approver add`.

On the new machine, `import` lists each TPM approver as `bound to the source machine`. It cannot sign there. Approve
the first config with a software approver, remove the TPM approvers with `approver remove`, and enroll a new TPM
approver on the new machine if you want one.
