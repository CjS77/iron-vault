# Use a YubiKey

**Not yet available.** Planned for a later phase ([roadmap](../../../../README.md#roadmap)).

A YubiKey will become a recipient that unlocks the vault and signs approvals with a PIN or touch, and a route will be
able to ask for a touch on each request.

Until then, the vault unlocks with the vault passphrase or [TPM unlock](../tpm-unlock.md), approvals are signed with an
approval passphrase or a [TPM PIN](../tpm-approval.md), and a config with a route that asks for a touch is refused when it is
read.
