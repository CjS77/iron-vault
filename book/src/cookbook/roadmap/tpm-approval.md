# Approve configs with a TPM PIN

**Not yet available.** Planned for v0 ([roadmap](../../../../README.md#roadmap)).

A signing key held in the TPM, separate from the key that unlocks the vault, signs each approved config once you
type its PIN. A vault that unlocks unattended still needs you present to change its policy.

Until then, the approval passphrase signs each approval; see [widen or narrow a route](../change-route.md).
Requirements: [§12](../../../../design/iron-vault-specification.md#12-configuration-approval-and-reload).

In the [Docker Compose](../compose.md) install the same applies, and the key would stay on the host: the container
could ask only for the service's own approval transaction to be signed.
