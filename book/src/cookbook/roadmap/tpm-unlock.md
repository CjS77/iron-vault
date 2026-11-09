# Unlock at boot with a TPM

**Not yet available.** Planned for v0 ([roadmap](../../../../README.md#roadmap)).

The vault identity gets a TPM recipient, so a server restarts and unlocks without anyone typing a passphrase, and a
laptop unlocks with a TPM PIN.

Until then, in a development or protected Linux install, every start needs `iron-vault unlock` with the vault passphrase; see
[lock, unlock and restart](../lock-unlock-restart.md). Requirements:
[§14](../../../../design/iron-vault-specification.md#14-recipients-startup-and-memory).
