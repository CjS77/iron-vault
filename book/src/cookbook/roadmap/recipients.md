# Add or remove a recipient

**Not yet available.** Planned for v0 and in progress ([roadmap](../../../../README.md#roadmap)).

`iron-vault recipient add` and `remove` change who can open the vault identity, such as a new passphrase or a
replacement recovery key, without re-encrypting the credentials. A change that would leave fewer than two independent
ways in is refused.

Until then, a vault has the recipients `init` gave it: the vault passphrase and the offline recovery key. Keep the
recovery key safe; see [check and store your recovery key](../recovery-key.md). Design:
[recipients.md](../../../../design/recipients.md).
