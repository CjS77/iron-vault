// SPDX-License-Identifier: MPL-2.0
//! Recognises the three messages the helper signs
//! ([TPM approval signer: what the helper signs](../../../design/tpm-approval-signer.md#what-the-helper-signs)).
//!
//! The helper signs an approval payload, a presence payload or a migration proof payload, and nothing else, so a
//! compromised service cannot use the TPM approval key as a general signing oracle.

/// Each signable message's magic, format version and exact length.
///
/// The magics separate the domains: no message can be read as another, so the helper needs no state to tell them
/// apart.
const SIGNABLE: [(&[u8; 4], u8, usize); 3] = [(b"IVAP", 1, 89), (b"IVPP", 1, 69), (b"IVMA", 1, 37)];

/// Returns `true` if and only if `message` has the magic, version and length of an approval payload, a presence payload
/// or a migration proof payload.
///
/// The helper calls this before any TPM command, so a refused message spends no dictionary-attack try.
pub fn is_signable(message: &[u8]) -> bool {
    SIGNABLE
        .iter()
        .any(|(magic, version, len)| message.len() == *len && message.starts_with(*magic) && message[4] == *version)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(magic: &[u8; 4], len: usize) -> Vec<u8> {
        [magic.as_slice(), &[1], &vec![0; len - 5]].concat()
    }

    #[test]
    fn the_three_payloads_are_signable() {
        assert!(is_signable(&message(b"IVAP", 89)));
        assert!(is_signable(&message(b"IVPP", 69)));
        assert!(is_signable(&message(b"IVMA", 37)));
    }

    #[test]
    fn anything_else_is_refused() {
        [
            message(b"IVAP", 88),
            message(b"IVAP", 69),
            message(b"IVPP", 89),
            message(b"IVMA", 38),
            message(b"IVAS", 89),
            vec![0; 32],
            Vec::new(),
        ]
        .iter()
        .for_each(|refused| assert!(!is_signable(refused), "{refused:?}"));
        let mut version_two = message(b"IVPP", 69);
        version_two[4] = 2;
        assert!(!is_signable(&version_two));
    }
}
