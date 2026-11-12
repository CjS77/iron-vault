//! The migration bundle: the gzip-compressed ustar archive `export` writes and `import` reads
//! ([spec §16](../../../design/iron-vault-specification.md#16-administration-recovery-and-migration) steps 2 and 4). The layout is
//! [migration bundle v1](../../../design/storage-formats.md#migration-bundle-v1).
//!
//! The archive is a container only: every entry that holds a secret is encrypted on its own. The entries form a closed
//! list in a fixed order:
//!
//! ```text
//! bundle-header            37 bytes: IVBH, version, vault ID, approver count, record count
//! exported-identity.age    the vault identity under the export passphrase
//! manifest.age             byte for byte from the state directory
//! approval.age             byte for byte from the state directory
//! config.toml              the committed config, byte for byte
//! approver-<ID>.age …      1 to 16 bundled approver keys, ascending approver ID
//! record-<ID>.age …        0 to 4096 record files, ascending record ID
//! two zero blocks          the end of the archive
//! ```
//!
//! Every ustar header field except the name, size and checksum is fixed, so each entry has exactly one encoding, and
//! the decoder requires each header to equal the one the encoder would write. No `tar` crate is used: its readers accept
//! many forms the bundle must refuse, and its writers fill fields this format fixes.

mod bundle_header;
mod decode;
mod encoder;
mod entry_name;
mod ustar;

pub use bundle_header::{BUNDLE_FORMAT_VERSION, BUNDLE_HEADER_LEN, BundleHeader, BundleHeaderError};
pub use decode::{BundleDecoder, BundleError, DecodedBundle};
pub use encoder::{BundleEncoder, EncodeError};
pub use entry_name::{EntryName, EntryNameError};

/// The largest migration bundle accepted, 260 MiB, bounding both the compressed bytes import receives and the archive
/// they decompress to. A full bundle's archive is 271,692,800 bytes, and gzip's stored blocks add about 20,750 more, so
/// every bundle the service can build fits ([size limit](../../../design/storage-formats.md#size-limit-5)).
pub const MAX_BUNDLE_LEN: u64 = 272_629_760;

/// The largest bundled approver key: a 1 KiB approver key envelope, plus the `age` header with its X25519 stanza and a
/// grease stanza, the payload nonce and the tag.
pub const MAX_BUNDLED_APPROVER_LEN: usize = 2048;
