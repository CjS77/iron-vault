//! Binding the admin socket (`design/admin-protocol.md`, "Admin socket"): `admin.sock` in the runtime directory, owned
//! by the service account with mode `0600`, and never connectable at a wider mode.
//!
//! [`crate::socket_file`] does the binding; this module fixes the path and the mode.

use std::os::unix::net::UnixListener;
use std::path::Path;

use super::ADMIN_SOCKET_NAME;
use crate::socket_file::{self, SocketRole, SocketSpec};
pub use crate::socket_file::{BindError, SocketFile};
use crate::trusted_path::ExpectedOwner;

/// The only mode the admin socket may have: the service account alone can connect.
const SOCKET_MODE: u32 = 0o600;

/// The admin socket, bound at mode `0600` and listening. The listener is non-blocking, ready for the async server.
///
/// It owns its socket file: dropping it removes the file, so no exit after binding leaves one behind.
#[derive(Debug)]
pub struct AdminSocket {
    listener: UnixListener,
    file: SocketFile,
}

impl AdminSocket {
    /// Binds `admin.sock` in `runtime_dir` for the service account `owner`, replacing a stale socket that account owns.
    pub fn bind(runtime_dir: &Path, owner: ExpectedOwner) -> Result<Self, BindError> {
        let path = runtime_dir.join(ADMIN_SOCKET_NAME);
        let spec = SocketSpec {
            role: SocketRole::Admin,
            path: &path,
            owner,
            mode: SOCKET_MODE,
        };
        let (listener, file) = socket_file::bind(spec)?;
        Ok(Self { listener, file })
    }

    /// The socket file's path.
    pub fn path(&self) -> &Path {
        self.file.path()
    }

    /// The listener and the socket file, which the server holds until it stops.
    pub fn into_parts(self) -> (UnixListener, SocketFile) {
        (self.listener, self.file)
    }
}
