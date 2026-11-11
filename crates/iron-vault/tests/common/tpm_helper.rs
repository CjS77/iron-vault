//! A stand-in for the TPM signing helper's socket (`design/tpm-approval-signer.md`, "Helper protocol"), for tests of the
//! service side of enrollment: a stub that holds one P-256 key in memory and answers as told, and a bridge that starts the
//! real helper binary per connection against `swtpm`, as systemd's socket unit does.

use std::os::fd::OwnedFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;

use iron_vault_tpm_protocol::{Request, Response, TpmKeyParts, read_frame};
use p256::ecdsa::{Signature, SigningKey};

/// What the stub answers.
#[derive(Clone, Default)]
pub struct Script {
    /// Answers every create request with this instead of a key.
    pub create: Option<Response>,
    /// Answers every sign request with this instead of a signature.
    pub sign: Option<Response>,
}

/// A running stub: its calls, in order (`create` or `sign`).
#[derive(Clone)]
pub struct Stub {
    calls: Arc<Mutex<Vec<&'static str>>>,
}

impl Stub {
    /// The requests the stub has answered, in order.
    pub fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }
}

/// Serves `script` on a socket at `path` from a detached thread.
pub fn serve_stub(path: &Path, script: Script) -> Stub {
    let (listener, stub) = (UnixListener::bind(path).unwrap(), Stub { calls: Arc::default() });
    let calls = Arc::clone(&stub.calls);
    thread::spawn(move || {
        listener.incoming().flatten().for_each(|stream| answer(stream, &script, &calls));
    });
    stub
}

fn answer(mut stream: UnixStream, script: &Script, calls: &Mutex<Vec<&'static str>>) {
    use std::io::Write;
    let key = SigningKey::from_slice(&[7; 32]).unwrap();
    let request = Request::decode(&read_frame(&mut stream).unwrap()).unwrap();
    let (name, response) = match request {
        Request::Create { .. } => ("create", script.create.clone().unwrap_or_else(|| created(&key))),
        Request::Sign(sign) => ("sign", script.sign.clone().unwrap_or_else(|| signed(&key, &sign.message))),
    };
    calls.lock().unwrap_or_else(PoisonError::into_inner).push(name);
    stream.write_all(&response.encode().unwrap()).unwrap();
}

fn created(key: &SigningKey) -> Response {
    Response::Created {
        key: TpmKeyParts {
            primary_name: vec![1; 34],
            public: vec![2; 90],
            private: vec![3; 100],
        },
        public_key: key.verifying_key().to_encoded_point(false).as_bytes().try_into().unwrap(),
    }
}

fn signed(key: &SigningKey, message: &[u8]) -> Response {
    let signature: Signature = p256::ecdsa::signature::Signer::sign(key, message);
    Response::Signed {
        signature: signature.normalize_s().unwrap_or(signature).to_bytes().into(),
    }
}

/// Serves the real helper binary at `binary` on a socket at `path`, one instance per connection, against the emulator
/// `tcti` names. The helper accepts the current account as its peer.
pub fn serve_real(path: &Path, binary: PathBuf, tcti: String) {
    let listener = UnixListener::bind(path).unwrap();
    let user = current_user();
    thread::spawn(move || {
        listener.incoming().flatten().for_each(|stream| {
            let input = OwnedFd::from(stream.try_clone().unwrap());
            let child = Command::new(&binary)
                .args(["--tcti", &tcti, "--peer-user", &user])
                .stdin(Stdio::from(input))
                .stdout(Stdio::from(OwnedFd::from(stream)))
                .spawn()
                .unwrap();
            let _ = child.wait_with_output();
        });
    });
}

/// The name of the account running the tests.
fn current_user() -> String {
    let uid = rustix::process::getuid().as_raw().to_string();
    std::fs::read_to_string("/etc/passwd")
        .unwrap()
        .lines()
        .map(|line| line.split(':').collect::<Vec<_>>())
        .find(|fields| fields.get(2) == Some(&uid.as_str()))
        .map(|fields| fields[0].to_owned())
        .unwrap()
}
