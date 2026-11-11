//! A stand-in for the TPM signing helper's socket (`design/tpm-approval-signer.md`, "Helper protocol"), for tests of the
//! service side of enrollment: a stub that holds one P-256 key in memory and answers as told, and a bridge that starts the
//! real helper binary per connection against `swtpm`, as systemd's socket unit does.

use std::collections::VecDeque;
use std::os::fd::OwnedFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
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

/// The stub's state, shared with the thread that serves it.
#[derive(Default)]
struct State {
    script: Script,
    /// Answers for the next sign requests, one each, in order; `None` signs for real. Ahead of the script.
    next_signs: VecDeque<Option<Response>>,
    calls: Vec<&'static str>,
    /// The first four bytes of every message signed: `IVPP` for presence, `IVAP` for an approval.
    signed: Vec<[u8; 4]>,
    /// Holds the answer to the next approval-payload sign until its sender sends or drops.
    stall_approval: Option<Receiver<()>>,
}

/// A running stub: its calls, in order (`create` or `sign`).
#[derive(Clone)]
pub struct Stub {
    state: Arc<Mutex<State>>,
}

impl Stub {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The requests the stub has answered, in order.
    pub fn calls(&self) -> Vec<&'static str> {
        self.state().calls.clone()
    }

    /// The magic of each message the stub was asked to sign, in order.
    pub fn signed_magics(&self) -> Vec<[u8; 4]> {
        self.state().signed.clone()
    }

    /// Replaces the answers the stub gives from now on.
    pub fn set_script(&self, script: Script) {
        self.state().script = script;
    }

    /// Holds the answer to the next request to sign an approval payload (`IVAP`) until the returned sender sends or drops.
    pub fn stall_next_approval(&self) -> Sender<()> {
        let (release, stall) = channel();
        self.state().stall_approval = Some(stall);
        release
    }

    /// Answers the next sign requests with `answers`, one each, in order; `None` signs for real.
    pub fn answer_next_signs(&self, answers: impl IntoIterator<Item = Option<Response>>) {
        self.state().next_signs = answers.into_iter().collect();
    }
}

/// Serves `script` on a socket at `path` from a detached thread.
pub fn serve_stub(path: &Path, script: Script) -> Stub {
    let listener = UnixListener::bind(path).unwrap();
    let stub = Stub {
        state: Arc::new(Mutex::new(State {
            script,
            ..State::default()
        })),
    };
    let state = Arc::clone(&stub.state);
    thread::spawn(move || {
        listener.incoming().flatten().for_each(|stream| answer(stream, &state));
    });
    stub
}

fn answer(mut stream: UnixStream, state: &Mutex<State>) {
    use std::io::Write;
    let key = SigningKey::from_slice(&[7; 32]).unwrap();
    let request = Request::decode(&read_frame(&mut stream).unwrap()).unwrap();
    let mut state = state.lock().unwrap_or_else(PoisonError::into_inner);
    let mut stall = None;
    let (name, response) = match request {
        Request::Create { .. } => ("create", state.script.create.clone().unwrap_or_else(|| created(&key))),
        Request::Sign(sign) => {
            state.signed.push(sign.message[..4].try_into().unwrap());
            if sign.message.starts_with(b"IVAP") {
                stall = state.stall_approval.take();
            }
            let scripted = state.next_signs.pop_front().unwrap_or_else(|| state.script.sign.clone());
            ("sign", scripted.unwrap_or_else(|| signed(&key, &sign.message)))
        }
    };
    state.calls.push(name);
    drop(state);
    if let Some(stall) = stall {
        let _ = stall.recv();
    }
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
pub fn current_user() -> String {
    let uid = rustix::process::getuid().as_raw().to_string();
    std::fs::read_to_string("/etc/passwd")
        .unwrap()
        .lines()
        .map(|line| line.split(':').collect::<Vec<_>>())
        .find(|fields| fields.get(2) == Some(&uid.as_str()))
        .map(|fields| fields[0].to_owned())
        .unwrap()
}
