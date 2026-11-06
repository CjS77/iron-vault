//! A real passed socket under `systemd-socket-activate`, which sets `LISTEN_*` and passes a listening socket to the
//! service the way systemd does (specification §3.4, R-6; the end-to-end run `socket_activation.rs` leaves to EP-34).
//!
//! The service is the built binary in development mode, which adopts passed sockets too. `init`, `unlock` and
//! `config approve` run over its real admin socket: `init` shows the recovery key on a terminal only, and there is none
//! here. The test skips, printing why, when `systemd-socket-activate` is not on `PATH` or the build tree is not a
//! trusted path (the service refuses to run from a directory other accounts can write).

#![cfg(all(target_os = "linux", feature = "dev-mode"))]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use common::WAIT;
use common::approval_harness::{read_frame, send};
use iron_vault::admin::protocol::{AdminRequest, AdminResponse, Frame, OwnerInput, ProposedConfig};
use rustix::process::{Pid, Signal, kill_process_group};
use tokio::net::UnixStream;
use zeroize::Zeroizing;

const VAULT_PASSPHRASE: &str = "ACT-vault-passphrase-52a1";
const APPROVAL_PASSPHRASE: &str = "ACT-approval-passphrase-7c4d";
const LISTENER: &str = "loopback";

static NEXT: AtomicU32 = AtomicU32::new(0);

/// A free loopback port: bound to find it, then released. A race with another process is possible but unlikely.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn socket_activate() -> Option<PathBuf> {
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
        .map(|dir| dir.join("systemd-socket-activate"))
        .find(|candidate| candidate.is_file())
}

/// A private tree with the XDG bases and a copy of the service binary, removed on drop. The copy is `0500` in a `0700`
/// directory, because a binary the build user's group can write (as cargo's umask often leaves it) is refused.
struct Install(PathBuf);

impl Install {
    fn new() -> Self {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("iv-act-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let install = Self(root);
        ["", "config", "state", "run"]
            .iter()
            .for_each(|name| chmod(&install.dir(name), 0o700));
        fs::copy(env!("CARGO_BIN_EXE_iron-vault"), install.binary()).unwrap();
        chmod(&install.binary(), 0o500);
        install
    }

    fn dir(&self, name: &str) -> PathBuf {
        let dir = self.0.join(name);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn binary(&self) -> PathBuf {
        self.0.join("iron-vault")
    }

    fn admin_socket(&self) -> PathBuf {
        self.0.join("run/iron-vault-dev/admin.sock")
    }

    fn log(&self) -> String {
        fs::read_to_string(self.0.join("serve.log")).unwrap_or_default()
    }
}

impl Drop for Install {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

/// `systemd-socket-activate` and the service it runs, in a process group of their own that is killed on drop, so a
/// failed assertion leaves nothing running.
struct Activated(Child);

impl Activated {
    /// Passes a listening socket on `passed`, named `fdname`, to `iron-vault serve`.
    fn start(install: &Install, activate: &Path, passed: SocketAddr, fdname: &str) -> Self {
        let log = fs::File::create(install.0.join("serve.log")).unwrap();
        // systemd-socket-activate passes the service only `LISTEN_*` and what `-E` names, not its own environment.
        let environment = [
            ("HOME", install.0.clone()),
            ("XDG_CONFIG_HOME", install.dir("config")),
            ("XDG_STATE_HOME", install.dir("state")),
            ("XDG_RUNTIME_DIR", install.dir("run")),
        ];
        let child = Command::new(activate)
            .arg("-l")
            .arg(passed.to_string())
            .arg(format!("--fdname={fdname}"))
            .args(environment.iter().map(|(name, path)| format!("-E{name}={}", path.display())))
            .arg(install.binary())
            .args(["serve", "--log-to-stdout"])
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .process_group(0)
            .spawn()
            .unwrap();
        Self(child)
    }
}

impl Drop for Activated {
    fn drop(&mut self) {
        let group = Pid::from_raw(i32::try_from(self.0.id()).unwrap()).unwrap();
        let _ = kill_process_group(group, Signal::KILL);
        let _ = self.0.wait();
    }
}

/// Polls until `done` holds, failing with `what` and the service's log after [`WAIT`].
fn wait_for(install: &Install, what: &str, done: impl Fn() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < WAIT, "timed out waiting for {what}; log:\n{}", install.log());
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Sends `request` to the service and answers its prompts in turn, ignoring the recovery key it reveals.
async fn exchange(install: &Install, request: AdminRequest, answers: &[&str]) -> AdminResponse {
    let mut stream = UnixStream::connect(install.admin_socket()).await.unwrap();
    send(&mut stream, &Frame::Request(request)).await;
    let mut answers = answers.iter();
    loop {
        match read_frame(&mut stream).await {
            Frame::Response(response) => return response,
            Frame::Prompt(_) => {
                let answer = answers.next().expect("a prompt beyond the answers given");
                send(
                    &mut stream,
                    &Frame::OwnerInput(OwnerInput::new(Zeroizing::new(answer.as_bytes().to_vec()))),
                )
                .await;
            }
            _ => {}
        }
    }
}

/// `init`, `unlock`, then approves a config whose one listener is `loopback` at `configured`.
async fn set_up(install: &Install, configured: SocketAddr) {
    wait_for(install, "the admin socket", || install.admin_socket().exists());
    let (vault, approval) = (VAULT_PASSPHRASE, APPROVAL_PASSPHRASE);
    let init = exchange(install, AdminRequest::Init, &[vault, vault, approval, approval, "yes"]).await;
    assert!(
        matches!(init, AdminResponse::Init { version: 1, .. }),
        "{init:?}\n{}",
        install.log()
    );
    let unlock = exchange(install, AdminRequest::Unlock, &[vault]).await;
    assert!(matches!(unlock, AdminResponse::Success), "{unlock:?}\n{}", install.log());
    let config = format!("schema_version = 1\n\n[listeners.{LISTENER}]\naddress = \"{configured}\"\n");
    let proposed = ProposedConfig::new(config.into_bytes()).unwrap();
    let approved = exchange(install, AdminRequest::ConfigApprove(proposed), &["yes", approval]).await;
    assert!(
        matches!(approved, AdminResponse::ConfigApprove { .. }),
        "{approved:?}\n{}",
        install.log()
    );
}

/// The status line of `GET /` sent to `address` with no caller token, or the error connecting.
fn status_line(address: SocketAddr, wait: Duration) -> std::io::Result<String> {
    let mut stream = TcpStream::connect_timeout(&address, WAIT)?;
    stream.set_read_timeout(Some(wait))?;
    stream.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut response = String::new();
    // The service may reset the connection after the response, which still leaves the status line read.
    let _ = stream.read_to_string(&mut response);
    Ok(response.lines().next().unwrap_or_default().to_owned())
}

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// Starts the service with a socket on `passed` named `fdname` and the config's listener at `configured`, or `None`
/// when this host cannot run the test.
async fn serve_configured(passed: SocketAddr, fdname: &str, configured: SocketAddr) -> Option<(Install, Activated)> {
    let Some(activate) = socket_activate() else {
        eprintln!("skipped: systemd-socket-activate is not on PATH");
        return None;
    };
    let install = Install::new();
    let service = Activated::start(&install, &activate, passed, fdname);
    // systemd-socket-activate, like a socket unit, starts the service on the first connection to the socket.
    wait_for(&install, "the socket to listen", || install.log().contains("Listening on"));
    drop(TcpStream::connect(passed).unwrap());
    wait_for(&install, "the service to start", || {
        install.log().contains("service started") || install.log().contains("refusing to start")
    });
    if install.log().contains("refusing to start") {
        assert!(
            std::env::var_os("CI").is_none(),
            "the build tree is not a trusted path in CI:\n{}",
            install.log()
        );
        eprintln!("skipped: the build tree is not a trusted path on this host:\n{}", install.log());
        return None;
    }
    set_up(&install, configured).await;
    Some((install, service))
}

#[tokio::test]
async fn a_passed_socket_named_for_its_listener_serves_requests() {
    let address = loopback(free_port());
    let Some((install, _service)) = serve_configured(address, LISTENER, address).await else {
        return;
    };
    let status = status_line(address, WAIT).unwrap();
    assert!(status.contains(" 401 "), "{status}\n{}", install.log());
}

#[tokio::test]
async fn a_passed_socket_on_another_port_is_refused_and_the_listener_stays_unavailable() {
    let (passed, configured) = (loopback(free_port()), loopback(free_port()));
    let Some((install, _service)) = serve_configured(passed, LISTENER, configured).await else {
        return;
    };
    wait_for(&install, "the mismatch to be logged", || install.log().contains("is bound to"));
    assert!(
        status_line(configured, WAIT).is_err(),
        "the configured address answers\n{}",
        install.log()
    );
    assert!(
        install.log().contains(&format!("config says TCP {configured}")),
        "{}",
        install.log()
    );
}

/// In a development build a listener no passed socket is named for binds its configured address itself (`check_origin` refuses
/// that only for TCP in a protected install), so the listener is available; what the test checks is that the socket
/// passed under another name is never adopted.
#[tokio::test]
async fn a_passed_socket_named_for_no_listener_is_not_adopted() {
    let (passed, configured) = (loopback(free_port()), loopback(free_port()));
    let Some((install, _service)) = serve_configured(passed, "elsewhere", configured).await else {
        return;
    };
    let own = status_line(configured, WAIT).unwrap();
    assert!(own.contains(" 401 "), "{own}\n{}", install.log());
    let unserved = status_line(passed, Duration::from_secs(1)).unwrap();
    assert!(
        unserved.is_empty(),
        "the unmatched passed socket answered: {unserved}\n{}",
        install.log()
    );
}
