// SPDX-License-Identifier: MPL-2.0
//! Bundle data frames over the admin server's exchange (`design/migration-bundle.md`, "Transfer"): the service sends a
//! bundle and receives one, and each frame and the whole transfer have a deadline.

#![cfg(target_os = "linux")]

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iron_vault::admin::dispatch::{AdminHandler, HandlerFuture, Handlers};
use iron_vault::admin::principal::{AdminPrincipal, AdminPrincipals};
use iron_vault::admin::protocol::{self, AdminCommand, AdminRequest, AdminResponse, BundleChunk, Decoded, ErrorCode, Frame, MAX_BODY_LEN};
use iron_vault::admin::server::{AdminServer, Exchange, ExchangeError, Limits};
use iron_vault::deployment::DeploymentProfile;
use iron_vault::path_metadata::invoking_user;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// How long a test waits for anything the server should do promptly.
const PATIENCE: Duration = Duration::from_secs(5);

/// What a handler reports: the bundle bytes it received, or the `Debug` form of the exchange error that ended it.
type Outcome = Result<Vec<u8>, String>;

/// The test command, registered for `ping`: it sends `chunks` and then the end of the bundle.
struct Sending {
    chunks: Vec<Vec<u8>>,
    outcome: mpsc::UnboundedSender<Outcome>,
}

impl AdminHandler for Sending {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, _request: AdminRequest, exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        Box::pin(async move {
            let mut sent = Ok(());
            for chunk in self.chunks.iter().map(Vec::as_slice).chain([&[][..]]) {
                sent = exchange.send_bundle_chunk(chunk).await;
                if sent.is_err() {
                    break;
                }
            }
            let _ = self.outcome.send(sent.as_ref().map(|()| Vec::new()).map_err(|e| format!("{e:?}")));
            sent.map(|()| AdminResponse::Success)
        })
    }
}

/// The test command, registered for `ping`: it receives bundle data frames up to the empty one.
struct Receiving(mpsc::UnboundedSender<Outcome>);

impl AdminHandler for Receiving {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, _request: AdminRequest, exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        Box::pin(async move {
            let mut bundle = Vec::new();
            let received = loop {
                match exchange.receive_bundle_chunk().await {
                    Ok(chunk) if chunk.is_end() => break Ok(bundle),
                    Ok(chunk) => bundle.extend_from_slice(chunk.bytes()),
                    Err(e) => break Err(e),
                }
            };
            let _ = self.0.send(received.as_ref().map(Clone::clone).map_err(|e| format!("{e:?}")));
            received.map(|_| AdminResponse::Success)
        })
    }
}

/// Serves one connection with `handler` under `limits`; returns the CLI's end and the served connection.
fn serve(handler: impl AdminHandler + 'static, limits: Limits) -> (UnixStream, JoinHandle<()>) {
    let me = invoking_user().unwrap();
    let handlers = Handlers::default().with(AdminCommand::Ping, handler);
    let server = AdminServer::new(AdminPrincipals::new(DeploymentProfile::Development, me.uid), handlers, limits);
    let (ours, theirs) = UnixStream::pair().unwrap();
    (theirs, tokio::spawn(async move { server.serve_connection(ours).await }))
}

fn frame_bytes(frame: &Frame) -> Vec<u8> {
    let mut out = Vec::new();
    protocol::encode(frame, &mut out).unwrap();
    out
}

fn chunk_bytes(bytes: &[u8]) -> Vec<u8> {
    frame_bytes(&Frame::BundleData(BundleChunk::new(bytes.to_vec()).unwrap()))
}

async fn send_ping(cli: &mut UnixStream) {
    cli.write_all(&frame_bytes(&Frame::Request(AdminRequest::Ping))).await.unwrap();
}

/// Reads one frame, stopping at its end.
async fn read_frame(stream: &mut UnixStream) -> Frame {
    let read = async {
        let mut bytes = Vec::new();
        loop {
            match protocol::decode(&bytes).unwrap() {
                Decoded::Frame { frame, .. } => return frame,
                Decoded::NeedMore(n) => {
                    let mut more = vec![0; n];
                    let read = stream.read(&mut more).await.unwrap();
                    assert_ne!(read, 0, "connection closed after {} bytes", bytes.len());
                    bytes.extend_from_slice(more.get(..read).unwrap());
                }
            }
        }
    };
    tokio::time::timeout(PATIENCE, read).await.expect("a frame arrives")
}

async fn outcome(received: &mut mpsc::UnboundedReceiver<Outcome>) -> Outcome {
    tokio::time::timeout(PATIENCE, received.recv()).await.unwrap().unwrap()
}

/// A bundle of three frames: a full one, a short one and a single byte.
fn bundle_chunks() -> Vec<Vec<u8>> {
    vec![vec![1; MAX_BODY_LEN], vec![2; 100], vec![3]]
}

#[tokio::test]
async fn the_service_sends_a_bundle_the_cli_receives_whole() {
    let (outcomes, mut received) = mpsc::unbounded_channel();
    let chunks = bundle_chunks();
    let (mut cli, served) = serve(
        Sending {
            chunks: chunks.clone(),
            outcome: outcomes,
        },
        Limits::default(),
    );
    send_ping(&mut cli).await;
    let mut bundle = Vec::new();
    loop {
        match read_frame(&mut cli).await {
            Frame::BundleData(chunk) if chunk.is_end() => break,
            Frame::BundleData(chunk) => bundle.extend_from_slice(chunk.bytes()),
            other => panic!("expected a bundle data frame, got {other:?}"),
        }
    }
    assert_eq!(bundle, chunks.concat());
    assert!(matches!(read_frame(&mut cli).await, Frame::Response(AdminResponse::Success)));
    assert_eq!(outcome(&mut received).await, Ok(Vec::new()));
    served.await.unwrap();
}

#[tokio::test]
async fn the_service_receives_a_bundle_the_cli_sends() {
    let (outcomes, mut received) = mpsc::unbounded_channel();
    let (mut cli, served) = serve(Receiving(outcomes), Limits::default());
    send_ping(&mut cli).await;
    let chunks = bundle_chunks();
    for frame in chunks.iter().map(|chunk| chunk_bytes(chunk)).chain([chunk_bytes(&[])]) {
        cli.write_all(&frame).await.unwrap();
    }
    assert_eq!(outcome(&mut received).await, Ok(chunks.concat()));
    assert!(matches!(read_frame(&mut cli).await, Frame::Response(AdminResponse::Success)));
    served.await.unwrap();
}

#[tokio::test]
async fn a_cli_that_stalls_between_frames_misses_the_frame_deadline() {
    let (outcomes, mut received) = mpsc::unbounded_channel();
    let limits = Limits {
        request_deadline: Duration::from_millis(150),
        ..Limits::default()
    };
    let (mut cli, served) = serve(Receiving(outcomes), limits);
    send_ping(&mut cli).await;
    cli.write_all(&chunk_bytes(b"first")).await.unwrap();
    assert_eq!(outcome(&mut received).await, Err(format!("{:?}", ExchangeError::TimedOut)));
    served.await.unwrap();
}

#[tokio::test]
async fn a_cli_that_trickles_frames_misses_the_transfer_deadline() {
    let (outcomes, mut received) = mpsc::unbounded_channel();
    let limits = Limits {
        request_deadline: Duration::from_millis(300),
        transfer_deadline: Duration::from_millis(500),
        ..Limits::default()
    };
    let (mut cli, served) = serve(Receiving(outcomes), limits);
    send_ping(&mut cli).await;
    let trickle = async {
        loop {
            if cli.write_all(&chunk_bytes(b"x")).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    // A failed write means the service closed the socket at its deadline, and its outcome may not have reached the channel
    // yet (or `select!` may poll the trickle first), so the outcome is awaited afterwards rather than raced.
    let ended = tokio::select! {
        ended = outcome(&mut received) => ended,
        () = trickle => outcome(&mut received).await,
    };
    assert_eq!(ended, Err(format!("{:?}", ExchangeError::TransferTimedOut)));
    served.await.unwrap();
}

#[tokio::test]
async fn a_cli_that_stops_reading_misses_the_frame_deadline_and_then_the_transfer_deadline() {
    let big = vec![vec![7; MAX_BODY_LEN]; 64];
    for (request, transfer, expected) in [
        (150, 60_000, ExchangeError::TimedOut),
        (60_000, 150, ExchangeError::TransferTimedOut),
    ] {
        let (outcomes, mut received) = mpsc::unbounded_channel();
        let limits = Limits {
            request_deadline: Duration::from_millis(request),
            transfer_deadline: Duration::from_millis(transfer),
            ..Limits::default()
        };
        let (mut cli, served) = serve(
            Sending {
                chunks: big.clone(),
                outcome: outcomes,
            },
            limits,
        );
        send_ping(&mut cli).await;
        assert_eq!(outcome(&mut received).await, Err(format!("{expected:?}")));
        served.await.unwrap();
    }
}

#[tokio::test]
async fn a_cli_that_closes_before_the_end_of_the_bundle_is_a_closed_peer() {
    let (outcomes, mut received) = mpsc::unbounded_channel();
    let (mut cli, served) = serve(Receiving(outcomes), Limits::default());
    send_ping(&mut cli).await;
    cli.write_all(&chunk_bytes(b"first")).await.unwrap();
    cli.shutdown().await.unwrap();
    assert_eq!(outcome(&mut received).await, Err(format!("{:?}", ExchangeError::Closed)));
    served.await.unwrap();
}

#[tokio::test]
async fn a_frame_other_than_bundle_data_mid_bundle_is_out_of_turn() {
    let (outcomes, mut received) = mpsc::unbounded_channel();
    let (mut cli, served) = serve(Receiving(outcomes), Limits::default());
    send_ping(&mut cli).await;
    cli.write_all(&chunk_bytes(b"first")).await.unwrap();
    cli.write_all(&frame_bytes(&Frame::Switch)).await.unwrap();
    assert_eq!(outcome(&mut received).await, Err(format!("{:?}", ExchangeError::Unexpected)));
    served.await.unwrap();
}

/// The test command, registered for `ping`: it sends `chunks` pausing `pause` before the second, reports how the sends
/// ended, and answers `export-failed` (or success) whatever happened, as an `export` handler would.
struct Pausing {
    chunks: Vec<Vec<u8>>,
    pause: Duration,
    outcome: mpsc::UnboundedSender<Outcome>,
}

impl AdminHandler for Pausing {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, _request: AdminRequest, exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        Box::pin(async move {
            let mut sent = Ok(());
            for (n, chunk) in self.chunks.iter().enumerate() {
                if n == 1 {
                    tokio::time::sleep(self.pause).await;
                }
                sent = exchange.send_bundle_chunk(chunk).await;
                if sent.is_err() {
                    break;
                }
            }
            let _ = self.outcome.send(sent.as_ref().map(|()| Vec::new()).map_err(|e| format!("{e:?}")));
            Ok(match sent {
                Ok(()) => AdminResponse::Success,
                Err(e) => AdminResponse::Error {
                    code: ErrorCode::ExportFailed,
                    message: format!("{e}"),
                },
            })
        })
    }
}

#[tokio::test]
async fn a_transfer_deadline_that_passed_between_frames_is_noticed_before_any_byte_moves() {
    let (outcomes, mut received) = mpsc::unbounded_channel();
    let limits = Limits {
        transfer_deadline: Duration::from_millis(100),
        ..Limits::default()
    };
    let (mut cli, served) = serve(
        Pausing {
            chunks: vec![vec![1; 10], vec![2; 10]],
            pause: Duration::from_millis(300),
            outcome: outcomes,
        },
        limits,
    );
    send_ping(&mut cli).await;
    assert_eq!(outcome(&mut received).await, Err(format!("{:?}", ExchangeError::TransferTimedOut)));
    // The first frame arrived whole, the second never started, and the response is readable right after the first frame.
    assert!(matches!(read_frame(&mut cli).await, Frame::BundleData(chunk) if chunk.bytes() == [1; 10]));
    assert!(matches!(
        read_frame(&mut cli).await,
        Frame::Response(AdminResponse::Error {
            code: ErrorCode::ExportFailed,
            ..
        })
    ));
    served.await.unwrap();
}

/// Log lines, shared with the subscriber that records them.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn a_frame_write_cut_off_by_its_deadline_leaves_no_response_behind_it() {
    let logs = Captured::default();
    let writer = logs.clone();
    let _logging = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish(),
    );
    let (outcomes, mut received) = mpsc::unbounded_channel();
    let limits = Limits {
        request_deadline: Duration::from_millis(150),
        ..Limits::default()
    };
    let (mut cli, served) = serve(
        Pausing {
            chunks: vec![vec![7; MAX_BODY_LEN]; 64],
            pause: Duration::ZERO,
            outcome: outcomes,
        },
        limits,
    );
    send_ping(&mut cli).await;
    assert_eq!(outcome(&mut received).await, Err(format!("{:?}", ExchangeError::TimedOut)));
    served.await.unwrap();
    let logged = String::from_utf8_lossy(&logs.0.lock().unwrap()).into_owned();
    assert!(logged.contains("response was not sent"), "{logged}");
    // The service closed: the CLI reads to the end of the stream, and every byte of it belongs to bundle data frames,
    // the last of them cut off part-way.
    let mut rest = Vec::new();
    tokio::time::timeout(PATIENCE, cli.read_to_end(&mut rest)).await.unwrap().unwrap();
    let mut bytes = rest.as_slice();
    while let Ok(Decoded::Frame { frame, used }) = protocol::decode(bytes) {
        assert!(matches!(frame, Frame::BundleData(_)), "{frame:?}");
        bytes = &bytes[used..];
    }
    assert!(
        matches!(protocol::decode(bytes), Ok(Decoded::NeedMore(_))),
        "{} bytes left over",
        bytes.len()
    );
}
