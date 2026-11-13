// SPDX-License-Identifier: MPL-2.0
//! An HTTP/2 server that refuses every request before processing it, written in raw frames.
//!
//! `h2`'s server cannot do this: it counts a stream as processed as soon as its HEADERS frame is read, so any GOAWAY it
//! sends after a request arrives names that stream as processed. This server reads frames itself and answers each
//! request's HEADERS with a refusal that RFC 9113 §8.7 says the server never acted on, which is what reqwest's default
//! retry policy treats as safe to re-send.

use std::sync::atomic::{AtomicUsize, Ordering};

use h2::Reason;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The HTTP/2 connection preface a client sends before its first frame (RFC 9113 §3.4).
const PREFACE_LEN: usize = 24;
const FRAME_HEADER_LEN: usize = 9;
const HEADERS: u8 = 0x1;
const RST_STREAM: u8 = 0x3;
const SETTINGS: u8 = 0x4;
const GOAWAY: u8 = 0x7;
const ACK: u8 = 0x1;

/// How the server refuses each request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// `RST_STREAM` with `REFUSED_STREAM` on the request's stream (RFC 9113 §8.7).
    RefusedStream,
    /// `GOAWAY` with `NO_ERROR` and last-stream-id 0, below every request stream, so none was processed (RFC 9113 §6.8).
    GoAwayUnprocessed,
}

/// One frame's type, flags and stream; its payload is read and dropped.
struct FrameHeader {
    kind: u8,
    flags: u8,
    stream: u32,
}

/// Serves `stream` until the client closes it, refusing every request and counting each request head in `heads`.
pub async fn refuse<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, refusal: Refusal, heads: &AtomicUsize) {
    let mut preface = [0; PREFACE_LEN];
    if stream.read_exact(&mut preface).await.is_err() || send(&mut stream, frame(SETTINGS, 0, 0, &[])).await.is_err() {
        return;
    }
    while let Some(header) = next_frame(&mut stream).await {
        let Some(answer) = answer(&header, refusal) else {
            continue;
        };
        if header.kind == HEADERS {
            heads.fetch_add(1, Ordering::SeqCst);
        }
        if send(&mut stream, answer).await.is_err() {
            return;
        }
    }
}

/// What the server writes back for `header`: an ack for the client's settings, the refusal for a request, or nothing.
fn answer(header: &FrameHeader, refusal: Refusal) -> Option<Vec<u8>> {
    match header.kind {
        SETTINGS if header.flags & ACK == 0 => Some(frame(SETTINGS, ACK, 0, &[])),
        HEADERS => Some(refusal_frame(refusal, header.stream)),
        _ => None,
    }
}

fn refusal_frame(refusal: Refusal, stream: u32) -> Vec<u8> {
    match refusal {
        Refusal::RefusedStream => frame(RST_STREAM, 0, stream, &code(Reason::REFUSED_STREAM)),
        Refusal::GoAwayUnprocessed => frame(GOAWAY, 0, 0, &[[0; 4], code(Reason::NO_ERROR)].concat()),
    }
}

fn code(reason: Reason) -> [u8; 4] {
    u32::from(reason).to_be_bytes()
}

/// One frame: 24-bit length, type, flags, 31-bit stream identifier, payload (RFC 9113 §4.1).
fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let length = u32::try_from(payload.len()).unwrap().to_be_bytes();
    [&length[1..], &[kind, flags], &stream.to_be_bytes(), payload].concat()
}

/// Reads the next frame, or `None` once the client has closed the connection.
async fn next_frame<S: AsyncRead + Unpin>(stream: &mut S) -> Option<FrameHeader> {
    let mut header = [0; FRAME_HEADER_LEN];
    stream.read_exact(&mut header).await.ok()?;
    let length = u32::from_be_bytes([0, header[0], header[1], header[2]]);
    let mut payload = vec![0; usize::try_from(length).unwrap()];
    stream.read_exact(&mut payload).await.ok()?;
    Some(FrameHeader {
        kind: header[3],
        flags: header[4],
        stream: u32::from_be_bytes([header[5], header[6], header[7], header[8]]) & 0x7fff_ffff,
    })
}

async fn send<S: AsyncWrite + Unpin>(stream: &mut S, bytes: Vec<u8>) -> std::io::Result<()> {
    stream.write_all(&bytes).await?;
    stream.flush().await
}
