// SPDX-License-Identifier: MPL-2.0
//! Relays an upstream response to the caller ([spec §8][s8] step 10, [§11][s11]): its status, its headers without
//! connection-scoped or caller-authentication headers and scrubbed, and its body decoded, scrubbed and, when the caller
//! requires it, re-encoded chunk by chunk.
//!
//! Every response passes through the scrubber with the scrub patterns of the credential injected for its request; no
//! path relays a response without it. A response the scrubber cannot see through, because its content coding is not
//! one the service decodes or a transfer coding besides `chunked` hides the bytes, is refused with `502` before
//! anything is sent ([§11][s11]: no coding is forwarded opaquely). The order of the stages is set out once, on
//! [`RelayedBody`]:
//!
//! ```text
//! upstream head ─► coding check ─► strip headers ─► rewrite Location ─► scrub headers ─► describe emitted body ─► caller
//!                  (502 if unscreenable)            (502 if refused)
//!
//! upstream chunk ─► decode ─► decompression budget ─► scrub ─► encode, if the caller rules identity out ─► caller
//!                   (each piece counted before it is scrubbed; any failure aborts the caller's connection)
//! ```
//!
//! [s8]: ../../../../design/iron-vault-specification.md#8-request-flow
//! [s11]: ../../../../design/iron-vault-specification.md#11-responses-redirects-and-scrubbing

use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Bytes, BytesMut};
use futures_core::Stream;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame};
use hyper::header::{CONNECTION, HeaderMap, HeaderName as HttpHeaderName, HeaderValue as HttpHeaderValue, LOCATION, TRANSFER_ENCODING};
use hyper::{Response, StatusCode};
use iron_vault_kinds::ScrubPatterns;
use iron_vault_policy::reserved_headers::HOP_BY_HOP_HEADERS;
use iron_vault_policy::{HeaderName, Limits, LocationRewrite, Method, RouteConfig, rewrite_location};
use url::Url;

use crate::audit::{ReasonCode, RequestFacts, count_of};
use crate::content_coding::{
    BudgetExceeded, ContentCoding, DecodeError, DecompressionBudget, EncodeError, ResponseDecoder, ResponseEncoder, choose_emitted,
    parse_content_encoding, rewrite_headers,
};
use crate::pipeline::RefusalResponse;
use crate::request_server::{BoxError, ResponseBody, has_no_body};
use crate::scrub::{Scrubber, scrub_headers};
use crate::upstream::client::{ResponseChunks, UpstreamResponse};

/// What the response stage takes from the request the pipeline accepted.
pub(crate) struct ResponseContext {
    /// The request's method: a `HEAD` response has no body.
    pub(crate) method: Method,
    /// The forms of the injected secret to scrub; the response body owns them until it ends.
    pub(crate) patterns: ScrubPatterns,
    /// Where the response's refusal or failure reason and its scrub matches are recorded, for the request event.
    pub(crate) facts: RequestFacts,
    /// The caller's own `Accept-Encoding`, which was never forwarded, for choosing the coding the caller gets.
    pub(crate) accept_encoding: Option<HttpHeaderValue>,
    /// The operational limits, for the decompression budget.
    pub(crate) limits: Limits,
}

/// Builds the caller's response for `upstream`: the upstream's status, its headers less those [`strip_headers`] removes, with
/// `Location` rewritten, then scrubbed, then rewritten to describe the emitted body, and its body as a [`RelayedBody`].
/// `token_header` is the caller-token header of the listener the request arrived on. `route` and `request_url` (the URL
/// actually sent, which may hold the secret) decide the `Location`. A response whose coding the service cannot screen,
/// or a `Location` that must not reach the caller, is refused with `502` and its body dropped unread; the refusal's
/// reason is recorded in the context's facts.
pub(super) fn relay(
    upstream: UpstreamResponse,
    token_header: Option<HeaderName>,
    context: ResponseContext,
    route: &RouteConfig,
    request_url: &Url,
) -> Result<Response<ResponseBody>, RefusalResponse> {
    let (status, mut headers, chunks) = upstream.into_parts();
    let refused = |reason| {
        context.facts.refuse(reason);
        RefusalResponse::fixed(StatusCode::BAD_GATEWAY.as_u16())
    };
    let coding = upstream_coding(&headers, status).map_err(|Unscreenable| refused(ReasonCode::UnsupportedCoding))?;
    strip_headers(&mut headers, token_header.as_ref());
    rewrite_location_header(&mut headers, route, request_url).map_err(|RedirectRefused| refused(ReasonCode::RedirectRefused))?;
    let header_matches = scrub_headers(&mut headers, &context.patterns);
    let emitted = choose_emitted(context.accept_encoding.as_ref());
    // A scrub may replace bytes, so a scrubbed body is changed even when no coding is: its length and integrity headers
    // could no longer be trusted, and its strong `ETag` no longer promises byte identity.
    let body_changed = coding.is_some() || emitted.is_some() || !context.patterns.is_empty();
    // A response with no body gets the headers its `GET` would, so `Content-Encoding` and `Content-Length` describe that
    // body; with nothing to decode or encode it needs neither a decoder nor an encoder.
    rewrite_headers(&mut headers, emitted, body_changed);
    let codings = match has_no_body(context.method == Method::Head, status) {
        true => BodyCodings::default(),
        false => BodyCodings { upstream: coding, emitted },
    };
    Ok(response(
        status,
        headers,
        RelayedBody::new(chunks, context, codings, header_matches),
    ))
}

/// The upstream applied a coding the scrubber cannot see through.
struct Unscreenable;

/// The upstream's `Location` must not reach the caller.
struct RedirectRefused;

/// Returns the coding the upstream applied to the body, or [`Unscreenable`] when the scrubber could not see through it: a content coding
/// [`parse_content_encoding`] refuses, a transfer coding besides `chunked` (the only one hyper removes, so `gzip, chunked`
/// would reach the scrubber still coded), or a coded `206`.
///
/// Judged before stripping, which drops `Transfer-Encoding` and every header `Connection` names, `Content-Encoding`
/// included: a coding hidden that way would still be in the body.
fn upstream_coding(headers: &HeaderMap, status: StatusCode) -> Result<Option<ContentCoding>, Unscreenable> {
    if !transfer_codings(headers).all(|coding| coding.eq_ignore_ascii_case(b"chunked")) {
        return Err(Unscreenable);
    }
    let coding = parse_content_encoding(headers).map_err(|_| Unscreenable)?;
    // A byte range of a coded body starts mid-stream, without the coding's header and the window state before it, so it
    // cannot be decoded on its own and the scrubber could not screen it.
    if status == StatusCode::PARTIAL_CONTENT && coding.is_some() {
        return Err(Unscreenable);
    }
    Ok(coding)
}

/// Applies [`rewrite_location`] to the response's `Location`, on any status. Several `Location` headers are ambiguous
/// and refused like an out-of-base one.
fn rewrite_location_header(headers: &mut HeaderMap, route: &RouteConfig, request_url: &Url) -> Result<(), RedirectRefused> {
    let mut values = headers.get_all(LOCATION).iter();
    let Some(location) = values.next() else {
        return Ok(());
    };
    if values.next().is_some() {
        return Err(RedirectRefused);
    }
    match rewrite_location(route, request_url, location.as_bytes()) {
        LocationRewrite::PassThrough => Ok(()),
        LocationRewrite::Refused(_) => Err(RedirectRefused),
        LocationRewrite::Rewritten(value) => {
            let value = HttpHeaderValue::from_bytes(value.as_bytes()).map_err(|_| RedirectRefused)?;
            headers.insert(LOCATION, value);
            Ok(())
        }
    }
}

/// Removes the headers that must not reach the caller: the hop-by-hop headers and every header a `Connection` header
/// names, which describe the upstream connection only, and the caller-authentication headers, which an upstream may
/// echo back: `Proxy-Authenticate` and `Proxy-Authorization` (both hop-by-hop) and the listener's token header.
fn strip_headers(headers: &mut HeaderMap, token_header: Option<&HeaderName>) {
    let named: Vec<HttpHeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .flat_map(|value| value.as_bytes().split(|b| *b == b','))
        .filter_map(|member| HttpHeaderName::from_bytes(member.trim_ascii()).ok())
        .collect();
    named.iter().for_each(|name| {
        headers.remove(name);
    });
    HOP_BY_HOP_HEADERS
        .iter()
        .copied()
        .chain(token_header.map(HeaderName::lowercase))
        .for_each(|name| {
            headers.remove(name);
        });
}

/// Lists every transfer coding the `Transfer-Encoding` headers name, trimmed, with empty list members skipped.
fn transfer_codings(headers: &HeaderMap) -> impl Iterator<Item = &[u8]> {
    headers
        .get_all(TRANSFER_ENCODING)
        .into_iter()
        .flat_map(|value| value.as_bytes().split(|b| *b == b','))
        .map(<[u8]>::trim_ascii)
        .filter(|coding| !coding.is_empty())
}

fn response(status: StatusCode, headers: HeaderMap, body: RelayedBody) -> Response<ResponseBody> {
    let mut response = Response::new(body.map_err(BoxError::from).boxed_unsync());
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

/// What the response stage knows about a response once it has ended cleanly, for the request event
/// ([audit logging: Request event](../../../../design/audit-logging.md#request-event)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseOutcome {
    /// `true` if and only if a scrub pattern matched in the response's headers or body.
    pub scrubbed: bool,
    /// The bytes the scrubber screened: the body after decoding, or as received when it had no content coding.
    pub decoded_bytes: u64,
}

/// Why a relayed body failed after its head was sent. Each names only the kind of failure, never a byte or the URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RelayFailure {
    /// The body is not valid for its content coding, or continues after the coded stream ended.
    #[error("corrupt")]
    Corrupt,
    /// The body ended before its coded stream did.
    #[error("truncated")]
    Truncated,
    /// The decoded body passed `max_decompressed_response_bytes`.
    #[error("size limit")]
    SizeLimit,
    /// The decoded body grew faster than `max_decompression_ratio` allows.
    #[error("ratio limit")]
    RatioLimit,
    /// The scrubbed body could not be re-encoded.
    #[error("encode error")]
    Encode,
    /// The upstream body stopped before its end.
    #[error("upstream body error")]
    Upstream,
}

impl From<DecodeError> for RelayFailure {
    fn from(error: DecodeError) -> Self {
        match error {
            DecodeError::Truncated => Self::Truncated,
            DecodeError::Corrupt | DecodeError::TrailingData | DecodeError::Abandoned => Self::Corrupt,
        }
    }
}

impl From<EncodeError> for RelayFailure {
    fn from(_: EncodeError) -> Self {
        Self::Encode
    }
}

impl From<BudgetExceeded> for RelayFailure {
    fn from(error: BudgetExceeded) -> Self {
        match error {
            BudgetExceeded::TooLarge { .. } => Self::SizeLimit,
            BudgetExceeded::RatioExceeded { .. } => Self::RatioLimit,
        }
    }
}

/// The codings around the scrubber: the one to decode from, and the one to encode into. Both are `None` for identity,
/// and for a response with no body, which has nothing to decode or encode.
#[derive(Debug, Clone, Copy, Default)]
struct BodyCodings {
    upstream: Option<ContentCoding>,
    emitted: Option<ContentCoding>,
}

/// An upstream response body on its way to the caller, each chunk passed through the body stages and on as it arrives,
/// never buffered to the end. Only bytes that could still begin a secret are held back between chunks.
///
/// The response stages run in this order, each on what the one before left:
///
/// - headers: coding check, header stripping, `Location` rewrite, header scrub, content-coding header rewrite. The
///   rewrite precedes the scrub so the scrub covers a `Location` passed through or rewritten, and the rewrite never
///   parses scrub replacement text;
/// - body: decode, then the [decompression budget](DecompressionBudget) per decoded piece, then scrub, then encode when
///   the caller's `Accept-Encoding` rules identity out. Decoding first lets the scrubber see the plaintext; encoding last
///   means nothing the scrubber has not screened is ever compressed into the output.
///
/// It owns the request's scrub patterns: they, the held bytes and the decoder's window are wiped when the body ends,
/// fails or is dropped.
///
/// A failure is returned as an error, never as the end of the body: a decode error, a truncated coded stream, an
/// exceeded budget or an upstream body error. The held bytes are dropped unreleased, since they may be a secret prefix,
/// the failure's [kind](RelayFailure) is recorded as the request's reason, and the request server's HTTP stack aborts
/// the caller's connection instead of finishing the response, so a cut-off body never looks complete.
///
/// It records its running match count in the request's facts after every poll, so the request record, which writes the
/// scrub event, sees every match screened before the body ended, failed or was dropped.
pub struct RelayedBody {
    chunks: ResponseChunks,
    /// `None` once the body has ended or failed, so the patterns are gone with the response.
    stages: Option<Stages>,
    facts: RequestFacts,
    /// Matches replaced in the headers, and in the body once the stages are gone.
    matches: u64,
    /// The match total last told to the request record, so it is told again only when it grows.
    reported: u64,
    /// Bytes the scrubber screened, once the body has ended.
    decoded: u64,
    ended: bool,
}

/// The body stages of one response.
struct Stages {
    /// `None` for an identity body.
    decoder: Option<ResponseDecoder>,
    /// An identity body's chunk not yet taken, which is one piece.
    identity: Option<Bytes>,
    budget: DecompressionBudget,
    /// Compressed bytes fed and not yet recorded; they are recorded with the chunk's first piece, or alone if it has none.
    compressed: u64,
    scrubber: Scrubber<'static>,
    /// `None` unless the caller is sent a coding.
    encoder: Option<ResponseEncoder>,
}

impl Stages {
    fn new(patterns: ScrubPatterns, limits: &Limits, codings: BodyCodings) -> Self {
        let budget = match codings.upstream {
            Some(_) => DecompressionBudget::new(limits),
            None => DecompressionBudget::identity(limits),
        };
        Self {
            decoder: codings.upstream.map(ResponseDecoder::new),
            identity: None,
            budget,
            compressed: 0,
            scrubber: Scrubber::owning(patterns),
            encoder: codings.emitted.map(ResponseEncoder::new),
        }
    }

    /// Takes the next upstream chunk. Nothing is decoded until [`next_output`](Self::next_output) pulls it, and the
    /// previous chunk must have been pulled to its end.
    fn feed(&mut self, chunk: Bytes) {
        match self.decoder.as_mut() {
            Some(decoder) => {
                self.compressed = count_of(chunk.len());
                decoder.feed(chunk);
            }
            None => self.identity = Some(chunk),
        }
    }

    /// Runs the fed chunk's next piece through the stages and returns the bytes to send now. `None` means the chunk is
    /// used up and the next one is wanted.
    ///
    /// One piece is held at a time, so a chunk that decodes to many pieces is never in memory whole: each piece is counted
    /// before it is scrubbed, and the first over the budget fails the body. A piece the scrubber holds back whole sends
    /// nothing, and the next is taken.
    fn next_output(&mut self) -> Result<Option<Bytes>, RelayFailure> {
        while let Some(piece) = self.next_piece()? {
            self.budget.record(std::mem::take(&mut self.compressed), count_of(piece.len()))?;
            let scrubbed = self.scrubber.push(&piece);
            let out = self.encode(scrubbed)?;
            if !out.is_empty() {
                return Ok(Some(out));
            }
        }
        self.budget.record(std::mem::take(&mut self.compressed), 0)?;
        Ok(None)
    }

    /// Takes the fed chunk's next decoded piece, or the whole chunk for an identity body.
    fn next_piece(&mut self) -> Result<Option<Bytes>, RelayFailure> {
        match self.decoder.as_mut() {
            Some(decoder) => Ok(decoder.next_piece().transpose()?),
            None => Ok(self.identity.take()),
        }
    }

    fn encode(&mut self, scrubbed: Bytes) -> Result<Bytes, RelayFailure> {
        match self.encoder.as_mut() {
            None => Ok(scrubbed),
            Some(encoder) => Ok(encoder.push(&scrubbed)?),
        }
    }
}

impl RelayedBody {
    fn new(chunks: ResponseChunks, context: ResponseContext, codings: BodyCodings, header_matches: u64) -> Self {
        context.facts.scrub_matches(header_matches);
        Self {
            chunks,
            stages: Some(Stages::new(context.patterns, &context.limits, codings)),
            facts: context.facts,
            matches: header_matches,
            reported: header_matches,
            decoded: 0,
            ended: false,
        }
    }

    /// Returns the outcome once the body has ended cleanly; `None` before then or after a failure.
    pub fn outcome(&self) -> Option<ResponseOutcome> {
        self.ended.then_some(ResponseOutcome {
            scrubbed: self.matches > 0,
            decoded_bytes: self.decoded,
        })
    }

    /// Tells the request record the running match total, when it differs from the last report.
    fn report_matches(&mut self) {
        let total = self.total_matches();
        if total != self.reported {
            self.reported = total;
            self.facts.scrub_matches(total);
        }
    }

    /// Counts every match replaced so far, in the headers and the body.
    fn total_matches(&self) -> u64 {
        self.matches + self.stages.as_ref().map_or(0, |stages| stages.scrubber.matches())
    }

    /// Ends the body in stage order: the decoder must have reached the end of its coded stream, then the scrubber
    /// releases its held bytes, then the encoder writes its trailer. Returns the bytes left to send, which may be none.
    fn end(&mut self) -> Result<Bytes, RelayFailure> {
        // On failure the stages are kept, so `fail` drops the scrubber unfinished.
        if let Some(decoder) = self.stages.as_mut().and_then(|stages| stages.decoder.take()) {
            decoder.finish()?;
        }
        let Some(Stages {
            scrubber, encoder, budget, ..
        }) = self.stages.take()
        else {
            return Ok(Bytes::new());
        };
        let finished = scrubber.finish();
        self.matches += finished.matches;
        let tail = match encoder {
            None => finished.tail,
            Some(mut encoder) => {
                let mut out = BytesMut::from(encoder.push(&finished.tail)?.as_ref());
                out.extend_from_slice(&encoder.finish()?);
                out.freeze()
            }
        };
        self.decoded = budget.decoded();
        self.ended = true;
        Ok(tail)
    }

    /// Polls the next upstream frame and passes it through the body stages.
    fn poll_stages(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, RelayFailure>>> {
        loop {
            let Some(stages) = self.stages.as_mut() else {
                return Poll::Ready(None);
            };
            // The fed chunk's pieces go out one frame at a time before the next chunk is read.
            match stages.next_output() {
                Err(failure) => return Poll::Ready(Some(Err(self.fail(failure)))),
                Ok(Some(out)) => return Poll::Ready(Some(Ok(Frame::data(out)))),
                Ok(None) => {}
            }
            let out = match ready!(Pin::new(&mut self.chunks).poll_next(cx)) {
                Some(Ok(chunk)) => {
                    stages.feed(chunk);
                    continue;
                }
                Some(Err(_)) => Err(RelayFailure::Upstream),
                None => self.end(),
            };
            match out {
                Err(failure) => return Poll::Ready(Some(Err(self.fail(failure)))),
                // Nothing is left to send; the stages are gone, so the next poll ends the body.
                Ok(out) if out.is_empty() => {}
                Ok(out) => return Poll::Ready(Some(Ok(Frame::data(out)))),
            }
        }
    }

    /// Drops the stages without releasing the scrubber's held bytes, keeping its match count for the scrub event, and
    /// records the failure as the request's reason. Returns `failure` for the caller to pass on.
    fn fail(&mut self, failure: RelayFailure) -> RelayFailure {
        self.facts.refuse(failure.into());
        self.matches = self.total_matches();
        self.stages = None;
        failure
    }
}

impl Body for RelayedBody {
    type Data = Bytes;
    type Error = RelayFailure;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, RelayFailure>>> {
        let this = self.get_mut();
        let frame = this.poll_stages(cx);
        this.report_matches();
        frame
    }
}

#[cfg(test)]
mod tests {
    use std::task::Waker;

    use hyper::header::HeaderValue;

    use super::*;
    use crate::audit::RequestRecord;
    use crate::connection_tags::ServiceClose;
    use crate::content_coding::PIECE_SIZE;

    /// A relayed body over `chunks` in `codings` with no scrub patterns, after `header_matches` matches in the headers.
    fn coded_body(chunks: Vec<Bytes>, codings: BodyCodings, limits: Limits) -> RelayedBody {
        let context = ResponseContext {
            method: Method::Get,
            patterns: ScrubPatterns::default(),
            facts: RequestRecord::new("local".parse().unwrap(), "GET", ServiceClose::default()).facts(),
            accept_encoding: None,
            limits,
        };
        RelayedBody::new(ResponseChunks::of(chunks), context, codings, 0)
    }

    /// A relayed identity body over `chunks` with no scrub patterns, after `header_matches` matches in the headers.
    fn body(chunks: &[&'static [u8]], header_matches: u64) -> RelayedBody {
        let chunks = chunks.iter().copied().map(Bytes::from_static).collect();
        let mut relayed = coded_body(chunks, BodyCodings::default(), Limits::default());
        relayed.matches = header_matches;
        relayed
    }

    /// Every frame of `body` up to its end or first error; the chunks are all ready, so nothing waits.
    fn frames(body: &mut RelayedBody) -> Vec<Result<Bytes, RelayFailure>> {
        let mut cx = Context::from_waker(Waker::noop());
        let mut failed = false;
        std::iter::from_fn(|| match (failed, Pin::new(&mut *body).poll_frame(&mut cx)) {
            (false, Poll::Ready(Some(frame))) => {
                failed = frame.is_err();
                Some(frame.map(|frame| frame.into_data().unwrap()))
            }
            _ => None,
        })
        .collect()
    }

    /// Every frame of `body`, each of which must be data and not empty.
    fn drain(body: &mut RelayedBody) -> Vec<Bytes> {
        frames(body).into_iter().map(Result::unwrap).collect()
    }

    fn gzip(data: &[u8]) -> Bytes {
        let mut encoder = ResponseEncoder::new(ContentCoding::Gzip);
        [encoder.push(data).unwrap(), encoder.finish().unwrap()].concat().into()
    }

    fn gunzip(data: &[u8]) -> Vec<u8> {
        let mut decoder = ResponseDecoder::new(ContentCoding::Gzip);
        let out = decoder.push(data).map(Result::unwrap).collect::<Vec<_>>().concat();
        decoder.finish().unwrap();
        out
    }

    fn limits(toml: &str) -> Limits {
        #[derive(serde::Deserialize)]
        struct Config {
            limits: Limits,
        }
        toml::from_str::<Config>(toml).unwrap().limits
    }

    const GZIP: BodyCodings = BodyCodings {
        upstream: Some(ContentCoding::Gzip),
        emitted: None,
    };

    #[test]
    fn a_gzip_body_split_anywhere_is_decoded_and_counted() {
        let coded = gzip(b"hello, decoded world");
        let chunks = vec![coded.slice(..3), coded.slice(3..15), coded.slice(15..)];
        let mut relayed = coded_body(chunks, GZIP, Limits::default());
        assert_eq!(drain(&mut relayed).concat(), b"hello, decoded world");
        let outcome = relayed.outcome().unwrap();
        assert_eq!((outcome.scrubbed, outcome.decoded_bytes), (false, 20));
    }

    #[test]
    fn one_upstream_chunk_that_decodes_to_many_pieces_is_sent_a_piece_at_a_time() {
        let plain = vec![b'a'; 3 * PIECE_SIZE + 5];
        let mut relayed = coded_body(vec![gzip(&plain)], GZIP, Limits::default());
        let frames = drain(&mut relayed);
        assert_eq!(
            frames.iter().map(Bytes::len).collect::<Vec<_>>(),
            [PIECE_SIZE, PIECE_SIZE, PIECE_SIZE, 5]
        );
        assert_eq!(frames.concat(), plain);
    }

    #[test]
    fn an_identity_body_is_re_encoded_when_the_caller_needs_a_coding() {
        let codings = BodyCodings {
            upstream: None,
            emitted: Some(ContentCoding::Gzip),
        };
        let chunks = vec![Bytes::from_static(b"first "), Bytes::from_static(b"second")];
        let mut relayed = coded_body(chunks, codings, Limits::default());
        assert_eq!(gunzip(&drain(&mut relayed).concat()), b"first second");
        assert_eq!(relayed.outcome().map(|outcome| outcome.decoded_bytes), Some(12));
    }

    #[test]
    fn each_failure_after_the_head_is_an_error_of_its_kind_and_no_outcome() {
        let coded = gzip(&[b'a'; 4096]);
        let cases = [
            (vec![coded.slice(..coded.len() - 1)], Limits::default(), RelayFailure::Truncated),
            (vec![Bytes::from_static(b"not gzip")], Limits::default(), RelayFailure::Corrupt),
            (
                vec![coded.clone(), Bytes::from_static(b"x")],
                Limits::default(),
                RelayFailure::Corrupt,
            ),
            (
                vec![coded],
                limits("[limits]\nmax_decompressed_response_bytes = 1000"),
                RelayFailure::SizeLimit,
            ),
            (vec![gzip(&[0; 4 << 20])], Limits::default(), RelayFailure::RatioLimit),
        ];
        cases.into_iter().for_each(|(chunks, limits, expected)| {
            let mut relayed = coded_body(chunks, GZIP, limits);
            assert_eq!(frames(&mut relayed).pop(), Some(Err(expected)));
            assert!(relayed.stages.is_none() && relayed.outcome().is_none(), "{expected:?}");
        });
    }

    #[test]
    fn a_body_over_the_size_limit_fails_even_without_a_coding() {
        let chunks = vec![Bytes::from(vec![b'a'; 1001])];
        let mut relayed = coded_body(
            chunks,
            BodyCodings::default(),
            limits("[limits]\nmax_decompressed_response_bytes = 1000"),
        );
        assert_eq!(frames(&mut relayed), [Err(RelayFailure::SizeLimit)]);
    }

    #[test]
    fn a_response_without_a_body_needs_no_decoder() {
        // Its headers say gzip, but `relay` gives a response with no body empty codings, so its empty body ends cleanly.
        let mut relayed = coded_body(Vec::new(), BodyCodings::default(), Limits::default());
        assert!(drain(&mut relayed).is_empty());
        assert!(relayed.outcome().is_some());
    }

    #[test]
    fn the_outcome_is_known_once_the_body_has_ended_and_empty_chunks_send_no_frame() {
        let mut relayed = body(&[b"a", b"", b"b"], 0);
        assert_eq!(relayed.outcome(), None);
        assert_eq!(drain(&mut relayed), [Bytes::from_static(b"a"), Bytes::from_static(b"b")]);
        assert_eq!(
            relayed.outcome(),
            Some(ResponseOutcome {
                scrubbed: false,
                decoded_bytes: 2
            })
        );
    }

    #[test]
    fn a_match_in_the_headers_alone_marks_the_response_scrubbed() {
        let mut relayed = body(&[], 2);
        assert!(drain(&mut relayed).is_empty());
        assert_eq!(relayed.outcome().map(|outcome| outcome.scrubbed), Some(true));
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        pairs
            .iter()
            .map(|(name, value)| (name.parse().unwrap(), HeaderValue::from_str(value).unwrap()))
            .collect()
    }

    fn names(headers: &HeaderMap) -> Vec<&str> {
        headers.keys().map(HttpHeaderName::as_str).collect()
    }

    #[test]
    fn connection_scoped_and_caller_auth_headers_are_removed() {
        let mut map = headers(&[
            ("content-type", "text/plain"),
            ("content-length", "2"),
            ("connection", "X-Hop, , keep-alive"),
            ("connection", "x-other"),
            ("x-hop", "1"),
            ("x-other", "1"),
            ("keep-alive", "timeout=5"),
            ("transfer-encoding", "chunked"),
            ("proxy-authenticate", "Basic"),
            ("proxy-authorization", "Bearer ivt_x"),
            ("x-iron-vault-token", "ivt_x"),
            ("location", "/next"),
        ]);
        strip_headers(&mut map, Some(&"X-Iron-Vault-Token".parse().unwrap()));
        assert_eq!(names(&map), ["content-type", "content-length", "location"]);
    }

    #[test]
    fn without_a_token_header_only_the_connection_scoped_headers_go() {
        let mut map = headers(&[("x-api-key", "echo"), ("upgrade", "h2c"), ("te", "trailers")]);
        strip_headers(&mut map, None);
        assert_eq!(names(&map), ["x-api-key"]);
    }

    #[test]
    fn only_decodable_content_codings_and_chunked_transfer_codings_are_relayed() {
        let ok = StatusCode::OK;
        [
            (&[][..], ok, None),
            (&[("content-encoding", "identity")], ok, None),
            (&[("content-encoding", "gzip")], ok, Some(ContentCoding::Gzip)),
            (
                &[("content-encoding", "br"), ("transfer-encoding", "Chunked")],
                ok,
                Some(ContentCoding::Br),
            ),
            (&[("transfer-encoding", "chunked")], StatusCode::PARTIAL_CONTENT, None),
        ]
        .iter()
        .for_each(|(pairs, status, expected)| assert_eq!(upstream_coding(&headers(pairs), *status).ok(), Some(*expected), "{pairs:?}"));
        [
            (&[("content-encoding", "zstd")][..], ok),
            (&[("content-encoding", "gzip, br")], ok),
            (&[("content-encoding", "identity, br")], ok),
            (&[("content-encoding", "gzip"), ("content-encoding", "gzip")], ok),
            (&[("content-encoding", "gzip")], StatusCode::PARTIAL_CONTENT),
            (&[("transfer-encoding", "gzip, chunked")], ok),
            (&[("transfer-encoding", "gzip"), ("transfer-encoding", "chunked")], ok),
            (&[("transfer-encoding", "identity")], ok),
        ]
        .iter()
        .for_each(|(pairs, status)| assert!(upstream_coding(&headers(pairs), *status).is_err(), "{pairs:?} {status}"));
    }
}
