use std::io;
use std::sync::{Arc, Mutex, PoisonError};

use iron_vault_policy::{FinalCheckError, HeaderValueError, OutgoingHeadersError, UpstreamTargetError};
use tracing_subscriber::fmt::MakeWriter;

use super::*;

/// A refusal from the real pipeline, so the table holds the errors the steps produce.
fn refused(head: RequestHead) -> PipelineRefusal {
    TestSources::new().run(&loopback(), head).unwrap_err()
}

fn route(name: &str) -> RouteName {
    name.parse().unwrap()
}

fn credential(name: &str) -> CredentialName {
    name.parse().unwrap()
}

fn rate_limited() -> PipelineRefusal {
    let sources = TestSources::new();
    run(&sources, &loopback(), brave_search("placeholder", &[]), sources.start).unwrap_err()
}

fn unauthenticated() -> PipelineRefusal {
    refused(head("GET", "/brave/res/v1/web/search", &[]))
}

fn not_found(token: &str) -> PipelineRefusal {
    refused(head("GET", "/nowhere", &[("Proxy-Authorization", token)]))
}

fn forbidden(token: &str) -> PipelineRefusal {
    refused(head("GET", "/fx/latest", &[("Proxy-Authorization", token)]))
}

fn unavailable() -> PipelineRefusal {
    AuthzError::Unavailable { route: route("brave") }.into()
}

fn no_record() -> PipelineRefusal {
    PipelineRefusal::NoHealthyRecord {
        route: route("brave"),
        credential: credential("brave"),
    }
}

fn kind() -> PipelineRefusal {
    KindError::SlotMismatch {
        kind: "static",
        slot: "basic",
    }
    .into()
}

fn target() -> PipelineRefusal {
    let token = bearer();
    refused(head("GET", "/brave/../fx", &[("Proxy-Authorization", &token)]))
}

fn sanitize() -> PipelineRefusal {
    SanitizeError::ConflictingContentLength.into()
}

fn construction() -> PipelineRefusal {
    AssembleError::NonAsciiSlotValue.into()
}

fn unknown_route() -> PipelineRefusal {
    ChargeError::UnknownRoute { route: route("brave") }.into()
}

fn not_granted() -> PipelineRefusal {
    ChargeError::NotGranted {
        caller: "brave-cli".parse().unwrap(),
        route: route("brave"),
    }
    .into()
}

/// Every refusal only a service defect causes.
fn defects() -> Vec<PipelineRefusal> {
    vec![
        construction(),
        AssembleError::HeaderValue(HeaderValueError::Nul).into(),
        AssembleError::Header(OutgoingHeadersError::Reserved {
            name: "host".parse().unwrap(),
        })
        .into(),
        AssembleError::Target(UpstreamTargetError::Path).into(),
        unknown_route(),
        not_granted(),
        FinalCheckError::Slot.into(),
        FinalCheckError::Host.into(),
    ]
}

#[test]
fn every_variant_has_its_status_body_and_headers() {
    let token = bearer();
    let plain = [("Content-Type", "text/plain; charset=utf-8".to_owned())];
    let cases = [
        (unauthenticated(), 401, "unauthorized"),
        (forbidden(&token), 403, "forbidden"),
        (not_found(&token), 404, "not found"),
        (unavailable(), 503, "service unavailable"),
        (no_record(), 503, "service unavailable"),
        (kind(), 503, "service unavailable"),
        (target(), 400, "bad request"),
        (PipelineRefusal::Method, 400, "bad request"),
        (sanitize(), 400, "bad request"),
        (AssembleError::ForeignMarker.into(), 400, "bad request"),
        (AssembleError::MalformedMarker.into(), 400, "bad request"),
        (construction(), 500, "internal error"),
    ];
    let defects = defects().into_iter().map(|refusal| (refusal, 500, "internal error"));
    let cases = cases.into_iter().chain(defects);
    cases.into_iter().for_each(|(refusal, status, body)| {
        let response = refusal.respond();
        assert_eq!((response.status(), response.body()), (status, body), "{refusal}");
        assert_eq!(refusal.status(), status);
        assert_eq!(response.headers(), plain, "{refusal}");
    });
}

#[test]
fn a_500_is_answered_exactly_when_the_event_is_logged() {
    let token = bearer();
    let caller_errors = [
        unauthenticated(),
        forbidden(&token),
        not_found(&token),
        unavailable(),
        no_record(),
        kind(),
        target(),
        PipelineRefusal::Method,
        sanitize(),
        rate_limited(),
        AssembleError::ForeignMarker.into(),
        AssembleError::MalformedMarker.into(),
    ];
    defects()
        .into_iter()
        .chain(caller_errors)
        .for_each(|refusal| assert_eq!(refusal.status() == 500, !logged(&refusal).is_empty(), "{refusal}"));
}

#[test]
fn rate_limited_answers_429_with_retry_after_in_whole_seconds() {
    let refusal = rate_limited();
    let PipelineRefusal::Charge(ChargeError::Limited(limited)) = &refusal else {
        panic!("{refusal:?}")
    };
    let response = refusal.respond();

    assert_eq!((response.status(), response.body()), (429, "too many requests"));
    let retry = limited.retry_after().as_secs().to_string();
    assert_eq!(response.headers()[1], ("Retry-After", retry));
    assert!(response.headers().iter().all(|(name, _)| *name != "WWW-Authenticate"));
}

#[test]
fn every_401_and_every_404_looks_the_same() {
    let token = bearer();
    let mut wrong_token = brave_search("placeholder", &[]);
    wrong_token.headers.retain(|(name, _)| name.as_str() != "Proxy-Authorization");
    wrong_token.headers.push((
        "Proxy-Authorization".parse().unwrap(),
        HeaderValue::try_from("Bearer nope").unwrap(),
    ));
    let unauthorized = [
        unauthenticated(),
        refused(wrong_token),
        PipelineRefusal::Unauthenticated(Unauthenticated),
    ];
    let missing = [not_found(&token), refused(head("GET", "/", &[("Proxy-Authorization", &token)]))];

    [&unauthorized[..], &missing[..]].into_iter().for_each(|class| {
        let first = class[0].respond();
        class.iter().for_each(|refusal| assert_eq!(refusal.respond(), first, "{refusal}"));
    });
    assert_eq!(unauthorized[0].respond().status(), 401);
    assert_eq!(missing[0].respond().status(), 404);
}

#[test]
fn no_body_repeats_a_route_a_scheme_or_a_header() {
    let token = bearer();
    let all = [forbidden(&token), not_found(&token), unavailable(), no_record(), unauthenticated()];
    all.iter().for_each(|refusal| {
        let body = refusal.respond().body().to_ascii_lowercase();
        ["fx", "brave", "bearer", "proxy-authorization", "token"]
            .iter()
            .for_each(|word| assert!(!body.contains(word), "{refusal}: {body}"));
    });
}

/// Collects what a `tracing` subscriber writes.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Captured {
    type Writer = Captured;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// What `f` logs.
fn capture<T>(f: impl FnOnce() -> T) -> (T, String) {
    let captured = Captured::default();
    let subscriber = tracing_subscriber::fmt().with_writer(captured.clone()).with_ansi(false).finish();
    let value = tracing::subscriber::with_default(subscriber, f);
    let bytes = captured.0.lock().unwrap_or_else(PoisonError::into_inner).clone();
    (value, String::from_utf8(bytes).unwrap())
}

/// What `report` logs for `refusal` on the brave route.
fn logged(refusal: &PipelineRefusal) -> String {
    capture(|| refusal.report(&route("brave"), &credential("brave"))).1
}

#[test]
fn running_into_a_defect_raises_the_event_without_the_request() {
    // A limiter built without the brave route: authorization passes, the charge cannot find the route.
    let sources = TestSources::with_limiter_config(&without_brave_route());
    let (result, event) = capture(|| sources.run(&loopback(), brave_search(MARKER, &[])));

    assert!(matches!(result, Err(PipelineRefusal::Charge(ChargeError::UnknownRoute { .. }))));
    assert!(event.contains("ERROR"), "{event}");
    assert!(event.contains("severity=\"high\""), "{event}");
    assert!(event.contains("route=brave"), "{event}");
    assert!(event.contains("credential=brave"), "{event}");
    assert!(!event.contains(MARKER) && !event.contains("q=rust"), "{event}");
}

/// The configuration without the brave route or any grant of it.
fn without_brave_route() -> String {
    let config = config();
    let (head, rest) = config.split_once("[routes.brave]").unwrap();
    let (_, tail) = rest.split_once("[routes.billing]").unwrap();
    format!("{head}[routes.billing]{tail}")
        .replace("routes = [\"brave\"]", "routes = [\"fx\"]")
        .replace("\"venice\", \"brave\", \"billing\"", "\"venice\", \"billing\"")
}

#[test]
fn a_final_check_failure_raises_a_high_severity_event_without_secrets() {
    let event = logged(&FinalCheckError::CredentialOutsideSlot.into());

    assert!(event.contains("ERROR"), "{event}");
    assert!(event.contains("severity=\"high\""), "{event}");
    assert!(event.contains("route=brave"), "{event}");
    assert!(event.contains("credential=brave"), "{event}");
    assert!(event.contains("defect=\"CredentialOutsideSlot\""), "{event}");
    assert!(!event.contains(MARKER), "{event}");
}

#[test]
fn a_construction_failure_raises_the_event_and_a_caller_error_does_not() {
    assert!(logged(&construction()).contains("severity=\"high\""));
    assert!(logged(&unknown_route()).contains("severity=\"high\""));
    [
        AssembleError::ForeignMarker.into(),
        no_record(),
        kind(),
        unauthenticated(),
        rate_limited(),
    ]
    .iter()
    .for_each(|refusal| assert_eq!(logged(refusal), "", "{refusal}"));
}
