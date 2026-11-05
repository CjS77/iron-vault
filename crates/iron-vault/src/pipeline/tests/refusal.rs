use iron_vault_policy::{FinalCheckError, HeaderValueError, OutgoingHeadersError, Refusal, UpstreamTargetError};

use super::*;
use crate::audit::{ReasonCode, RequestRecord};
use crate::connection_tags::ServiceClose;
use crate::logging::tests::{capture, parse};

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
    run(
        &sources,
        &loopback(),
        brave_search("placeholder", &[]),
        sources.start,
        &mut Identified::default(),
    )
    .unwrap_err()
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
fn a_500_is_answered_exactly_when_the_refusal_is_a_defect() {
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
        .for_each(|refusal| assert_eq!(refusal.status() == 500, refusal.defect().is_some(), "{refusal}"));
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

#[test]
fn every_refusal_maps_to_its_reason_code() {
    let token = bearer();
    let forbidden_because = |reason| {
        AuthzError::Forbidden {
            route: route("brave"),
            reason,
        }
        .into()
    };
    let caller_errors = [
        (unauthenticated(), ReasonCode::Unauthenticated),
        (target(), ReasonCode::BadTarget),
        (PipelineRefusal::Method, ReasonCode::BadMethod),
        (not_found(&token), ReasonCode::NoRoute),
        (forbidden(&token), ReasonCode::NotGranted),
        (forbidden_because(Refusal::NotGranted), ReasonCode::NotGranted),
        (forbidden_because(Refusal::Method), ReasonCode::MethodNotAllowed),
        (forbidden_because(Refusal::Path), ReasonCode::PathNotAllowed),
        (unavailable(), ReasonCode::RouteUnavailable),
        (sanitize(), ReasonCode::AmbiguousFraming),
        (rate_limited(), ReasonCode::RateLimited),
        (no_record(), ReasonCode::CredentialUnavailable),
        (kind(), ReasonCode::CredentialUnusable),
        (AssembleError::ForeignMarker.into(), ReasonCode::ForeignMarker),
        (AssembleError::MalformedMarker.into(), ReasonCode::MalformedMarker),
    ];
    let defects = defects().into_iter().map(|refusal| (refusal, ReasonCode::ServiceDefect));
    caller_errors
        .into_iter()
        .chain(defects)
        .for_each(|(refusal, reason)| assert_eq!(ReasonCode::from(&refusal), reason, "{refusal}"));
}

#[test]
fn running_into_a_defect_leaves_the_route_and_credential_it_found() {
    // A limiter built without the brave route: authorization passes, the charge cannot find the route.
    let sources = TestSources::with_limiter_config(&without_brave_route());
    let (result, identified) = sources.run_identified(&loopback(), brave_search(MARKER, &[]));

    let refusal = result.unwrap_err();
    assert!(matches!(refusal, PipelineRefusal::Charge(ChargeError::UnknownRoute { .. })));
    assert_eq!(refusal.defect(), Some("charge_unknown_route"));
    assert_eq!(
        identified.route.map(|(route, credential, _)| (route, credential)),
        Some((route("brave"), credential("brave")))
    );
    assert!(identified.caller.is_some());
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
    let refusal: PipelineRefusal = FinalCheckError::CredentialOutsideSlot.into();
    let mut id = None;
    let out = capture(|| {
        let record = RequestRecord::new("local".parse().unwrap(), "GET", ServiceClose::default());
        let facts = record.facts();
        facts.route(&route("brave"), &credential("brave"), &"api.search.brave.com".parse().unwrap());
        facts.report_defect(refusal.defect().unwrap());
        id = Some(facts.id().to_string());
        record.refuse(ReasonCode::ServiceDefect);
    });
    let event = out
        .lines()
        .map(parse)
        .find(|record| record["event"] == "request.defect")
        .expect(&out);

    assert_eq!(event["level"], "ERROR", "{out}");
    assert_eq!(event["target"], "iron-vault.audit", "{out}");
    assert_eq!(event["request_id"].as_str(), id.as_deref(), "{out}");
    assert_eq!(event["route"], "brave", "{out}");
    assert_eq!(event["credential"], "brave", "{out}");
    assert_eq!(event["defect"], "credential_outside_slot", "{out}");
}

#[test]
fn a_construction_failure_has_a_defect_label_and_a_caller_error_does_not() {
    assert_eq!(construction().defect(), Some("assemble_non_ascii_slot_value"));
    assert_eq!(unknown_route().defect(), Some("charge_unknown_route"));
    [
        AssembleError::ForeignMarker.into(),
        no_record(),
        kind(),
        unauthenticated(),
        rate_limited(),
    ]
    .iter()
    .for_each(|refusal: &PipelineRefusal| assert_eq!(refusal.defect(), None, "{refusal}"));
}
