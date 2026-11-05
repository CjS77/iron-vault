use std::collections::BTreeSet;

use super::*;
use crate::logging::tests::{capture, parse};
use crate::request_server::FormViolation;

const ALL_REASONS: [ReasonCode; 34] = [
    ReasonCode::ConnectNotSupported,
    ReasonCode::NotOriginForm,
    ReasonCode::UpgradeNotSupported,
    ReasonCode::UnsupportedVersion,
    ReasonCode::RequestTooLarge,
    ReasonCode::RequestTimeout,
    ReasonCode::Locked,
    ReasonCode::PolicyInvalid,
    ReasonCode::Checking,
    ReasonCode::RecoveryNeeded,
    ReasonCode::BadHeader,
    ReasonCode::Withdrawn,
    ReasonCode::Unauthenticated,
    ReasonCode::BadTarget,
    ReasonCode::BadMethod,
    ReasonCode::NoRoute,
    ReasonCode::NotGranted,
    ReasonCode::MethodNotAllowed,
    ReasonCode::PathNotAllowed,
    ReasonCode::RouteUnavailable,
    ReasonCode::AmbiguousFraming,
    ReasonCode::RateLimited,
    ReasonCode::CredentialUnavailable,
    ReasonCode::CredentialUnusable,
    ReasonCode::ForeignMarker,
    ReasonCode::MalformedMarker,
    ReasonCode::ServiceDefect,
    ReasonCode::UpstreamTimeout,
    ReasonCode::UpstreamConnect,
    ReasonCode::UpstreamTls,
    ReasonCode::UpstreamProtocol,
    ReasonCode::UpstreamBody,
    ReasonCode::CallerGone,
    ReasonCode::ServiceClosed,
];

fn record() -> RequestRecord {
    RequestRecord::new("local".parse().unwrap(), "GET", ServiceClose::default())
}

/// The request events `f` writes, as parsed records.
fn events(f: impl FnOnce()) -> Vec<serde_json::Value> {
    let out = capture(f);
    let records: Vec<_> = out.lines().map(parse).collect();
    records
        .iter()
        .for_each(|record| assert_eq!(record["target"], REQUEST_TARGET, "{out}"));
    records
}

fn the_event(f: impl FnOnce()) -> serde_json::Value {
    let mut records = events(f);
    assert_eq!(records.len(), 1, "{records:?}");
    records.remove(0)
}

fn keys(record: &serde_json::Value) -> BTreeSet<&str> {
    record.as_object().unwrap().keys().map(String::as_str).collect()
}

#[test]
fn a_refused_request_writes_one_failure_event_with_only_the_facts_known_by_then() {
    let event = the_event(|| {
        let mut record = record();
        record.refuse(ReasonCode::NotOriginForm);
        record.answered(400);
    });
    let expected = [
        "timestamp",
        "level",
        "target",
        "message",
        "event",
        "service",
        "service_version",
        "schema_version",
        "deployment_profile",
        "request_id",
        "listener",
        "http_method",
        "status",
        "request_bytes",
        "duration_ms",
        "outcome",
        "reason",
    ];
    assert_eq!(keys(&event), expected.into_iter().collect(), "{event}");
    assert_eq!(event["event"], "request.completed");
    assert_eq!(event["level"], "INFO");
    assert_eq!(
        (event["listener"].as_str(), event["http_method"].as_str()),
        (Some("local"), Some("GET"))
    );
    assert_eq!(
        (event["outcome"].as_str(), event["reason"].as_str()),
        (Some("failure"), Some("not_origin_form"))
    );
    assert_eq!((event["status"].as_u64(), event["request_bytes"].as_u64()), (Some(400), Some(0)));
    assert!(event["duration_ms"].is_u64(), "{event}");
}

#[test]
fn facts_the_handler_records_reach_the_event() {
    let event = the_event(|| {
        let mut record = record();
        let facts = record.facts();
        facts.caller(&"agent".parse().unwrap());
        facts.route(&"fx".parse().unwrap(), &"fx-key".parse().unwrap(), &"api.example".parse().unwrap());
        facts.add_request_bytes(7);
        facts.refuse(ReasonCode::RateLimited);
        facts.refuse(ReasonCode::UpstreamTls);
        record.answered(429);
    });
    assert_eq!(event["caller"], "agent");
    assert_eq!(event["route"], "fx");
    assert_eq!(event["credential"], "fx-key");
    assert_eq!(event["upstream_host"], "api.example");
    assert_eq!(event["request_bytes"], 7);
    assert_eq!(event["reason"], "rate_limited", "the first reason wins: {event}");
}

#[test]
fn the_servers_replacement_overrides_the_handler_and_disowns_its_answer() {
    let event = the_event(|| {
        let mut record = record();
        let facts = record.facts();
        facts.caller(&"agent".parse().unwrap());
        facts.route(&"fx".parse().unwrap(), &"fx-key".parse().unwrap(), &"api.example".parse().unwrap());
        facts.refuse(ReasonCode::UpstreamTimeout);
        record.replace_answer(ReasonCode::RequestTimeout);
        facts.refuse(ReasonCode::UpstreamTls);
        facts.route(
            &"other".parse().unwrap(),
            &"other-key".parse().unwrap(),
            &"other.example".parse().unwrap(),
        );
        record.answered(408);
    });
    assert_eq!(event["reason"], "request_timeout");
    assert_eq!(
        (event["caller"].as_str(), event["route"].as_str(), event["credential"].as_str()),
        (Some("agent"), Some("fx"), Some("fx-key"))
    );
    assert!(event.get("upstream_host").is_none(), "{event}");
}

#[test]
fn a_request_dropped_before_any_response_says_who_closed_it() {
    let caller = the_event(|| drop(record()));
    assert_eq!(caller["reason"], "caller_gone");
    assert!(caller.get("status").is_none(), "{caller}");

    let close = ServiceClose::default();
    let event = the_event(|| {
        let record = RequestRecord::new("local".parse().unwrap(), "GET", close.clone());
        close.set();
        drop(record);
    });
    assert_eq!(event["reason"], "service_closed");
}

#[test]
fn a_reason_recorded_before_a_drop_is_kept() {
    let event = the_event(|| {
        let record = record();
        record.facts().refuse(ReasonCode::BadHeader);
    });
    assert_eq!(event["reason"], "bad_header");
}

#[test]
fn a_relayed_answer_writes_nothing_here() {
    assert!(
        events(|| {
            let mut record = record();
            record.answered(200);
        })
        .is_empty()
    );
}

#[test]
fn each_request_gets_its_own_hyphenated_lowercase_uuid() {
    let ids: Vec<_> = (0..2)
        .map(|_| {
            the_event(|| {
                let mut record = record();
                record.refuse(ReasonCode::BadHeader);
                record.answered(400);
            })["request_id"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_ne!(ids[0], ids[1]);
    ids.iter().for_each(|id| {
        let parsed = Uuid::parse_str(id).unwrap();
        assert_eq!(
            (id.as_str(), parsed.get_version_num()),
            (parsed.hyphenated().to_string().as_str(), 4)
        );
    });
}

#[test]
fn the_method_is_escaped() {
    let event = the_event(|| {
        let mut record = RequestRecord::new("local".parse().unwrap(), "G\u{202e}T", ServiceClose::default());
        record.refuse(ReasonCode::BadHeader);
        record.answered(400);
    });
    assert_eq!(event["http_method"], "G\\u{202e}T");
}

#[test]
fn reason_labels_are_distinct_snake_case() {
    let labels: BTreeSet<_> = ALL_REASONS.iter().map(|reason| reason.as_str()).collect();
    assert_eq!(labels.len(), ALL_REASONS.len());
    labels
        .iter()
        .for_each(|label| assert!(label.chars().all(|c| c.is_ascii_lowercase() || c == '_'), "{label}"));
}

#[test]
fn each_other_source_maps_to_its_reason() {
    use UnavailableReason as U;
    let unavailable = [
        (U::Locked, "locked"),
        (U::PolicyInvalid, "policy_invalid"),
        (U::Checking, "checking"),
        (U::RecoveryNeeded, "recovery_needed"),
    ];
    unavailable
        .into_iter()
        .for_each(|(reason, label)| assert_eq!(ReasonCode::from(reason).as_str(), label));
    let transport = [
        (TransportError::Timeout, "upstream_timeout"),
        (TransportError::Connect, "upstream_connect"),
        (TransportError::Tls, "upstream_tls"),
        (TransportError::Protocol, "upstream_protocol"),
        (TransportError::Body, "upstream_body"),
    ];
    transport
        .into_iter()
        .for_each(|(error, label)| assert_eq!(ReasonCode::from(error).as_str(), label));
    let form = [
        (FormViolation::Connect, "connect_not_supported"),
        (FormViolation::NotOriginForm, "not_origin_form"),
        (FormViolation::Upgrade, "upgrade_not_supported"),
        (FormViolation::Version, "unsupported_version"),
    ];
    form.into_iter()
        .for_each(|(violation, label)| assert_eq!(ReasonCode::from(violation).as_str(), label));
}
