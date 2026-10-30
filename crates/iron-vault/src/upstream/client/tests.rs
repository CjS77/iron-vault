// The integration tests' checked-request builder, so these tests build their request through the public policy API too.
#[path = "../../../tests/common/checked.rs"]
mod checked;

use super::*;

const SECRET: &str = "IVs3cr3tvalue";

fn request() -> CheckedRequest {
    let headers = [("Accept", "application/json"), ("X-Custom", "one")];
    checked::checked("https://localhost:8443", Method::Get, "/header/rates", &headers, SECRET)
}

#[test]
fn the_reqwest_request_carries_the_checked_method_url_and_headers_only() {
    let checked = request();
    let built = to_reqwest(&checked).unwrap();
    assert_eq!(built.method(), reqwest::Method::GET);
    assert_eq!(built.url(), checked.url());
    let names: Vec<&str> = built.headers().keys().map(|name| name.as_str()).collect();
    assert_eq!(names, ["accept", "x-custom", "x-api-key"]);
    assert!(built.body().is_none());
}

#[test]
fn every_outgoing_header_value_is_sensitive() {
    let built = to_reqwest(&request()).unwrap();
    assert!(built.headers().values().all(header::HeaderValue::is_sensitive));
    assert!(!format!("{:?}", built.headers()).contains(SECRET));
}

#[test]
fn every_method_maps_to_its_reqwest_method() {
    let all = [
        Method::Get,
        Method::Head,
        Method::Post,
        Method::Put,
        Method::Patch,
        Method::Delete,
        Method::Options,
    ];
    all.into_iter()
        .for_each(|method_| assert_eq!(method(method_).as_str(), method_.as_str()));
}

#[test]
fn the_client_offers_http2_then_http1() {
    let config = tls_config(&UpstreamTrust::BuiltIn).unwrap();
    assert_eq!(config.alpn_protocols, [b"h2".to_vec(), b"http/1.1".to_vec()]);
}
