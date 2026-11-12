//! `status` lists each approved listener that did not open, with a fixed reason (specification §15, §16;
//! `design/admin-protocol.md#status`), and an approval that fixes or removes the listener clears the entry.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::approval_harness::{APPROVAL_PASSPHRASE, Fixture, approve, get, mkdir};
use common::proxy_harness::{TOKEN_BYTES, token_hash};
use iron_vault::admin::protocol::{AdminResponse, ApprovalResult};
use iron_vault::deployment::DeploymentProfile;
use iron_vault::listener_failure::{ListenerFailure, ListenerFailureReason};
use iron_vault::path_metadata::invoking_user;
use iron_vault::service_context::ServiceContext;
use iron_vault::service_state::ServiceState;

/// A `0700` directory holding a leaf certificate and a key that is not its own, under a base the trusted-path rules accept.
struct TlsDir(PathBuf);

impl TlsDir {
    fn new(name: &str) -> Self {
        let bases = [
            Some(PathBuf::from(env!("CARGO_TARGET_TMPDIR"))),
            std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
        ];
        bases
            .into_iter()
            .flatten()
            .map(|base| Self::create(&base, name))
            .find(|tls| {
                let read = iron_vault::admin_file::read(
                    iron_vault::admin_file::AdminFile::Certificate,
                    DeploymentProfile::Development,
                    invoking_user().unwrap(),
                    &tls.path("server.crt"),
                );
                read.is_ok()
            })
            .expect("no base directory the trusted-path rules accept for listener TLS files")
    }

    fn create(base: &Path, name: &str) -> Self {
        let dir = base.join(format!("iv-lf-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        mkdir(&dir);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
            .unwrap()
            .self_signed(&leaf_key)
            .unwrap();
        let tls = Self(dir);
        tls.write("server.crt", &leaf.pem(), 0o644);
        tls.write("server.key", &rcgen::KeyPair::generate().unwrap().serialize_pem(), 0o600);
        // Kept aside so a test can put the certificate's own key in place of the wrong one.
        tls.write("good.key", &leaf_key.serialize_pem(), 0o600);
        tls
    }

    fn write(&self, file: &str, pem: &str, mode: u32) {
        fs::write(self.path(file), pem).unwrap();
        fs::set_permissions(self.path(file), fs::Permissions::from_mode(mode)).unwrap();
    }

    fn path(&self, file: &str) -> PathBuf {
        self.0.join(file)
    }

    /// Makes `server.key` the certificate's own key.
    fn fix_key(&self) {
        fs::copy(self.path("good.key"), self.path("server.key")).unwrap();
    }
}

impl Drop for TlsDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The fixture's config with the TLS listener `wide` on these files.
fn config_with_wide(fixture: &Fixture, tls: &TlsDir) -> String {
    format!(
        "{}\n[listeners.wide]\naddress = \"0.0.0.0:{port}\"\ntls_certificate = \"{crt}\"\ntls_key = \"{key}\"\n\n\
         [callers.wide-caller]\nlistener = \"wide\"\ntoken_hash = \"{hash}\"\nroutes = [\"fx\"]\n",
        fixture.config("fx"),
        port = common::proxy_harness::next_free_port(),
        crt = tls.path("server.crt").display(),
        key = tls.path("server.key").display(),
        hash = token_hash(TOKEN_BYTES),
    )
}

async fn approve_config(service: &Arc<ServiceContext>, config: &str) {
    let approved = approve(service, config, &["yes", APPROVAL_PASSPHRASE]).await;
    assert!(
        matches!(approved.response, AdminResponse::ConfigApprove(ApprovalResult { .. })),
        "{approved:?}"
    );
}

async fn failures(service: &Arc<ServiceContext>) -> Vec<ListenerFailure> {
    let report = service.status().await;
    assert_eq!(report.state, ServiceState::Ready);
    report.listener_failures
}

fn wide_mismatch() -> Vec<ListenerFailure> {
    vec![ListenerFailure {
        name: "wide".parse().unwrap(),
        reason: ListenerFailureReason::TlsKeyMismatch,
    }]
}

/// The good listener serves, `status` is Ready and lists the bad listener; an approval after the key is fixed clears it.
#[tokio::test]
async fn an_approval_that_fixes_the_key_clears_the_listed_failure() {
    let (fixture, tls) = (Fixture::new().await, TlsDir::new("fix"));
    let service = fixture.ready().await;
    assert!(failures(&service).await.is_empty());

    approve_config(&service, &config_with_wide(&fixture, &tls)).await;
    assert_eq!(failures(&service).await, wide_mismatch());
    assert_eq!(get(&fixture, "fx").await.status, 200);

    tls.fix_key();
    approve_config(&service, &config_with_wide(&fixture, &tls)).await;
    assert!(failures(&service).await.is_empty());
}

/// An approval that removes the failed listener from the config clears its entry.
#[tokio::test]
async fn an_approval_that_removes_the_failed_listener_clears_the_listed_failure() {
    let (fixture, tls) = (Fixture::new().await, TlsDir::new("remove"));
    let service = fixture.ready().await;
    approve_config(&service, &config_with_wide(&fixture, &tls)).await;
    assert_eq!(failures(&service).await, wide_mismatch());

    approve_config(&service, &fixture.config("fx")).await;
    assert!(failures(&service).await.is_empty());
}
