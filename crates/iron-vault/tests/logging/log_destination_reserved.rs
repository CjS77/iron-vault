// SPDX-License-Identifier: MPL-2.0
//! `config approve` refuses a `[logging] destination` that is, or lies inside, the state or config directory, named
//! directly or through a symlink, before it reserves a version (`design/audit-logging.md`, "Switching at activation").

#![cfg(target_os = "linux")]

use crate::common;

use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::sync::Arc;

use common::approval_harness::{APPROVAL_PASSPHRASE, Fixture, approve, mkdir, versions};
use iron_vault::admin::protocol::{AdminResponse, ErrorCode};
use iron_vault::service_context::ServiceContext;
use iron_vault::service_state::ServiceState;

/// Approves the base config with its log in `dir`, and checks the pre-check refused it for lying in `reserved`.
async fn assert_refused(service: &Arc<ServiceContext>, fixture: &Fixture, dir: &Path, reserved: &str) {
    let config = format!("{}\n[logging]\ndestination = \"{}\"\n", fixture.config("fx"), dir.display());
    let exchanged = approve(service, &config, &["yes", APPROVAL_PASSPHRASE]).await;
    match &exchanged.response {
        AdminResponse::Error {
            code: ErrorCode::ConfigInvalid,
            message,
        } => assert!(
            message.contains(&format!("the log directory is, or is inside, the {reserved}")),
            "{message}"
        ),
        other => panic!("expected config-invalid, got {other:?}"),
    }
    assert!(exchanged.prompts.is_empty(), "{:?}", exchanged.prompts);
    assert_eq!(versions(service).await, (Some(1), 1));
}

#[tokio::test]
async fn the_pre_check_refuses_a_log_directory_in_the_state_or_config_directory_however_it_is_named() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    let inside_state = fixture.path("state/logs");
    mkdir(&inside_state);
    let (state_link, config_link) = (fixture.path("logs-in-state"), fixture.path("logs-in-config"));
    symlink(&inside_state, &state_link).unwrap();
    symlink(fixture.path("etc"), &config_link).unwrap();

    assert_refused(&service, &fixture, &inside_state, "state directory").await;
    assert_refused(&service, &fixture, &fixture.path("etc"), "config directory").await;
    assert_refused(&service, &fixture, &state_link, "state directory").await;
    assert_refused(&service, &fixture, &config_link, "config directory").await;

    [&state_link, &config_link].iter().for_each(|link| fs::remove_file(link).unwrap());
    fs::remove_dir(&inside_state).unwrap();
    assert_eq!(service.state().await, ServiceState::Ready);
}
