// SPDX-License-Identifier: MPL-2.0
use super::*;

const PID: u32 = 4242;

fn name(s: &str) -> ListenerName {
    ListenerName::try_from(s).unwrap()
}

fn env(pid: Option<&str>, fds: Option<&str>, names: Option<&str>) -> ActivationEnv {
    ActivationEnv {
        listen_pid: pid.map(str::to_string),
        listen_fds: fds.map(str::to_string),
        listen_fdnames: names.map(str::to_string),
        listen_fds_first_fd: None,
    }
}

fn for_us(fds: &str, names: &str) -> Result<Inheritance, ActivationError> {
    inheritance(&env(Some("4242"), Some(fds), Some(names)), PID)
}

#[test]
fn named_sockets_are_claimed_in_fd_order() {
    assert_eq!(
        for_us("2", "backoffice:local"),
        Ok(Inheritance::Listeners(vec![name("backoffice"), name("local")]))
    );
}

#[test]
fn missing_listen_pid_inherits_nothing() {
    assert_eq!(inheritance(&env(None, Some("1"), Some("local")), PID), Ok(Inheritance::Nothing));
}

#[test]
fn another_process_or_no_process_inherits_nothing() {
    ["4243", "pid", "", "-4242", "4242 "].into_iter().for_each(|pid| {
        assert_eq!(
            inheritance(&env(Some(pid), Some("1"), Some("local")), PID),
            Ok(Inheritance::OtherProcess {
                listen_pid: format!("\"{}\"", pid.escape_default())
            }),
            "{pid:?}"
        )
    });
}

#[test]
fn listen_fds_must_be_a_positive_number() {
    ["0", "two", "", "-1"].into_iter().for_each(|fds| {
        assert_eq!(
            for_us(fds, "local"),
            Err(ActivationError::BadCount {
                value: format!("\"{fds}\"")
            }),
            "{fds:?}"
        )
    });
    assert_eq!(
        inheritance(&env(Some("4242"), None, Some("local")), PID),
        Err(ActivationError::MissingCount)
    );
}

#[test]
fn count_must_agree_with_the_names() {
    assert_eq!(for_us("2", "local"), Err(ActivationError::CountMismatch { count: 2, names: 1 }));
    assert_eq!(
        for_us("1", "local:backoffice"),
        Err(ActivationError::CountMismatch { count: 1, names: 2 })
    );
}

#[test]
fn every_socket_needs_a_name() {
    assert_eq!(for_us("1", ""), Err(ActivationError::Unnamed { fd: 3 }));
    assert_eq!(for_us("2", "local:"), Err(ActivationError::Unnamed { fd: 4 }));
    assert_eq!(
        inheritance(&env(Some("4242"), Some("1"), None), PID),
        Err(ActivationError::Unnamed { fd: 3 })
    );
}

#[test]
fn a_name_the_config_may_lack_is_still_claimed() {
    assert_eq!(
        for_us("2", "local:other"),
        Ok(Inheritance::Listeners(vec![name("local"), name("other")]))
    );
}

#[test]
fn names_that_cannot_be_listener_names_are_refused() {
    // systemd names an unnamed socket after its unit, which is never a listener name.
    assert_eq!(
        for_us("1", "iron-vault.socket"),
        Err(ActivationError::UnknownName {
            fd: 3,
            name: "\"iron-vault.socket\"".to_string()
        })
    );
    let Err(ActivationError::UnknownName { name, .. }) = for_us("1", "a\u{1b}[31m") else {
        panic!("expected an unknown name")
    };
    assert!(!name.contains('\u{1b}'), "{name}");
}

#[test]
fn duplicate_names_are_refused() {
    assert_eq!(
        for_us("3", "local:backoffice:local"),
        Err(ActivationError::DuplicateName {
            name: name("local"),
            first: 3,
            second: 5
        })
    );
}

#[test]
fn a_first_fd_other_than_systemds_is_refused() {
    let shifted = ActivationEnv {
        listen_fds_first_fd: Some("0".to_string()),
        ..env(Some("4242"), Some("1"), Some("local"))
    };
    assert_eq!(inheritance(&shifted, PID), Err(ActivationError::FirstFdSet));
}

#[test]
fn profile_rule_table() {
    let tcp = Endpoint::Tcp {
        address: "127.0.0.1:7878".parse().unwrap(),
        tls: None,
    };
    let unix = Endpoint::UnixSocket("/run/iron-vault/proxy.sock".parse().unwrap());
    let listener = name("local");
    let refused = Err(NotActivated {
        listener: listener.clone(),
    });
    [
        (DeploymentProfile::Protected, &tcp, false, refused),
        (DeploymentProfile::Protected, &tcp, true, Ok(())),
        (DeploymentProfile::Protected, &unix, false, Ok(())),
        (DeploymentProfile::Protected, &unix, true, Ok(())),
        (DeploymentProfile::Development, &tcp, false, Ok(())),
        (DeploymentProfile::Development, &tcp, true, Ok(())),
        (DeploymentProfile::Development, &unix, false, Ok(())),
        (DeploymentProfile::Container, &tcp, false, Ok(())),
        (DeploymentProfile::Container, &tcp, true, Ok(())),
        (DeploymentProfile::Container, &unix, false, Ok(())),
    ]
    .into_iter()
    .for_each(|(profile, endpoint, adopted, expected)| {
        assert_eq!(
            check_origin(profile, &listener, endpoint, adopted),
            expected,
            "{profile:?} {endpoint:?} {adopted}"
        )
    });
}

#[test]
fn refusal_names_the_unit_to_add() {
    let message = NotActivated { listener: name("local") }.to_string();
    assert!(message.contains("add a .socket unit for listener local"), "{message}");
}

#[test]
fn take_takes_nothing_when_the_variables_are_not_for_this_process() {
    [env(None, Some("1"), Some("local")), env(Some("4243"), Some("1"), Some("local"))]
        .iter()
        .for_each(|env| assert_eq!(PassedSockets::take(env, PID).unwrap().names().count(), 0));
}

#[test]
fn take_refuses_a_name_no_listener_can_have_before_taking_any_fd() {
    let refused = PassedSockets::take(&env(Some("4242"), Some("1"), Some("iron-vault.socket")), PID).unwrap_err();
    assert_eq!(
        refused,
        AdoptError::Activation(ActivationError::UnknownName {
            fd: FIRST_FD,
            name: "\"iron-vault.socket\"".to_string()
        })
    );
}
