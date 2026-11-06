use super::*;

const SERVICE: u32 = 997;
const USER: u32 = 1000;

fn env() -> ProfileEnv {
    ProfileEnv {
        home: Some(PathBuf::from("/home/alice")),
        xdg_config_home: None,
        xdg_state_home: None,
        xdg_runtime_dir: Some(PathBuf::from("/run/user/1000")),
        invoking_uid: USER,
        service_account_uid: Some(SERVICE),
    }
}

#[test]
fn the_current_profile_follows_the_dev_mode_feature() {
    let expected = if cfg!(feature = "dev-mode") {
        DeploymentProfile::Development
    } else {
        DeploymentProfile::Protected
    };
    assert_eq!(DeploymentProfile::current(), expected);
}

#[test]
fn protected_paths_are_fixed_and_owned_by_the_service_account() {
    let paths = ServicePaths::for_profile(DeploymentProfile::Protected, &env()).unwrap();
    assert_eq!(
        paths,
        ServicePaths {
            profile: DeploymentProfile::Protected,
            owner: ExpectedOwner { uid: SERVICE },
            config: PathBuf::from("/etc/iron-vault/config.toml"),
            state_dir: PathBuf::from("/var/lib/iron-vault"),
            runtime_dir: Some(PathBuf::from("/run/iron-vault")),
        }
    );
}

#[test]
fn protected_paths_ignore_the_xdg_variables() {
    let env = ProfileEnv {
        xdg_config_home: Some(PathBuf::from("/tmp/config")),
        xdg_state_home: Some(PathBuf::from("/tmp/state")),
        ..env()
    };
    let paths = ServicePaths::for_profile(DeploymentProfile::Protected, &env).unwrap();
    assert_eq!(paths.config, PathBuf::from("/etc/iron-vault/config.toml"));
    assert_eq!(paths.state_dir, PathBuf::from("/var/lib/iron-vault"));
}

#[test]
fn a_missing_service_account_is_an_error_naming_it() {
    let env = ProfileEnv {
        service_account_uid: None,
        ..env()
    };
    let error = ServicePaths::for_profile(DeploymentProfile::Protected, &env).unwrap_err();
    assert_eq!(error, ProfileError::MissingServiceAccount { account: "iron-vault" });
    assert!(error.to_string().contains("`iron-vault` does not exist"), "{error}");
}

#[test]
fn the_protected_bootstrap_log_directory_is_fixed_and_ignores_the_xdg_variables() {
    let env = ProfileEnv {
        xdg_state_home: Some(PathBuf::from("/srv/state")),
        ..env()
    };
    assert_eq!(
        bootstrap_log_dir(DeploymentProfile::Protected, &env),
        Ok(PathBuf::from("/var/log/iron-vault"))
    );
}

#[test]
fn the_service_owner_is_the_service_account_when_protected_and_the_invoking_user_in_development() {
    assert_eq!(
        env().service_owner(DeploymentProfile::Protected),
        Ok(ExpectedOwner { uid: SERVICE })
    );
    assert_eq!(env().service_owner(DeploymentProfile::Development), Ok(ExpectedOwner { uid: USER }));
}

#[cfg(not(feature = "dev-mode"))]
#[test]
fn a_build_without_dev_mode_cannot_resolve_development_paths() {
    assert_eq!(
        ServicePaths::for_profile(DeploymentProfile::Development, &env()),
        Err(ProfileError::DevelopmentNotBuilt)
    );
}

#[cfg(feature = "dev-mode")]
mod development {
    use super::*;

    fn development(env: &ProfileEnv) -> Result<ServicePaths, ProfileError> {
        ServicePaths::for_profile(DeploymentProfile::Development, env)
    }

    #[test]
    fn unset_xdg_variables_fall_back_to_their_home_defaults() {
        assert_eq!(
            development(&env()).unwrap(),
            ServicePaths {
                profile: DeploymentProfile::Development,
                owner: ExpectedOwner { uid: USER },
                config: PathBuf::from("/home/alice/.config/iron-vault-dev/config.toml"),
                state_dir: PathBuf::from("/home/alice/.local/state/iron-vault-dev"),
                runtime_dir: Some(PathBuf::from("/run/user/1000/iron-vault-dev")),
            }
        );
    }

    #[test]
    fn the_development_log_directory_sits_beside_the_state_directory() {
        assert_eq!(
            bootstrap_log_dir(DeploymentProfile::Development, &env()),
            Ok(PathBuf::from("/home/alice/.local/state/iron-vault-dev-log"))
        );
        let env = ProfileEnv {
            xdg_state_home: Some(PathBuf::from("/srv/state")),
            ..env()
        };
        assert_eq!(
            bootstrap_log_dir(DeploymentProfile::Development, &env),
            Ok(PathBuf::from("/srv/state/iron-vault-dev-log"))
        );
    }

    #[test]
    fn set_xdg_variables_are_used_as_given() {
        let env = ProfileEnv {
            home: None,
            xdg_config_home: Some(PathBuf::from("/srv/config")),
            xdg_state_home: Some(PathBuf::from("/srv/state")),
            ..env()
        };
        let paths = development(&env).unwrap();
        assert_eq!(paths.config, PathBuf::from("/srv/config/iron-vault-dev/config.toml"));
        assert_eq!(paths.state_dir, PathBuf::from("/srv/state/iron-vault-dev"));
    }

    #[test]
    fn a_missing_runtime_dir_is_an_error() {
        let env = ProfileEnv {
            xdg_runtime_dir: None,
            ..env()
        };
        let error = development(&env).unwrap_err();
        assert_eq!(
            error,
            ProfileError::MissingVariable {
                variable: "XDG_RUNTIME_DIR",
                purpose: "runtime directory"
            }
        );
        assert!(error.to_string().starts_with("`XDG_RUNTIME_DIR` is not set"), "{error}");
    }

    #[test]
    fn an_unset_xdg_variable_without_a_home_is_an_error() {
        let env = ProfileEnv { home: None, ..env() };
        assert_eq!(
            development(&env),
            Err(ProfileError::MissingVariable {
                variable: "HOME",
                purpose: "config file"
            })
        );
    }

    #[test]
    fn development_is_owned_by_the_invoking_user_even_when_the_service_account_is_missing() {
        let env = ProfileEnv {
            service_account_uid: None,
            ..env()
        };
        assert_eq!(development(&env).unwrap().owner, ExpectedOwner { uid: USER });
    }

    #[test]
    fn root_is_refused_with_the_system_service_warning() {
        let error = development_banner(0, "root").unwrap_err();
        assert_eq!(error, ProfileError::DevelopmentAsRoot);
        assert!(
            error
                .to_string()
                .contains("a development build must never be installed as the system service"),
            "{error}"
        );
    }

    #[test]
    fn any_other_user_gets_the_no_isolation_banner() {
        assert_eq!(
            development_banner(USER, "alice").unwrap(),
            "development mode: no isolation from malware running as alice"
        );
    }
}

#[test]
fn passwd_lines_give_names_and_uids() {
    let accounts =
        Accounts::parse("# comment\nroot:x:0:0:root:/root:/bin/sh\n\nbroken\nbad:x:nan:0::/:\niron-vault:x:997:997::/:/sbin/nologin\n");
    assert_eq!(accounts.uid("iron-vault"), Some(997));
    assert_eq!(accounts.uid("root"), Some(0));
    assert_eq!(accounts.uid("bad"), None);
    assert_eq!(accounts.uid("broken"), None);
    assert_eq!(accounts.name(997), Some("iron-vault"));
    assert_eq!(accounts.name(1000), None);
}

/// A host with root, the service account, one login account and an alias sharing its uid.
const PASSWD: &str = "root:x:0:0:root:/root:/bin/sh\n\
iron-vault:x:997:997::/var/lib/iron-vault:/usr/sbin/nologin\n\
code:x:1000:1000:Code:/home/code:/bin/bash\n\
code-alias:x:1000:1000::/home/code:/bin/bash\n";

/// A fresh file under the system temp directory holding `contents`, named for the test that writes it.
fn overflow_fixture(test: &str, contents: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("iv-overflowuid-{test}-{}", std::process::id()));
    std::fs::write(&path, contents).unwrap();
    path
}

/// [`PASSWD`] with the overflow uid read from `overflow_uid_file`.
fn directory_with(overflow_uid_file: &Path) -> Result<PasswdDirectory, ProfileError> {
    let paths = ServicePaths::for_profile(DeploymentProfile::Protected, &env()).unwrap();
    PasswdDirectory::new(Accounts::parse(PASSWD), &paths, overflow_uid_file)
}

fn directory() -> PasswdDirectory {
    directory_with(Path::new("/nonexistent/overflowuid")).unwrap()
}

fn account(name: &str) -> AccountName {
    name.parse().unwrap()
}

#[test]
fn the_directory_resolves_passwd_accounts() {
    let directory = directory();
    assert_eq!(directory.uid(&account("code")), Some(1000));
    assert_eq!(directory.uid(&account("code-alias")), Some(1000));
    assert_eq!(directory.uid(&account("root")), Some(0));
    assert_eq!(directory.uid(&account("iron-vault")), Some(997));
}

#[test]
fn an_account_missing_from_passwd_is_unknown() {
    assert_eq!(directory().uid(&account("ldap-user")), None);
}

#[test]
fn the_service_account_is_the_owner_of_the_service_paths() {
    assert_eq!(directory().service_account_uid(), SERVICE);
}

#[test]
fn the_overflow_uid_is_read_from_the_kernel_file() {
    let file = overflow_fixture("read", "65000\n");
    let directory = directory_with(&file);
    std::fs::remove_file(&file).unwrap();
    assert_eq!(directory.unwrap().overflow_uid(), 65000);
}

#[test]
fn a_missing_overflow_uid_file_means_the_kernel_default() {
    assert_eq!(directory().overflow_uid(), 65534);
}

#[test]
fn a_malformed_overflow_uid_file_is_an_error_naming_the_file_but_not_its_contents() {
    let file = overflow_fixture("garbage", "not-a-uid\n");
    let err = directory_with(&file).unwrap_err();
    std::fs::remove_file(&file).unwrap();
    assert_eq!(err, ProfileError::OverflowUidMalformed { path: file.clone() });
    let text = err.to_string();
    assert_eq!(text, format!("{} does not hold a uid", file.display()));
    assert!(!text.contains("not-a-uid"), "{text}");
}

#[test]
fn the_version_names_the_enabled_features() {
    let enabled: Vec<&str> = [
        ("dev-mode", cfg!(feature = "dev-mode")),
        ("test-support", cfg!(feature = "test-support")),
    ]
    .into_iter()
    .filter_map(|(name, on)| on.then_some(name))
    .collect();
    let features = if enabled.is_empty() {
        "none".to_string()
    } else {
        enabled.join(", ")
    };
    assert_eq!(version(), format!("{} (features: {features})", env!("CARGO_PKG_VERSION")));
}

#[test]
fn the_version_knows_every_cargo_feature() {
    let manifest: toml::Table = include_str!("../../Cargo.toml").parse().unwrap();
    let mut declared: Vec<&str> = manifest["features"].as_table().unwrap().keys().map(String::as_str).collect();
    let mut known: Vec<&str> = CARGO_FEATURES.iter().map(|(name, _)| *name).collect();
    declared.sort_unstable();
    known.sort_unstable();
    assert_eq!(known, declared, "add each feature in Cargo.toml's [features] to CARGO_FEATURES");
}

#[test]
fn protected_runs_only_as_the_service_account() {
    let as_uid = |invoking_uid| ProfileEnv { invoking_uid, ..env() };
    assert_eq!(require_service_account(DeploymentProfile::Protected, &as_uid(SERVICE)), Ok(()));
    assert_eq!(
        require_service_account(DeploymentProfile::Protected, &as_uid(0)),
        Err(ProfileError::NotServiceAccount { uid: 0 })
    );
    assert_eq!(
        require_service_account(DeploymentProfile::Protected, &as_uid(USER)),
        Err(ProfileError::NotServiceAccount { uid: USER })
    );
}

#[test]
fn protected_without_a_service_account_reports_it_missing() {
    let env = ProfileEnv {
        service_account_uid: None,
        ..env()
    };
    assert_eq!(
        require_service_account(DeploymentProfile::Protected, &env),
        Err(ProfileError::MissingServiceAccount { account: SERVICE_ACCOUNT })
    );
}

#[test]
fn development_passes_for_any_non_root_uid() {
    let env = ProfileEnv {
        invoking_uid: 4242,
        ..env()
    };
    assert_eq!(require_service_account(DeploymentProfile::Development, &env), Ok(()));
}

#[test]
fn the_not_service_account_message_names_the_account_and_no_path() {
    let message = require_service_account(DeploymentProfile::Protected, &env())
        .unwrap_err()
        .to_string();
    assert!(message.contains("`iron-vault`"), "{message}");
    assert!(message.contains("systemctl start iron-vault"), "{message}");
    assert!(!message.contains("/home/alice") && !message.contains("/run/user/1000"), "{message}");
}
