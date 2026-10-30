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

#[test]
fn the_version_names_the_enabled_features() {
    let features = if cfg!(feature = "dev-mode") { "dev-mode" } else { "none" };
    assert_eq!(version(), format!("{} (features: {features})", env!("CARGO_PKG_VERSION")));
}
