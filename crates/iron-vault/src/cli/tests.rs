use std::path::Path;

use clap::error::ErrorKind;

use super::*;

fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
    Cli::try_from_args(std::iter::once("iron-vault").chain(args.iter().copied()))
}

#[test]
fn serve_runs_the_service() {
    let cli = parse(&["serve"]).unwrap();
    assert_eq!(cli.command, Command::Serve { log_to_stdout: false });
    assert_eq!(cli.admin_socket, None);
}

#[test]
fn serve_log_to_stdout_selects_stdout_and_takes_no_path() {
    assert_eq!(
        parse(&["serve", "--log-to-stdout"]).unwrap().command,
        Command::Serve { log_to_stdout: true }
    );
    assert_eq!(parse(&["serve", "--log-to-stdout=/tmp/x"]).unwrap_err().exit_code(), 2);
    assert_eq!(parse(&["serve", "--log-destination", "/tmp/x"]).unwrap_err().exit_code(), 2);
}

#[test]
fn ping_is_a_client_command() {
    assert_eq!(parse(&["ping"]).unwrap().command, Command::Ping);
}

#[test]
fn status_is_a_client_command_and_not_ready_has_its_own_exit_code() {
    assert_eq!(parse(&["status"]).unwrap().command, Command::Status);
    assert_eq!(Exit::NotReady as u8, 4);
    assert!(EXIT_CODES.contains("4  `status`"));
}

#[test]
fn unlock_is_a_client_command_without_arguments() {
    assert_eq!(parse(&["unlock"]).unwrap().command, Command::Unlock);
    assert_eq!(parse(&["unlock", "hunter2"]).unwrap_err().exit_code(), 2);
}

#[test]
fn lock_is_a_client_command() {
    assert_eq!(parse(&["lock"]).unwrap().command, Command::Lock);
}

#[test]
fn caller_token_is_a_client_command_without_arguments() {
    assert_eq!(parse(&["caller-token"]).unwrap().command, Command::CallerToken);
    assert_eq!(parse(&["caller-token", "fx-mcp"]).unwrap_err().exit_code(), 2);
}

#[test]
fn init_is_a_client_command_without_arguments() {
    assert_eq!(parse(&["init"]).unwrap().command, Command::Init { host_unlock: false });
    assert_eq!(parse(&["init", "hunter2-correct"]).unwrap_err().exit_code(), 2);
}

/// A dev-mode build has no host unlock to enrol, so its parser does not know the flag.
#[test]
fn init_host_unlock_is_accepted_by_every_build_but_dev_mode() {
    let parsed = parse(&["init", "--host-unlock"]);
    match cfg!(feature = "dev-mode") {
        false => assert_eq!(parsed.unwrap().command, Command::Init { host_unlock: true }),
        true => assert_eq!(parsed.unwrap_err().exit_code(), 2),
    }
}

#[test]
fn recipient_list_is_a_client_command_without_arguments() {
    assert_eq!(
        parse(&["recipient", "list"]).unwrap().command,
        Command::Recipient(RecipientCommand::List)
    );
    assert_eq!(parse(&["recipient", "list", "age1x"]).unwrap_err().exit_code(), 2);
    assert_eq!(parse(&["recipient"]).unwrap_err().exit_code(), 2);
}

#[test]
fn recipient_add_takes_a_key_and_requires_a_label() {
    assert_eq!(
        parse(&["recipient", "add", "age1abc", "--label", "alice laptop"]).unwrap().command,
        Command::Recipient(RecipientCommand::Add {
            recipient: Some("age1abc".to_owned()),
            recovery: false,
            host_unlock: false,
            label: "alice laptop".to_owned()
        })
    );
    assert_eq!(
        parse(&["recipient", "add", "--recovery", "--label", "recovery 2026"])
            .unwrap()
            .command,
        Command::Recipient(RecipientCommand::Add {
            recipient: None,
            recovery: true,
            host_unlock: false,
            label: "recovery 2026".to_owned()
        })
    );
    assert_eq!(
        parse(&["recipient", "add", "age1abc", "--recovery", "--label", "x"])
            .unwrap_err()
            .exit_code(),
        2
    );
    assert_eq!(parse(&["recipient", "add", "age1abc"]).unwrap_err().exit_code(), 2);
    assert_eq!(parse(&["recipient", "add", "--label", "x"]).unwrap_err().exit_code(), 2);
}

#[test]
fn recipient_add_host_unlock_takes_a_key_and_conflicts_with_recovery() {
    assert_eq!(
        parse(&["recipient", "add", "--host-unlock", "age1abc", "--label", "host unlock, new TPM"])
            .unwrap()
            .command,
        Command::Recipient(RecipientCommand::Add {
            recipient: Some("age1abc".to_owned()),
            recovery: false,
            host_unlock: true,
            label: "host unlock, new TPM".to_owned()
        })
    );
    let usage = |args: &[&str]| parse(args).unwrap_err().exit_code();
    assert_eq!(usage(&["recipient", "add", "--host-unlock", "--recovery", "--label", "x"]), 2);
    assert_eq!(
        usage(&["recipient", "add", "age1abc", "--host-unlock", "--recovery", "--label", "x"]),
        2
    );
    assert_eq!(usage(&["recipient", "add", "--host-unlock", "--label", "x"]), 2);
}

#[test]
fn recovery_check_is_a_client_command_without_arguments() {
    assert_eq!(
        parse(&["recovery", "check"]).unwrap().command,
        Command::Recovery(RecoveryCommand::Check)
    );
    assert_eq!(parse(&["recovery", "check", "AGE-SECRET-KEY-1X"]).unwrap_err().exit_code(), 2);
    assert_eq!(parse(&["recovery"]).unwrap_err().exit_code(), 2);
}

#[test]
fn config_approve_takes_one_required_file() {
    let command = Command::Config(ConfigCommand::Approve {
        file: PathBuf::from("proposed.toml"),
    });
    assert_eq!(parse(&["config", "approve", "proposed.toml"]).unwrap().command, command);
    assert_eq!(parse(&["config", "approve"]).unwrap_err().exit_code(), 2);
    assert_eq!(parse(&["config", "approve", "a.toml", "b.toml"]).unwrap_err().exit_code(), 2);
    assert_eq!(Exit::Usage as u8, 2);
}

#[test]
fn admin_socket_overrides_the_path_before_or_after_the_command() {
    let before = parse(&["--admin-socket", "/tmp/fwd.sock", "ping"]).unwrap();
    let after = parse(&["ping", "--admin-socket", "/tmp/fwd.sock"]).unwrap();
    assert_eq!(before.admin_socket.as_deref(), Some(Path::new("/tmp/fwd.sock")));
    assert_eq!(after.admin_socket.as_deref(), Some(Path::new("/tmp/fwd.sock")));
}

#[test]
fn serve_refuses_an_admin_socket_override() {
    let error = parse(&["serve", "--admin-socket", "/tmp/fwd.sock"]).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
    assert_eq!(error.exit_code(), 2);
}

#[test]
fn version_names_the_build_features() {
    let error = parse(&["--version"]).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::DisplayVersion);
    assert_eq!(error.exit_code(), 0);
    assert_eq!(error.to_string(), format!("iron-vault {}\n", deployment::version()));
}

#[test]
fn an_unknown_command_is_a_usage_error() {
    let error = parse(&["unlock-everything"]).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidSubcommand);
    assert_eq!(error.exit_code(), 2);
}

#[test]
fn no_command_shows_help_as_a_usage_error() {
    let error = parse(&[]).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand);
    assert_eq!(error.exit_code(), 2);
}

#[test]
fn help_lists_the_exit_codes() {
    let help = Cli::command().render_help().to_string();
    assert!(help.contains(EXIT_CODES), "{help}");
}

/// `add`'s parsed arguments: the name, the kind, and each origin's host text and port.
type AddArgs = (String, KindArg, Vec<(String, u16)>);

/// The `add` command's arguments, or the usage error.
fn add(args: &[&str]) -> Result<AddArgs, clap::Error> {
    match parse(&[&["add"], args].concat())?.command {
        Command::Add { name, kind, origins } => Ok((
            name,
            kind,
            origins.iter().map(|(host, port)| (host.to_string(), port.get())).collect(),
        )),
        other => panic!("parsed as {other:?}"),
    }
}

#[test]
fn rm_takes_one_name_and_nothing_else() {
    assert_eq!(
        parse(&["rm", "old_key"]).unwrap().command,
        Command::Rm {
            name: "old_key".to_owned()
        }
    );
    assert!(parse(&["rm"]).is_err());
    assert!(parse(&["rm", "a", "b"]).is_err());
}

#[test]
fn add_takes_a_name_and_origins_and_defaults_to_a_static_kind() {
    let (name, kind, origins) = add(&["fx", "--origin", "api.fx.example"]).unwrap();
    assert_eq!((name.as_str(), kind), ("fx", KindArg::Static));
    assert_eq!(origins, [("api.fx.example".to_owned(), 443)]);
    assert_eq!(CredentialKind::from(kind), CredentialKind::Static);
}

#[test]
fn add_accepts_every_origin_form() {
    let args = [
        "fx",
        "--origin",
        "a.example",
        "--origin",
        "B.example:8443",
        "--origin",
        "[::1]",
        "--origin",
        "[2001:db8::1]:1",
    ];
    let (_, _, origins) = add(&args).unwrap();
    let expected = [("a.example", 443), ("b.example", 8443), ("[::1]", 443), ("[2001:db8::1]", 1)];
    assert_eq!(origins, expected.map(|(host, port)| (host.to_owned(), port)));
}

#[test]
fn add_takes_a_basic_kind() {
    let (_, kind, _) = add(&["fx", "--kind", "basic", "--origin", "x"]).unwrap();
    assert_eq!(CredentialKind::from(kind), CredentialKind::Basic);
    assert_eq!(add(&["fx", "--kind", "oauth", "--origin", "x"]).unwrap_err().exit_code(), 2);
}

#[test]
fn add_refuses_a_scheme_a_path_or_a_bad_port_without_echoing_it() {
    ["https://x", "x/path", "x:0", "x:65536"].into_iter().for_each(|origin| {
        let error = add(&["fx", "--origin", origin]).unwrap_err();
        assert_eq!((error.kind(), error.exit_code()), (ErrorKind::ValueValidation, 2), "{origin}");
        assert!(!error.to_string().contains(origin), "{error}");
    });
}

#[test]
fn add_needs_an_origin_and_at_most_32() {
    let error = add(&["fx"]).unwrap_err();
    assert_eq!((error.kind(), error.exit_code()), (ErrorKind::MissingRequiredArgument, 2));
    let too_many: Vec<&str> = std::iter::once("fx").chain(["--origin", "x"].repeat(33)).collect();
    assert_eq!(add(&too_many).unwrap_err().kind(), ErrorKind::TooManyValues);
    let enough: Vec<&str> = std::iter::once("fx").chain(["--origin", "x"].repeat(32)).collect();
    assert_eq!(add(&enough).unwrap().2.len(), 32);
}

#[test]
fn replace_takes_adds_arguments() {
    let parsed = parse(&[
        "replace",
        "fx",
        "--kind",
        "basic",
        "--origin",
        "a.example",
        "--origin",
        "b.example:8443",
    ])
    .unwrap();
    let Command::Replace { name, kind, origins } = parsed.command else {
        panic!("parsed as {:?}", parsed.command);
    };
    let origins: Vec<_> = origins.iter().map(|(host, port)| (host.to_string(), port.get())).collect();
    assert_eq!((name.as_str(), kind), ("fx", KindArg::Basic));
    assert_eq!(origins, [("a.example".to_owned(), 443), ("b.example".to_owned(), 8443)]);
    let defaulted = parse(&["replace", "fx", "--origin", "x"]).unwrap();
    assert!(matches!(defaulted.command, Command::Replace { kind: KindArg::Static, .. }));
}

#[test]
fn replace_needs_an_origin_and_at_most_32() {
    assert_eq!(parse(&["replace", "fx"]).unwrap_err().kind(), ErrorKind::MissingRequiredArgument);
    let too_many: Vec<&str> = ["replace", "fx"].into_iter().chain(["--origin", "x"].repeat(33)).collect();
    let error = parse(&too_many).unwrap_err();
    assert_eq!((error.kind(), error.exit_code()), (ErrorKind::TooManyValues, 2));
    assert!(error.to_string().contains("`replace` takes at most 32"), "{error}");
}

#[test]
fn completions_bash_parses_and_unknown_shell_lists_bash() {
    assert_eq!(
        parse(&["completions", "bash"]).unwrap().command,
        Command::Completions {
            shell: CompletionShell::Bash
        }
    );
    let err = parse(&["completions", "tcsh"]).unwrap_err();
    assert_eq!(err.exit_code(), 2);
    assert!(err.to_string().contains("bash"), "{err}");
}

fn bash_script() -> String {
    String::from_utf8(completions::script(CompletionShell::Bash)).unwrap()
}

// clap_complete turns the `-` in the binary name into `__` in the function name.
#[test]
fn bash_script_defines_the_function_and_names_every_command() {
    let script = bash_script();
    assert!(script.contains("_iron__vault()"), "{script}");
    let command = Cli::command();
    let missing: Vec<_> = command
        .get_subcommands()
        .map(|c| c.get_name())
        .chain(["approve"])
        .filter(|name| !script.contains(name))
        .collect();
    assert!(missing.is_empty(), "missing {missing:?}");
}

#[test]
fn bash_script_is_deterministic() {
    assert_eq!(bash_script(), bash_script());
}

#[test]
fn bash_script_passes_bash_syntax_check() {
    use std::io::Write as _;
    use std::process::{Command as Process, Stdio};
    let Ok(mut child) = Process::new("bash").arg("-n").stdin(Stdio::piped()).spawn() else {
        eprintln!("skipped: bash is not on PATH");
        return;
    };
    child.stdin.take().unwrap().write_all(bash_script().as_bytes()).unwrap();
    assert!(child.wait().unwrap().success());
}

#[test]
fn a_closed_pipe_is_a_typed_error() {
    struct Closed;
    impl std::io::Write for Closed {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    assert!(matches!(
        completions::write_script(&mut Closed, CompletionShell::Bash),
        Err(completions::CompletionsError::Write(_))
    ));
}
