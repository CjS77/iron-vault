use std::path::Path;

use clap::error::ErrorKind;

use super::*;

fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
    Cli::try_from_args(std::iter::once("iron-vault").chain(args.iter().copied()))
}

#[test]
fn serve_runs_the_service() {
    let cli = parse(&["serve"]).unwrap();
    assert_eq!(cli.command, Command::Serve);
    assert_eq!(cli.admin_socket, None);
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
    assert_eq!(parse(&["init"]).unwrap().command, Command::Init);
    assert_eq!(parse(&["init", "hunter2-correct"]).unwrap_err().exit_code(), 2);
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
