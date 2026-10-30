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
