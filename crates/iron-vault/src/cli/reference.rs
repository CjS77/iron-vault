// SPDX-License-Identifier: MPL-2.0
//! The command reference in the book, `book/src/reference/cli.md`, generated from the same [`Cli`] the parser uses so
//! the page names every command and option and cannot drift from `--help`.
//!
//! It is test-only code, so the release binary carries none of it. The page keeps a hand-written introduction above
//! [`GENERATED_MARKER`]; the generator owns everything below it. `cargo test` fails when the committed page differs from
//! the generated one, and `IRON_VAULT_BLESS_CLI_REFERENCE=1 cargo test -p iron-vault --bin iron-vault cli::reference`
//! rewrites it.

use std::fmt::Write as _;

use clap::builder::PossibleValue;
use clap::{Arg, ArgAction, CommandFactory};

use super::Cli;

/// The line that ends the hand-written introduction. Everything after it is generated.
const GENERATED_MARKER: &str = "<!-- Generated from the CLI definition below this line. Do not edit by hand. -->";

/// The committed page.
const PAGE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../book/src/reference/cli.md");

/// The environment variable that makes the staleness test rewrite the page instead of comparing it.
const BLESS: &str = "IRON_VAULT_BLESS_CLI_REFERENCE";

/// The generated part of the page: one section per command, in definition order, depth first.
fn generated() -> String {
    let mut cli = Cli::command();
    // Building propagates global options and sets each subcommand's full name, as the parser sees them.
    cli.build();
    let mut out = String::new();
    write_command(&mut out, &mut cli, true);
    out
}

/// The commands the page documents, by full name: every command except clap's own `help` subcommand.
fn documented_commands() -> Vec<String> {
    let mut cli = Cli::command();
    cli.build();
    let mut names = Vec::new();
    collect_names(&cli, &mut names);
    names
}

/// Appends the full name of `cmd` and of each documented subcommand under it, depth first.
fn collect_names(cmd: &clap::Command, names: &mut Vec<String>) {
    names.push(full_name(cmd));
    cmd.get_subcommands()
        .filter(|sub| documented_subcommand(sub))
        .for_each(|sub| collect_names(sub, names));
}

/// Returns `true` if and only if the page documents `sub`: it is neither hidden nor the `help` subcommand clap adds,
/// since `--help` is described once, in the introduction.
fn documented_subcommand(sub: &clap::Command) -> bool {
    sub.get_name() != "help" && !sub.is_hide_set()
}

/// The command as the owner types it, such as `iron-vault config approve`, once the command is built.
fn full_name(cmd: &clap::Command) -> String {
    cmd.get_bin_name().unwrap_or(cmd.get_name()).to_owned()
}

/// Writes the section for `cmd`, then one for each documented subcommand. `top` marks the `iron-vault` command itself,
/// which also lists the global options and the text clap shows after the help.
fn write_command(out: &mut String, cmd: &mut clap::Command, top: bool) {
    let usage = cmd.render_usage().to_string();
    let synopsis = usage.strip_prefix("Usage: ").unwrap_or(&usage);
    let _ = write!(out, "\n## `{}`\n\n```text\n{synopsis}\n```\n", full_name(cmd));
    let about = cmd
        .get_long_about()
        .or(cmd.get_about())
        .map(ToString::to_string)
        .unwrap_or_default();
    let _ = writeln!(out, "\n{}", sentence(&about));
    write_arguments(out, cmd, top);
    if top && let Some(after) = cmd.get_after_help() {
        let _ = write!(out, "\n```text\n{}\n```\n", after.to_string().trim_end());
    }
    cmd.get_subcommands_mut()
        .filter(|sub| documented_subcommand(sub))
        .for_each(|sub| write_command(out, sub, false));
}

/// Lists the arguments and options of `cmd`. Global options are listed once, on the top-level command.
fn write_arguments(out: &mut String, cmd: &clap::Command, top: bool) {
    let args: Vec<&Arg> = cmd
        .get_arguments()
        .filter(|arg| documented(arg) && (top || !arg.is_global_set()))
        .collect();
    if args.is_empty() {
        return;
    }
    out.push('\n');
    args.iter().for_each(|arg| write_argument(out, arg, top));
}

/// Returns `true` if and only if `arg` is one of the command's own visible arguments, not clap's `--help` or
/// `--version`.
fn documented(arg: &Arg) -> bool {
    !arg.is_hide_set()
        && !matches!(
            arg.get_action(),
            ArgAction::Help | ArgAction::HelpShort | ArgAction::HelpLong | ArgAction::Version
        )
}

/// Writes one argument as a list item, with its facts (required, repeatable, global, default) and possible values
/// nested under it.
fn write_argument(out: &mut String, arg: &Arg, top: bool) {
    let help = arg.get_long_help().or(arg.get_help()).map(ToString::to_string).unwrap_or_default();
    let _ = writeln!(out, "- `{}`: {}", argument_form(arg), sentence(&help));
    let facts = [
        arg.is_required_set().then(|| "required".to_owned()),
        repeatable(arg).then(|| "repeatable".to_owned()),
        (top && arg.is_global_set()).then(|| "global: it may also follow the command".to_owned()),
        default_value(arg),
    ];
    facts.into_iter().flatten().for_each(|fact| {
        let _ = writeln!(out, "  - {fact}");
    });
    write_possible_values(out, arg);
}

/// How `arg` is written on the command line: `<NAME>`, `--flag` or `--option <VALUE>`.
fn argument_form(arg: &Arg) -> String {
    let values = arg
        .get_value_names()
        .map(|names| names.iter().map(|name| format!("<{name}>")).collect::<Vec<_>>().join(" "));
    match (arg.get_long(), values) {
        (Some(long), Some(values)) if takes_value(arg) => format!("--{long} {values}"),
        (Some(long), _) => format!("--{long}"),
        (None, Some(values)) => values,
        (None, None) => format!("<{}>", arg.get_id().as_str().to_uppercase()),
    }
}

/// Returns `true` if and only if `arg` takes a value, as opposed to a flag.
fn takes_value(arg: &Arg) -> bool {
    matches!(arg.get_action(), ArgAction::Set | ArgAction::Append)
}

/// Returns `true` if and only if `arg` may be given more than once.
fn repeatable(arg: &Arg) -> bool {
    matches!(arg.get_action(), ArgAction::Append)
}

/// The `default:` fact for an argument that takes a value and has a default.
fn default_value(arg: &Arg) -> Option<String> {
    let defaults = arg.get_default_values();
    // A flag's implicit `false` is not a default worth stating.
    (takes_value(arg) && !defaults.is_empty()).then(|| {
        let values = defaults
            .iter()
            .map(|value| format!("`{}`", value.to_string_lossy()))
            .collect::<Vec<_>>();
        format!("default: {}", values.join(", "))
    })
}

/// Writes the visible values `arg` accepts, each with its help, when clap knows a fixed set.
fn write_possible_values(out: &mut String, arg: &Arg) {
    let values: Vec<PossibleValue> = arg.get_possible_values().into_iter().filter(|value| !value.is_hide_set()).collect();
    if values.is_empty() {
        return;
    }
    let _ = writeln!(out, "  - possible values:");
    values.iter().for_each(|value| {
        let help = value
            .get_help()
            .map(|help| format!(": {}", sentence(&help.to_string())))
            .unwrap_or_default();
        let _ = writeln!(out, "    - `{}`{help}", value.get_name());
    });
}

/// `text` ending in a full stop: clap drops the doc comment's last full stop from a one-paragraph help.
fn sentence(text: &str) -> String {
    let text = text.trim_end();
    match text.chars().last() {
        None => String::new(),
        Some('.' | ':' | '?' | '!') => text.to_owned(),
        Some(_) => format!("{text}."),
    }
}

/// The committed page's hand-written introduction, up to and including [`GENERATED_MARKER`].
fn introduction(page: &str) -> &str {
    page.find(GENERATED_MARKER).map_or(page, |at| &page[..at + GENERATED_MARKER.len()])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn committed() -> String {
        std::fs::read_to_string(PAGE).unwrap()
    }

    #[test]
    fn committed_page_is_current() {
        // A dev-mode build leaves `init --host-unlock` out of the parser, so only the other builds match the page. The page's
        // introduction names the option.
        if cfg!(feature = "dev-mode") {
            return;
        }
        let page = committed();
        assert!(page.contains(GENERATED_MARKER), "{PAGE} lost its generated-part marker");
        let expected = format!("{}\n{}", introduction(&page), generated());
        if std::env::var_os(BLESS).is_some() {
            std::fs::write(PAGE, &expected).unwrap();
            return;
        }
        assert!(
            page == expected,
            "{PAGE} is out of date with the CLI definition; regenerate it with \
             `{BLESS}=1 cargo test -p iron-vault --bin iron-vault cli::reference` and commit the result"
        );
    }

    #[test]
    fn page_names_every_command() {
        let page = generated();
        let names = documented_commands();
        [
            "iron-vault config approve",
            "iron-vault recovery check",
            "iron-vault serve",
            "iron-vault completions",
        ]
        .iter()
        .for_each(|name| assert!(names.iter().any(|n| n == name), "{name} is not a documented command"));
        names
            .iter()
            .for_each(|name| assert!(page.contains(&format!("\n## `{name}`\n")), "the page has no section for {name}"));
    }

    #[test]
    fn page_names_every_option_and_possible_value() {
        let page = generated();
        [
            "`--admin-socket <PATH>`",
            "`--origin <ORIGIN>`",
            "`--kind <KIND>`",
            "`--log-to-stdout`",
            "`<FILE>`",
            "`<SHELL>`",
        ]
        .iter()
        .for_each(|form| assert!(page.contains(form), "the page does not name {form}"));
        assert!(page.contains("    - `basic`: A username and password"));
        assert!(page.contains("  - default: `static`"));
    }

    #[test]
    fn page_is_deterministic_and_has_no_version() {
        assert_eq!(generated(), generated());
        assert!(!generated().contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn sentence_restores_the_full_stop_clap_drops() {
        assert_eq!(sentence("Print a script"), "Print a script.");
        assert_eq!(sentence("Done."), "Done.");
        assert_eq!(sentence("as `Basic`"), "as `Basic`.");
        assert_eq!(sentence(""), "");
    }

    #[test]
    fn introduction_ends_at_the_marker() {
        let page = format!("# CLI\n\nintro\n\n{GENERATED_MARKER}\n## old\n");
        assert_eq!(introduction(&page), format!("# CLI\n\nintro\n\n{GENERATED_MARKER}"));
    }
}
