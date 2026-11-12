//! The Linux package's man pages, `packaging/linux/man/*.1`, generated from the same [`Cli`] the parser uses so they
//! cannot drift from `--help`. There is one page per command, because `clap_mangen` lists each subcommand as a page of
//! its own: `iron-vault.1` names `iron-vault-config(1)`, which names `iron-vault-config-approve(1)`.
//!
//! It is test-only code, so the release binary carries none of it. `cargo test` fails when the committed pages differ
//! from the generated ones, and `IRON_VAULT_BLESS_MAN_PAGES=1 cargo test -p iron-vault --bin iron-vault cli::man_page`
//! rewrites them.

use std::collections::BTreeMap;

use clap::CommandFactory;
use clap_mangen::Man;

use super::Cli;

/// The committed pages' directory, which the package installs as `/usr/share/man/man1`.
const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../packaging/linux/man");

/// The environment variable that makes the staleness test rewrite the pages instead of comparing them.
const BLESS: &str = "IRON_VAULT_BLESS_MAN_PAGES";

/// The heading of the section that [`without_version`] removes.
const VERSION_HEADING: &str = ".SH VERSION\n";

/// Every page, by file name.
fn pages() -> BTreeMap<String, String> {
    // `--help` is described on each page, so clap's `help` subcommand gets no page of its own.
    let mut cli = Cli::command().disable_help_subcommand(true);
    cli.build();
    pages_of(&cli).into_iter().collect()
}

/// The page for `cmd`, then the pages for each of its subcommands, depth first.
fn pages_of(cmd: &clap::Command) -> Vec<(String, String)> {
    let man = Man::new(cmd.clone()).source("Iron Vault").manual("Iron Vault Manual");
    std::iter::once((man.get_filename(), render(&man)))
        .chain(cmd.get_subcommands().filter(|sub| !sub.is_hide_set()).flat_map(pages_of))
        .collect()
}

/// One page's roff source, without its VERSION section.
fn render(man: &Man) -> String {
    let mut out = Vec::new();
    man.render(&mut out).unwrap();
    without_version(&String::from_utf8(out).unwrap())
}

/// `page` without its VERSION section, which holds the version and the build's feature list. Either would make every
/// release, and every feature build, change the pages.
fn without_version(page: &str) -> String {
    let Some(start) = page.find(VERSION_HEADING) else {
        return page.to_owned();
    };
    let rest = &page[start + VERSION_HEADING.len()..];
    let end = rest
        .find("\n.SH ")
        .map_or(page.len(), |next| start + VERSION_HEADING.len() + next + 1);
    format!("{}{}", &page[..start], &page[end..])
}

/// The committed pages, by file name. Only section 1 is generated: `iron-vault-config.5` beside them is hand-written,
/// so blessing never removes it.
fn committed() -> BTreeMap<String, String> {
    std::fs::read_dir(DIR)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "1"))
        .map(|path| {
            (
                path.file_name().unwrap().to_string_lossy().into_owned(),
                std::fs::read_to_string(&path).unwrap(),
            )
        })
        .collect()
}

/// Replaces the committed pages with `pages`, removing any page whose command is gone.
fn bless(pages: &BTreeMap<String, String>) {
    committed()
        .keys()
        .for_each(|name| std::fs::remove_file(format!("{DIR}/{name}")).unwrap());
    pages
        .iter()
        .for_each(|(name, page)| std::fs::write(format!("{DIR}/{name}"), page).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_pages_are_current() {
        // A dev-mode build leaves `init --host-unlock` out of the parser, so only the other builds match the pages.
        if cfg!(feature = "dev-mode") {
            return;
        }
        let expected = pages();
        if std::env::var_os(BLESS).is_some() {
            bless(&expected);
            return;
        }
        let names = |pages: &BTreeMap<String, String>| pages.keys().cloned().collect::<Vec<_>>();
        assert_eq!(
            names(&committed()),
            names(&expected),
            "{DIR} does not hold one page per command; {}",
            regenerate()
        );
        expected
            .iter()
            .for_each(|(name, page)| assert!(committed()[name] == *page, "{DIR}/{name} is out of date; {}", regenerate()));
    }

    fn regenerate() -> String {
        format!("regenerate the pages with `{BLESS}=1 cargo test -p iron-vault --bin iron-vault cli::man_page` and commit them")
    }

    #[test]
    fn every_listed_subcommand_has_a_page() {
        let pages = pages();
        [
            "iron-vault.1",
            "iron-vault-serve.1",
            "iron-vault-config.1",
            "iron-vault-config-approve.1",
        ]
        .iter()
        .for_each(|name| assert!(pages.contains_key(*name), "no page {name}"));
        assert!(!pages.contains_key("iron-vault-help.1"));
    }

    #[test]
    fn pages_are_deterministic_and_have_no_version() {
        assert_eq!(pages(), pages());
        pages().iter().for_each(|(name, page)| {
            assert!(!page.contains(env!("CARGO_PKG_VERSION")), "{name} names the version");
            assert!(!page.contains(VERSION_HEADING), "{name} has a VERSION section");
        });
    }

    #[test]
    fn without_version_removes_only_that_section() {
        assert_eq!(
            without_version(".SH NAME\nx\n.SH VERSION\nv1\n.SH AUTHORS\na\n"),
            ".SH NAME\nx\n.SH AUTHORS\na\n"
        );
        assert_eq!(without_version(".SH NAME\nx\n.SH VERSION\nv1\n"), ".SH NAME\nx\n");
        assert_eq!(without_version(".SH NAME\nx\n"), ".SH NAME\nx\n");
    }
}
