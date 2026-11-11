//! The Linux package's config man page (`packaging/linux/man/iron-vault-config.5`) is hand-written, so these tests keep
//! it in step with the parser: it must name every key and value the parser accepts, and its EXAMPLE section must be a
//! valid config.

use std::collections::BTreeSet;

use iron_vault_policy::{ParsedConfig, ValidatedConfig};

/// The page, read at build time so a change to it reruns these tests.
const PAGE: &str = include_str!("../../../../packaging/linux/man/iron-vault-config.5");

/// A key no table accepts, so the parser's refusal lists the keys, or values, that one table does accept.
const PROBE: &str = "zz_probe";

/// One document per table and per enumerated value, each refused only for [`PROBE`].
fn probes() -> [String; 11] {
    [
        format!("{PROBE} = 1\n"),
        format!("[listeners.a]\n{PROBE} = 1\n"),
        format!("[callers.a]\n{PROBE} = 1\n"),
        format!("[callers.a]\nlistener = \"l\"\nauth = \"{PROBE}\"\n"),
        format!("[routes.a]\n{PROBE} = 1\n"),
        format!("[routes.a]\nslot = {{ {PROBE} = 1 }}\n"),
        format!("[routes.a]\nrate_limit = {{ {PROBE} = 1 }}\n"),
        format!("[routes.a]\nconfirm = \"{PROBE}\"\n"),
        format!("[limits]\n{PROBE} = 1\n"),
        format!("[logging]\n{PROBE} = 1\n"),
        format!("[recovery]\n{PROBE} = 1\n"),
    ]
}

/// The names a refusal lists after "expected", which serde puts in backticks.
fn expected_names(refusal: &str) -> Vec<String> {
    let (_, expected) = refusal.split_once("expected").unwrap();
    expected.split('`').skip(1).step_by(2).map(str::to_owned).collect()
}

/// Every key and enumerated value the parser accepts, read from its own refusals.
fn accepted_names() -> BTreeSet<String> {
    probes()
        .iter()
        .flat_map(|body| {
            let refusal = ParsedConfig::from_toml(format!("schema_version = 1\n{body}").as_bytes())
                .unwrap_err()
                .to_string();
            assert!(refusal.contains(PROBE), "the probe was refused for something else: {refusal}");
            expected_names(&refusal)
        })
        .collect()
}

/// The words the page sets in bold, with roff's escaped hyphen made plain.
fn bold_words() -> BTreeSet<String> {
    PAGE.split("\\fB")
        .skip(1)
        .filter_map(|run| run.split("\\f").next())
        .flat_map(|run| {
            run.replace("\\-", "-")
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect()
}

/// The config between `.EX` and `.EE`, with roff's escaped hyphen made plain.
fn example() -> String {
    let (_, rest) = PAGE.split_once(".EX\n").unwrap();
    let (example, _) = rest.split_once(".EE\n").unwrap();
    example.replace("\\-", "-")
}

#[test]
fn the_page_names_every_key_and_value_the_parser_accepts() {
    let names = accepted_names();
    // A few the probes must find, so a change to the refusal's wording cannot pass by finding nothing.
    [
        "schema_version",
        "unix_socket",
        "token_hash",
        "isolated-network",
        "query",
        "per_seconds",
        "touch",
        "reminder_days",
    ]
    .iter()
    .for_each(|name| assert!(names.contains(*name), "the probes did not find {name}"));
    let bold = bold_words();
    names
        .iter()
        .for_each(|name| assert!(bold.contains(name), "iron-vault-config.5 does not name {name} in bold"));
}

#[test]
fn the_page_example_is_a_valid_config() {
    let parsed = ParsedConfig::from_toml(example().as_bytes()).unwrap();
    let config = ValidatedConfig::try_from(parsed).unwrap();
    assert_eq!(config.listeners().len(), 2);
    assert_eq!(config.callers().len(), 3);
    assert_eq!(config.routes().len(), 3);
}

#[test]
fn expected_names_reads_one_or_many() {
    assert_eq!(
        expected_names("unknown field `x`, expected `destination` at line 3"),
        ["destination"]
    );
    assert_eq!(expected_names("unknown variant `x`, expected `none` or `touch`"), ["none", "touch"]);
}
