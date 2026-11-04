//! The service's own account of what an approval changes (spec §3.2, design/config-approval.md "Approval summary").
//!
//! [`summarize`] diffs the pending validated config against the active one. It is a pure function of the two configs, so
//! the same inputs always give the same text: every collection is walked in `BTreeMap` or `BTreeSet` order. The
//! committed version, vault ID and digest are not known to this crate; the command that shows the summary writes that
//! header and puts [`ApprovalSummary::render`] below it. A token hash is never rendered, and every configured value is
//! escaped, so a hostile value cannot forge a summary line (spec §3.15).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;

use crate::caller::{CallerAuth, CallerConfig};
use crate::display::escaped;
use crate::limits::Limits;
use crate::listener::{Endpoint, ListenerConfig};
use crate::name::{CallerName, RouteName};
use crate::rate_limit::RateLimit;
use crate::route::RouteConfig;
use crate::slot::Slot;
use crate::validated::ValidatedConfig;

/// The line printed when the bytes differ but no section has an entry (whitespace or comments, spec §3.9).
const TEXT_ONLY: &str = "no policy change; text changed";

/// The line printed when there is no active config to diff against.
const NO_ACTIVE: &str = "no active config";

/// How an entry differs between the active and pending config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mark {
    Added,
    Removed,
    Changed,
}

impl Mark {
    fn symbol(self) -> char {
        match self {
            Mark::Added => '+',
            Mark::Removed => '-',
            Mark::Changed => '~',
        }
    }
}

/// One line of a section: a name and what happened to it. Both are already escaped.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    mark: Mark,
    name: String,
    detail: String,
}

impl Entry {
    fn line(&self) -> String {
        match self.detail.is_empty() {
            true => format!("  {} {}", self.mark.symbol(), self.name),
            false => format!("  {} {}: {}", self.mark.symbol(), self.name, self.detail),
        }
    }
}

/// A labelled configured value, already escaped, compared field by field.
type Field = (&'static str, String);

/// The diff of a pending config against the active one, in the order the owner reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalSummary {
    no_active_config: bool,
    callers: Vec<Entry>,
    grants: Vec<Entry>,
    routes: Vec<Entry>,
    listeners: Vec<Entry>,
    limits: Vec<Entry>,
}

/// Diffs `pending` against `active`; `None` means nothing is active, so everything is listed as added.
///
/// Call it only for a config whose bytes differ from the active config's: a summary with no entries renders as "no
/// policy change; text changed".
pub fn summarize(active: Option<&ValidatedConfig>, pending: &ValidatedConfig) -> ApprovalSummary {
    let (no_callers, no_routes, no_listeners) = (BTreeMap::new(), BTreeMap::new(), BTreeMap::new());
    let old_callers = active.map_or(&no_callers, ValidatedConfig::callers);
    let old_routes = active.map_or(&no_routes, ValidatedConfig::routes);
    let old_listeners = active.map_or(&no_listeners, ValidatedConfig::listeners);
    let old_limits = active.map_or_else(Limits::default, |c| *c.limits());
    ApprovalSummary {
        no_active_config: active.is_none(),
        callers: diff_maps(old_callers, pending.callers(), caller_fields, caller_extra),
        grants: grant_entries(old_callers, pending.callers()),
        routes: diff_maps(old_routes, pending.routes(), route_fields, |_, _| None),
        listeners: diff_maps(old_listeners, pending.listeners(), listener_fields, |_, _| None),
        limits: limit_entries(&old_limits, pending.limits()),
    }
}

impl ApprovalSummary {
    fn sections(&self) -> [(&'static str, &Vec<Entry>); 5] {
        [
            ("callers", &self.callers),
            ("route grants", &self.grants),
            ("routes", &self.routes),
            ("listeners", &self.listeners),
            ("limits", &self.limits),
        ]
    }

    /// Whether no section has an entry.
    pub fn is_empty(&self) -> bool {
        self.sections().iter().all(|(_, entries)| entries.is_empty())
    }

    /// The summary body: "no active config" when nothing is active, then each non-empty section in fixed order, or the
    /// text-only line when no section has an entry. Every line ends with a newline.
    pub fn render(&self) -> String {
        let intro = self.no_active_config.then(|| format!("{NO_ACTIVE}\n"));
        let sections = self
            .sections()
            .into_iter()
            .filter(|(_, entries)| !entries.is_empty())
            .map(|(title, entries)| {
                let lines: String = entries.iter().map(|entry| format!("{}\n", entry.line())).collect();
                format!("{title}:\n{lines}")
            });
        let body: String = intro.into_iter().chain(sections).collect();
        match self.is_empty() {
            true => format!("{body}{TEXT_ONLY}\n"),
            false => body,
        }
    }

    /// One line of counts per section, such as `callers: 1 added, 2 changed; route grants: none; ...`. Its length
    /// does not depend on the size of the config.
    pub fn headline(&self) -> String {
        let counts = self.sections().map(|(title, entries)| format!("{title}: {}", count_text(entries)));
        counts.join("; ")
    }
}

fn count_text(entries: &[Entry]) -> String {
    let counts = [(Mark::Added, "added"), (Mark::Removed, "removed"), (Mark::Changed, "changed")]
        .into_iter()
        .map(|(mark, word)| (entries.iter().filter(|e| e.mark == mark).count(), word))
        .filter(|(n, _)| *n > 0)
        .map(|(n, word)| format!("{n} {word}"))
        .collect::<Vec<_>>();
    match counts.is_empty() {
        true => "none".to_owned(),
        false => counts.join(", "),
    }
}

/// Escapes a configured value for one summary line.
fn esc(value: impl Display) -> String {
    escaped(&value.to_string())
}

fn join<T: Display>(items: impl IntoIterator<Item = T>) -> String {
    let joined = items.into_iter().map(esc).collect::<Vec<_>>().join(", ");
    match joined.is_empty() {
        true => "none".to_owned(),
        false => joined,
    }
}

/// Entries for every key in either map, in key order. `fields` lists a value's compared fields; `extra` adds a change
/// the fields cannot show, such as a replaced token.
fn diff_maps<K: Ord + Display, V: PartialEq>(
    old: &BTreeMap<K, V>,
    new: &BTreeMap<K, V>,
    fields: impl Fn(&V) -> Vec<Field>,
    extra: impl Fn(&V, &V) -> Option<String>,
) -> Vec<Entry> {
    let keys: BTreeSet<&K> = old.keys().chain(new.keys()).collect();
    keys.into_iter()
        .filter_map(|key| {
            let name = esc(key);
            match (old.get(key), new.get(key)) {
                (None, Some(added)) => Some(entry(Mark::Added, name, field_text(&fields(added)))),
                (Some(_), None) => Some(entry(Mark::Removed, name, String::new())),
                (Some(before), Some(after)) => {
                    changed_detail(&fields(before), &fields(after), extra(before, after)).map(|detail| entry(Mark::Changed, name, detail))
                }
                (None, None) => None,
            }
        })
        .collect()
}

fn entry(mark: Mark, name: String, detail: String) -> Entry {
    Entry { mark, name, detail }
}

fn field_text(fields: &[Field]) -> String {
    fields
        .iter()
        .map(|(label, value)| format!("{label} {value}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The fields that differ, old -> new, then any extra change; `None` when nothing differs.
fn changed_detail(before: &[Field], after: &[Field], extra: Option<String>) -> Option<String> {
    let changes: Vec<String> = before
        .iter()
        .zip(after)
        .filter(|((_, old), (_, new))| old != new)
        .map(|((label, old), (_, new))| format!("{label} {old} -> {new}"))
        .chain(extra)
        .collect();
    (!changes.is_empty()).then(|| changes.join("; "))
}

fn caller_fields(caller: &CallerConfig) -> Vec<Field> {
    let auth = match caller.auth() {
        CallerAuth::Token(_) => "token".to_owned(),
        CallerAuth::IsolatedNetwork => "isolated-network".to_owned(),
        CallerAuth::Peer(user) => format!("peer user {}", esc(user)),
    };
    let limits = caller
        .rate_limits()
        .iter()
        .map(|(route, limit)| format!("{} {}", esc(route), rate_text(*limit)));
    vec![
        ("listener", esc(caller.listener())),
        ("auth", auth),
        ("rate limits", join(limits.collect::<Vec<_>>())),
    ]
}

/// "token changed" when both callers use tokens and the hashes differ; the hash itself is never shown.
fn caller_extra(before: &CallerConfig, after: &CallerConfig) -> Option<String> {
    match (before.auth(), after.auth()) {
        (CallerAuth::Token(old), CallerAuth::Token(new)) if old != new => Some("token changed".to_owned()),
        _ => None,
    }
}

fn rate_text(limit: RateLimit) -> String {
    format!("{} per {}s burst {}", limit.requests(), limit.per_seconds(), limit.burst())
}

fn slot_text(slot: &Slot) -> String {
    match slot {
        Slot::Header(header) => format!("header {} format {}", esc(header.name()), esc(header.format())),
        Slot::Query(name) => format!("query {}", esc(name)),
        Slot::Basic => "basic".to_owned(),
    }
}

fn route_fields(route: &RouteConfig) -> Vec<Field> {
    let ca_file = route.ca_file().map_or_else(|| "none".to_owned(), esc);
    vec![
        ("prefix", esc(route.prefix())),
        ("upstream", esc(route.upstream())),
        ("credential", esc(route.credential())),
        ("slot", slot_text(route.slot())),
        ("ca file", ca_file),
        ("methods", join(route.methods().iter().map(|m| m.as_str()).collect::<BTreeSet<_>>())),
        ("paths", join(route.paths().iter().map(|p| p.as_str()).collect::<BTreeSet<_>>())),
        ("rate limit", rate_text(route.rate_limit())),
        ("confirm", format!("{:?}", route.confirm()).to_lowercase()),
    ]
}

fn listener_fields(listener: &ListenerConfig) -> Vec<Field> {
    let endpoint = match listener.endpoint() {
        Endpoint::UnixSocket(path) => format!("unix socket {}", esc(path)),
        Endpoint::Tcp { address, tls } => {
            let tls = tls.as_ref().map_or_else(
                || "no tls".to_owned(),
                |files| format!("tls cert {} key {}", esc(files.certificate()), esc(files.key())),
            );
            format!("tcp {}, {tls}", esc(address))
        }
    };
    let header = listener.token_header().map_or_else(|| "default".to_owned(), esc);
    vec![("endpoint", endpoint), ("token header", header)]
}

/// One line per caller whose granted routes differ: the routes granted and the routes revoked.
fn grant_entries(old: &BTreeMap<CallerName, CallerConfig>, new: &BTreeMap<CallerName, CallerConfig>) -> Vec<Entry> {
    let routes = |callers: &BTreeMap<CallerName, CallerConfig>, name: &CallerName| -> BTreeSet<RouteName> {
        callers.get(name).map(|c| c.routes().iter().cloned().collect()).unwrap_or_default()
    };
    let names: BTreeSet<&CallerName> = old.keys().chain(new.keys()).collect();
    names
        .into_iter()
        .filter_map(|name| {
            let (before, after) = (routes(old, name), routes(new, name));
            let granted: Vec<_> = after.difference(&before).collect();
            let revoked: Vec<_> = before.difference(&after).collect();
            let detail = [("granted", granted), ("revoked", revoked)]
                .into_iter()
                .filter(|(_, routes)| !routes.is_empty())
                .map(|(word, routes)| format!("{word} {}", join(routes)))
                .collect::<Vec<_>>()
                .join("; ");
            let mark = match (old.contains_key(name), new.contains_key(name)) {
                (false, _) => Mark::Added,
                (_, false) => Mark::Removed,
                _ => Mark::Changed,
            };
            (!detail.is_empty()).then(|| entry(mark, esc(name), detail))
        })
        .collect()
}

fn limit_entries(old: &Limits, new: &Limits) -> Vec<Entry> {
    let values = |l: &Limits| {
        [
            ("max_header_bytes", l.max_header_bytes()),
            ("max_header_count", l.max_header_count()),
            ("max_request_body_bytes", l.max_request_body_bytes()),
            ("max_decompressed_response_bytes", l.max_decompressed_response_bytes()),
            ("max_decompression_ratio", l.max_decompression_ratio()),
            ("request_timeout_secs", l.request_timeout_secs()),
            ("upstream_timeout_secs", l.upstream_timeout_secs()),
            ("max_connections", l.max_connections()),
        ]
    };
    values(old)
        .into_iter()
        .zip(values(new))
        .filter(|((_, before), (_, after))| before != after)
        .map(|((name, before), (_, after))| entry(Mark::Changed, name.to_owned(), format!("{before} -> {after}")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ParsedConfig;
    use crate::spec_example::SPEC_EXAMPLE;

    fn config(text: &str) -> ValidatedConfig {
        ValidatedConfig::try_from(ParsedConfig::from_toml(text.as_bytes()).expect("parses")).expect("validates")
    }

    fn spec() -> ValidatedConfig {
        config(SPEC_EXAMPLE)
    }

    fn edited(from: &str, to: &str) -> ValidatedConfig {
        assert!(SPEC_EXAMPLE.contains(from), "{from}");
        config(&SPEC_EXAMPLE.replacen(from, to, 1))
    }

    /// The rendered lines of the summary of `pending` against the spec example.
    fn lines(pending: &ValidatedConfig) -> Vec<String> {
        summarize(Some(&spec()), pending).render().lines().map(str::to_owned).collect()
    }

    #[test]
    fn first_approval_lists_everything_as_added() {
        let summary = summarize(None, &spec());
        let text = summary.render();
        assert!(text.starts_with("no active config\ncallers:\n  + brave-cli: listener loopback, auth token, rate limits none\n"));
        assert!(text.contains("route grants:\n  + brave-cli: granted brave\n"));
        assert!(text.contains("  + naomi-backoffice: granted brave, venice\n"));
        assert!(text.contains("routes:\n  + brave: prefix /brave, upstream https://api.search.brave.com"));
        assert!(text.contains("listeners:\n  + local: endpoint unix socket /run/iron-vault/proxy.sock, token header default\n"));
        assert!(!text.contains("limits:"), "defaults are not a change");
        assert!(!text.contains(TEXT_ONLY));
        assert_eq!(
            summary.headline(),
            "callers: 3 added; route grants: 3 added; routes: 3 added; listeners: 3 added; limits: none"
        );
    }

    #[test]
    fn identical_configs_render_the_text_only_line() {
        let summary = summarize(Some(&spec()), &spec());
        assert!(summary.is_empty());
        assert_eq!(summary.render(), "no policy change; text changed\n");
    }

    #[test]
    fn whitespace_and_comments_are_a_text_only_change() {
        let commented = config(&format!("# reviewed\n\n{SPEC_EXAMPLE}\n"));
        assert_eq!(lines(&commented), ["no policy change; text changed"]);
    }

    #[test]
    fn removed_caller_is_one_line_in_callers_and_one_in_grants() {
        let pending = config(&SPEC_EXAMPLE.replace(
            "[callers.fx-mcp]\nlistener = \"local\"\nauth = \"peer\"\nuser = \"fx-mcp\"\nroutes = [\"fx\"]\n",
            "",
        ));
        assert_eq!(
            lines(&pending),
            ["callers:", "  - fx-mcp", "route grants:", "  - fx-mcp: revoked fx"]
        );
    }

    #[test]
    fn changed_token_says_so_and_never_shows_the_hash() {
        let pending = edited("0123456789abcdef0011", "ffffffffffffffff0011");
        assert_eq!(lines(&pending), ["callers:", "  ~ brave-cli: token changed"]);
    }

    #[test]
    fn changed_peer_account_is_one_caller_line() {
        let pending = edited("user = \"fx-mcp\"", "user = \"code\"");
        assert_eq!(lines(&pending), ["callers:", "  ~ fx-mcp: auth peer user fx-mcp -> peer user code"]);
    }

    #[test]
    fn grant_change_alone_is_one_grants_line() {
        let pending = edited("routes = [\"fx\"]", "routes = [\"fx\", \"venice\"]");
        assert_eq!(lines(&pending), ["route grants:", "  ~ fx-mcp: granted venice"]);
    }

    #[test]
    fn each_route_field_change_is_one_routes_line() {
        let cases = [
            (
                "upstream = \"https://api.fx.example\"",
                "upstream = \"https://api.fx.example:8443/v2\"",
                "upstream https://api.fx.example/ -> ",
            ),
            (
                "credential = \"fx_key\"",
                "credential = \"fx_other\"",
                "credential fx_key -> fx_other",
            ),
            (
                "methods = [\"GET\"]\npaths = [\"/latest\"",
                "methods = [\"GET\", \"POST\"]\npaths = [\"/latest\"",
                "methods GET -> GET, POST",
            ),
            (
                "\"/historical/**\"]",
                "\"/historical/**\", \"/rates\"]",
                "paths /historical/**, /latest -> ",
            ),
            (
                "requests = 60, per_seconds = 60, burst = 10 }\n\n[routes.venice]",
                "requests = 30, per_seconds = 60, burst = 10 }\n\n[routes.venice]",
                "rate limit 60 per 60s burst 10 -> 30 per 60s burst 10",
            ),
            (
                "per_seconds = 60, burst = 10 }\n\n[routes.venice]",
                "per_seconds = 60, burst = 10 }\nconfirm = \"touch\"\n\n[routes.venice]",
                "confirm none -> touch",
            ),
        ];
        cases.iter().for_each(|(from, to, expected)| {
            let out = lines(&edited(from, to));
            assert_eq!(out.len(), 2, "{out:?}");
            assert_eq!(out[0], "routes:");
            assert!(out[1].starts_with("  ~ fx: ") && out[1].contains(expected), "{out:?}");
        });
    }

    #[test]
    fn listener_change_alone_is_one_listeners_line() {
        let pending = edited("127.0.0.1:7878", "127.0.0.1:7979");
        assert_eq!(
            lines(&pending),
            [
                "listeners:",
                "  ~ loopback: endpoint tcp 127.0.0.1:7878, no tls -> tcp 127.0.0.1:7979, no tls"
            ]
        );
    }

    #[test]
    fn limit_change_alone_is_one_limits_line() {
        let pending = config(&format!("{SPEC_EXAMPLE}\n[limits]\nmax_connections = 512\n"));
        assert_eq!(lines(&pending), ["limits:", "  ~ max_connections: 256 -> 512"]);
    }

    #[test]
    fn headline_counts_each_section() {
        let pending = config(&format!("{SPEC_EXAMPLE}\n[limits]\nmax_connections = 512\n").replace("\"/latest\"", "\"/new\""));
        assert_eq!(
            summarize(Some(&spec()), &pending).headline(),
            "callers: none; route grants: none; routes: 1 changed; listeners: none; limits: 1 changed"
        );
    }

    #[test]
    fn hostile_values_cannot_forge_a_line() {
        assert_eq!(esc("fx\n  + admin"), "fx\\n  + admin");
        assert_eq!(esc("a\u{202e}b\u{1b}[2J"), "a\\u{202e}b\\u{1b}[2J");
        let hostile = entry(Mark::Added, esc("x\n  - y"), esc("a\r\nroutes:"));
        assert_eq!(hostile.line(), "  + x\\n  - y: a\\r\\nroutes:");
    }

    #[test]
    fn same_inputs_give_identical_output() {
        let pending = edited("127.0.0.1:7878", "127.0.0.1:7979");
        let render = || summarize(Some(&spec()), &pending).render();
        assert_eq!(render(), render());
        assert_eq!(summarize(None, &pending).render(), summarize(None, &pending).render());
    }
}
