//! The service's own account of what an approval changes (spec §5, design/config-approval.md "Approval summary").
//!
//! [`summarize`] diffs the pending validated config against the active one. It is a pure function of the two configs, so
//! the same inputs always give the same text: every collection is walked in `BTreeMap` or `BTreeSet` order. The
//! committed version, vault ID and digest are not known to this crate; the command that shows the summary writes that
//! header and puts [`ApprovalSummary::render`] below it. A token hash is never rendered, and every configured value is
//! escaped, so a hostile value cannot forge a summary line (spec §18).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;

use crate::caller::{CallerAuth, CallerConfig};
use crate::confirmation::Confirmation;
use crate::display::{escaped, quoted};
use crate::limits::Limits;
use crate::listener::{Endpoint, ListenerConfig};
use crate::log_destination::LogDestinationSetting;
use crate::name::{CallerName, RouteName};
use crate::rate_limit::RateLimit;
use crate::reminder_interval::ReminderInterval;
use crate::route::RouteConfig;
use crate::slot::Slot;
use crate::validated::ValidatedConfig;

/// The line printed when the bytes differ but no section has an entry (whitespace or comments, spec §12).
const TEXT_ONLY: &str = "no policy change; text changed";

/// The line printed, with the committed version, when the pending config's bytes equal the active config's: the
/// approval only signs the same config again, as when an approval signer is rotated.
fn same_config(version: u64) -> String {
    format!("no change; same config as version {version}")
}

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
    /// The committed version whose config the pending bytes repeat, when they are identical.
    same_as: Option<u64>,
    callers: Vec<Entry>,
    grants: Vec<Entry>,
    routes: Vec<Entry>,
    listeners: Vec<Entry>,
    limits: Vec<Entry>,
    logging: Vec<Entry>,
    recovery: Vec<Entry>,
}

/// Diffs `pending` against `active`; `None` means nothing is active, so everything is listed as added.
///
/// Call it only for a config whose bytes differ from the active config's: a summary with no entries renders as "no
/// policy change; text changed". For identical bytes use [`ApprovalSummary::same_config`].
pub fn summarize(active: Option<&ValidatedConfig>, pending: &ValidatedConfig) -> ApprovalSummary {
    let (no_callers, no_routes, no_listeners) = (BTreeMap::new(), BTreeMap::new(), BTreeMap::new());
    let old_callers = active.map_or(&no_callers, ValidatedConfig::callers);
    let old_routes = active.map_or(&no_routes, ValidatedConfig::routes);
    let old_listeners = active.map_or(&no_listeners, ValidatedConfig::listeners);
    let old_limits = active.map_or_else(Limits::default, |c| *c.limits());
    ApprovalSummary {
        no_active_config: active.is_none(),
        same_as: None,
        callers: diff_maps(old_callers, pending.callers(), caller_fields, caller_extra),
        grants: grant_entries(old_callers, pending.callers()),
        routes: diff_maps(old_routes, pending.routes(), route_fields, |_, _| None),
        listeners: diff_maps(old_listeners, pending.listeners(), listener_fields, |_, _| None),
        limits: limit_entries(&old_limits, pending.limits()),
        logging: logging_entries(active.and_then(ValidatedConfig::log_destination), pending.log_destination()),
        recovery: recovery_entries(active.and_then(ValidatedConfig::recovery_reminder), pending.recovery_reminder()),
    }
}

impl ApprovalSummary {
    /// The summary of a pending config whose bytes equal the config committed as `version`: it has no entries and
    /// renders as "no change; same config as version N", so the owner sees the approval only signs the config again.
    pub fn same_config(version: u64) -> Self {
        Self {
            no_active_config: false,
            same_as: Some(version),
            callers: Vec::new(),
            grants: Vec::new(),
            routes: Vec::new(),
            listeners: Vec::new(),
            limits: Vec::new(),
            logging: Vec::new(),
            recovery: Vec::new(),
        }
    }

    fn sections(&self) -> [(&'static str, &Vec<Entry>); 7] {
        [
            ("callers", &self.callers),
            ("route grants", &self.grants),
            ("routes", &self.routes),
            ("listeners", &self.listeners),
            ("limits", &self.limits),
            ("logging", &self.logging),
            ("recovery", &self.recovery),
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
        match (self.same_as, self.is_empty()) {
            (Some(version), _) => format!("{}\n", same_config(version)),
            (None, true) => format!("{body}{TEXT_ONLY}\n"),
            (None, false) => body,
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

/// A free-text configured value in double quotes, escaped, so it cannot pass for the summary's own separators.
fn quote(value: impl Display) -> String {
    quoted(&value.to_string())
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
        Slot::Header(header) => format!("header {} format {}", esc(header.name()), quote(header.format())),
        Slot::Query(name) => format!("query {}", esc(name)),
        Slot::Basic => "basic".to_owned(),
    }
}

fn route_fields(route: &RouteConfig) -> Vec<Field> {
    let ca_file = route.ca_file().map_or_else(|| "none".to_owned(), quote);
    vec![
        ("prefix", esc(route.prefix())),
        ("upstream", esc(route.upstream())),
        ("credential", esc(route.credential())),
        ("slot", slot_text(route.slot())),
        ("ca file", ca_file),
        ("methods", join(route.methods().iter().map(|m| m.as_str()).collect::<BTreeSet<_>>())),
        ("paths", join(route.paths().iter().map(|p| p.as_str()).collect::<BTreeSet<_>>())),
        ("rate limit", rate_text(route.rate_limit())),
        ("confirm", confirm_text(route.confirm()).to_owned()),
    ]
}

fn confirm_text(confirm: Confirmation) -> &'static str {
    match confirm {
        Confirmation::None => "none",
        Confirmation::Touch => "touch",
    }
}

fn listener_fields(listener: &ListenerConfig) -> Vec<Field> {
    let endpoint = match listener.endpoint() {
        Endpoint::UnixSocket(path) => format!("unix socket {}", quote(path)),
        Endpoint::Tcp { address, tls } => {
            let tls = tls.as_ref().map_or_else(
                || "no tls".to_owned(),
                |files| format!("tls cert {} key {}", quote(files.certificate()), quote(files.key())),
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

/// The reminder shown when the log moves to a directory, because the shipped logrotate rule names only the default one.
const LOGROTATE_REMINDER: &str = "add a logrotate rule for the new directory";

/// How a destination reads in the summary. `None` is shown as `default`, not as the bootstrap destination it resolves
/// to, so the text depends only on the two configs and not on the deployment profile.
fn destination_text(setting: Option<&LogDestinationSetting>) -> String {
    match setting {
        None => "default".to_owned(),
        Some(LogDestinationSetting::Stdout) => "stdout".to_owned(),
        Some(LogDestinationSetting::Directory(path)) => quote(path),
    }
}

/// One line when the destination changed, including a change to or from the default; a move to a directory adds the
/// logrotate reminder.
fn logging_entries(old: Option<&LogDestinationSetting>, new: Option<&LogDestinationSetting>) -> Vec<Entry> {
    let reminder = matches!(new, Some(LogDestinationSetting::Directory(_))).then(|| format!("; {LOGROTATE_REMINDER}"));
    let detail = format!(
        "{} -> {}{}",
        destination_text(old),
        destination_text(new),
        reminder.unwrap_or_default()
    );
    (old != new)
        .then(|| entry(Mark::Changed, "destination".to_owned(), detail))
        .into_iter()
        .collect()
}

/// How an interval reads in the summary. `None` is shown as `default`, not as 90, so adding an explicit 90 is a visible
/// change, as it is for the log destination.
fn interval_text(interval: Option<ReminderInterval>) -> String {
    interval.map_or_else(|| "default".to_owned(), |i| i.days().to_string())
}

/// One line when the `[recovery]` setting changed, including a change to or from the default.
fn recovery_entries(old: Option<ReminderInterval>, new: Option<ReminderInterval>) -> Vec<Entry> {
    (old != new)
        .then(|| {
            let detail = format!("every {} -> {} days", interval_text(old), interval_text(new));
            entry(Mark::Changed, "reminder".to_owned(), detail)
        })
        .into_iter()
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
        assert!(text.contains("listeners:\n  + local: endpoint unix socket \"/run/iron-vault/proxy.sock\", token header default\n"));
        assert!(!text.contains("limits:"), "defaults are not a change");
        assert!(!text.contains(TEXT_ONLY));
        assert_eq!(
            summary.headline(),
            "callers: 3 added; route grants: 3 added; routes: 3 added; listeners: 3 added; limits: none; logging: none; recovery: none"
        );
    }

    #[test]
    fn identical_configs_render_the_text_only_line() {
        let summary = summarize(Some(&spec()), &spec());
        assert!(summary.is_empty());
        assert_eq!(summary.render(), "no policy change; text changed\n");
    }

    #[test]
    fn identical_bytes_render_the_same_config_line() {
        let summary = ApprovalSummary::same_config(7);
        assert!(summary.is_empty());
        assert_eq!(summary.render(), "no change; same config as version 7\n");
        assert_eq!(
            summary.headline(),
            "callers: none; route grants: none; routes: none; listeners: none; limits: none; logging: none; recovery: none"
        );
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

    const FX_LIMIT_END: &str = "per_seconds = 60, burst = 10 }\n\n[routes.venice]";

    const EXTRA_ROUTE: &str = "\n[routes.extra]\nprefix = \"/extra\"\nupstream = \"https://api.extra.example\"\ncredential = \"extra\"\n\
        slot = \"basic\"\nmethods = [\"GET\"]\npaths = [\"/x\"]\nrate_limit = { requests = 1, per_seconds = 1, burst = 1 }\n";

    const EXTRA_LISTENER: &str = "\n[listeners.extra]\nunix_socket = \"/run/iron-vault/extra.sock\"\n";

    #[test]
    fn each_route_field_change_is_one_routes_line() {
        let cases = [
            ("prefix = \"/fx\"", "prefix = \"/fx2\"", "prefix /fx -> /fx2"),
            (
                "upstream = \"https://api.fx.example\"",
                "upstream = \"https://api.fx.example:8443/v2\"",
                "upstream https://api.fx.example/ -> https://api.fx.example:8443/v2",
            ),
            (
                "credential = \"fx_key\"",
                "credential = \"fx_other\"",
                "credential fx_key -> fx_other",
            ),
            (
                "slot = { query = \"access_key\" }",
                "slot = \"basic\"",
                "slot query access_key -> basic",
            ),
            (
                "methods = [\"GET\"]\npaths = [\"/latest\"",
                "methods = [\"GET\", \"POST\"]\npaths = [\"/latest\"",
                "methods GET -> GET, POST",
            ),
            (
                "\"/historical/**\"]",
                "\"/historical/**\", \"/rates\"]",
                "paths /historical/**, /latest -> /historical/**, /latest, /rates",
            ),
            (
                "requests = 60, per_seconds = 60, burst = 10 }\n\n[routes.venice]",
                "requests = 30, per_seconds = 60, burst = 10 }\n\n[routes.venice]",
                "rate limit 60 per 60s burst 10 -> 30 per 60s burst 10",
            ),
            (
                FX_LIMIT_END,
                &FX_LIMIT_END.replace("\n\n", "\nconfirm = \"touch\"\n\n"),
                "confirm none -> touch",
            ),
            (
                FX_LIMIT_END,
                &FX_LIMIT_END.replace("\n\n", "\nca_file = \"/etc/iron-vault/ca/fx.pem\"\n\n"),
                "ca file none -> \"/etc/iron-vault/ca/fx.pem\"",
            ),
        ];
        cases.iter().for_each(|(from, to, detail)| {
            assert_eq!(lines(&edited(from, to)), ["routes:", &format!("  ~ fx: {detail}")]);
        });
    }

    #[test]
    fn route_added_and_removed_are_one_line_each() {
        let (base, with_extra) = (spec(), config(&format!("{SPEC_EXAMPLE}{EXTRA_ROUTE}")));
        let added = summarize(Some(&base), &with_extra).render();
        assert!(added.starts_with("routes:\n  + extra: prefix /extra, upstream https://api.extra.example/, credential extra, slot basic"));
        assert_eq!(added.lines().count(), 2);
        assert_eq!(summarize(Some(&with_extra), &base).render(), "routes:\n  - extra\n");
    }

    #[test]
    fn listener_added_and_removed_are_one_line_each() {
        let (base, with_extra) = (spec(), config(&format!("{SPEC_EXAMPLE}{EXTRA_LISTENER}")));
        let added = "listeners:\n  + extra: endpoint unix socket \"/run/iron-vault/extra.sock\", token header default\n";
        assert_eq!(summarize(Some(&base), &with_extra).render(), added);
        assert_eq!(summarize(Some(&with_extra), &base).render(), "listeners:\n  - extra\n");
    }

    #[test]
    fn hostile_ca_file_cannot_forge_a_line_or_a_field() {
        let ca = "ca_file = \"/x\\n  ~ fx-mcp: token changed; credential fx_key -> evil\"\n";
        let pending = edited(FX_LIMIT_END, &FX_LIMIT_END.replace("\n\n", &format!("\n{ca}\n")));
        let out = lines(&pending);
        assert_eq!(out.len(), 2, "{out:?}");
        assert_eq!(
            out[1],
            "  ~ fx: ca file none -> \"/x\\n  ~ fx-mcp: token changed; credential fx_key -> evil\""
        );
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

    fn with_recovery(days: Option<i64>) -> ValidatedConfig {
        let table = days.map_or_else(String::new, |d| format!("\n[recovery]\nreminder_days = {d}\n"));
        config(&format!("{SPEC_EXAMPLE}{table}"))
    }

    fn recovery_lines(active: &ValidatedConfig, pending: &ValidatedConfig) -> Vec<String> {
        let summary = summarize(Some(active), pending);
        summary
            .render()
            .lines()
            .skip_while(|l| *l != "recovery:")
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn recovery_added_changed_and_removed_each_give_one_line() {
        assert_eq!(
            recovery_lines(&spec(), &with_recovery(Some(30))),
            ["recovery:", "  ~ reminder: every default -> 30 days"]
        );
        assert_eq!(
            recovery_lines(&with_recovery(Some(30)), &with_recovery(Some(200))),
            ["recovery:", "  ~ reminder: every 30 -> 200 days"]
        );
        assert_eq!(
            recovery_lines(&with_recovery(Some(30)), &spec()),
            ["recovery:", "  ~ reminder: every 30 -> default days"]
        );
        let headline = summarize(Some(&spec()), &with_recovery(Some(30))).headline();
        assert!(headline.ends_with("logging: none; recovery: 1 changed"), "{headline}");
    }

    #[test]
    fn explicit_ninety_and_an_absent_table_differ() {
        assert_eq!(
            recovery_lines(&spec(), &with_recovery(Some(90))),
            ["recovery:", "  ~ reminder: every default -> 90 days"]
        );
        assert_eq!(
            recovery_lines(&with_recovery(Some(90)), &spec()),
            ["recovery:", "  ~ reminder: every 90 -> default days"]
        );
    }

    #[test]
    fn unchanged_recovery_interval_gives_no_line() {
        [(None, None), (Some(30), Some(30)), (Some(90), Some(90))]
            .into_iter()
            .for_each(|(old, new)| {
                let summary = summarize(Some(&with_recovery(old)), &with_recovery(new));
                assert!(!summary.render().contains("recovery:"));
                assert!(summary.headline().ends_with("recovery: none"));
            });
    }

    #[test]
    fn recovery_follows_logging_in_the_fixed_order() {
        let pending = config(&format!(
            "{SPEC_EXAMPLE}\n[logging]\ndestination = \"stdout\"\n[recovery]\nreminder_days = 30\n"
        ));
        let text = summarize(Some(&spec()), &pending).render();
        let (logging, recovery) = (text.find("logging:"), text.find("recovery:"));
        assert!(logging.is_some() && recovery.is_some(), "both sections present: {text}");
        assert!(logging < recovery);
        assert_eq!(text, summarize(Some(&spec()), &pending).render());
    }

    #[test]
    fn headline_counts_each_section() {
        let pending = config(&format!("{SPEC_EXAMPLE}\n[limits]\nmax_connections = 512\n").replace("\"/latest\"", "\"/new\""));
        assert_eq!(
            summarize(Some(&spec()), &pending).headline(),
            "callers: none; route grants: none; routes: 1 changed; listeners: none; limits: 1 changed; logging: none; recovery: none"
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

    fn with_logging(setting: &str) -> ValidatedConfig {
        config(&format!("{SPEC_EXAMPLE}\n[logging]\ndestination = \"{setting}\"\n"))
    }

    fn logging_lines(active: &ValidatedConfig, pending: &ValidatedConfig) -> Vec<String> {
        summarize(Some(active), pending).render().lines().map(str::to_owned).collect()
    }

    #[test]
    fn default_destination_is_not_a_change() {
        assert_eq!(summarize(Some(&spec()), &spec()).headline().matches("logging: none").count(), 1);
        assert_eq!(
            logging_lines(&with_logging("stdout"), &with_logging("stdout")),
            ["no policy change; text changed"]
        );
    }

    #[test]
    fn configured_directory_is_old_to_new_with_logrotate_reminder() {
        assert_eq!(
            logging_lines(&spec(), &with_logging("/srv/iv-log")),
            [
                "logging:",
                "  ~ destination: default -> \"/srv/iv-log\"; add a logrotate rule for the new directory"
            ]
        );
    }

    #[test]
    fn stdout_has_no_logrotate_reminder() {
        assert_eq!(
            logging_lines(&spec(), &with_logging("stdout")),
            ["logging:", "  ~ destination: default -> stdout"]
        );
    }

    #[test]
    fn moving_between_destinations_shows_both() {
        assert_eq!(
            logging_lines(&with_logging("stdout"), &with_logging("/srv/iv-log")),
            [
                "logging:",
                "  ~ destination: stdout -> \"/srv/iv-log\"; add a logrotate rule for the new directory"
            ]
        );
        assert_eq!(
            logging_lines(&with_logging("/srv/iv-log"), &spec()),
            ["logging:", "  ~ destination: \"/srv/iv-log\" -> default"]
        );
    }

    #[test]
    fn unprintable_characters_in_the_path_are_escaped() {
        // Control characters are rejected when the config is parsed; bidi overrides are not, and must not reach the owner raw.
        let out = logging_lines(&spec(), &with_logging("/srv/a\u{202e}b"));
        assert_eq!(out.len(), 2, "{out:?}");
        assert!(out[1].contains("\"/srv/a\\u{202e}b\""), "{out:?}");
        assert!(!out.concat().contains('\u{202e}'));
    }
}
