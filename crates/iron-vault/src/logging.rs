//! The service's log subscriber: JSON Lines records and the caps on HTTP and TLS dependency logging.
//!
//! Every record is one flat JSON object on one line ([`RecordFormat`]); JSON escapes newlines and control characters in
//! values, so no value can start a second record. The writer is a parameter, so the destination can change without
//! touching the format: [`LogFile`] appends to `iron-vault.log` in a verified log directory, [`LogStdout`] writes to
//! stdout for Docker, and either trips [`LogFailure`] on its first failed write so `serve` stops rather than run without
//! its audit log. [`install`] opens the destination and installs the subscriber on it.
//!
//! At `DEBUG` and `TRACE`, `hyper` and `h2` log frames and headers, and those headers carry the injected credential
//! (§3.7, §3.15). [`dependency_caps`] is installed as its own layer, so no global level, `RUST_LOG` value or trace
//! setting can lift it: a layer filter only ever narrows what reaches the subscriber. EP-26 must keep this layer
//! whatever logging configuration it adds.
//!
//! `reqwest` and `rustls` also log through the `log` crate. No `log` backend is installed, so those records are
//! discarded. If a future change installs a `log` bridge, the bridged records carry the same targets and the caps
//! apply to them too.

use std::fmt;

// The log file and stdout writers use rustix and tokio, which this crate depends on only on Linux.
#[cfg(target_os = "linux")]
mod destination;
#[cfg(target_os = "linux")]
mod log_file;
#[cfg(target_os = "linux")]
mod log_stdout;
mod writer;

#[cfg(target_os = "linux")]
pub use destination::{LogDestination, LogOpenError, install};
#[cfg(target_os = "linux")]
pub use log_file::{FileProblem, LOG_FILE_NAME, LogDir, LogFile};
#[cfg(target_os = "linux")]
pub use log_stdout::{JOURNAL_STREAM, LogStdout};
pub use writer::LogFailure;

use tracing::{Event, Subscriber};
use tracing_subscriber::{
    filter::{LevelFilter, Targets},
    fmt::{
        FmtContext, FormatEvent, FormatFields, MakeWriter,
        format::{Format, Json, JsonFields, Writer},
    },
    layer::SubscriberExt,
    registry::LookupSpan,
    util::{SubscriberInitExt, TryInitError},
};

use crate::deployment::DeploymentProfile;

/// The record schema's version, written as `schema_version` in every record. It rises when a field or event name is
/// removed or renamed or a field's type changes, so a dashboard can pin the version it was written for.
pub const SCHEMA_VERSION: u32 = 1;

/// Dependencies whose verbose logs can carry raw HTTP traffic or TLS secrets.
pub const CAPPED_TARGETS: [&str; 8] = ["hyper", "hyper_util", "h2", "http", "reqwest", "rustls", "tokio_rustls", "webpki"];

/// The highest level a capped dependency may log at.
pub const DEPENDENCY_CAP: LevelFilter = LevelFilter::WARN;

/// A filter capping each of [`CAPPED_TARGETS`] (and its sub-modules) at [`DEPENDENCY_CAP`]; every other target passes.
pub fn dependency_caps() -> Targets {
    CAPPED_TARGETS
        .iter()
        .fold(Targets::new().with_default(LevelFilter::TRACE), |caps, target| {
            caps.with_target(*target, DEPENDENCY_CAP)
        })
}

/// Formats a record as `tracing-subscriber`'s flat JSON and puts the constant fields first.
///
/// The constants (`service`, `service_version`, `schema_version`, `deployment_profile`) are the same in every record,
/// diagnostic ones included, so they are added here rather than by each emitter. The JSON formatter's own output is
/// reused, so escaping stays its job.
pub struct RecordFormat {
    inner: Format<Json>,
    constants: String,
}

impl RecordFormat {
    /// Builds the formatter for a deployment profile. The constants' text is made once; every value is plain ASCII with
    /// nothing to escape (the crate version is semver).
    pub fn new(profile: DeploymentProfile) -> Self {
        let inner = tracing_subscriber::fmt::format()
            .json()
            .flatten_event(true)
            .with_current_span(false)
            .with_span_list(false);
        let constants = format!(
            r#""service":"iron-vault","service_version":"{}","schema_version":{SCHEMA_VERSION},"deployment_profile":"{}","#,
            env!("CARGO_PKG_VERSION"),
            profile.label()
        );
        Self { inner, constants }
    }
}

impl<S, N> FormatEvent<S, N> for RecordFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'w> FormatFields<'w> + 'static,
{
    fn format_event(&self, ctx: &FmtContext<'_, S, N>, mut writer: Writer<'_>, event: &Event<'_>) -> fmt::Result {
        let mut record = String::new();
        self.inner.format_event(ctx, Writer::new(&mut record), event)?;
        // The JSON formatter always opens an object and writes at least `timestamp` and `level`.
        let body = record.strip_prefix('{').ok_or(fmt::Error)?;
        write!(writer, "{{{}{body}", self.constants)
    }
}

/// The service's subscriber: records at `INFO` and above written to `writer`, with [`dependency_caps`] as its own layer.
///
/// `log_internal_errors(false)` keeps the formatter from writing a plain-text "unable to format" line into the log,
/// which would break JSON Lines.
pub fn subscriber<W>(writer: W, profile: DeploymentProfile) -> impl Subscriber + Send + Sync
where
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    let output = tracing_subscriber::fmt::layer()
        .event_format(RecordFormat::new(profile))
        .fmt_fields(JsonFields::new())
        .with_writer(writer)
        .with_ansi(false)
        .log_internal_errors(false);
    tracing_subscriber::registry()
        .with(LevelFilter::INFO)
        .with(dependency_caps())
        .with(output)
}

/// Installs [`subscriber`] as the global default.
pub fn init<W>(writer: W, profile: DeploymentProfile) -> Result<(), TryInitError>
where
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    subscriber(writer, profile).try_init()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use tracing::Level;

    #[test]
    fn capped_targets_allow_warn_but_not_debug_or_trace() {
        let caps = dependency_caps();
        CAPPED_TARGETS.iter().for_each(|target| {
            assert!(!caps.would_enable(target, &Level::TRACE), "{target} TRACE");
            assert!(!caps.would_enable(target, &Level::DEBUG), "{target} DEBUG");
            assert!(caps.would_enable(target, &Level::WARN), "{target} WARN");
        });
    }

    #[test]
    fn capped_sub_module_is_capped() {
        let caps = dependency_caps();
        assert!(!caps.would_enable("hyper::proto::h1", &Level::DEBUG));
        assert!(caps.would_enable("hyper::proto::h1", &Level::WARN));
    }

    #[test]
    fn uncapped_target_passes_through() {
        let caps = dependency_caps();
        assert!(caps.would_enable("iron_vault::admin", &Level::INFO));
        assert!(caps.would_enable("iron_vault::admin", &Level::TRACE));
    }

    #[test]
    fn caps_hold_under_a_trace_global_level() {
        let subscriber = tracing_subscriber::registry().with(LevelFilter::TRACE).with(dependency_caps());
        tracing::subscriber::with_default(subscriber, || {
            assert!(!tracing::enabled!(target: "hyper", Level::DEBUG));
            assert!(!tracing::enabled!(target: "h2", Level::TRACE));
            assert!(tracing::enabled!(target: "hyper", Level::WARN));
            assert!(tracing::enabled!(target: "iron_vault", Level::TRACE));
        });
    }

    #[test]
    fn init_installs_no_log_backend() {
        assert!(init(std::io::sink, DeploymentProfile::Protected).is_ok());
        assert_eq!(log::max_level(), log::LevelFilter::Off);
    }

    /// A writer that appends each record to a shared buffer.
    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().map_err(|_| std::io::Error::other("poisoned"))?.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Capture {
        type Writer = Capture;

        fn make_writer(&'a self) -> Capture {
            self.clone()
        }
    }

    fn capture(emit: impl FnOnce()) -> String {
        let out = Capture::default();
        tracing::subscriber::with_default(subscriber(out.clone(), DeploymentProfile::Protected), emit);
        let bytes = out.0.lock().map(|b| b.clone()).unwrap_or_default();
        String::from_utf8(bytes).unwrap_or_default()
    }

    fn parse(line: &str) -> serde_json::Value {
        serde_json::from_str(line).expect("valid JSON")
    }

    #[test]
    fn a_record_is_one_json_line_with_the_constant_fields() {
        let out = capture(|| tracing::info!(event = "service.started", "started"));
        assert_eq!(out.lines().count(), 1);
        assert!(out.ends_with('\n'));
        let record = parse(&out);
        assert_eq!(record["service"], "iron-vault");
        assert_eq!(record["service_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(record["schema_version"], 1);
        assert_eq!(record["deployment_profile"], "protected");
        assert_eq!(record["level"], "INFO");
        assert_eq!(record["event"], "service.started");
        assert_eq!(record["message"], "started");
        assert!(record["target"].is_string());
        assert!(!out.contains("\u{1b}"));
        ["span", "spans"].iter().for_each(|key| assert!(record.get(key).is_none(), "{key}"));
    }

    #[test]
    fn timestamp_is_rfc3339_utc_with_fractional_seconds() {
        let record = parse(&capture(|| tracing::info!("x")));
        let stamp = record["timestamp"].as_str().expect("timestamp string");
        assert!(stamp.ends_with('Z') && stamp.contains('.') && stamp.contains('T'), "{stamp}");
    }

    #[test]
    fn spans_do_not_change_the_record_shape() {
        let out = capture(|| tracing::info_span!("request", id = 7).in_scope(|| tracing::info!("inside")));
        let record = parse(&out);
        ["span", "spans"].iter().for_each(|key| assert!(record.get(key).is_none(), "{key}"));
    }

    #[test]
    fn newlines_and_control_characters_stay_on_one_line() {
        let value = "a\nb\r\u{7}\u{1b}[31m\"{\"event\":\"forged\"}";
        let out = capture(|| tracing::info!(detail = value, "m"));
        assert_eq!(out.lines().count(), 1);
        assert_eq!(parse(&out)["detail"], value);
    }

    #[test]
    fn a_capped_target_at_debug_writes_no_record() {
        let out = capture(|| {
            tracing::debug!(target: "hyper::proto::h1", "headers");
            tracing::trace!(target: "h2", "frame");
        });
        assert!(out.is_empty(), "{out}");
    }

    #[test]
    fn a_capped_target_at_warn_still_writes() {
        assert_eq!(capture(|| tracing::warn!(target: "hyper", "w")).lines().count(), 1);
    }

    #[test]
    fn development_profile_is_named_in_every_record() {
        let out = Capture::default();
        tracing::subscriber::with_default(subscriber(out.clone(), DeploymentProfile::Development), || tracing::info!("x"));
        let text = String::from_utf8(out.0.lock().map(|b| b.clone()).unwrap_or_default()).unwrap_or_default();
        assert_eq!(parse(&text)["deployment_profile"], "development");
    }
}
