//! The service's log subscriber and the caps on HTTP and TLS dependency logging.
//!
//! At `DEBUG` and `TRACE`, `hyper` and `h2` log frames and headers, and those headers carry the injected credential
//! (§3.7, §3.15). [`dependency_caps`] is installed as its own layer, so no global level, `RUST_LOG` value or trace
//! setting can lift it: a layer filter only ever narrows what reaches the subscriber. EP-26 must keep this layer
//! whatever logging configuration it adds.
//!
//! `reqwest` and `rustls` also log through the `log` crate. No `log` backend is installed, so those records are
//! discarded. If a future change installs a `log` bridge, the bridged records carry the same targets and the caps
//! apply to them too.

use tracing_subscriber::{
    filter::{LevelFilter, Targets},
    layer::SubscriberExt,
    util::{SubscriberInitExt, TryInitError},
};

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

/// Installs a human-readable subscriber on stderr at `INFO` and above, without colour codes because systemd and Docker
/// capture stderr, with [`dependency_caps`] as a separate layer.
pub fn init() -> Result<(), TryInitError> {
    let output = tracing_subscriber::fmt::layer().with_writer(std::io::stderr).with_ansi(false);
    tracing_subscriber::registry()
        .with(LevelFilter::INFO)
        .with(dependency_caps())
        .with(output)
        .try_init()
}

#[cfg(test)]
mod tests {
    use super::*;
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
        assert!(init().is_ok());
        assert_eq!(log::max_level(), log::LevelFilter::Off);
    }
}
