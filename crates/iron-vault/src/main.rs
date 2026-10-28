//! Iron Vault service binary: HTTP and admin interfaces, CLI client, config loading, deployment adapters, response
//! scrubbing, logging, and notifications.

mod hardening;

fn main() -> anyhow::Result<()> {
    init_logging()?;
    // Hardening comes before anything that could hold a secret, so no secret is ever dumpable or swappable.
    let report = hardening::harden_process();
    hardening::log_report(&report);
    Ok(())
}

/// Installs a human-readable subscriber on stderr at INFO and above, without colour codes, because systemd and Docker
/// capture stderr. EP-26 replaces this with the configurable audit and logging design.
fn init_logging() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .try_init()
        .map_err(|e| anyhow::anyhow!("could not install the log subscriber: {e}"))
}
