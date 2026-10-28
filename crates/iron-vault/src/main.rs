//! Iron Vault service binary: HTTP and admin interfaces, CLI client, config loading, deployment adapters, response
//! scrubbing, logging, and notifications.

mod hardening;

fn main() -> anyhow::Result<()> {
    // Hardening comes before anything that could hold a secret, so no secret is ever dumpable or swappable.
    let report = hardening::harden_process();
    hardening::log_report(&report);
    Ok(())
}
