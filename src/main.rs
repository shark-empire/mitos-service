//! mitos-service — MITOS's permission policy daemon.
//!
//! This is the "brain of the permission system" the MITOS permissions
//! design describes: it owns the rulebook (`rulebook.rs`), classifies
//! how dangerous a requested capability is (`risk.rs`), and answers
//! `CHECK` requests over a control socket (`ipc.rs`) with a stored
//! decision or `ASK` when none exists.
//!
//! **What this is not, yet.** The full flow the design describes needs
//! three other components this repository doesn't build: mitos-kernel
//! (to actually intercept and report sensitive syscalls), mitos-session
//! (to verify a password before an `Always`/`Session` grant is
//! recorded), and mitos-gui (to draw a prompt no other app can fake or
//! spy on). None of those exist yet in this codebase, so:
//! - There's no enforcement here - `CHECK` only ever *answers a
//!   question*, it never blocks a syscall itself. That's mitos-kernel's
//!   job once it exists.
//! - There's no interactive prompt flow - an `ASK` response means
//!   exactly that mitos-service has nothing stored and no way to go get
//!   a decision itself. `mitosvc-ctl grant` is today's only way to turn
//!   an `ASK` into a stored decision (standing in for what a real
//!   password-verified prompt would eventually do automatically).
//! - No password is ever checked by this process, matching the design's
//!   own rule that only mitos-session may do that - there's simply no
//!   password-checking code path here at all to get wrong.
//!
//! This process itself can run as an ordinary mitos-services-supervised
//! service (see that project's `INTEGRATION.md`) - it doesn't need to be
//! PID 1 or anything special, just running before anything tries to
//! `CHECK` against it.

mod ipc;
mod logging;
mod risk;
mod rulebook;

fn main() {
    logging::init();
    apply_log_level_from_env();
    logging::info("mitos-service starting");

    rulebook::load(rulebook::DEFAULT_PATH);
    ipc::spawn_listener();

    logging::info(&format!(
        "ready - rulebook at {}, control socket up",
        rulebook::DEFAULT_PATH
    ));

    // No child processes to supervise and no in-memory state that isn't
    // already persisted synchronously on every change (see
    // `rulebook::grant`/`revoke`) - so there's nothing for this thread
    // to do but stay alive while the IPC listener thread (spawned
    // above) handles connections. A plain sleep loop is enough: SIGTERM
    // and friends terminate the process the normal way, and there's no
    // in-flight state that needs graceful draining first.
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

/// `MITOS_SERVICE_LOGLEVEL=debug` (or `error`/`warn`/`info`) - the only
/// configuration this daemon has today, so it's an environment variable
/// (set via `Environment=` in this process's own mitos-services unit
/// file - see `INTEGRATION.md`) rather than a dedicated config file
/// format for just one key. An unset or unrecognized value leaves the
/// default (`Info`) alone.
fn apply_log_level_from_env() {
    if let Ok(value) = std::env::var("MITOS_SERVICE_LOGLEVEL") {
        match logging::Level::parse(&value) {
            Some(level) => logging::set_level(level),
            None => logging::warn(&format!(
                "MITOS_SERVICE_LOGLEVEL='{value}' isn't error/warn/info/debug, ignoring"
            )),
        }
    }
}
