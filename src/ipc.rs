//! The control socket - `/run/mitos-service/control.sock`, same
//! transport shape as mitos-services' own `ipc.rs` (one line in, one
//! line or block of lines back, disconnect): a plain newline-delimited
//! text protocol, not JSON, for the same reason that crate gives -
//! there's no need for a serialization crate for a handful of simple
//! commands.
//!
//! Commands:
//! - `CHECK <sha256> <capability>` - the one mitos-services' `apps.rs`
//!   (or, eventually, mitos-kernel directly) calls before letting an app
//!   do something sensitive. Replies `ALLOW`, `DENY`, or `ASK <risk>`
//!   (`<risk>` is `low`/`moderate`/`dangerous`/`critical` - see
//!   `risk.rs`) - `ASK` means no stored decision exists yet and this
//!   daemon has no way to interactively resolve it itself (see the
//!   crate's top-level doc comment for why: that needs mitos-session and
//!   mitos-gui, neither of which exist yet). What a caller *does* with
//!   `ASK` is up to it; `mitosvc-ctl grant` is today's only way to turn
//!   an `ASK` into a stored decision.
//! - `GRANT <sha256> <capability> <allow|deny> <once|session|always>` -
//!   records a decision. Meant to be called by whatever eventually
//!   implements the real password-verified prompt flow; today, only by
//!   an administrator via `mitosvc-ctl grant`.
//! - `REVOKE <sha256> <capability>` - removes a decision, whatever its
//!   scope or origin.
//! - `LIST` - every currently-held grant, for audit/administration.
//! - `PING` - liveness check.

use crate::logging;
use crate::risk;
use crate::rulebook::{self, Decision, Scope};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};

const SOCKET_PATH: &str = "/run/mitos-service/control.sock";

/// Starts the control socket listener on its own thread. Best-effort:
/// if the socket can't be created (e.g. `/run/mitos-service` doesn't
/// exist and can't be made), this logs an error and mitos-service keeps
/// running without it rather than refusing to start - the rulebook
/// itself doesn't depend on the socket existing.
pub fn spawn_listener() {
    if let Some(parent) = std::path::Path::new(SOCKET_PATH).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::remove_file(SOCKET_PATH);

    let listener = match UnixListener::bind(SOCKET_PATH) {
        Ok(l) => l,
        Err(e) => {
            logging::error(&format!("couldn't bind {SOCKET_PATH}: {e}"));
            return;
        }
    };
    // Root-only, same reasoning as mitos-services' own control socket:
    // this is an administrative and policy-decision interface, not
    // something every process on the system should be able to reach.
    let _ = std::fs::set_permissions(SOCKET_PATH, std::fs::Permissions::from_mode(0o600));

    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || handle(stream));
        }
    });
}

fn handle(stream: UnixStream) {
    let Ok(cloned) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(cloned);
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }
    let mut writer = stream;

    let trimmed = line.trim();
    let (cmd, rest) = trimmed.split_once(' ').unwrap_or((trimmed, ""));
    let rest = rest.trim();

    let response = match cmd {
        "PING" => "PONG\n".to_string(),
        "CHECK" => check_response(rest),
        "GRANT" => grant_response(rest),
        "REVOKE" => revoke_response(rest),
        "LIST" => list_response(),
        other => format!("unknown command '{other}'\n"),
    };

    let _ = writer.write_all(response.as_bytes());
}

fn check_response(rest: &str) -> String {
    let mut parts = rest.split_whitespace();
    let (Some(sha256), Some(capability)) = (parts.next(), parts.next()) else {
        return "usage: CHECK <sha256> <capability>\n".to_string();
    };

    match rulebook::lookup(sha256, capability) {
        Some(Decision::Allow) => {
            logging::info(&format!("CHECK {sha256} {capability} -> ALLOW (stored)"));
            "ALLOW\n".to_string()
        }
        Some(Decision::Deny) => {
            logging::info(&format!("CHECK {sha256} {capability} -> DENY (stored)"));
            "DENY\n".to_string()
        }
        None => {
            let r = risk::classify(capability);
            logging::info(&format!(
                "CHECK {sha256} {capability} -> ASK (risk: {})",
                r.as_str()
            ));
            format!("ASK {}\n", r.as_str())
        }
    }
}

fn grant_response(rest: &str) -> String {
    let mut parts = rest.split_whitespace();
    let (Some(sha256), Some(capability), Some(decision_str), Some(scope_str)) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return "usage: GRANT <sha256> <capability> <allow|deny> <once|session|always>\n"
            .to_string();
    };

    let decision = match decision_str {
        "allow" => Decision::Allow,
        "deny" => Decision::Deny,
        other => return format!("error: '{other}' is not allow or deny\n"),
    };
    let scope = match scope_str {
        "once" => Scope::Once,
        "session" => Scope::Session,
        "always" => Scope::Always,
        other => return format!("error: '{other}' is not once, session, or always\n"),
    };

    rulebook::grant(sha256, capability, decision, scope, rulebook::DEFAULT_PATH);
    logging::info(&format!(
        "GRANT {sha256} {capability} {} ({})",
        decision.as_str(),
        scope_str
    ));
    "granted\n".to_string()
}

fn revoke_response(rest: &str) -> String {
    let mut parts = rest.split_whitespace();
    let (Some(sha256), Some(capability)) = (parts.next(), parts.next()) else {
        return "usage: REVOKE <sha256> <capability>\n".to_string();
    };
    rulebook::revoke(sha256, capability, rulebook::DEFAULT_PATH);
    logging::info(&format!("REVOKE {sha256} {capability}"));
    "revoked\n".to_string()
}

fn list_response() -> String {
    let grants = rulebook::list();
    if grants.is_empty() {
        return "no grants\n".to_string();
    }
    let mut lines = vec![format!("{} grant(s):", grants.len())];
    for g in grants {
        let scope_str = match g.scope {
            Scope::Once => "once",
            Scope::Session => "session",
            Scope::Always => "always",
        };
        lines.push(format!(
            "  {} {} -> {} ({}, granted {})",
            g.sha256,
            g.capability,
            g.decision.as_str(),
            scope_str,
            g.granted_at
        ));
    }
    lines.push(String::new());
    lines.join("\n")
}
