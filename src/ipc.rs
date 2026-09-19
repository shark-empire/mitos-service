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
//!   `risk.rs`) - `ASK` means no stored decision exists yet.
//! - `GRANT <sha256> <capability> <allow|deny> <once|session|always> <uid>` -
//!   records a decision on `uid`'s behalf. For a `Dangerous`/`Critical`
//!   capability (`risk::requires_elevation`), this blocks until `uid`'s
//!   own mitos-session session answers a real, password-verified
//!   elevation prompt (`session_client::request_elevation`) - which can
//!   take up to a couple of minutes, and can come back `denied: ...`
//!   (wrong password too many times, or declined) as well as `granted`.
//!   `Low`/`Moderate` apply immediately, no `uid` verification, same as
//!   every `GRANT` did before this daemon could talk to mitos-session at
//!   all - matching the permissions design's own framing of those as
//!   reversible and not worth interrupting anyone's workflow over.
//! - `REVOKE <sha256> <capability>` - removes a decision, whatever its
//!   scope, origin, or risk - revoking is never dangerous the way
//!   granting is, so it never needs elevating.
//! - `LIST` - every currently-held grant, formatted for a human reading
//!   `mitosvc-ctl list`'s output directly.
//! - `LIST-RAW` - the same data, one grant per line,
//!   `sha256|capability|decision|scope|granted_at` - for a caller (e.g.
//!   mitos-settings) that wants to parse it rather than display it
//!   verbatim; kept separate from `LIST` rather than changing that
//!   command's own format, so `mitosvc-ctl list`'s existing output
//!   doesn't change underneath anyone relying on it.
//! - `PING` - liveness check.

use crate::logging;
use crate::risk::{self, Risk};
use crate::rulebook::{self, Decision, Scope};
use crate::session_client;
use crate::session_wire::AuthOutcome;
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
        "LIST-RAW" => list_raw_response(),
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
    let (Some(sha256), Some(capability), Some(decision_str), Some(scope_str), Some(uid_str)) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return "usage: GRANT <sha256> <capability> <allow|deny> <once|session|always> <uid>\n"
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
    let uid: u32 = match uid_str.parse() {
        Ok(u) => u,
        Err(_) => return format!("error: '{uid_str}' is not a valid uid\n"),
    };

    let risk = risk::classify(capability);
    if risk::requires_elevation(risk) {
        let description = format!(
            "Allow this app to use '{capability}' ({scope_str}, risk: {})",
            risk.as_str()
        );
        match session_client::request_elevation(uid, &description, risk) {
            Ok(outcome) if outcome == AuthOutcome::Success => {
                // Verified -- fall through to actually record it below,
                // same as the Low/Moderate path never needed to ask
                // about in the first place.
            }
            Ok(outcome) => {
                logging::info(&format!(
                    "GRANT {sha256} {capability} refused: elevation not approved ({outcome:?})"
                ));
                return format!("denied: not approved ({outcome:?})\n");
            }
            Err(e) => {
                logging::error(&format!("GRANT {sha256} {capability}: {e}"));
                return format!("error: could not verify identity: {e}\n");
            }
        }
    }

    rulebook::grant(sha256, capability, decision, scope, rulebook::DEFAULT_PATH);
    logging::info(&format!(
        "GRANT {sha256} {capability} {} ({}) for uid {uid}",
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

/// Same data as `LIST`, one grant per line as
/// `sha256|capability|decision|scope|granted_at`, for a caller that
/// wants to parse it (e.g. mitos-settings) rather than display it -
/// see this module's doc comment for why it's a separate command
/// instead of changing `LIST`'s own format.
fn list_raw_response() -> String {
    let mut out = String::new();
    for g in rulebook::list() {
        let scope_str = match g.scope {
            Scope::Once => "once",
            Scope::Session => "session",
            Scope::Always => "always",
        };
        out.push_str(&format!(
            "{}|{}|{}|{}|{}\n",
            g.sha256,
            g.capability,
            g.decision.as_str(),
            scope_str,
            g.granted_at
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // These only exercise `grant_response`'s argument parsing, never
    // its success path (which would touch the real, process-global
    // rulebook `STORE` that `rulebook.rs`'s own tests also share) or
    // attempt a real elevation (which needs a live mitos-session this
    // test environment doesn't have) - every case here returns before
    // either of those.

    #[test]
    fn grant_with_too_few_arguments_is_a_usage_error() {
        assert!(grant_response("abc123 camera allow always").starts_with("usage:"));
        assert!(grant_response("").starts_with("usage:"));
    }

    #[test]
    fn grant_with_an_invalid_decision_is_rejected_before_touching_anything() {
        let resp = grant_response("abc123 camera maybe always 1000");
        assert!(resp.starts_with("error:"), "got: {resp}");
        assert!(resp.contains("allow or deny"), "got: {resp}");
    }

    #[test]
    fn grant_with_an_invalid_scope_is_rejected_before_touching_anything() {
        let resp = grant_response("abc123 camera allow forever 1000");
        assert!(resp.starts_with("error:"), "got: {resp}");
        assert!(resp.contains("once, session, or always"), "got: {resp}");
    }

    #[test]
    fn grant_with_a_non_numeric_uid_is_rejected_before_touching_anything() {
        let resp = grant_response("abc123 camera allow always not-a-uid");
        assert!(resp.starts_with("error:"), "got: {resp}");
        assert!(resp.contains("valid uid"), "got: {resp}");
    }
}
