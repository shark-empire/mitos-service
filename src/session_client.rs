//! Talks to mitos-session's real, running elevation endpoint over its
//! Unix socket - the one place this crate crosses into another
//! daemon's actual wire protocol rather than its own hand-rolled one.
//! See `session_wire`'s doc comment for the wire-compatibility
//! approach.
//!
//! **Why mitos-session accepts a request from this daemon
//! specifically.** mitos-session's own authorization
//! (`policy::security_policy::authorize` in that project) accepts
//! `RequestElevation` from exactly two things: root, or its configured
//! `[elevation].service_user`. This daemon is meant to run as - or be
//! configured as - that account (see `INTEGRATION.md`), which is the
//! whole reason mitos-session grew that config knob in the first
//! place: this is the caller it was built to expect. A non-root,
//! non-service-account process making the same request is refused
//! outright, by mitos-session's own design - letting arbitrary
//! processes trigger a real system password prompt with caller-chosen
//! display text is exactly the phishing vector that restriction
//! exists to close off. This module only ever supplies that display
//! text itself (`"mitos-service"`, plus a capability/decision
//! description it built), never anything caller-controlled from
//! whatever's on the other end of the control socket.

use crate::session_wire::{self, AuthOutcome, ElevationAction, ElevationRisk, Message, Request, Response};
use std::io;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Default location of mitos-session's socket - see that project's
/// `config::defaults`/`session.toml` (`[ipc]` section). Not
/// configurable here yet; a real deployment that relocates it would
/// need a matching change - tracked as a known gap in `SECURITY.md`.
fn default_socket_path() -> PathBuf {
    PathBuf::from("/run/mitos-session/session.sock")
}

#[derive(Debug)]
pub enum SessionClientError {
    /// Couldn't even reach mitos-session's socket - e.g. it isn't
    /// running.
    Connect(io::Error),
    /// Reached it, but the request/response exchange itself failed.
    Protocol(io::Error),
    /// mitos-session understood the request but refused it outright.
    Refused(String),
    /// No mitos-session session belongs to this uid - there's nobody
    /// to show a prompt to.
    NoSessionForUser(u32),
}

impl std::fmt::Display for SessionClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(e) => write!(f, "could not reach mitos-session: {e}"),
            Self::Protocol(e) => write!(f, "mitos-session communication error: {e}"),
            Self::Refused(msg) => write!(f, "mitos-session refused the request: {msg}"),
            Self::NoSessionForUser(uid) => {
                write!(f, "no active mitos-session session found for uid {uid}")
            }
        }
    }
}

/// Ask mitos-session to verify `uid`'s password before a grant takes
/// effect. Blocks until the person answers the resulting prompt (or
/// it's cancelled, times out, or their session ends) - which can take
/// up to mitos-session's own `[elevation].prompt_timeout_secs` (a
/// couple of minutes by default). Fine to block the calling thread:
/// `ipc::spawn_listener` hands each connection its own thread, so one
/// pending prompt only holds up the single `GRANT` call that triggered
/// it, not `PING`/`CHECK`/`LIST` from anyone else - see
/// `rulebook::grant`'s own doc comment for the parallel reasoning on
/// why the rulebook's mutex is never held across this call either.
pub fn request_elevation(
    uid: u32,
    description: &str,
    risk: crate::risk::Risk,
) -> Result<AuthOutcome, SessionClientError> {
    let socket_path = default_socket_path();
    let mut stream = connect(&socket_path)?;

    let session_id = find_session_id(&mut stream, uid)?;

    let action = ElevationAction {
        requesting_app: "mitos-service".to_string(),
        description: description.to_string(),
        risk: match risk {
            crate::risk::Risk::Critical => ElevationRisk::Critical,
            // Only Dangerous/Critical ever reach this function (see
            // `risk::requires_elevation`); Dangerous maps to Elevated.
            // Low/Moderate are mapped the same way purely so this
            // match stays exhaustive if that threshold ever changes
            // without this call site being updated to match.
            crate::risk::Risk::Dangerous | crate::risk::Risk::Moderate | crate::risk::Risk::Low => {
                ElevationRisk::Elevated
            }
        },
        duration_label: "Until revoked".to_string(),
    };

    session_wire::write_message(&mut stream, &Request::RequestElevation { session_id, action })
        .map_err(SessionClientError::Protocol)?;

    let msg: Message = session_wire::read_message(&mut stream).map_err(SessionClientError::Protocol)?;
    match msg {
        Message::Response(Response::AuthResult(outcome)) => Ok(outcome),
        Message::Response(Response::Error(e)) => Err(SessionClientError::Refused(e)),
        Message::Response(other) => Err(SessionClientError::Refused(format!(
            "unexpected reply to RequestElevation: {other:?}"
        ))),
        Message::Event(e) => Err(SessionClientError::Refused(format!(
            "unexpected unsolicited event on what should never be a registered-compositor connection: {e:?}"
        ))),
    }
}

fn connect(path: &Path) -> Result<UnixStream, SessionClientError> {
    let stream = UnixStream::connect(path).map_err(SessionClientError::Connect)?;
    // Comfortably past mitos-session's own prompt-timeout default
    // (120s), so a slow-but-healthy exchange (someone taking their
    // time reading the prompt) is never mistaken for a dead one.
    let _ = stream.set_read_timeout(Some(Duration::from_secs(180)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    Ok(stream)
}

fn find_session_id(
    stream: &mut UnixStream,
    uid: u32,
) -> Result<session_wire::SessionId, SessionClientError> {
    session_wire::write_message(stream, &Request::ListSessions).map_err(SessionClientError::Protocol)?;
    let msg: Message = session_wire::read_message(stream).map_err(SessionClientError::Protocol)?;
    match msg {
        Message::Response(Response::Sessions(sessions)) => sessions
            .into_iter()
            .find(|s| s.uid == uid)
            .map(|s| s.id)
            .ok_or(SessionClientError::NoSessionForUser(uid)),
        Message::Response(Response::Error(e)) => Err(SessionClientError::Refused(e)),
        Message::Response(other) => Err(SessionClientError::Refused(format!(
            "unexpected reply to ListSessions: {other:?}"
        ))),
        Message::Event(e) => Err(SessionClientError::Refused(format!(
            "unexpected unsolicited event on what should never be a registered-compositor connection: {e:?}"
        ))),
    }
}
