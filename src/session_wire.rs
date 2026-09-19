//! A minimal, hand-picked mirror of mitos-session's `ipc::messages` wire
//! types -- just enough to send `RequestElevation` and `ListSessions`
//! and decode their replies, without depending on the `mitos-session`
//! crate itself (see `Cargo.toml`'s comment on why: that crate would
//! drag `pam`/`nix`/`calloop` into this daemon for functionality it
//! never uses).
//!
//! This is a direct copy of mitos-settings' own `grants::session_wire`
//! module -- same wire, same reasoning, same crate versions pinned for
//! the same reason. Kept as two separately-maintained copies rather
//! than a shared library crate, matching this project's own established
//! stance on duplicating `logging.rs` rather than sharing it (see that
//! module's doc comment): every MITOS binary stays independently
//! buildable.
//!
//! **These types MUST stay byte-for-byte compatible with
//! mitos-session's real `src/ipc/messages.rs`, `src/elevation/action.rs`,
//! and `src/authentication/result.rs`.** `bincode` (pinned to the same
//! `"1.3"` mitos-session uses, see `Cargo.toml`) encodes enum variants
//! by ordinal position and structs by field order, not by name -- so
//! every enum here lists *every* variant mitos-session's real one has,
//! in the *same order*, even variants this crate never constructs or
//! reads, and every field is declared in the same order with the same
//! type. If mitos-session's wire types ever change, these have to
//! change to match, by hand -- there is no shared source of truth
//! enforcing it, and no test here can fully cover that: the tests in
//! this module prove these types round-trip consistently *with
//! themselves* (real bugs in the shapes below), not that they still
//! match mitos-session's real ones (which would need a running
//! mitos-session to check against, and this crate can't assume one
//! exists at build or test time).

use serde::{Deserialize, Serialize};
use std::time::SystemTime;

pub type SessionId = u32;
pub type ElevationRequestId = u64;

// --- authentication::AuthOutcome ---
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthOutcome {
    Success,
    Failure { attempts_remaining: u32 },
    LockedOut { retry_after_secs: u64 },
    Error(String),
    Cancelled,
}

// --- elevation::{ElevationRisk, ElevationAction, ElevationResponse} ---
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ElevationRisk {
    Elevated,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElevationAction {
    pub requesting_app: String,
    pub description: String,
    pub risk: ElevationRisk,
    pub duration_label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ElevationResponse {
    Password(String),
    Cancelled,
}

// --- lock::{LockReason, InhibitWhat, InhibitMode} ---
// Only needed so `Request`/`Event` below have valid field types for
// variants this client never constructs or inspects the contents of --
// see this module's doc comment on why full fidelity is kept anyway.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum LockReason {
    Manual,
    Idle,
    Suspend,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum InhibitWhat {
    Idle,
    Lock,
    Suspend,
    Shutdown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum InhibitMode {
    Block,
    Delay,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InhibitorInfo {
    pub id: u64,
    pub what: InhibitWhat,
    pub who: String,
    pub why: String,
    pub mode: InhibitMode,
}

// --- session::SessionType ---
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SessionType {
    Wayland,
    X11,
    Tty,
}

// --- ipc::messages::SessionInfo ---
// This is the one reply payload besides AuthOutcome this client
// actually reads field-by-field (`session_client::find_session_id`
// needs `id` and `uid`) -- every field has to be here, in order, even
// the ones nothing here reads, for the struct's total byte layout to
// match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: SessionId,
    pub uid: u32,
    pub user_name: String,
    pub seat_id: String,
    pub session_type: SessionType,
    pub state: String,
    pub locked: bool,
    pub created_at: SystemTime,
}

// --- ipc::messages::Request ---
// Every variant mitos-session's real `Request` has, in the same
// order. This client only ever constructs `ListSessions` and
// `RequestElevation`; the rest exist purely to keep those two at the
// right ordinal position.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    CreateSession {
        user_name: String,
        seat_id: Option<String>,
        session_type: Option<String>,
    },
    TerminateSession {
        session_id: SessionId,
    },
    RegisterCompositor {
        session_id: SessionId,
    },
    ListSessions,
    SessionStatus {
        session_id: SessionId,
    },
    LockSession {
        session_id: SessionId,
    },
    Unlock {
        session_id: SessionId,
        user_name: String,
        password: String,
    },
    ReportActivity {
        seat_id: String,
    },
    SwitchSession {
        seat_id: String,
        session_id: SessionId,
    },
    Inhibit {
        what: InhibitWhat,
        who: String,
        why: String,
        mode: InhibitMode,
    },
    ReleaseInhibit {
        inhibit_id: u64,
    },
    ListInhibitors,
    Suspend,
    Reboot,
    PowerOff,
    RequestElevation {
        session_id: SessionId,
        action: ElevationAction,
    },
    RespondElevation {
        request_id: ElevationRequestId,
        response: ElevationResponse,
    },
}

// --- ipc::messages::Response ---
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    Ok,
    Sessions(Vec<SessionInfo>),
    Session(SessionInfo),
    AuthResult(AuthOutcome),
    InhibitGranted { inhibit_id: u64 },
    Inhibitors(Vec<InhibitorInfo>),
    Error(String),
}

// --- ipc::messages::Event ---
// This client never registers as a compositor, so mitos-session
// structurally never sends it one of these. Kept fully accurate
// anyway rather than a placeholder: if that invariant is ever wrong,
// decoding fails cleanly with an error instead of either panicking or
// silently misreading bytes meant for a differently-shaped variant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    ShowLockScreen {
        session_id: SessionId,
        reason: LockReason,
    },
    HideLockScreen {
        session_id: SessionId,
    },
    AuthFeedback {
        session_id: SessionId,
        outcome: AuthOutcome,
    },
    Dim {
        seat_id: String,
    },
    Undim {
        seat_id: String,
    },
    PrepareForSleep,
    ResumedFromSleep,
    SessionActivated {
        seat_id: String,
        session_id: SessionId,
    },
    ShowElevationPrompt {
        request_id: ElevationRequestId,
        session_id: SessionId,
        action: ElevationAction,
    },
    ElevationFeedback {
        request_id: ElevationRequestId,
        outcome: AuthOutcome,
    },
    HideElevationPrompt {
        request_id: ElevationRequestId,
    },
}

// --- ipc::messages::Message ---
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    Response(Response),
    Event(Event),
}

/// Mirrors mitos-session's `ipc::protocol::MAX_MESSAGE_LEN`.
const MAX_MESSAGE_LEN: u32 = 16 * 1024 * 1024;

/// Mirrors mitos-session's `ipc::protocol::write_message`: a 4-byte
/// little-endian length prefix followed by that many bincode-encoded
/// payload bytes.
pub fn write_message<W: std::io::Write, T: Serialize>(
    writer: &mut W,
    msg: &T,
) -> std::io::Result<()> {
    let payload = bincode::serialize(msg)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let len = u32::try_from(payload.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "message too large"))?;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()
}

/// Mirrors mitos-session's `ipc::protocol::read_message`.
pub fn read_message<R: std::io::Read, T: serde::de::DeserializeOwned>(
    reader: &mut R,
) -> std::io::Result<T> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_MESSAGE_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("message of {len} bytes exceeds the {MAX_MESSAGE_LEN} byte limit"),
        ));
    }
    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload)?;
    bincode::deserialize(&payload).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn request_elevation_round_trips_through_the_real_framing() {
        let req = Request::RequestElevation {
            session_id: 7,
            action: ElevationAction {
                requesting_app: "mitos-service".into(),
                description: "Allow raw_disk for a1b2c3...".into(),
                risk: ElevationRisk::Critical,
                duration_label: "Always (until revoked)".into(),
            },
        };
        let mut buf = Vec::new();
        write_message(&mut buf, &req).unwrap();
        let decoded: Request = read_message(&mut Cursor::new(buf)).unwrap();
        match decoded {
            Request::RequestElevation { session_id, action } => {
                assert_eq!(session_id, 7);
                assert_eq!(action.requesting_app, "mitos-service");
                assert_eq!(action.risk, ElevationRisk::Critical);
            }
            other => panic!("expected RequestElevation, got {other:?}"),
        }
    }

    #[test]
    fn list_sessions_request_round_trips() {
        let mut buf = Vec::new();
        write_message(&mut buf, &Request::ListSessions).unwrap();
        let decoded: Request = read_message(&mut Cursor::new(buf)).unwrap();
        assert!(matches!(decoded, Request::ListSessions));
    }

    #[test]
    fn auth_outcome_variants_round_trip_including_the_last_one_added() {
        for outcome in [
            AuthOutcome::Success,
            AuthOutcome::Failure { attempts_remaining: 2 },
            AuthOutcome::LockedOut { retry_after_secs: 30 },
            AuthOutcome::Error("pam broke".into()),
            AuthOutcome::Cancelled,
        ] {
            let mut buf = Vec::new();
            write_message(&mut buf, &Response::AuthResult(outcome.clone())).unwrap();
            let decoded: Response = read_message(&mut Cursor::new(buf)).unwrap();
            match decoded {
                Response::AuthResult(got) => assert_eq!(got, outcome),
                other => panic!("expected AuthResult, got {other:?}"),
            }
        }
    }
}
