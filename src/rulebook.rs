//! The permission rulebook - MITOS's `permissions.db`. Owns every
//! granted or denied capability decision: `Always`-scoped ones persisted
//! to disk (`DEFAULT_PATH`), `Session`/`Once`-scoped ones kept in memory
//! only, since by definition they don't need to survive this process
//! restarting.
//!
//! Grants are keyed by **binary SHA-256, not app id**: `apps.rs` (in
//! mitos-services) generates a fresh app id per launch, so it's an
//! identifier for one running *instance*, not a stable identity for
//! "this application" across many launches. The hash is what's stable -
//! matching the MITOS permissions design's own description of an
//! "Always allow" grant: "tied to the app's binary hash, so if the
//! app's executable ever changes, the permission resets and you're
//! asked again". A capability name is looked up per exact `(hash,
//! capability)` pair - no wildcarding a grant across every capability an
//! app might ever ask for.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_PATH: &str = "/var/lib/mitos-service/permissions.db";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

impl Decision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
        }
    }

    fn parse(s: &str) -> Option<Decision> {
        match s {
            "allow" => Some(Decision::Allow),
            "deny" => Some(Decision::Deny),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Consumed after being looked up once - see `lookup`.
    Once,
    /// Valid until this process restarts. Never written to disk.
    Session,
    /// Persisted to disk; valid until explicitly revoked or the
    /// binary's hash changes (a different hash is simply a different
    /// key - see the module doc).
    Always,
}

#[derive(Debug, Clone)]
pub struct Grant {
    pub sha256: String,
    pub capability: String,
    pub decision: Decision,
    pub scope: Scope,
    pub granted_at: u64,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Default)]
struct Store {
    grants: HashMap<(String, String), Grant>,
}

static STORE: OnceLock<Mutex<Store>> = OnceLock::new();

fn store() -> &'static Mutex<Store> {
    STORE.get_or_init(|| Mutex::new(Store::default()))
}

/// Loads every persisted (`Always`-scoped) grant from `path` into
/// memory. Call once, at startup. A missing file isn't an error - it
/// just means no grants have been persisted yet, same as a freshly
/// installed system.
pub fn load(path: &str) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    let Ok(mut s) = store().lock() else { return };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(grant) = parse_line(line) {
            s.grants
                .insert((grant.sha256.clone(), grant.capability.clone()), grant);
        } else {
            crate::logging::debug(&format!("permissions.db: skipping malformed line: {line}"));
        }
    }
}

fn parse_line(line: &str) -> Option<Grant> {
    let mut parts = line.splitn(4, '|');
    let sha256 = parts.next()?.to_string();
    let capability = parts.next()?.to_string();
    let decision = Decision::parse(parts.next()?)?;
    let granted_at = parts.next()?.parse().ok()?;
    Some(Grant {
        sha256,
        capability,
        decision,
        scope: Scope::Always,
        granted_at,
    })
}

/// Writes every currently-held `Always`-scoped grant to `path`,
/// overwriting it. Called after every `grant`/`revoke` that touches an
/// `Always`-scoped entry - this rulebook is small enough (individual
/// permission decisions, not a general-purpose database) that rewriting
/// the whole file each time is simpler and safer than an append-only
/// log plus compaction, and cheap at the sizes this ever reaches.
fn persist(path: &str) {
    let Ok(s) = store().lock() else { return };
    let mut out = String::from("# MITOS permissions.db - do not edit while mitos-service is running\n");
    for grant in s.grants.values() {
        if grant.scope != Scope::Always {
            continue;
        }
        out.push_str(&format!(
            "{}|{}|{}|{}\n",
            grant.sha256,
            grant.capability,
            grant.decision.as_str(),
            grant.granted_at
        ));
    }
    if let Some(parent) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, out);
}

/// Records a new decision. `Once`/`Session` grants are kept in memory
/// only; an `Always` grant is also immediately persisted to `path`.
pub fn grant(sha256: &str, capability: &str, decision: Decision, scope: Scope, path: &str) {
    let g = Grant {
        sha256: sha256.to_string(),
        capability: capability.to_string(),
        decision,
        scope,
        granted_at: now(),
    };
    if let Ok(mut s) = store().lock() {
        s.grants
            .insert((sha256.to_string(), capability.to_string()), g);
    }
    if scope == Scope::Always {
        persist(path);
    }
}

/// Removes any grant for `(sha256, capability)`, wherever it came from.
/// Persists the change if an `Always`-scoped grant was actually removed.
pub fn revoke(sha256: &str, capability: &str, path: &str) {
    let removed_persisted = if let Ok(mut s) = store().lock() {
        s.grants
            .remove(&(sha256.to_string(), capability.to_string()))
            .is_some_and(|g| g.scope == Scope::Always)
    } else {
        false
    };
    if removed_persisted {
        persist(path);
    }
}

/// Looks up the current decision for `(sha256, capability)`, if any. A
/// `Once`-scoped grant is consumed (removed) by this call, whatever the
/// result - the next check for the same pair finds nothing and falls
/// through to asking again, matching the permissions design's own
/// definition of "Allow once".
pub fn lookup(sha256: &str, capability: &str) -> Option<Decision> {
    let Ok(mut s) = store().lock() else {
        return None;
    };
    let key = (sha256.to_string(), capability.to_string());
    match s.grants.get(&key) {
        Some(g) if g.scope == Scope::Once => {
            let decision = g.decision;
            s.grants.remove(&key);
            Some(decision)
        }
        Some(g) => Some(g.decision),
        None => None,
    }
}

/// Every currently-held grant, for `mitosvc-ctl list`/audit purposes.
/// Doesn't consume any `Once`-scoped grants (unlike `lookup`) - this is
/// a read-only listing, not a check.
pub fn list() -> Vec<Grant> {
    store()
        .lock()
        .map(|s| s.grants.values().cloned().collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    // Global store (see STORE above), same reasoning as
    // mitos-services' journal.rs tests for why concurrent `#[test]`
    // functions touching it need to be serialized against each other.
    static TEST_LOCK: StdMutex<()> = StdMutex::new(());

    fn reset() {
        if let Ok(mut s) = store().lock() {
            s.grants.clear();
        }
    }

    #[test]
    fn grant_then_lookup_round_trips() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset();
        grant("abc123", "camera", Decision::Allow, Scope::Session, "/tmp/does-not-matter");
        assert_eq!(lookup("abc123", "camera"), Some(Decision::Allow));
    }

    #[test]
    fn unknown_pair_looks_up_to_none() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset();
        assert_eq!(lookup("no-such-hash", "camera"), None);
    }

    #[test]
    fn once_scoped_grant_is_consumed_after_one_lookup() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset();
        grant("abc123", "microphone", Decision::Deny, Scope::Once, "/tmp/does-not-matter");
        assert_eq!(lookup("abc123", "microphone"), Some(Decision::Deny));
        assert_eq!(lookup("abc123", "microphone"), None);
    }

    #[test]
    fn session_scoped_grant_survives_repeated_lookups() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset();
        grant("abc123", "location", Decision::Allow, Scope::Session, "/tmp/does-not-matter");
        assert_eq!(lookup("abc123", "location"), Some(Decision::Allow));
        assert_eq!(lookup("abc123", "location"), Some(Decision::Allow));
    }

    #[test]
    fn revoke_removes_a_grant() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset();
        grant("abc123", "camera", Decision::Allow, Scope::Session, "/tmp/does-not-matter");
        revoke("abc123", "camera", "/tmp/does-not-matter");
        assert_eq!(lookup("abc123", "camera"), None);
    }

    #[test]
    fn parses_a_well_formed_line() {
        let g = parse_line("abc123|raw_disk|allow|1700000000").unwrap();
        assert_eq!(g.sha256, "abc123");
        assert_eq!(g.capability, "raw_disk");
        assert_eq!(g.decision, Decision::Allow);
        assert_eq!(g.granted_at, 1700000000);
        assert_eq!(g.scope, Scope::Always);
    }

    #[test]
    fn rejects_a_malformed_line() {
        assert!(parse_line("not enough fields").is_none());
        assert!(parse_line("abc123|raw_disk|not-a-decision|1700000000").is_none());
        assert!(parse_line("abc123|raw_disk|allow|not-a-number").is_none());
    }

    #[test]
    fn persisted_grants_survive_a_save_and_load_round_trip() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset();
        let dir = std::env::temp_dir().join(format!(
            "mitos-service-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let path = dir.join("permissions.db");
        let path = path.to_str().unwrap();

        grant("hash-a", "raw_disk", Decision::Allow, Scope::Always, path);
        // A Session-scoped grant should NOT show up after a reload -
        // only Always-scoped ones are persisted.
        grant("hash-b", "camera", Decision::Deny, Scope::Session, path);

        reset(); // simulate a restart: drop everything held in memory
        load(path);

        assert_eq!(lookup("hash-a", "raw_disk"), Some(Decision::Allow));
        assert_eq!(lookup("hash-b", "camera"), None);

        let _ = std::fs::remove_dir_all(dir);
    }
}
